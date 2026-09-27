"""Hardened read-only adapters for Prometheus, Loki and Tempo HTTP APIs."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit

import httpx
from pydantic import Field, SecretStr, model_validator

from sentinelops.domain import Evidence, EvidenceSource, QuerySpec, StrictModel
from sentinelops.privacy import redact_private_text


class ProviderPayloadError(ValueError):
    pass


class ResponseTooLarge(ProviderPayloadError):
    pass


class ProviderEndpoint(StrictModel):
    base_url: str = Field(min_length=8, max_length=500)
    allowed_hosts: frozenset[str] = Field(min_length=1)
    bearer_token: SecretStr | None = None
    tenant_id: str | None = Field(default=None, min_length=1, max_length=120)
    allow_insecure_http: bool = False
    timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    max_response_bytes: int = Field(default=1_000_000, ge=1_024, le=5_000_000)

    @model_validator(mode="after")
    def validate_endpoint(self) -> "ProviderEndpoint":
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("provider base_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("provider base_url cannot contain credentials, query or fragment")
        if parsed.scheme != "https" and not self.allow_insecure_http:
            raise ValueError("plain HTTP requires explicit allow_insecure_http=true")
        normalized_hosts = frozenset(host.casefold().strip(".") for host in self.allowed_hosts)
        if parsed.hostname.casefold().strip(".") not in normalized_hosts:
            raise ValueError("provider hostname is not in allowed_hosts")
        if self.tenant_id and any(character in self.tenant_id for character in "\r\n"):
            raise ValueError("tenant_id cannot contain header control characters")
        self.allowed_hosts = normalized_hosts
        self.base_url = self.base_url.rstrip("/")
        return self


class EvidenceProvider(Protocol):
    source: EvidenceSource

    def query(self, spec: QuerySpec) -> list[Evidence]:
        """Return normalized evidence from one read-only provider."""


class _JsonEndpointClient:
    def __init__(
        self,
        config: ProviderEndpoint,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self.config = config
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=config.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def get_json(self, path: str, params: Mapping[str, object]) -> dict[str, Any]:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("provider path must be an absolute local path")
        url = f"{self.config.base_url}{path}"
        parsed = urlsplit(url)
        if parsed.hostname is None or parsed.hostname.casefold().strip(".") not in self.config.allowed_hosts:
            raise PermissionError("provider request escaped the hostname allowlist")
        headers = {"Accept": "application/json"}
        if self.config.bearer_token is not None:
            headers["Authorization"] = f"Bearer {self.config.bearer_token.get_secret_value()}"
        if self.config.tenant_id:
            headers["X-Scope-OrgID"] = self.config.tenant_id
        try:
            with self._client.stream(
                "GET",
                url,
                params=params,
                headers=headers,
                follow_redirects=False,
                timeout=self.config.timeout_seconds,
            ) as response:
                if 300 <= response.status_code < 400:
                    raise ProviderPayloadError("provider redirects are not allowed")
                if response.status_code == 408 or response.status_code == 429 or response.status_code >= 500:
                    raise ConnectionError(f"provider returned retryable HTTP {response.status_code}")
                if response.status_code >= 400:
                    raise ProviderPayloadError(f"provider returned HTTP {response.status_code}")
                declared_size = response.headers.get("content-length")
                if declared_size and int(declared_size) > self.config.max_response_bytes:
                    raise ResponseTooLarge("provider response exceeds configured byte limit")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > self.config.max_response_bytes:
                        raise ResponseTooLarge("provider response exceeds configured byte limit")
        except httpx.TimeoutException as exc:
            raise TimeoutError("provider request timed out") from exc
        except httpx.TransportError as exc:
            raise ConnectionError("provider network request failed") from exc
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderPayloadError("provider returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ProviderPayloadError("provider response root must be an object")
        return payload


def _require_window(spec: QuerySpec) -> tuple[datetime, datetime]:
    if spec.start_time is None or spec.end_time is None:
        raise ValueError("observability queries require a bounded time window")
    return spec.start_time, spec.end_time


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _observed_at(value: object, fallback: datetime) -> datetime:
    try:
        raw = int(str(value))
        seconds = raw / 1_000_000_000 if raw > 10_000_000_000 else float(raw)
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        return fallback


def _evidence_id(provider: str, spec: QuerySpec, identity: str) -> str:
    payload = f"{provider}|{spec.incident_id}|{spec.source.value}|{identity}"
    return f"ev-{provider}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:20]}"


class PrometheusEvidenceProvider:
    source = EvidenceSource.METRICS

    def __init__(self, endpoint: ProviderEndpoint, *, client: httpx.Client | None = None) -> None:
        self.endpoint = _JsonEndpointClient(endpoint, client=client)

    def query(self, spec: QuerySpec) -> list[Evidence]:
        _, end = _require_window(spec)
        service = _escape_label(spec.service or "")
        payload = self.endpoint.get_json(
            "/api/v1/query",
            {
                "query": f'{{service="{service}"}}',
                "time": end.isoformat(),
                "limit": spec.limit,
            },
        )
        if payload.get("status") != "success":
            raise ProviderPayloadError("Prometheus query did not succeed")
        result = payload.get("data", {}).get("result", [])
        if not isinstance(result, list):
            raise ProviderPayloadError("Prometheus result must be a list")
        evidence: list[Evidence] = []
        for index, item in enumerate(result[: spec.limit]):
            if not isinstance(item, dict):
                continue
            metric = item.get("metric", {}) if isinstance(item.get("metric", {}), dict) else {}
            sample = item.get("value")
            if not isinstance(sample, list) or len(sample) < 2:
                values = item.get("values")
                sample = values[-1] if isinstance(values, list) and values else None
            if not isinstance(sample, list) or len(sample) < 2:
                continue
            metric_name = redact_private_text(str(metric.get("__name__", "metric")), max_length=120)
            value = redact_private_text(str(sample[1]), max_length=120)
            identity = f"{index}|{metric_name}|{sample[0]}"
            evidence.append(
                Evidence(
                    evidence_id=_evidence_id("prometheus", spec, identity),
                    incident_id=spec.incident_id,
                    service=spec.service or "unknown-service",
                    source=self.source,
                    observed_at=_observed_at(sample[0], end),
                    summary=f"Prometheus metric {metric_name} value={value}",
                    raw_ref=f"{self.endpoint.config.base_url}/api/v1/query#{index}",
                    reliability=0.9,
                    attributes={"metric": metric_name, "value": value},
                )
            )
        return evidence


class LokiEvidenceProvider:
    source = EvidenceSource.LOGS

    def __init__(self, endpoint: ProviderEndpoint, *, client: httpx.Client | None = None) -> None:
        self.endpoint = _JsonEndpointClient(endpoint, client=client)

    def query(self, spec: QuerySpec) -> list[Evidence]:
        start, end = _require_window(spec)
        service = _escape_label(spec.service or "")
        payload = self.endpoint.get_json(
            "/loki/api/v1/query_range",
            {
                "query": f'{{service="{service}"}} |~ "(?i)(error|timeout|fail)"',
                "start": int(start.timestamp() * 1_000_000_000),
                "end": int(end.timestamp() * 1_000_000_000),
                "limit": spec.limit,
                "direction": "backward",
            },
        )
        if payload.get("status") != "success":
            raise ProviderPayloadError("Loki query did not succeed")
        streams = payload.get("data", {}).get("result", [])
        if not isinstance(streams, list):
            raise ProviderPayloadError("Loki result must be a list")
        evidence: list[Evidence] = []
        for stream_index, stream in enumerate(streams):
            if not isinstance(stream, dict):
                continue
            labels = stream.get("stream", {}) if isinstance(stream.get("stream", {}), dict) else {}
            values = stream.get("values", [])
            if not isinstance(values, list):
                continue
            for value_index, value in enumerate(values):
                if len(evidence) >= spec.limit:
                    return evidence
                if not isinstance(value, list) or len(value) < 2:
                    continue
                timestamp, line = value[0], value[1]
                summary = redact_private_text(str(line))
                identity = f"{stream_index}|{value_index}|{timestamp}"
                safe_attributes = {
                    key: redact_private_text(str(labels[key]), max_length=120)
                    for key in ("level", "job", "service")
                    if key in labels
                }
                evidence.append(
                    Evidence(
                        evidence_id=_evidence_id("loki", spec, identity),
                        incident_id=spec.incident_id,
                        service=spec.service or "unknown-service",
                        source=self.source,
                        observed_at=_observed_at(timestamp, end),
                        summary=summary or "Loki returned an empty log line",
                        raw_ref=f"{self.endpoint.config.base_url}/loki/api/v1/query_range#{stream_index}-{value_index}",
                        reliability=0.85,
                        attributes=safe_attributes,
                    )
                )
        return evidence


class TempoEvidenceProvider:
    source = EvidenceSource.TRACES

    def __init__(self, endpoint: ProviderEndpoint, *, client: httpx.Client | None = None) -> None:
        self.endpoint = _JsonEndpointClient(endpoint, client=client)

    def query(self, spec: QuerySpec) -> list[Evidence]:
        start, end = _require_window(spec)
        service = spec.service or ""
        payload = self.endpoint.get_json(
            "/api/search",
            {
                "tags": f"service.name={json.dumps(service, ensure_ascii=False)}",
                "start": int(start.timestamp()),
                "end": int(end.timestamp()),
                "limit": spec.limit,
            },
        )
        traces = payload.get("traces", [])
        if not isinstance(traces, list):
            raise ProviderPayloadError("Tempo traces must be a list")
        evidence: list[Evidence] = []
        for index, trace in enumerate(traces[: spec.limit]):
            if not isinstance(trace, dict):
                continue
            trace_id = str(trace.get("traceID", index))
            trace_name = redact_private_text(str(trace.get("rootTraceName", "trace")), max_length=300)
            duration = trace.get("durationMs")
            start_nanos = trace.get("startTimeUnixNano")
            evidence.append(
                Evidence(
                    evidence_id=_evidence_id("tempo", spec, trace_id),
                    incident_id=spec.incident_id,
                    service=spec.service or "unknown-service",
                    source=self.source,
                    observed_at=_observed_at(start_nanos, start),
                    summary=f"Tempo trace {trace_name} duration_ms={duration}",
                    raw_ref=f"{self.endpoint.config.base_url}/api/traces/{trace_id}",
                    reliability=0.9,
                    attributes={"duration_ms": duration},
                )
            )
        return evidence


class ObservabilityEvidenceTool:
    name = "observability_http"
    read_only = True

    def __init__(self, providers: list[EvidenceProvider]) -> None:
        sources = [provider.source for provider in providers]
        if len(sources) != len(set(sources)):
            raise ValueError("duplicate observability provider source")
        self._providers = {provider.source: provider for provider in providers}
        if not self._providers:
            raise ValueError("at least one observability provider is required")

    @property
    def sources(self) -> frozenset[EvidenceSource]:
        return frozenset(self._providers)

    def query(self, spec: QuerySpec) -> list[Evidence]:
        provider = self._providers.get(spec.source)
        if provider is None:
            raise PermissionError(f"observability source is not configured: {spec.source.value}")
        return provider.query(spec)


def observability_tool_from_env(
    environ: Mapping[str, str] | None = None,
) -> ObservabilityEvidenceTool:
    values = os.environ if environ is None else environ
    allowed_hosts = frozenset(
        host.strip() for host in values.get("SENTINELOPS_ALLOWED_OBSERVABILITY_HOSTS", "").split(",")
        if host.strip()
    )
    if not allowed_hosts:
        raise ValueError("SENTINELOPS_ALLOWED_OBSERVABILITY_HOSTS is required")
    allow_http = values.get("SENTINELOPS_ALLOW_INSECURE_HTTP") == "1"
    tenant_id = values.get("SENTINELOPS_OBSERVABILITY_TENANT") or None
    providers: list[EvidenceProvider] = []
    definitions = (
        ("PROMETHEUS", PrometheusEvidenceProvider),
        ("LOKI", LokiEvidenceProvider),
        ("TEMPO", TempoEvidenceProvider),
    )
    for prefix, provider_type in definitions:
        url = values.get(f"SENTINELOPS_{prefix}_URL")
        if not url:
            continue
        token = values.get(f"SENTINELOPS_{prefix}_TOKEN")
        config = ProviderEndpoint(
            base_url=url,
            allowed_hosts=allowed_hosts,
            bearer_token=SecretStr(token) if token else None,
            tenant_id=tenant_id if prefix in {"LOKI", "TEMPO"} else None,
            allow_insecure_http=allow_http,
        )
        providers.append(provider_type(config))
    return ObservabilityEvidenceTool(providers)
