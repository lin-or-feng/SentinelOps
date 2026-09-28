"""Low-cardinality operational metrics and request correlation primitives."""

from __future__ import annotations

import json
import logging
import re
import threading
import uuid
from collections import defaultdict
from contextvars import ContextVar, Token
from dataclasses import dataclass

from sentinelops.domain import EvidenceSource
from sentinelops.privacy import scan_content


PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
HTTP_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
PROVIDER_DURATION_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
INVESTIGATION_DURATION_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
MODEL_POLICY_DURATION_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")
SAFE_HTTP_METHODS = frozenset({"GET", "POST"})
SAFE_HTTP_ROUTES = frozenset(
    {
        "/healthz",
        "/readyz",
        "/metrics",
        "/v1/investigations",
        "/v1/investigations/{incident_id}",
        "/v1/audit/verify",
        "/v1/audit/events",
    }
)
SAFE_PROVIDER_STATUSES = frozenset({"ok", "error", "denied", "circuit_open"})
SAFE_INVESTIGATION_OUTCOMES = frozenset(
    {"diagnosed", "needs_human", "conflict", "idempotent_replay", "error"}
)
SAFE_MODEL_POLICY_OUTCOMES = frozenset({"accepted", "fallback", "deterministic"})
SAFE_MODEL_POLICY_REASONS = frozenset(
    {
        "proposal_accepted",
        "deterministic_terminal",
        "transport_failure",
        "invalid_structured_output",
        "response_too_large",
        "private_output_rejected",
        "source_outside_guard",
        "model_busy",
        "model_rate_limited",
        "unexpected_model_failure",
    }
)


_REQUEST_ID: ContextVar[str | None] = ContextVar("sentinelops_request_id", default=None)
_LOGGER = logging.getLogger("sentinelops.http")


def request_id_from_header(value: str | None) -> str:
    if (
        value
        and SAFE_REQUEST_ID.fullmatch(value)
        and not scan_content("request-id.txt", value.encode("utf-8"))
    ):
        return value
    return f"req-{uuid.uuid4().hex}"


def set_request_id(value: str) -> Token[str | None]:
    return _REQUEST_ID.set(value)


def reset_request_id(token: Token[str | None]) -> None:
    _REQUEST_ID.reset(token)


def current_request_id() -> str | None:
    return _REQUEST_ID.get()


def safe_http_method(value: str) -> str:
    method = value.upper()
    return method if method in SAFE_HTTP_METHODS else "OTHER"


def safe_http_route(value: str | None) -> str:
    return value if value in SAFE_HTTP_ROUTES else "unmatched"


def http_status_class(status_code: int) -> str:
    if 100 <= status_code <= 599:
        return f"{status_code // 100}xx"
    return "unknown"


def log_http_request(
    *,
    request_id: str,
    method: str,
    route: str,
    status_code: int,
    duration_seconds: float,
) -> None:
    event = {
        "duration_ms": round(max(0.0, duration_seconds) * 1_000, 3),
        "event": "http_request_completed",
        "method": safe_http_method(method),
        "request_id": request_id,
        "route": safe_http_route(route),
        "status_code": status_code,
    }
    _LOGGER.info(json.dumps(event, sort_keys=True, separators=(",", ":")))


@dataclass
class _Histogram:
    buckets: tuple[float, ...]
    counts: list[int]
    count: int = 0
    total: float = 0.0

    @classmethod
    def create(cls, buckets: tuple[float, ...]) -> "_Histogram":
        return cls(buckets=buckets, counts=[0 for _ in buckets])

    def observe(self, value: float) -> None:
        bounded = max(0.0, float(value))
        self.count += 1
        self.total += bounded
        for index, upper_bound in enumerate(self.buckets):
            if bounded <= upper_bound:
                self.counts[index] += 1


class OperationalMetrics:
    """Thread-safe fixed-schema metrics registry with no user-controlled labels."""

    def __init__(self, *, version: str) -> None:
        self.version = version
        self._lock = threading.Lock()
        self._http_requests: dict[tuple[str, str, str], int] = defaultdict(int)
        self._http_duration: dict[tuple[str, str], _Histogram] = {}
        self._provider_queries: dict[tuple[str, str], int] = defaultdict(int)
        self._provider_duration: dict[tuple[str, str], _Histogram] = {}
        self._investigations: dict[str, int] = defaultdict(int)
        self._investigation_duration: dict[str, _Histogram] = {}
        self._model_policy_decisions: dict[tuple[str, str], int] = defaultdict(int)
        self._model_policy_duration: dict[str, _Histogram] = {}
        self._circuit_open: dict[str, int] = {}

    def record_http(
        self,
        *,
        method: str,
        route: str | None,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        safe_method = safe_http_method(method)
        safe_route = safe_http_route(route)
        status_class = http_status_class(status_code)
        key = (safe_method, safe_route, status_class)
        histogram_key = (safe_method, safe_route)
        with self._lock:
            self._http_requests[key] += 1
            histogram = self._http_duration.setdefault(
                histogram_key,
                _Histogram.create(HTTP_DURATION_BUCKETS),
            )
            histogram.observe(duration_seconds)

    def record_provider(
        self,
        *,
        source: EvidenceSource,
        status: str,
        duration_seconds: float,
    ) -> None:
        safe_status = status if status in SAFE_PROVIDER_STATUSES else "error"
        key = (source.value, safe_status)
        with self._lock:
            self._provider_queries[key] += 1
            histogram = self._provider_duration.setdefault(
                key,
                _Histogram.create(PROVIDER_DURATION_BUCKETS),
            )
            histogram.observe(duration_seconds)

    def set_circuit(self, source: EvidenceSource, *, opened: bool) -> None:
        with self._lock:
            self._circuit_open[source.value] = int(opened)

    def record_investigation(self, *, outcome: str, duration_seconds: float) -> None:
        safe_outcome = outcome if outcome in SAFE_INVESTIGATION_OUTCOMES else "needs_human"
        with self._lock:
            self._investigations[safe_outcome] += 1
            histogram = self._investigation_duration.setdefault(
                safe_outcome,
                _Histogram.create(INVESTIGATION_DURATION_BUCKETS),
            )
            histogram.observe(duration_seconds)

    def record_model_policy(
        self,
        *,
        outcome: str,
        reason_code: str,
        duration_seconds: float | None,
    ) -> None:
        safe_outcome = outcome if outcome in SAFE_MODEL_POLICY_OUTCOMES else "fallback"
        safe_reason = (
            reason_code
            if reason_code in SAFE_MODEL_POLICY_REASONS
            else "unexpected_model_failure"
        )
        with self._lock:
            self._model_policy_decisions[(safe_outcome, safe_reason)] += 1
            if duration_seconds is not None:
                histogram = self._model_policy_duration.setdefault(
                    safe_outcome,
                    _Histogram.create(MODEL_POLICY_DURATION_BUCKETS),
                )
                histogram.observe(duration_seconds)

    @staticmethod
    def _escape_label(value: str) -> str:
        return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')

    @staticmethod
    def _labels(**labels: str) -> str:
        if not labels:
            return ""
        encoded = ",".join(
            f'{key}="{OperationalMetrics._escape_label(value)}"'
            for key, value in sorted(labels.items())
        )
        return "{" + encoded + "}"

    @staticmethod
    def _format_number(value: float | int) -> str:
        if isinstance(value, int):
            return str(value)
        return format(value, ".12g")

    @staticmethod
    def _copy_histogram(histogram: _Histogram) -> _Histogram:
        return _Histogram(
            buckets=histogram.buckets,
            counts=list(histogram.counts),
            count=histogram.count,
            total=histogram.total,
        )

    def _render_histogram(
        self,
        lines: list[str],
        *,
        name: str,
        help_text: str,
        values: dict[tuple[str, ...], _Histogram] | dict[str, _Histogram],
        label_names: tuple[str, ...],
    ) -> None:
        lines.extend((f"# HELP {name} {help_text}", f"# TYPE {name} histogram"))
        for raw_key, histogram in sorted(values.items(), key=lambda item: str(item[0])):
            key = raw_key if isinstance(raw_key, tuple) else (raw_key,)
            base_labels = dict(zip(label_names, key, strict=True))
            for upper_bound, count in zip(histogram.buckets, histogram.counts, strict=True):
                labels = {**base_labels, "le": self._format_number(upper_bound)}
                lines.append(f"{name}_bucket{self._labels(**labels)} {count}")
            lines.append(
                f'{name}_bucket{self._labels(**base_labels, le="+Inf")} {histogram.count}'
            )
            lines.append(
                f"{name}_sum{self._labels(**base_labels)} {self._format_number(histogram.total)}"
            )
            lines.append(f"{name}_count{self._labels(**base_labels)} {histogram.count}")

    def render_prometheus(self) -> str:
        with self._lock:
            http_requests = dict(self._http_requests)
            http_duration = {
                key: self._copy_histogram(value)
                for key, value in self._http_duration.items()
            }
            provider_queries = dict(self._provider_queries)
            provider_duration = {
                key: self._copy_histogram(value)
                for key, value in self._provider_duration.items()
            }
            investigations = dict(self._investigations)
            investigation_duration = {
                key: self._copy_histogram(value)
                for key, value in self._investigation_duration.items()
            }
            model_policy_decisions = dict(self._model_policy_decisions)
            model_policy_duration = {
                key: self._copy_histogram(value)
                for key, value in self._model_policy_duration.items()
            }
            circuit_open = dict(self._circuit_open)

        lines = [
            "# HELP sentinelops_build_info Static SentinelOps build information.",
            "# TYPE sentinelops_build_info gauge",
            f"sentinelops_build_info{self._labels(version=self.version)} 1",
            "# HELP sentinelops_http_requests_total Total HTTP requests handled.",
            "# TYPE sentinelops_http_requests_total counter",
        ]
        for (method, route, status_class), count in sorted(http_requests.items()):
            lines.append(
                "sentinelops_http_requests_total"
                f"{self._labels(method=method, route=route, status_class=status_class)} {count}"
            )
        self._render_histogram(
            lines,
            name="sentinelops_http_request_duration_seconds",
            help_text="HTTP request duration in seconds.",
            values=http_duration,
            label_names=("method", "route"),
        )
        lines.extend(
            (
                "# HELP sentinelops_provider_queries_total Total evidence provider queries.",
                "# TYPE sentinelops_provider_queries_total counter",
            )
        )
        for (source, status), count in sorted(provider_queries.items()):
            lines.append(
                "sentinelops_provider_queries_total"
                f"{self._labels(source=source, status=status)} {count}"
            )
        self._render_histogram(
            lines,
            name="sentinelops_provider_query_duration_seconds",
            help_text="Evidence provider query duration in seconds.",
            values=provider_duration,
            label_names=("source", "status"),
        )
        lines.extend(
            (
                "# HELP sentinelops_investigations_total Total investigations by outcome.",
                "# TYPE sentinelops_investigations_total counter",
            )
        )
        for outcome, count in sorted(investigations.items()):
            lines.append(
                f"sentinelops_investigations_total{self._labels(outcome=outcome)} {count}"
            )
        self._render_histogram(
            lines,
            name="sentinelops_investigation_duration_seconds",
            help_text="Investigation duration in seconds.",
            values=investigation_duration,
            label_names=("outcome",),
        )
        lines.extend(
            (
                "# HELP sentinelops_model_policy_decisions_total Total controlled model policy decisions.",
                "# TYPE sentinelops_model_policy_decisions_total counter",
            )
        )
        for (outcome, reason_code), count in sorted(model_policy_decisions.items()):
            lines.append(
                "sentinelops_model_policy_decisions_total"
                f"{self._labels(outcome=outcome, reason_code=reason_code)} {count}"
            )
        self._render_histogram(
            lines,
            name="sentinelops_model_policy_call_duration_seconds",
            help_text="Controlled model policy call duration in seconds.",
            values=model_policy_duration,
            label_names=("outcome",),
        )
        lines.extend(
            (
                "# HELP sentinelops_provider_circuit_open Whether a provider circuit is open.",
                "# TYPE sentinelops_provider_circuit_open gauge",
            )
        )
        for source, opened in sorted(circuit_open.items()):
            lines.append(
                f"sentinelops_provider_circuit_open{self._labels(source=source)} {opened}"
            )
        return "\n".join(lines) + "\n"
