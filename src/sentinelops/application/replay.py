"""Privacy-gated offline replay for observability provider contracts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import AwareDatetime, Field, model_validator

from sentinelops.adapters.observability import (
    LokiEvidenceProvider,
    PrometheusEvidenceProvider,
    ProviderEndpoint,
    ProviderPayloadError,
    TempoEvidenceProvider,
)
from sentinelops.domain import EvidenceSource, QuerySpec, StrictModel
from sentinelops.privacy import MAX_SCANNABLE_BYTES, scan_content


MAX_SCHEMA_DEPTH = 20
MAX_SCHEMA_NODES = 10_000


class ReplayDatasetError(ValueError):
    """Raised when a replay dataset cannot be safely validated."""


class ReplayPrivacyError(ReplayDatasetError):
    """Raised without exposing the matched private value."""


class ReplayProvider(str, Enum):
    PROMETHEUS = "prometheus"
    LOKI = "loki"
    TEMPO = "tempo"


class ReplayOutcome(str, Enum):
    SUCCESS = "success"
    RETRYABLE_ERROR = "retryable_error"
    SCHEMA_ERROR = "schema_error"


PROVIDER_SOURCES = {
    ReplayProvider.PROMETHEUS: EvidenceSource.METRICS,
    ReplayProvider.LOKI: EvidenceSource.LOGS,
    ReplayProvider.TEMPO: EvidenceSource.TRACES,
}
PROVIDER_PATHS = {
    ReplayProvider.PROMETHEUS: "/api/v1/query",
    ReplayProvider.LOKI: "/loki/api/v1/query_range",
    ReplayProvider.TEMPO: "/api/search",
}


class ReplayCase(StrictModel):
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{2,79}$")
    provider: ReplayProvider
    origin: Literal["synthetic", "sanitized_export"]
    captured_at: AwareDatetime
    query: QuerySpec
    response_status: int = Field(ge=100, le=599)
    response_payload: dict[str, Any]
    expected_schema_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_outcome: ReplayOutcome
    expected_evidence_count: int = Field(default=0, ge=0, le=100)

    @model_validator(mode="after")
    def validate_provider_contract(self) -> "ReplayCase":
        if self.query.source != PROVIDER_SOURCES[self.provider]:
            raise ValueError("query source does not match replay provider")
        if self.query.start_time is None or self.query.end_time is None:
            raise ValueError("replay queries require a bounded time window")
        if self.expected_outcome != ReplayOutcome.SUCCESS and self.expected_evidence_count:
            raise ValueError("failed replay outcomes cannot expect evidence")
        return self


class ReplaySuite(StrictModel):
    schema_version: Literal["1.0"]
    privacy_policy: Literal["sentinelops-privacy-v1"]
    cases: list[ReplayCase] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def case_ids_must_be_unique(self) -> "ReplaySuite":
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("replay case_id values must be unique")
        return self


@dataclass(frozen=True)
class ReplayCaseResult:
    case_id: str
    passed: bool
    expected_outcome: str
    actual_outcome: str
    evidence_count: int
    schema_fingerprint: str
    reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


@dataclass(frozen=True)
class ReplaySummary:
    total: int
    passed: int
    failed: int
    schema_drift: int
    details: tuple[ReplayCaseResult, ...]

    @property
    def valid(self) -> bool:
        return self.failed == 0

    def as_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "schema_drift": self.schema_drift,
            "valid": self.valid,
            "details": [item.as_dict() for item in self.details],
        }


def _schema_shape(value: Any, *, depth: int, node_count: list[int]) -> object:
    if depth > MAX_SCHEMA_DEPTH:
        raise ReplayDatasetError("replay payload exceeds schema depth limit")
    node_count[0] += 1
    if node_count[0] > MAX_SCHEMA_NODES:
        raise ReplayDatasetError("replay payload exceeds schema node limit")
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        variants = {
            json.dumps(
                _schema_shape(item, depth=depth + 1, node_count=node_count),
                sort_keys=True,
                separators=(",", ":"),
            )
            for item in value
        }
        return {"array": sorted(variants)}
    if isinstance(value, dict):
        return {
            str(key): _schema_shape(item, depth=depth + 1, node_count=node_count)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    raise ReplayDatasetError("replay payload contains an unsupported JSON value")


def schema_fingerprint(payload: dict[str, Any]) -> str:
    """Hash JSON field names and value types, never the response values themselves."""

    shape = _schema_shape(payload, depth=0, node_count=[0])
    canonical = json.dumps(shape, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _raise_for_privacy_findings(path: str, payload: bytes) -> None:
    findings = scan_content(path, payload)
    if findings:
        rules = sorted({finding.rule for finding in findings})
        raise ReplayPrivacyError(f"replay dataset failed privacy rules: {', '.join(rules)}")


def load_replay_suite(path: str | Path) -> ReplaySuite:
    replay_path = Path(path)
    try:
        payload = replay_path.read_bytes()
    except OSError as exc:
        raise ReplayDatasetError("replay dataset could not be read") from exc
    if len(payload) > MAX_SCANNABLE_BYTES:
        raise ReplayDatasetError("replay dataset exceeds the privacy scan size limit")
    _raise_for_privacy_findings(replay_path.name, payload)
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReplayDatasetError("replay dataset is not valid UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise ReplayDatasetError("replay dataset root must be an object")
    try:
        return ReplaySuite.model_validate(decoded)
    except Exception as exc:
        raise ReplayDatasetError("replay dataset does not satisfy the strict contract") from exc


def _provider_for(case: ReplayCase, client: httpx.Client):
    endpoint = ProviderEndpoint(
        base_url="https://replay.invalid",
        allowed_hosts=frozenset({"replay.invalid"}),
    )
    provider_types = {
        ReplayProvider.PROMETHEUS: PrometheusEvidenceProvider,
        ReplayProvider.LOKI: LokiEvidenceProvider,
        ReplayProvider.TEMPO: TempoEvidenceProvider,
    }
    return provider_types[case.provider](endpoint, client=client)


def _run_case(case: ReplayCase) -> ReplayCaseResult:
    fingerprint = schema_fingerprint(case.response_payload)
    if fingerprint != case.expected_schema_fingerprint:
        return ReplayCaseResult(
            case_id=case.case_id,
            passed=False,
            expected_outcome=case.expected_outcome.value,
            actual_outcome="schema_drift",
            evidence_count=0,
            schema_fingerprint=fingerprint,
            reason="response structure differs from the approved fingerprint",
        )

    def handler(request: httpx.Request) -> httpx.Response:
        if (
            request.method != "GET"
            or request.url.host != "replay.invalid"
            or request.url.path != PROVIDER_PATHS[case.provider]
        ):
            raise ReplayDatasetError("provider request escaped the approved replay contract")
        return httpx.Response(case.response_status, json=case.response_payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = _provider_for(case, client)
    evidence_count = 0
    try:
        evidence_count = len(provider.query(case.query))
        actual_outcome = ReplayOutcome.SUCCESS
    except ConnectionError:
        actual_outcome = ReplayOutcome.RETRYABLE_ERROR
    except ProviderPayloadError:
        actual_outcome = ReplayOutcome.SCHEMA_ERROR
    finally:
        client.close()

    passed = (
        actual_outcome == case.expected_outcome
        and evidence_count == case.expected_evidence_count
    )
    return ReplayCaseResult(
        case_id=case.case_id,
        passed=passed,
        expected_outcome=case.expected_outcome.value,
        actual_outcome=actual_outcome.value,
        evidence_count=evidence_count,
        schema_fingerprint=fingerprint,
        reason=None if passed else "provider outcome or evidence count changed",
    )


def run_replay_suite(suite: ReplaySuite) -> ReplaySummary:
    _raise_for_privacy_findings(
        "in-memory-replay.json",
        suite.model_dump_json().encode("utf-8"),
    )
    details = tuple(_run_case(case) for case in suite.cases)
    passed = sum(item.passed for item in details)
    drift = sum(item.actual_outcome == "schema_drift" for item in details)
    return ReplaySummary(
        total=len(details),
        passed=passed,
        failed=len(details) - passed,
        schema_drift=drift,
        details=details,
    )
