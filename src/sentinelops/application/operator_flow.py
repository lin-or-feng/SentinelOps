"""Explicit, read-only operator inputs for a real observability pilot."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentinelops.domain import IncidentTask, QuerySpec
from sentinelops.adapters.observability import (
    ObservabilityEvidenceTool,
    ProviderAuthorizationError,
    ProviderPayloadError,
    ProviderRateLimitError,
    ResponseTooLarge,
)
from sentinelops.privacy import scan_content


class OperatorInputError(ValueError):
    pass


def _source_failure_code(error: Exception) -> str:
    if isinstance(error, ProviderAuthorizationError):
        return "authorization_denied"
    if isinstance(error, ProviderRateLimitError):
        return "rate_limited"
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, ResponseTooLarge):
        return "response_too_large"
    if isinstance(error, ProviderPayloadError):
        return "invalid_response"
    if isinstance(error, PermissionError):
        return "source_not_allowed"
    if isinstance(error, ConnectionError):
        return "network_or_server_error"
    return "unexpected_provider_error"


def load_operator_task(path: str | Path) -> IncidentTask:
    source = Path(path)
    if source.is_symlink() or source.suffix.casefold() != ".json" or not source.is_file():
        raise OperatorInputError("task must be a regular JSON file")
    try:
        with source.open("rb") as stream:
            raw = stream.read(64 * 1024 + 1)
    except OSError as exc:
        raise OperatorInputError("unable to read task file") from exc
    try:
        unsafe = scan_content(source.name, raw)
    except UnicodeDecodeError as exc:
        raise OperatorInputError("invalid incident task") from exc
    if len(raw) > 64 * 1024 or unsafe:
        raise OperatorInputError("task failed privacy or size check")
    try:
        return IncidentTask.model_validate_json(raw)
    except (ValidationError, ValueError, UnicodeDecodeError) as exc:
        raise OperatorInputError("invalid incident task") from exc


def check_observability_sources(
    tool: ObservabilityEvidenceTool, task: IncidentTask
) -> dict[str, Any]:
    """Run one bounded read per configured source; never return evidence contents."""
    sources = sorted(tool.sources, key=lambda item: item.value)
    checks: list[dict[str, object]] = []
    for source in sources:
        spec = QuerySpec(
            incident_id=task.incident_id,
            source=source,
            service=task.service,
            limit=1,
            start_time=task.started_at - timedelta(minutes=5),
            end_time=task.started_at + timedelta(minutes=15),
        )
        try:
            evidence = tool.query(spec)
        except Exception as exc:
            checks.append({
                "source": source.value,
                "status": "failed",
                "reason_code": _source_failure_code(exc),
                "error_type": type(exc).__name__,
            })
        else:
            checks.append({
                "source": source.value,
                "status": "ok",
                "evidence_count": len(evidence),
            })
    return {
        "all_reachable": bool(checks) and all(item["status"] == "ok" for item in checks),
        "checks": checks,
        "note": "A successful read does not prove evidence relevance or diagnostic accuracy.",
    }
