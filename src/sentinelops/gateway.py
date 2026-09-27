"""Allowlisted read-only evidence gateway with retries and audit events."""

from __future__ import annotations

import time
from dataclasses import dataclass

from sentinelops.audit import AuditLog
from sentinelops.domain import Evidence, EvidenceSource, QuerySpec
from sentinelops.ports import EvidenceTool


class EvidenceToolError(RuntimeError):
    pass


@dataclass(frozen=True)
class GatewayPolicy:
    allowed_sources: frozenset[EvidenceSource]
    max_attempts: int = 2
    max_results: int = 25


class EvidenceGateway:
    def __init__(self, tool: EvidenceTool, audit: AuditLog, policy: GatewayPolicy) -> None:
        if not getattr(tool, "read_only", False):
            raise ValueError("evidence gateway accepts read-only tools only")
        self._tool = tool
        self._audit = audit
        self._policy = policy

    def query(self, spec: QuerySpec, *, trace_id: str, actor: str = "investigation-agent") -> list[Evidence]:
        if spec.source not in self._policy.allowed_sources:
            self._audit.append(
                trace_id=trace_id,
                actor=actor,
                action="tool_query",
                resource=spec.source.value,
                status="denied",
                details={"reason": "source_not_allowlisted"},
            )
            raise PermissionError(f"source is not allowlisted: {spec.source.value}")

        attempts = max(1, min(self._policy.max_attempts, 3))
        started = time.perf_counter()
        for attempt in range(1, attempts + 1):
            try:
                bounded_spec = spec.model_copy(update={"limit": min(spec.limit, self._policy.max_results)})
                evidence = self._tool.query(bounded_spec)[: self._policy.max_results]
                self._audit.append(
                    trace_id=trace_id,
                    actor=actor,
                    action="tool_query",
                    resource=spec.source.value,
                    status="ok",
                    details={
                        "attempt": attempt,
                        "result_count": len(evidence),
                        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    },
                )
                return evidence
            except (TimeoutError, ConnectionError, OSError) as exc:
                if attempt >= attempts:
                    self._audit.append(
                        trace_id=trace_id,
                        actor=actor,
                        action="tool_query",
                        resource=spec.source.value,
                        status="error",
                        details={"attempt": attempt, "error_type": type(exc).__name__},
                    )
                    raise EvidenceToolError(f"{spec.source.value} evidence query failed") from exc
                time.sleep(0.01 * attempt)
            except Exception as exc:
                self._audit.append(
                    trace_id=trace_id,
                    actor=actor,
                    action="tool_query",
                    resource=spec.source.value,
                    status="error",
                    details={
                        "attempt": attempt,
                        "error_type": type(exc).__name__,
                        "retryable": False,
                    },
                )
                raise EvidenceToolError(f"{spec.source.value} evidence query failed") from exc
        raise RuntimeError("unreachable gateway retry state")
