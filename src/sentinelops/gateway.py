"""Allowlisted read-only evidence gateway with retries and audit events."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable

from sentinelops.audit import AuditLog
from sentinelops.domain import Evidence, EvidenceSource, QuerySpec
from sentinelops.ports import EvidenceTool
from sentinelops.telemetry import OperationalMetrics


class EvidenceToolError(RuntimeError):
    pass


class EvidenceContractError(EvidenceToolError):
    pass


@dataclass(frozen=True)
class GatewayPolicy:
    allowed_sources: frozenset[EvidenceSource]
    max_attempts: int = 2
    max_results: int = 25
    failure_threshold: int = 3
    cooldown_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if self.cooldown_seconds <= 0:
            raise ValueError("cooldown_seconds must be positive")


@dataclass
class _CircuitState:
    failures: int = 0
    opened_at: float | None = None
    probe_in_progress: bool = False
    generation: int = 0


@dataclass(frozen=True)
class _CircuitDecision:
    allowed: bool
    probe: bool
    generation: int
    retry_after_seconds: float = 0.0
    denial_reason: str = ""


class EvidenceGateway:
    def __init__(
        self,
        tool: EvidenceTool,
        audit: AuditLog,
        policy: GatewayPolicy,
        *,
        clock: Callable[[], float] = time.monotonic,
        metrics: OperationalMetrics | None = None,
    ) -> None:
        if not getattr(tool, "read_only", False):
            raise ValueError("evidence gateway accepts read-only tools only")
        self._tool = tool
        self._audit = audit
        self._policy = policy
        self._clock = clock
        self._metrics = metrics
        self._circuit_lock = threading.Lock()
        self._circuits = {source: _CircuitState() for source in policy.allowed_sources}
        if metrics is not None:
            for source in policy.allowed_sources:
                metrics.set_circuit(source, opened=False)

    def _record_metrics(
        self,
        source: EvidenceSource,
        *,
        status: str,
        started: float,
        circuit_opened: bool | None = None,
    ) -> None:
        if self._metrics is None:
            return
        self._metrics.record_provider(
            source=source,
            status=status,
            duration_seconds=time.perf_counter() - started,
        )
        if circuit_opened is not None:
            self._metrics.set_circuit(source, opened=circuit_opened)

    def _reserve_circuit(self, source: EvidenceSource) -> _CircuitDecision:
        with self._circuit_lock:
            state = self._circuits.setdefault(source, _CircuitState())
            if state.opened_at is None:
                return _CircuitDecision(True, False, state.generation)
            elapsed = max(0.0, self._clock() - state.opened_at)
            retry_after = max(0.0, self._policy.cooldown_seconds - elapsed)
            if retry_after > 0:
                return _CircuitDecision(
                    False,
                    False,
                    state.generation,
                    retry_after,
                    "circuit_open",
                )
            if state.probe_in_progress:
                return _CircuitDecision(
                    False,
                    False,
                    state.generation,
                    0.0,
                    "circuit_probe_in_progress",
                )
            state.probe_in_progress = True
            return _CircuitDecision(True, True, state.generation)

    def _record_success(self, source: EvidenceSource, decision: _CircuitDecision) -> None:
        with self._circuit_lock:
            state = self._circuits[source]
            if decision.generation != state.generation:
                return
            state.failures = 0
            state.opened_at = None
            state.probe_in_progress = False
            if decision.probe:
                state.generation += 1

    def _record_failure(self, source: EvidenceSource, decision: _CircuitDecision) -> bool:
        with self._circuit_lock:
            state = self._circuits[source]
            if decision.generation != state.generation:
                return False
            state.probe_in_progress = False
            if decision.probe:
                state.failures = self._policy.failure_threshold
                state.opened_at = self._clock()
                state.generation += 1
                return True
            state.failures += 1
            if state.failures >= self._policy.failure_threshold:
                state.opened_at = self._clock()
                state.generation += 1
                return True
            return False

    def query(self, spec: QuerySpec, *, trace_id: str, actor: str = "investigation-agent") -> list[Evidence]:
        started = time.perf_counter()
        if spec.source not in self._policy.allowed_sources:
            self._record_metrics(spec.source, status="denied", started=started)
            self._audit.append(
                trace_id=trace_id,
                actor=actor,
                action="tool_query",
                resource=spec.source.value,
                status="denied",
                details={"reason": "source_not_allowlisted"},
            )
            raise PermissionError(f"source is not allowlisted: {spec.source.value}")

        circuit = self._reserve_circuit(spec.source)
        if not circuit.allowed:
            self._record_metrics(
                spec.source,
                status="circuit_open",
                started=started,
                circuit_opened=True,
            )
            self._audit.append(
                trace_id=trace_id,
                actor=actor,
                action="tool_query",
                resource=spec.source.value,
                status="degraded",
                details={
                    "reason": circuit.denial_reason,
                    "retry_after_seconds": round(circuit.retry_after_seconds, 3),
                },
            )
            raise EvidenceToolError(f"{spec.source.value} evidence circuit is open")

        attempts = max(1, min(self._policy.max_attempts, 3))
        for attempt in range(1, attempts + 1):
            try:
                bounded_spec = spec.model_copy(update={"limit": min(spec.limit, self._policy.max_results)})
                evidence = self._tool.query(bounded_spec)[: self._policy.max_results]
                if any(
                    item.incident_id != bounded_spec.incident_id
                    or item.source != bounded_spec.source
                    or (bounded_spec.service is not None and item.service != bounded_spec.service)
                    for item in evidence
                ):
                    circuit_opened = self._record_failure(spec.source, circuit)
                    self._record_metrics(
                        spec.source,
                        status="error",
                        started=started,
                        circuit_opened=circuit_opened,
                    )
                    self._audit.append(
                        trace_id=trace_id,
                        actor=actor,
                        action="tool_query",
                        resource=spec.source.value,
                        status="error",
                        details={
                            "attempt": attempt,
                            "error_type": "EvidenceContractError",
                            "retryable": False,
                            "circuit_opened": circuit_opened,
                        },
                    )
                    raise EvidenceContractError("evidence response escaped the query scope")
                self._record_success(spec.source, circuit)
                self._record_metrics(
                    spec.source,
                    status="ok",
                    started=started,
                    circuit_opened=False,
                )
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
                        "circuit_recovered": circuit.probe,
                    },
                )
                return evidence
            except (TimeoutError, ConnectionError, OSError) as exc:
                if attempt >= attempts:
                    circuit_opened = self._record_failure(spec.source, circuit)
                    self._record_metrics(
                        spec.source,
                        status="error",
                        started=started,
                        circuit_opened=circuit_opened,
                    )
                    self._audit.append(
                        trace_id=trace_id,
                        actor=actor,
                        action="tool_query",
                        resource=spec.source.value,
                        status="error",
                        details={
                            "attempt": attempt,
                            "error_type": type(exc).__name__,
                            "circuit_opened": circuit_opened,
                        },
                    )
                    raise EvidenceToolError(f"{spec.source.value} evidence query failed") from exc
                time.sleep(0.01 * attempt)
            except EvidenceContractError:
                raise
            except Exception as exc:
                circuit_opened = self._record_failure(spec.source, circuit)
                self._record_metrics(
                    spec.source,
                    status="error",
                    started=started,
                    circuit_opened=circuit_opened,
                )
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
                        "circuit_opened": circuit_opened,
                    },
                )
                raise EvidenceToolError(f"{spec.source.value} evidence query failed") from exc
        raise RuntimeError("unreachable gateway retry state")
