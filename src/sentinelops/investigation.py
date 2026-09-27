"""Evidence-first bounded investigation Agent."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from sentinelops.application.baseline import rank_root_causes
from sentinelops.audit import AuditLog
from sentinelops.domain import (
    ActionType,
    DiagnosisReport,
    IncidentStatus,
    IncidentTask,
    InvestigationResult,
    InvestigationTraceStep,
    QuerySpec,
)
from sentinelops.gateway import EvidenceGateway, EvidenceToolError
from sentinelops.policy import HeuristicInvestigationPolicy, InvestigationPolicy, InvestigationState
from sentinelops.runtime import BudgetExceeded, InvestigationBudget
from sentinelops.storage import InvestigationStore


@dataclass(frozen=True)
class AgentConfig:
    max_steps: int = 8
    max_queries: int = 6
    deadline_seconds: float = 30.0


class BoundedInvestigationAgent:
    def __init__(
        self,
        gateway: EvidenceGateway,
        audit: AuditLog,
        store: InvestigationStore,
        policy: InvestigationPolicy | None = None,
        config: AgentConfig | None = None,
    ) -> None:
        self.gateway = gateway
        self.audit = audit
        self.store = store
        self.policy = policy or HeuristicInvestigationPolicy()
        self.config = config or AgentConfig()

    def run(self, task: IncidentTask) -> InvestigationResult:
        trace_id = f"trace-{uuid.uuid4().hex}"
        state = InvestigationState(task=task)
        trace: list[InvestigationTraceStep] = []
        degraded: list[str] = []
        budget = InvestigationBudget(
            max_steps=self.config.max_steps,
            max_queries=min(self.config.max_queries, task.query_budget),
            deadline_seconds=min(self.config.deadline_seconds, float(task.deadline_seconds)),
        )
        self.audit.append(
            trace_id=trace_id,
            actor="investigation-agent",
            action="investigation_started",
            resource=task.incident_id,
            status="ok",
            details={"service": task.service, "query_budget": budget.max_queries},
        )

        forced_status: IncidentStatus | None = None
        unresolved: list[str] = []
        try:
            while True:
                action = self.policy.decide(state)
                budget.consume(action)
                step_started = time.perf_counter()
                if action.action == ActionType.QUERY:
                    assert action.source is not None
                    state.queried_sources.add(action.source)
                    try:
                        evidence = self.gateway.query(
                            QuerySpec(
                                incident_id=task.incident_id,
                                source=action.source,
                                service=task.service,
                                keywords=action.keywords,
                                limit=25,
                            ),
                            trace_id=trace_id,
                        )
                        known = {item.evidence_id for item in state.evidence}
                        state.evidence.extend(item for item in evidence if item.evidence_id not in known)
                        status = "ok"
                    except (EvidenceToolError, PermissionError) as exc:
                        degraded.append(action.source.value)
                        evidence = []
                        status = "error"
                        unresolved.append(f"{action.source.value} query failed: {type(exc).__name__}")
                    trace.append(
                        InvestigationTraceStep(
                            step=budget.steps,
                            action=action.action,
                            source=action.source,
                            status=status,
                            rationale=action.rationale,
                            evidence_ids=[item.evidence_id for item in evidence],
                            duration_ms=round((time.perf_counter() - step_started) * 1000, 2),
                        )
                    )
                    continue

                forced_status = (
                    IncidentStatus.NEEDS_HUMAN
                    if action.action == ActionType.ESCALATE
                    else None
                )
                if action.action == ActionType.ESCALATE:
                    unresolved.append(action.rationale)
                trace.append(
                    InvestigationTraceStep(
                        step=budget.steps,
                        action=action.action,
                        status="ok",
                        rationale=action.rationale,
                        duration_ms=round((time.perf_counter() - step_started) * 1000, 2),
                    )
                )
                break
        except BudgetExceeded as exc:
            forced_status = IncidentStatus.NEEDS_HUMAN
            unresolved.append(str(exc))
            degraded.append("budget")
            self.audit.append(
                trace_id=trace_id,
                actor="investigation-agent",
                action="budget_exceeded",
                resource=task.incident_id,
                status="degraded",
                details={"reason": str(exc), "steps": budget.steps, "queries": budget.queries},
            )

        report = self._build_report(
            task=task,
            state=state,
            tool_queries=budget.queries,
            forced_status=forced_status,
            unresolved=unresolved,
        )
        result = InvestigationResult(
            trace_id=trace_id,
            task=task,
            report=report,
            trace=trace,
            degraded_components=sorted(set(degraded)),
        )
        self.store.save(result)
        self.audit.append(
            trace_id=trace_id,
            actor="investigation-agent",
            action="investigation_completed",
            resource=task.incident_id,
            status=report.status.value,
            details={
                "selected_code": report.selected_code,
                "evidence_count": len(report.evidence_ids),
                "tool_queries": report.tool_queries,
                "degraded_components": result.degraded_components,
            },
        )
        return result

    @staticmethod
    def _build_report(
        *,
        task: IncidentTask,
        state: InvestigationState,
        tool_queries: int,
        forced_status: IncidentStatus | None,
        unresolved: list[str],
    ) -> DiagnosisReport:
        candidates = rank_root_causes(state.evidence)
        selected = candidates[0] if candidates else None
        status = forced_status or (
            IncidentStatus.DIAGNOSED if selected else IncidentStatus.NEEDS_HUMAN
        )
        if status == IncidentStatus.NEEDS_HUMAN and not unresolved:
            unresolved = ["Available evidence is insufficient for a bounded diagnosis."]
        return DiagnosisReport(
            incident_id=task.incident_id,
            status=status,
            candidates=candidates,
            selected_code=selected.code if status == IncidentStatus.DIAGNOSED and selected else None,
            evidence_ids=selected.evidence_ids if selected else [],
            unresolved_questions=unresolved,
            tool_queries=tool_queries,
        )
