"""Bounded supervisor-worker investigation with structured evidence review."""

from __future__ import annotations

import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import timedelta

from sentinelops.application.baseline import rank_root_causes
from sentinelops.audit import AuditLog
from sentinelops.domain import (
    ActionType,
    DiagnosisReport,
    Evidence,
    EvidenceReview,
    EvidenceSource,
    IncidentStatus,
    IncidentTask,
    InvestigationResult,
    InvestigationTraceStep,
    InvestigatorAssignment,
    InvestigatorFinding,
    InvestigatorStatus,
    OrchestrationDecision,
    OrchestrationMode,
    QuerySpec,
)
from sentinelops.gateway import EvidenceGateway, EvidenceToolError
from sentinelops.policy import HeuristicInvestigationPolicy
from sentinelops.storage import InvestigationStore


@dataclass(frozen=True)
class MultiAgentConfig:
    max_workers: int = 4
    wave_size: int = 2
    max_queries: int = 4
    deadline_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_workers <= 8:
            raise ValueError("max_workers must be between 1 and 8")
        if not 1 <= self.wave_size <= self.max_workers:
            raise ValueError("wave_size must be between 1 and max_workers")
        if not 1 <= self.max_queries <= 8:
            raise ValueError("max_queries must be between 1 and 8")
        if not 1.0 <= self.deadline_seconds <= 300.0:
            raise ValueError("deadline_seconds must be between 1 and 300")


class SourceInvestigator:
    """One role-scoped worker that can query exactly one evidence source."""

    def __init__(self, source: EvidenceSource, gateway: EvidenceGateway) -> None:
        self.source = source
        self.actor = f"{source.value}-investigator"
        self._gateway = gateway

    def run(self, assignment: InvestigatorAssignment, *, trace_id: str) -> InvestigatorFinding:
        started = time.perf_counter()
        if assignment.actor != self.actor or assignment.query.source != self.source:
            raise ValueError("investigator assignment escaped its role scope")
        try:
            evidence = self._gateway.query(
                assignment.query,
                trace_id=trace_id,
                actor=self.actor,
            )
            return InvestigatorFinding(
                assignment_id=assignment.assignment_id,
                actor=self.actor,
                incident_id=assignment.query.incident_id,
                service=assignment.query.service or "unknown",
                source=self.source,
                status=InvestigatorStatus.OK,
                evidence=evidence,
                duration_ms=round((time.perf_counter() - started) * 1_000, 2),
            )
        except (EvidenceToolError, PermissionError) as exc:
            return InvestigatorFinding(
                assignment_id=assignment.assignment_id,
                actor=self.actor,
                incident_id=assignment.query.incident_id,
                service=assignment.query.service or "unknown",
                source=self.source,
                status=InvestigatorStatus.ERROR,
                error_type=type(exc).__name__,
                duration_ms=round((time.perf_counter() - started) * 1_000, 2),
            )


class EvidenceReviewer:
    """Deterministic critic that enforces confidence and source independence."""

    actor = "evidence-reviewer"

    def __init__(self, *, min_confidence: float = 0.65, min_sources: int = 2) -> None:
        self.min_confidence = min(max(min_confidence, 0.0), 1.0)
        self.min_sources = max(2, min_sources)

    def review(self, evidence: list[Evidence]) -> EvidenceReview:
        unique = {item.evidence_id: item for item in evidence}
        normalized = sorted(unique.values(), key=lambda item: item.evidence_id)
        candidates = rank_root_causes(normalized)
        if not candidates:
            return EvidenceReview(
                status=IncidentStatus.NEEDS_HUMAN,
                rationale="no known root-cause signal matched the reviewed evidence",
            )

        selected = candidates[0]
        evidence_by_id = {item.evidence_id: item for item in normalized}
        sources = sorted(
            {
                evidence_by_id[evidence_id].source
                for evidence_id in selected.evidence_ids
                if evidence_id in evidence_by_id
            },
            key=lambda source: source.value,
        )
        if selected.score >= self.min_confidence and len(sources) >= self.min_sources:
            return EvidenceReview(
                status=IncidentStatus.DIAGNOSED,
                candidates=candidates,
                selected_code=selected.code,
                evidence_ids=selected.evidence_ids,
                supporting_sources=sources,
                rationale=(
                    f"candidate {selected.code} reached confidence {selected.score:.2f} "
                    f"across {len(sources)} independent sources"
                ),
            )
        return EvidenceReview(
            status=IncidentStatus.NEEDS_HUMAN,
            candidates=candidates,
            evidence_ids=selected.evidence_ids,
            supporting_sources=sources,
            rationale="leading candidate lacks confidence or independent source support",
        )


class BoundedMultiAgentSupervisor:
    """Dispatch source specialists in bounded waves and merge only reviewed evidence."""

    orchestration_mode = OrchestrationMode.MULTI

    def __init__(
        self,
        gateway: EvidenceGateway,
        audit: AuditLog,
        store: InvestigationStore,
        *,
        allowed_sources: frozenset[EvidenceSource],
        config: MultiAgentConfig | None = None,
        policy: HeuristicInvestigationPolicy | None = None,
        reviewer: EvidenceReviewer | None = None,
    ) -> None:
        self.gateway = gateway
        self.audit = audit
        self.store = store
        self.allowed_sources = allowed_sources
        self.config = config or MultiAgentConfig()
        self.policy = policy or HeuristicInvestigationPolicy()
        self.reviewer = reviewer or EvidenceReviewer()
        self._workers = {
            source: SourceInvestigator(source, gateway) for source in allowed_sources
        }

    def _assignment(
        self,
        task: IncidentTask,
        source: EvidenceSource,
        *,
        deadline_seconds: float,
    ) -> InvestigatorAssignment:
        worker = self._workers[source]
        return InvestigatorAssignment(
            assignment_id=f"assignment-{uuid.uuid4().hex}",
            actor=worker.actor,
            query=QuerySpec(
                incident_id=task.incident_id,
                source=source,
                service=task.service,
                keywords=self.policy.keywords(task, source),
                limit=25,
                start_time=task.started_at - timedelta(minutes=5),
                end_time=task.started_at + timedelta(minutes=15),
            ),
            deadline_seconds=max(0.001, deadline_seconds),
        )

    def _run_wave(
        self,
        assignments: list[InvestigatorAssignment],
        *,
        trace_id: str,
        timeout_seconds: float,
    ) -> list[InvestigatorFinding]:
        futures: dict[str, Future[InvestigatorFinding]] = {}
        with ThreadPoolExecutor(
            max_workers=min(self.config.max_workers, len(assignments)),
            thread_name_prefix="sentinelops-investigator",
        ) as executor:
            for assignment in assignments:
                self.audit.append(
                    trace_id=trace_id,
                    actor="multi-agent-supervisor",
                    action="worker_dispatched",
                    resource=assignment.query.source.value,
                    status="ok",
                    details={
                        "assignment_id": assignment.assignment_id,
                        "worker": assignment.actor,
                    },
                )
                futures[assignment.assignment_id] = executor.submit(
                    self._workers[assignment.query.source].run,
                    assignment,
                    trace_id=trace_id,
                )
            done, pending = wait(futures.values(), timeout=max(0.001, timeout_seconds))
            for future in pending:
                future.cancel()

        findings: list[InvestigatorFinding] = []
        for assignment in assignments:
            future = futures[assignment.assignment_id]
            if future not in done:
                finding = InvestigatorFinding(
                    assignment_id=assignment.assignment_id,
                    actor=assignment.actor,
                    incident_id=assignment.query.incident_id,
                    service=assignment.query.service or "unknown",
                    source=assignment.query.source,
                    status=InvestigatorStatus.TIMEOUT,
                    error_type="DeadlineExceeded",
                    duration_ms=round(timeout_seconds * 1_000, 2),
                )
            else:
                try:
                    finding = future.result()
                except Exception as exc:
                    finding = InvestigatorFinding(
                        assignment_id=assignment.assignment_id,
                        actor=assignment.actor,
                        incident_id=assignment.query.incident_id,
                        service=assignment.query.service or "unknown",
                        source=assignment.query.source,
                        status=InvestigatorStatus.ERROR,
                        error_type=type(exc).__name__,
                        duration_ms=0,
                    )
            self.audit.append(
                trace_id=trace_id,
                actor="multi-agent-supervisor",
                action="worker_completed",
                resource=finding.source.value,
                status=finding.status.value,
                details={
                    "assignment_id": finding.assignment_id,
                    "worker": finding.actor,
                    "result_count": len(finding.evidence),
                    "error_type": finding.error_type,
                    "duration_ms": finding.duration_ms,
                },
            )
            findings.append(finding)
        return findings

    def run(
        self,
        task: IncidentTask,
        *,
        request_id: str | None = None,
        trace_id: str | None = None,
    ) -> InvestigationResult:
        trace_id = trace_id or f"trace-{uuid.uuid4().hex}"
        started = time.perf_counter()
        deadline_seconds = min(self.config.deadline_seconds, float(task.deadline_seconds))
        query_limit = min(self.config.max_queries, task.query_budget)
        source_plan = [
            source
            for source in self.policy.source_order(task)
            if source in self.allowed_sources
        ][:query_limit]
        start_details: dict[str, object] = {
            "service": task.service,
            "orchestration_mode": self.orchestration_mode.value,
            "query_budget": query_limit,
            "planned_workers": len(source_plan),
        }
        if request_id is not None:
            start_details["request_id"] = request_id
        self.audit.append(
            trace_id=trace_id,
            actor="multi-agent-supervisor",
            action="investigation_started",
            resource=task.incident_id,
            status="ok",
            details=start_details,
        )

        findings: list[InvestigatorFinding] = []
        reviewed_evidence: list[Evidence] = []
        trace: list[InvestigationTraceStep] = []
        review = self.reviewer.review([])
        for offset in range(0, len(source_plan), self.config.wave_size):
            elapsed = time.perf_counter() - started
            remaining = deadline_seconds - elapsed
            if remaining <= 0:
                break
            wave_sources = source_plan[offset : offset + self.config.wave_size]
            assignments = [
                self._assignment(task, source, deadline_seconds=remaining)
                for source in wave_sources
            ]
            wave_findings = self._run_wave(
                assignments,
                trace_id=trace_id,
                timeout_seconds=remaining,
            )
            findings.extend(wave_findings)
            for finding in wave_findings:
                reviewed_evidence.extend(finding.evidence)
                trace.append(
                    InvestigationTraceStep(
                        step=len(trace) + 1,
                        actor=finding.actor,
                        action=ActionType.QUERY,
                        source=finding.source,
                        status=finding.status.value,
                        rationale=f"role-scoped {finding.source.value} evidence investigation",
                        evidence_ids=[item.evidence_id for item in finding.evidence],
                        duration_ms=finding.duration_ms,
                    )
                )
            review = self.reviewer.review(reviewed_evidence)
            self.audit.append(
                trace_id=trace_id,
                actor=self.reviewer.actor,
                action="evidence_reviewed",
                resource=task.incident_id,
                status=review.status.value,
                details={
                    "candidate": review.selected_code,
                    "evidence_count": len(review.evidence_ids),
                    "supporting_sources": [source.value for source in review.supporting_sources],
                },
            )
            if review.status == IncidentStatus.DIAGNOSED:
                break

        timed_out = time.perf_counter() - started > deadline_seconds
        failures = [finding for finding in findings if finding.status != InvestigatorStatus.OK]
        unresolved: list[str] = []
        if review.status == IncidentStatus.NEEDS_HUMAN:
            unresolved.append(review.rationale)
        if failures:
            unresolved.append(
                "One or more evidence specialists failed; inspect the correlated audit trace."
            )
        if timed_out:
            unresolved.append("Multi-agent investigation deadline exceeded.")

        trace.append(
            InvestigationTraceStep(
                step=len(trace) + 1,
                actor=self.reviewer.actor,
                action=(
                    ActionType.FINISH
                    if review.status == IncidentStatus.DIAGNOSED
                    else ActionType.ESCALATE
                ),
                status="ok",
                rationale=review.rationale,
                evidence_ids=review.evidence_ids,
                duration_ms=0,
            )
        )
        report = DiagnosisReport(
            incident_id=task.incident_id,
            status=review.status,
            candidates=review.candidates,
            selected_code=review.selected_code,
            evidence_ids=review.evidence_ids,
            unresolved_questions=unresolved,
            tool_queries=len(findings),
        )
        result = InvestigationResult(
            trace_id=trace_id,
            orchestration_mode=self.orchestration_mode,
            task=task,
            report=report,
            trace=trace,
            degraded_components=sorted(
                {
                    finding.source.value
                    for finding in failures
                }
                | ({"deadline"} if timed_out else set())
            ),
        )
        self.store.save(result)
        completion_details: dict[str, object] = {
            "orchestration_mode": self.orchestration_mode.value,
            "selected_code": report.selected_code,
            "evidence_count": len(report.evidence_ids),
            "tool_queries": report.tool_queries,
            "workers_completed": len(findings),
            "degraded_components": result.degraded_components,
        }
        if request_id is not None:
            completion_details["request_id"] = request_id
        self.audit.append(
            trace_id=trace_id,
            actor="multi-agent-supervisor",
            action="investigation_completed",
            resource=task.incident_id,
            status=report.status.value,
            details=completion_details,
        )
        return result


class OrchestrationRouter:
    """Cost-aware deterministic router that enables parallelism only when justified."""

    _DOMAIN_TERMS = {
        EvidenceSource.METRICS: (
            "metric",
            "cpu",
            "memory",
            "qps",
            "error rate",
            "success rate",
            "指标",
        ),
        EvidenceSource.LOGS: (" log", "logs", "exception", "traceback", "日志"),
        EvidenceSource.TRACES: ("trace", "span", "latency", "timeout", "链路", "延迟"),
        EvidenceSource.CHANGES: (
            "deploy",
            "release",
            "rollback",
            "version",
            "config change",
            "发布",
            "变更",
        ),
    }

    def decide(self, task: IncidentTask) -> OrchestrationDecision:
        if task.query_budget < 2:
            return OrchestrationDecision(
                selected_mode=OrchestrationMode.SINGLE,
                reasons=["query_budget_below_parallel_minimum"],
            )

        text = " ".join(task.symptoms).casefold()
        matched_domains = sorted(
            source.value
            for source, terms in self._DOMAIN_TERMS.items()
            if any(term in text for term in terms)
        )
        multi_reasons: list[str] = []
        if task.deadline_seconds <= 10:
            multi_reasons.append("tight_deadline")
        if len(matched_domains) >= 2 and len(task.symptoms) >= 2:
            multi_reasons.append("cross_domain_symptoms:" + ",".join(matched_domains))
        if len(task.symptoms) >= 3:
            multi_reasons.append("multiple_independent_symptoms")

        if multi_reasons:
            return OrchestrationDecision(
                selected_mode=OrchestrationMode.MULTI,
                reasons=multi_reasons,
            )
        return OrchestrationDecision(
            selected_mode=OrchestrationMode.SINGLE,
            reasons=["single_domain_cost_preference"],
        )


class AdaptiveInvestigationAgent:
    """Route each incident to single or multi orchestration and audit the reason."""

    orchestration_mode = OrchestrationMode.AUTO

    def __init__(
        self,
        single: "BoundedInvestigationAgent",
        multi: BoundedMultiAgentSupervisor,
        audit: AuditLog,
        router: OrchestrationRouter | None = None,
    ) -> None:
        self.single = single
        self.multi = multi
        self.audit = audit
        self.router = router or OrchestrationRouter()

    def run(self, task: IncidentTask, *, request_id: str | None = None) -> InvestigationResult:
        trace_id = f"trace-{uuid.uuid4().hex}"
        decision = self.router.decide(task)
        details: dict[str, object] = {
            "requested_mode": self.orchestration_mode.value,
            "selected_mode": decision.selected_mode.value,
            "reasons": decision.reasons,
        }
        if request_id is not None:
            details["request_id"] = request_id
        self.audit.append(
            trace_id=trace_id,
            actor="orchestration-router",
            action="orchestration_selected",
            resource=task.incident_id,
            status="ok",
            details=details,
        )
        delegate = (
            self.multi
            if decision.selected_mode == OrchestrationMode.MULTI
            else self.single
        )
        return delegate.run(task, request_id=request_id, trace_id=trace_id)
