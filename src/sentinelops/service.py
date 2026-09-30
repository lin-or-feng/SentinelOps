"""Composition root for CLI and API entry points."""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from sentinelops import __version__
from sentinelops.adapters import (
    FixtureEvidenceTool,
    load_fixture_cases,
    observability_tool_from_env,
)
from sentinelops.audit import AuditLog
from sentinelops.domain import (
    EvidenceSource,
    IncidentTask,
    InvestigationResult,
    OrchestrationMode,
)
from sentinelops.gateway import EvidenceGateway, GatewayPolicy
from sentinelops.investigation import BoundedInvestigationAgent
from sentinelops.multi_agent import (
    AdaptiveInvestigationAgent,
    BoundedMultiAgentSupervisor,
    MultiAgentConfig,
)
from sentinelops.model_policy import (
    ControlledModelPolicy,
    OllamaSourceProposer,
    SOURCE_SELECTION_PROMPT_ID,
    SourceProposer,
    ollama_policy_config_from_env,
)
from sentinelops.policy import HeuristicInvestigationPolicy, InvestigationPolicy
from sentinelops.ports import EvidenceTool
from sentinelops.specialist_shadow import (
    HypothesisProposer,
    OllamaHypothesisProposer,
    ShadowJournal,
    ShadowSpecialist,
)
from sentinelops.storage import InvestigationRunJournal, InvestigationStore, RunReservationError
from sentinelops.telemetry import OperationalMetrics, current_request_id


class IncidentConflict(ValueError):
    pass


@dataclass
class SentinelOpsService:
    agent: BoundedInvestigationAgent | BoundedMultiAgentSupervisor | AdaptiveInvestigationAgent
    store: InvestigationStore
    run_journal: InvestigationRunJournal
    audit: AuditLog
    evidence_tool: EvidenceTool
    metrics: OperationalMetrics
    policy_resource: object | None = None
    shadow_resource: object | None = None

    def investigate(self, task: IncidentTask) -> InvestigationResult:
        started = time.perf_counter()
        request_id = current_request_id()
        existing = self.store.get(task.incident_id)
        if existing is not None:
            if existing.task == task:
                self.run_journal.reconcile_completed(existing)
                replay_details: dict[str, object] = {"result_reused": True}
                if request_id is not None:
                    replay_details["request_id"] = request_id
                self.audit.append(
                    trace_id=existing.trace_id,
                    actor="sentinelops-service",
                    action="idempotent_replay",
                    resource=task.incident_id,
                    status="ok",
                    details=replay_details,
                )
                self.metrics.record_investigation(
                    outcome="idempotent_replay",
                    duration_seconds=time.perf_counter() - started,
                )
                return existing
            conflict_details: dict[str, object] = {
                "reason": "incident_id_reused_with_different_task"
            }
            if request_id is not None:
                conflict_details["request_id"] = request_id
            self.audit.append(
                trace_id=existing.trace_id,
                actor="sentinelops-service",
                action="idempotency_conflict",
                resource=task.incident_id,
                status="denied",
                details=conflict_details,
            )
            self.metrics.record_investigation(
                outcome="conflict",
                duration_seconds=time.perf_counter() - started,
            )
            raise IncidentConflict("incident_id already exists with a different task payload")
        trace_id = f"trace-{uuid.uuid4().hex}"
        try:
            self.run_journal.reserve(task, trace_id)
        except RunReservationError as exc:
            reserved = self.run_journal.get(task.incident_id)
            self.audit.append(
                trace_id=reserved[0] if reserved is not None else trace_id,
                actor="sentinelops-service",
                action="run_reservation_conflict",
                resource=task.incident_id,
                status="denied",
                details={"reason": "incident_run_already_reserved"},
            )
            self.metrics.record_investigation(
                outcome="conflict",
                duration_seconds=time.perf_counter() - started,
            )
            raise IncidentConflict(
                "incident investigation already reserved; operator review required"
            ) from exc
        try:
            result = self.agent.run(task, request_id=request_id, trace_id=trace_id)
        except Exception:
            self.run_journal.finish(task.incident_id, trace_id, success=False)
            self.metrics.record_investigation(
                outcome="error",
                duration_seconds=time.perf_counter() - started,
            )
            raise
        self.run_journal.finish(task.incident_id, trace_id, success=True)
        self.metrics.record_investigation(
            outcome=result.report.status.value,
            duration_seconds=time.perf_counter() - started,
        )
        return result

    def is_ready(self) -> bool:
        """Report local dependency readiness without querying external providers."""
        return self.store.healthcheck()

    def close(self) -> None:
        closer = getattr(self.evidence_tool, "close", None)
        try:
            if callable(closer):
                closer()
        finally:
            policy_closer = getattr(self.policy_resource, "close", None)
            try:
                if callable(policy_closer):
                    policy_closer()
            finally:
                shadow_closer = getattr(self.shadow_resource, "close", None)
                if callable(shadow_closer):
                    shadow_closer()


def create_service(
    *,
    dataset_path: str | Path = "evals/incidents.json",
    db_path: str | Path = ".sentinelops/sentinelops.db",
    audit_key: str | bytes | None = None,
    evidence_mode: str | None = None,
    evidence_tool: EvidenceTool | None = None,
    allowed_sources: frozenset[EvidenceSource] | None = None,
    orchestration_mode: str | OrchestrationMode | None = None,
    multi_agent_config: MultiAgentConfig | None = None,
    policy_mode: str | None = None,
    model_proposer: SourceProposer | None = None,
    shadow_mode: str | None = None,
    shadow_proposer: HypothesisProposer | None = None,
) -> SentinelOpsService:
    requested_mode = orchestration_mode or os.getenv("SENTINELOPS_ORCHESTRATION_MODE") or "single"
    try:
        resolved_mode = (
            requested_mode
            if isinstance(requested_mode, OrchestrationMode)
            else OrchestrationMode(str(requested_mode).casefold())
        )
    except ValueError as exc:
        raise ValueError("orchestration_mode must be 'single', 'multi', or 'auto'") from exc

    resolved_shadow_mode = (
        shadow_mode or os.getenv("SENTINELOPS_SPECIALIST_SHADOW") or "off"
    ).casefold()
    if resolved_shadow_mode not in {"off", "ollama"}:
        raise ValueError("shadow_mode must be 'off' or 'ollama'")
    if shadow_proposer is not None and resolved_shadow_mode != "ollama":
        raise ValueError("shadow_proposer requires shadow_mode='ollama'")
    if resolved_shadow_mode == "ollama" and resolved_mode == OrchestrationMode.SINGLE:
        raise ValueError("specialist shadow requires multi or auto orchestration")

    resolved_policy_mode = (
        policy_mode or os.getenv("SENTINELOPS_POLICY_MODE") or "heuristic"
    ).casefold()
    if resolved_policy_mode not in {"heuristic", "ollama"}:
        raise ValueError("policy_mode must be 'heuristic' or 'ollama'")
    if resolved_policy_mode == "heuristic" and model_proposer is not None:
        raise ValueError("model_proposer requires policy_mode='ollama'")
    ollama_config = None
    if resolved_policy_mode == "ollama" and model_proposer is None:
        ollama_config = ollama_policy_config_from_env()
        if ollama_config.prompt_id != SOURCE_SELECTION_PROMPT_ID:
            raise ValueError("experimental source-selection prompts are evaluation-only")

    mode = (evidence_mode or os.getenv("SENTINELOPS_EVIDENCE_MODE") or "fixture").casefold()
    if evidence_tool is not None:
        tool = evidence_tool
    elif mode == "fixture":
        cases = load_fixture_cases(dataset_path)
        evidence = [item for case in cases for item in case.evidence]
        tool = FixtureEvidenceTool(evidence)
    elif mode == "observability":
        tool = observability_tool_from_env()
    else:
        raise ValueError("evidence_mode must be 'fixture' or 'observability'")

    if allowed_sources is None:
        allowed_sources = getattr(
            tool,
            "sources",
            frozenset(
                {
                    EvidenceSource.METRICS,
                    EvidenceSource.LOGS,
                    EvidenceSource.TRACES,
                    EvidenceSource.CHANGES,
                }
            ),
        )
    if not allowed_sources:
        raise ValueError("at least one evidence source must be allowed")
    audit = AuditLog(db_path, key=audit_key)
    store = InvestigationStore(db_path)
    run_journal = InvestigationRunJournal(db_path)
    metrics = OperationalMetrics(version=__version__)
    gateway = EvidenceGateway(
        tool,
        audit,
        GatewayPolicy(
            allowed_sources=allowed_sources
        ),
        metrics=metrics,
    )
    policy_resource: object | None = None
    policy: InvestigationPolicy
    if resolved_policy_mode == "ollama":
        if model_proposer is None:
            assert ollama_config is not None
            model_proposer = OllamaSourceProposer(ollama_config)
            policy_resource = model_proposer
        policy = ControlledModelPolicy(
            model_proposer,
            audit,
            allowed_sources=allowed_sources,
            metrics=metrics,
        )
    else:
        policy = HeuristicInvestigationPolicy()
    single_agent = BoundedInvestigationAgent(
        gateway, audit, store, policy=policy, allowed_sources=allowed_sources
    )
    shadow_resource: object | None = None
    shadow: ShadowSpecialist | None = None
    if resolved_shadow_mode == "ollama":
        if shadow_proposer is None:
            shadow_proposer = OllamaHypothesisProposer(ollama_policy_config_from_env())
            shadow_resource = shadow_proposer
        shadow = ShadowSpecialist(shadow_proposer, audit, ShadowJournal(db_path))
    agent: BoundedInvestigationAgent | BoundedMultiAgentSupervisor | AdaptiveInvestigationAgent
    if resolved_mode in {OrchestrationMode.MULTI, OrchestrationMode.AUTO}:
        multi_agent = BoundedMultiAgentSupervisor(
            gateway,
            audit,
            store,
            allowed_sources=allowed_sources,
            config=multi_agent_config,
            policy=policy,
            shadow=shadow,
        )
        if resolved_mode == OrchestrationMode.AUTO:
            agent = AdaptiveInvestigationAgent(single_agent, multi_agent, audit)
        else:
            agent = multi_agent
    else:
        agent = single_agent
    return SentinelOpsService(
        agent=agent,
        store=store,
        run_journal=run_journal,
        audit=audit,
        evidence_tool=tool,
        metrics=metrics,
        policy_resource=policy_resource,
        shadow_resource=shadow_resource,
    )
