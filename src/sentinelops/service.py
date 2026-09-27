"""Composition root for CLI and API entry points."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from sentinelops.adapters import (
    FixtureEvidenceTool,
    load_fixture_cases,
    observability_tool_from_env,
)
from sentinelops.audit import AuditLog
from sentinelops.domain import EvidenceSource, IncidentTask, InvestigationResult
from sentinelops.gateway import EvidenceGateway, GatewayPolicy
from sentinelops.investigation import BoundedInvestigationAgent
from sentinelops.ports import EvidenceTool
from sentinelops.storage import InvestigationStore


class IncidentConflict(ValueError):
    pass


@dataclass
class SentinelOpsService:
    agent: BoundedInvestigationAgent
    store: InvestigationStore
    audit: AuditLog

    def investigate(self, task: IncidentTask) -> InvestigationResult:
        existing = self.store.get(task.incident_id)
        if existing is not None:
            if existing.task == task:
                self.audit.append(
                    trace_id=existing.trace_id,
                    actor="sentinelops-service",
                    action="idempotent_replay",
                    resource=task.incident_id,
                    status="ok",
                    details={"result_reused": True},
                )
                return existing
            self.audit.append(
                trace_id=existing.trace_id,
                actor="sentinelops-service",
                action="idempotency_conflict",
                resource=task.incident_id,
                status="denied",
                details={"reason": "incident_id_reused_with_different_task"},
            )
            raise IncidentConflict("incident_id already exists with a different task payload")
        return self.agent.run(task)


def create_service(
    *,
    dataset_path: str | Path = "evals/incidents.json",
    db_path: str | Path = ".sentinelops/sentinelops.db",
    audit_key: str | bytes | None = None,
    evidence_mode: str | None = None,
    evidence_tool: EvidenceTool | None = None,
    allowed_sources: frozenset[EvidenceSource] | None = None,
) -> SentinelOpsService:
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
    gateway = EvidenceGateway(
        tool,
        audit,
        GatewayPolicy(
            allowed_sources=allowed_sources
        ),
    )
    return SentinelOpsService(
        agent=BoundedInvestigationAgent(gateway, audit, store),
        store=store,
        audit=audit,
    )
