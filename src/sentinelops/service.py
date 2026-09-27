"""Composition root for CLI and API entry points."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sentinelops.adapters import FixtureEvidenceTool, load_fixture_cases
from sentinelops.audit import AuditLog
from sentinelops.domain import EvidenceSource, IncidentTask, InvestigationResult
from sentinelops.gateway import EvidenceGateway, GatewayPolicy
from sentinelops.investigation import BoundedInvestigationAgent
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
) -> SentinelOpsService:
    cases = load_fixture_cases(dataset_path)
    evidence = [item for case in cases for item in case.evidence]
    audit = AuditLog(db_path, key=audit_key)
    store = InvestigationStore(db_path)
    gateway = EvidenceGateway(
        FixtureEvidenceTool(evidence),
        audit,
        GatewayPolicy(
            allowed_sources=frozenset(
                {
                    EvidenceSource.METRICS,
                    EvidenceSource.LOGS,
                    EvidenceSource.TRACES,
                    EvidenceSource.CHANGES,
                }
            )
        ),
    )
    return SentinelOpsService(
        agent=BoundedInvestigationAgent(gateway, audit, store),
        store=store,
        audit=audit,
    )
