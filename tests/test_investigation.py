from datetime import datetime, timezone

from sentinelops.adapters import load_fixture_cases
from sentinelops.domain import ActionType, Evidence, EvidenceSource, IncidentStatus, IncidentTask
from sentinelops.policy import HeuristicInvestigationPolicy, InvestigationState
from sentinelops.service import create_service


def test_agent_diagnoses_persists_and_audits(tmp_path) -> None:
    db_path = tmp_path / "sentinelops.db"
    service = create_service(db_path=db_path, audit_key="test-key")
    case = load_fixture_cases("evals/incidents.json")[0]

    result = service.investigate(case.task)

    assert result.report.status == IncidentStatus.DIAGNOSED
    assert result.report.selected_code == case.expected_root_cause
    assert result.report.tool_queries < 4
    assert result.trace[0].source.value == "changes"
    assert service.store.get(case.task.incident_id) == result
    verification = service.audit.verify()
    assert verification.valid is True
    assert verification.event_count >= 4

    replay = service.investigate(case.task)
    assert replay.trace_id == result.trace_id
    replay_events = service.audit.list_events(trace_id=result.trace_id)
    assert replay_events[0]["action"] == "idempotent_replay"


def test_unknown_incident_exhausts_read_only_domains_then_escalates(tmp_path) -> None:
    service = create_service(db_path=tmp_path / "sentinelops.db")
    task = IncidentTask(
        incident_id="inc-unknown-001",
        tenant_id="demo",
        service="unknown-service",
        started_at=datetime.now(timezone.utc),
        symptoms=["unknown behavior"],
    )

    result = service.investigate(task)

    assert result.report.status == IncidentStatus.NEEDS_HUMAN
    assert result.report.selected_code is None
    assert result.report.tool_queries == 4
    assert result.report.unresolved_questions
    assert service.audit.verify().valid is True


def test_policy_escalates_high_score_with_only_one_supporting_source() -> None:
    task = IncidentTask(
        incident_id="inc-single-source",
        tenant_id="demo",
        service="order-service",
        started_at=datetime.now(timezone.utc),
        symptoms=["failures after release"],
    )
    evidence = Evidence(
        evidence_id="ev-single-change",
        incident_id=task.incident_id,
        service=task.service,
        source=EvidenceSource.CHANGES,
        observed_at=datetime.now(timezone.utc),
        summary="deployment release new version rollback available",
        raw_ref="fixture://changes/inc-single-source",
    )
    state = InvestigationState(
        task=task,
        evidence=[evidence],
        queried_sources={
            EvidenceSource.METRICS,
            EvidenceSource.LOGS,
            EvidenceSource.TRACES,
            EvidenceSource.CHANGES,
        },
    )

    action = HeuristicInvestigationPolicy().decide(state)

    assert action.action == ActionType.ESCALATE
    assert "multi-source" in action.rationale
