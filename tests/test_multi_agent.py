import threading
import time

import pytest
from fastapi.testclient import TestClient

from sentinelops.adapters import FixtureEvidenceTool, load_fixture_cases
from sentinelops.application import compare_orchestration
from sentinelops.api import create_app
from sentinelops.domain import EvidenceSource, IncidentStatus, OrchestrationMode
from sentinelops.multi_agent import EvidenceReviewer, OrchestrationRouter
from sentinelops.policy import HeuristicInvestigationPolicy
from sentinelops.service import create_service
from sentinelops.storage import AssignmentJournal, AssignmentState, EvidenceJournal


def test_multi_agent_deadline_drains_running_readers_before_completion(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]

    class SlowReadOnlyTool:
        read_only = True
        name = "slow-read-only"

        def query(self, spec):
            time.sleep(1.2)
            return []

    service = create_service(
        db_path=tmp_path / "slow.db",
        orchestration_mode="multi",
        evidence_tool=SlowReadOnlyTool(),
    )
    task = case.task.model_copy(update={"deadline_seconds": 1, "query_budget": 2})
    result = service.investigate(task)

    assert result.report.status == IncidentStatus.NEEDS_HUMAN
    assert "deadline" in result.degraded_components
    records = AssignmentJournal(service.store.db_path).list_for_trace(result.trace_id)
    assert records
    assert all(record.state == AssignmentState.EXPIRED for record in records)
    events = service.audit.list_events(trace_id=result.trace_id)
    assert events[0]["action"] == "investigation_completed"
    assert service.audit.verify().valid


def test_multi_agent_dispatches_specialists_reviews_and_audits(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    service = create_service(
        db_path=tmp_path / "multi.db",
        audit_key="test-key",
        orchestration_mode="multi",
    )

    result = service.investigate(case.task)

    assert result.orchestration_mode == OrchestrationMode.MULTI
    assert result.report.status == IncidentStatus.DIAGNOSED
    assert result.report.selected_code == case.expected_root_cause
    assert result.report.tool_queries == 2
    assert {step.actor for step in result.trace[:-1]} == {
        "changes-investigator",
        "logs-investigator",
    }
    assert result.trace[-1].actor == "evidence-reviewer"
    assert service.audit.verify().valid is True
    assignment_records = AssignmentJournal(tmp_path / "multi.db").list_for_trace(result.trace_id)
    assert len(assignment_records) == 2
    assert {record.state for record in assignment_records} == {AssignmentState.COMPLETED}

    events = service.audit.list_events(trace_id=result.trace_id, limit=100)
    actions = [event["action"] for event in events]
    assert actions.count("worker_dispatched") == 2
    assert actions.count("worker_completed") == 2
    assert "evidence_reviewed" in actions
    assert next(
        event for event in events if event["action"] == "investigation_started"
    )["details"]["orchestration_mode"] == "multi"


def test_multi_agent_workers_really_overlap_in_a_bounded_wave(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]

    class CoordinatedTool:
        read_only = True
        name = "coordinated-fixture"

        def __init__(self) -> None:
            self._delegate = FixtureEvidenceTool(case.evidence)
            self._barrier = threading.Barrier(2)
            self._lock = threading.Lock()
            self.active = 0
            self.max_active = 0

        def query(self, spec):
            with self._lock:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            try:
                self._barrier.wait(timeout=2)
                return self._delegate.query(spec)
            finally:
                with self._lock:
                    self.active -= 1

    tool = CoordinatedTool()
    service = create_service(
        db_path=tmp_path / "parallel.db",
        evidence_tool=tool,
        orchestration_mode="multi",
    )

    result = service.investigate(case.task)

    assert result.report.status == IncidentStatus.DIAGNOSED
    assert tool.max_active == 2


def test_multi_agent_isolates_one_worker_failure_and_uses_next_wave(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[1]

    class SelectiveFailureTool:
        read_only = True
        name = "selective-failure"

        def __init__(self) -> None:
            self._delegate = FixtureEvidenceTool(case.evidence)

        def query(self, spec):
            if spec.source == EvidenceSource.METRICS:
                raise ConnectionError("synthetic provider outage")
            return self._delegate.query(spec)

    service = create_service(
        db_path=tmp_path / "degraded.db",
        evidence_tool=SelectiveFailureTool(),
        orchestration_mode="multi",
    )

    result = service.investigate(case.task)

    assert result.report.status == IncidentStatus.DIAGNOSED
    assert result.report.selected_code == case.expected_root_cause
    assert "metrics" in result.degraded_components
    assert result.report.tool_queries == 4
    assert any(step.actor == "traces-investigator" for step in result.trace)
    events = service.audit.list_events(trace_id=result.trace_id, limit=100)
    failed = next(
        event
        for event in events
        if event["action"] == "worker_completed" and event["resource"] == "metrics"
    )
    assert failed["status"] == "error"
    assert failed["details"]["error_type"] == "EvidenceToolError"
    assignment_records = AssignmentJournal(tmp_path / "degraded.db").list_for_trace(result.trace_id)
    assert [record.state for record in assignment_records].count(AssignmentState.FAILED) == 1


def test_multi_agent_global_query_budget_is_shared_across_workers(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[1]
    constrained = case.task.model_copy(update={"query_budget": 1})
    service = create_service(
        db_path=tmp_path / "budget.db",
        orchestration_mode="multi",
    )

    result = service.investigate(constrained)

    assert result.report.status == IncidentStatus.NEEDS_HUMAN
    assert result.report.tool_queries == 1
    assert len([step for step in result.trace if step.action.value == "query"]) == 1


def test_multi_agent_normalizes_duplicate_and_out_of_scope_source_plan(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[1]

    class NoisyPlanPolicy(HeuristicInvestigationPolicy):
        def source_order(self, task):
            del task
            return (
                EvidenceSource.METRICS,
                EvidenceSource.METRICS,
                EvidenceSource.LOGS,
                EvidenceSource.TRACES,
            )

        def plan_sources(self, task, *, allowed_sources, trace_id):
            del task, allowed_sources, trace_id
            return (
                EvidenceSource.METRICS,
                EvidenceSource.METRICS,
                EvidenceSource.RUNBOOK,
                EvidenceSource.LOGS,
                EvidenceSource.LOGS,
            )

    service = create_service(
        db_path=tmp_path / "noisy-plan.db",
        evidence_tool=FixtureEvidenceTool(case.evidence),
        orchestration_mode="multi",
    )
    service.agent.policy = NoisyPlanPolicy()

    result = service.investigate(case.task.model_copy(update={"query_budget": 2}))

    assert result.report.status == IncidentStatus.DIAGNOSED
    assert result.report.tool_queries == 2
    assert [step.source for step in result.trace[:-1]] == [
        EvidenceSource.METRICS, EvidenceSource.LOGS
    ]
    events = service.audit.list_events(trace_id=result.trace_id, limit=100)
    normalized = next(event for event in events if event["action"] == "source_plan_normalized")
    assert normalized["details"] == {
        "duplicates_removed": 2,
        "out_of_scope_removed": 1,
        "fallback_sources_added": 1,
        "effective_sources": ["metrics", "logs"],
    }


def test_reviewer_refuses_two_equally_supported_root_causes() -> None:
    case = load_fixture_cases("evals/incidents.json")[1]
    evidence = [
        item.model_copy(
            update={
                "summary": "connection pool and cache miss signals rose together",
                "attributes": {},
            }
        )
        for item in case.evidence[:2]
    ]

    review = EvidenceReviewer().review(evidence)

    assert review.status == IncidentStatus.NEEDS_HUMAN
    assert review.reason_code == "competing_candidates"
    assert review.selected_code is None
    assert {item.code for item in review.candidates[:2]} == {
        "database_pool_exhaustion", "cache_miss_storm"
    }
    assert "competing" in review.rationale
    with pytest.raises(ValueError, match="min_candidate_margin"):
        EvidenceReviewer(min_candidate_margin=-0.1)


def test_reviewer_rejects_reused_evidence_id_with_different_content() -> None:
    case = load_fixture_cases("evals/incidents.json")[1]
    metric, log = case.evidence[:2]
    conflicting_log = log.model_copy(update={"evidence_id": metric.evidence_id})

    review = EvidenceReviewer().review([metric, conflicting_log])

    assert review.status == IncidentStatus.NEEDS_HUMAN
    assert review.reason_code == "evidence_identity_conflict"
    assert review.candidates == []
    assert review.evidence_ids == []
    assert EvidenceReviewer().review([metric, metric, log]).reason_code == "supported"


def test_multi_agent_stops_after_evidence_identity_conflict(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[1]
    metric, log, trace = case.evidence
    tool = FixtureEvidenceTool(
        [metric, log.model_copy(update={"evidence_id": metric.evidence_id}), trace]
    )
    service = create_service(
        db_path=tmp_path / "identity-conflict.db",
        evidence_tool=tool,
        orchestration_mode="multi",
    )

    result = service.investigate(case.task)

    assert result.report.status == IncidentStatus.NEEDS_HUMAN
    assert result.report.selected_code is None
    assert result.report.tool_queries == 2
    assert "evidence_integrity" in result.degraded_components
    assert "conflicting contents" in result.report.unresolved_questions[0]
    reviews = [
        event for event in service.audit.list_events(trace_id=result.trace_id, limit=100)
        if event["action"] == "evidence_reviewed"
    ]
    assert len(reviews) == 1
    assert reviews[0]["details"]["reason_code"] == "evidence_identity_conflict"
    assert not any(step.actor == "traces-investigator" for step in result.trace)
    assert EvidenceJournal(service.store.db_path).list_for_trace(result.trace_id) == []


def test_multi_agent_uses_next_wave_to_resolve_competing_findings(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[1]
    evidence = [
        item.model_copy(
            update={
                "summary": "connection pool and cache miss signals rose together",
                "attributes": {},
            }
        )
        if item.source in {EvidenceSource.METRICS, EvidenceSource.LOGS}
        else item
        for item in case.evidence
    ]
    tool = FixtureEvidenceTool(evidence)
    service = create_service(
        db_path=tmp_path / "conflict-resolved.db",
        evidence_tool=tool,
        orchestration_mode="multi",
    )

    result = service.investigate(case.task.model_copy(update={"query_budget": 3}))

    assert result.report.status == IncidentStatus.DIAGNOSED
    assert result.report.selected_code == "database_pool_exhaustion"
    assert result.report.tool_queries == 3
    assert [step.actor for step in result.trace[:-1]] == [
        "metrics-investigator", "logs-investigator", "traces-investigator"
    ]
    reviews = [
        event for event in service.audit.list_events(trace_id=result.trace_id, limit=100)
        if event["action"] == "evidence_reviewed"
    ]
    assert [event["status"] for event in reversed(reviews)] == ["needs_human", "diagnosed"]
    assert [event["details"]["reason_code"] for event in reversed(reviews)] == [
        "competing_candidates", "supported"
    ]

    limited_service = create_service(
        db_path=tmp_path / "conflict-unresolved.db",
        evidence_tool=FixtureEvidenceTool(evidence),
        orchestration_mode="multi",
    )
    limited = limited_service.investigate(
        case.task.model_copy(update={"query_budget": 2})
    )
    assert limited.report.status == IncidentStatus.NEEDS_HUMAN
    assert limited.report.selected_code is None
    assert "competing" in limited.report.unresolved_questions[0]


def test_gateway_rejects_evidence_outside_worker_scope(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[1]
    wrong_source_evidence = next(
        item for item in case.evidence if item.source == EvidenceSource.LOGS
    )

    class CrossScopeTool:
        read_only = True
        name = "cross-scope"

        def query(self, spec):
            return [wrong_source_evidence]

    service = create_service(
        db_path=tmp_path / "scope.db",
        evidence_tool=CrossScopeTool(),
        allowed_sources=frozenset({EvidenceSource.METRICS}),
        orchestration_mode="multi",
    )

    result = service.investigate(case.task)

    assert result.report.status == IncidentStatus.NEEDS_HUMAN
    assert result.degraded_components == ["metrics"]
    events = service.audit.list_events(trace_id=result.trace_id, limit=100)
    contract_event = next(
        event
        for event in events
        if event["action"] == "tool_query" and event["status"] == "error"
    )
    assert contract_event["details"]["error_type"] == "EvidenceContractError"


def test_single_multi_ablation_keeps_accuracy_and_exposes_query_cost() -> None:
    summary = compare_orchestration(
        load_fixture_cases("evals/incidents.json"),
        provider_delay_ms=10,
    )

    assert summary["single"]["top1_accuracy"] == 1.0
    assert summary["multi"]["top1_accuracy"] == 1.0
    assert summary["auto"]["top1_accuracy"] == 1.0
    assert summary["single"]["evidence_validity"] == 1.0
    assert summary["multi"]["evidence_validity"] == 1.0
    assert summary["auto"]["evidence_validity"] == 1.0
    assert summary["delta"]["average_tool_queries"] == 0.5


def test_api_can_enable_multi_agent_without_changing_the_http_contract(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    app = create_app(
        db_path=tmp_path / "api-multi.db",
        orchestration_mode="multi",
    )

    with TestClient(app) as client:
        response = client.post(
            "/v1/investigations",
            json=case.task.model_dump(mode="json"),
        )

    assert response.status_code == 201
    assert response.json()["orchestration_mode"] == "multi"
    assert response.headers["x-sentinelops-trace-id"] == response.json()["trace_id"]
    assert response.json()["trace"][-1]["actor"] == "evidence-reviewer"


def test_invalid_orchestration_mode_fails_before_creating_state(tmp_path) -> None:
    database = tmp_path / "invalid.db"

    with pytest.raises(ValueError, match="orchestration_mode"):
        create_service(db_path=database, orchestration_mode="free-form-swarm")

    assert database.exists() is False


def test_auto_router_is_cost_aware_and_requires_a_parallelism_reason() -> None:
    cases = load_fixture_cases("evals/incidents.json")
    simple = cases[1].task
    cross_domain = simple.model_copy(
        update={"symptoms": ["CPU metric saturation", "trace latency increased"]}
    )
    budget_limited = cross_domain.model_copy(update={"query_budget": 1})
    router = OrchestrationRouter()

    assert router.decide(simple).selected_mode == OrchestrationMode.SINGLE
    decision = router.decide(cross_domain)
    assert decision.selected_mode == OrchestrationMode.MULTI
    assert any(reason.startswith("cross_domain_symptoms") for reason in decision.reasons)
    assert router.decide(budget_limited).selected_mode == OrchestrationMode.SINGLE


def test_auto_mode_audits_the_route_and_returns_the_selected_mode(tmp_path) -> None:
    cases = load_fixture_cases("evals/incidents.json")
    service = create_service(
        db_path=tmp_path / "auto.db",
        orchestration_mode="auto",
    )

    result = service.investigate(cases[1].task)

    assert result.orchestration_mode == OrchestrationMode.SINGLE
    routing_event = next(
        event
        for event in service.audit.list_events(trace_id=result.trace_id, limit=100)
        if event["action"] == "orchestration_selected"
    )
    assert routing_event["details"]["requested_mode"] == "auto"
    assert routing_event["details"]["selected_mode"] == "single"
    assert routing_event["details"]["reasons"] == ["single_domain_cost_preference"]

    complex_task = cases[1].task.model_copy(
        update={
            "symptoms": [
                "CPU metric reports connection pool saturation",
                "logs report pool timeout errors",
            ]
        }
    )
    complex_service = create_service(
        db_path=tmp_path / "auto-complex.db",
        orchestration_mode="auto",
    )

    complex_result = complex_service.investigate(complex_task)

    assert complex_result.orchestration_mode == OrchestrationMode.MULTI
    assert complex_result.report.status == IncidentStatus.DIAGNOSED
    complex_route = next(
        event
        for event in complex_service.audit.list_events(
            trace_id=complex_result.trace_id,
            limit=100,
        )
        if event["action"] == "orchestration_selected"
    )
    assert complex_route["details"]["selected_mode"] == "multi"
