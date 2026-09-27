from pathlib import Path

from sentinelops.adapters import FixtureEvidenceTool, load_fixture_cases
from sentinelops.application import BaselineDiagnoser, evaluate_cases
from sentinelops.domain import EvidenceSource, IncidentStatus, QuerySpec


DATASET = Path(__file__).parents[1] / "evals" / "incidents.json"


def test_fixture_tool_enforces_incident_source_and_service() -> None:
    case = load_fixture_cases(DATASET)[0]
    tool = FixtureEvidenceTool(case.evidence)
    results = tool.query(
        QuerySpec(
            incident_id=case.task.incident_id,
            source=EvidenceSource.CHANGES,
            service=case.task.service,
        )
    )
    assert [item.evidence_id for item in results] == ["ev-deploy-change"]
    assert tool.query_count == 1


def test_baseline_identifies_every_fixture_root_cause() -> None:
    cases = load_fixture_cases(DATASET)
    for case in cases:
        report = BaselineDiagnoser(FixtureEvidenceTool(case.evidence)).diagnose(case.task)
        assert report.status == IncidentStatus.DIAGNOSED
        assert report.selected_code == case.expected_root_cause
        assert report.evidence_ids


def test_evaluation_is_reproducible_and_evidence_bound() -> None:
    summary = evaluate_cases(load_fixture_cases(DATASET))
    assert summary.cases == 4
    assert summary.top1_accuracy == 1.0
    assert summary.evidence_validity == 1.0
    assert summary.average_tool_queries == 4.0


def test_unknown_signals_degrade_to_human_review() -> None:
    case = load_fixture_cases(DATASET)[0]
    empty_tool = FixtureEvidenceTool([])
    report = BaselineDiagnoser(empty_tool).diagnose(case.task)
    assert report.status == IncidentStatus.NEEDS_HUMAN
    assert report.selected_code is None
    assert report.unresolved_questions


def test_mutating_tools_are_rejected() -> None:
    class UnsafeTool:
        read_only = False

    try:
        BaselineDiagnoser(UnsafeTool())  # type: ignore[arg-type]
    except ValueError as exc:
        assert "read-only" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("unsafe tool should have been rejected")
