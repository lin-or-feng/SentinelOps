import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from sentinelops.adapters import FixtureEvidenceTool, load_fixture_cases
from sentinelops.service import IncidentConflict, create_service
from sentinelops.storage import (
    EvidenceIdentityError,
    EvidenceJournal,
    InvestigationRunJournal,
    RunReservationError,
)


def test_run_reservation_is_durable_and_never_automatically_reused(tmp_path) -> None:
    task = load_fixture_cases("evals/incidents.json")[0].task
    db_path = tmp_path / "runs.db"
    journal = InvestigationRunJournal(db_path)
    journal.reserve(task, "trace-one")
    assert InvestigationRunJournal(db_path).get(task.incident_id) == (
        "trace-one", journal.task_fingerprint(task), "running",
    )
    with pytest.raises(RunReservationError, match="already reserved"):
        journal.reserve(task, "trace-two")
    journal.finish(task.incident_id, "trace-one", success=False)
    assert journal.get(task.incident_id)[2] == "abandoned"
    with pytest.raises(RunReservationError, match="already reserved"):
        journal.reserve(task, "trace-three")
    with pytest.raises(RunReservationError, match="invalid investigation run transition"):
        journal.finish(task.incident_id, "trace-one", success=True)


def test_failed_investigation_is_not_rerun_after_service_restart(tmp_path, monkeypatch) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    db_path = tmp_path / "restart.db"
    service = create_service(db_path=db_path)

    def crash(*args, **kwargs):
        raise RuntimeError("synthetic crash")

    monkeypatch.setattr(service.agent, "run", crash)
    with pytest.raises(RuntimeError, match="synthetic crash"):
        service.investigate(case.task)
    assert service.run_journal.get(case.task.incident_id)[2] == "abandoned"

    restarted = create_service(db_path=db_path)
    with pytest.raises(IncidentConflict, match="operator review required"):
        restarted.investigate(case.task)
    assert restarted.store.get(case.task.incident_id) is None


def test_concurrent_same_incident_has_single_execution(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]

    class BlockingTool:
        read_only = True
        name = "blocking-fixture"

        def __init__(self):
            self.delegate = FixtureEvidenceTool(case.evidence)
            self.entered = threading.Event()
            self.release = threading.Event()
            self.calls = 0

        def query(self, spec):
            self.calls += 1
            self.entered.set()
            if not self.release.wait(timeout=5):
                raise TimeoutError("test synchronization timed out")
            return self.delegate.query(spec)

    tool = BlockingTool()
    service = create_service(db_path=tmp_path / "concurrent.db", evidence_tool=tool)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(service.investigate, case.task)
        try:
            assert tool.entered.wait(timeout=5)
            with pytest.raises(IncidentConflict, match="operator review required"):
                service.investigate(case.task)
        finally:
            tool.release.set()
        assert first.result(timeout=5).report.tool_queries >= 1
    assert service.run_journal.get(case.task.incident_id)[2] == "completed"
    assert service.investigate(case.task).trace_id == service.store.get(case.task.incident_id).trace_id


def test_completed_result_reconciles_result_first_crash_window(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    service = create_service(db_path=tmp_path / "reconcile.db")
    result = service.investigate(case.task)
    with sqlite3.connect(service.store.db_path) as connection:
        connection.execute(
            "UPDATE investigation_runs SET state = 'running' WHERE incident_id = ?",
            (case.task.incident_id,),
        )
    restarted = create_service(db_path=service.store.db_path)
    assert restarted.investigate(case.task) == result
    assert restarted.run_journal.get(case.task.incident_id)[2] == "completed"


@pytest.mark.parametrize("orchestration_mode", ["single", "multi"])
def test_completion_audit_failure_rolls_back_result(
    tmp_path, orchestration_mode: str
) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    service = create_service(
        db_path=tmp_path / f"{orchestration_mode}-rollback.db",
        orchestration_mode=orchestration_mode,
    )

    with sqlite3.connect(service.store.db_path) as connection:
        connection.execute(
            "CREATE TRIGGER reject_completion BEFORE INSERT ON audit_events "
            "WHEN NEW.action = 'investigation_completed' "
            "BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="synthetic audit failure"):
        service.investigate(case.task)

    assert service.store.get(case.task.incident_id) is None
    assert service.run_journal.get(case.task.incident_id)[2] == "abandoned"
    assert not any(
        event["action"] == "investigation_completed" for event in service.audit.list_events()
    )
    assert service.audit.verify().valid


def test_completion_audit_exists_before_run_journal_reconciliation(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    service = create_service(db_path=tmp_path / "completion-reconcile.db")
    result = service.investigate(case.task)
    with sqlite3.connect(service.store.db_path) as connection:
        connection.execute(
            "UPDATE investigation_runs SET state = 'running' WHERE incident_id = ?",
            (case.task.incident_id,),
        )
    assert service.store.get(case.task.incident_id) == result
    completion = [
        event for event in service.audit.list_events(trace_id=result.trace_id)
        if event["action"] == "investigation_completed"
    ]
    assert len(completion) == 1
    assert service.investigate(case.task) == result
    assert service.run_journal.get(case.task.incident_id)[2] == "completed"
    assert len([
        event for event in service.audit.list_events(trace_id=result.trace_id)
        if event["action"] == "investigation_completed"
    ]) == 1


def test_evidence_journal_hashes_content_and_rejects_atomic_collision(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    first, second = case.evidence[:2]
    db_path = tmp_path / "evidence.db"
    journal = EvidenceJournal(db_path)
    journal.record_batch("trace-one", [first])
    journal.record_batch("trace-one", [first])
    original = journal.list_for_trace("trace-one")
    assert len(original) == 1
    assert original[0].evidence_key_sha256 != first.evidence_id
    assert len(original[0].payload_sha256) == 64

    changed = first.model_copy(update={"summary": "different private content"})
    with pytest.raises(EvidenceIdentityError, match="conflicting contents"):
        journal.record_batch("trace-one", [second, changed])
    assert journal.list_for_trace("trace-one") == original
    journal.record_batch("trace-two", [changed])
    assert len(journal.list_for_trace("trace-two")) == 1
    assert first.summary not in db_path.read_bytes().decode("utf-8", errors="ignore")


def test_supervisor_persists_only_reviewed_wave_evidence_hashes(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    service = create_service(db_path=tmp_path / "multi.db", orchestration_mode="multi")
    result = service.investigate(case.task)
    records = EvidenceJournal(service.store.db_path).list_for_trace(result.trace_id)
    assert records
    assert {item.source for item in records} <= {"metrics", "logs", "traces", "changes"}
