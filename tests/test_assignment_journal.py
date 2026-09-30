import pytest

from sentinelops.domain import EvidenceSource, InvestigatorAssignment, InvestigatorStatus, QuerySpec
from sentinelops.storage import AssignmentJournal, AssignmentState, AssignmentStateError


def _assignment(assignment_id: str) -> InvestigatorAssignment:
    return InvestigatorAssignment(
        assignment_id=assignment_id,
        actor="metrics-investigator",
        query=QuerySpec(incident_id="inc-test-001", source=EvidenceSource.METRICS),
        deadline_seconds=10,
    )


def test_assignment_journal_persists_valid_lifecycle_without_evidence(tmp_path) -> None:
    database = tmp_path / "assignments.db"
    journal = AssignmentJournal(database)
    assignment = _assignment("assignment-one")

    journal.create("trace-test-001", assignment)
    assert journal.list_for_trace("trace-test-001")[0].state == AssignmentState.CREATED
    journal.start(assignment.assignment_id)
    journal.finish(assignment.assignment_id, InvestigatorStatus.OK)

    persisted = AssignmentJournal(database).list_for_trace("trace-test-001")
    assert len(persisted) == 1
    assert persisted[0].state == AssignmentState.COMPLETED
    assert persisted[0].source == "metrics"
    assert persisted[0].actor == "metrics-investigator"


def test_assignment_journal_rejects_duplicate_and_invalid_transitions(tmp_path) -> None:
    journal = AssignmentJournal(tmp_path / "assignments.db")
    assignment = _assignment("assignment-one")
    journal.create("trace-test-001", assignment)

    with pytest.raises(AssignmentStateError, match="already exists"):
        journal.create("trace-test-001", assignment)
    with pytest.raises(AssignmentStateError, match="invalid assignment state"):
        journal.finish(assignment.assignment_id, InvestigatorStatus.OK)
    journal.start(assignment.assignment_id)
    journal.finish(assignment.assignment_id, InvestigatorStatus.ERROR)
    with pytest.raises(AssignmentStateError, match="invalid assignment state"):
        journal.start(assignment.assignment_id)
    assert journal.list_for_trace("trace-test-001")[0].state == AssignmentState.FAILED


def test_assignment_journal_explicitly_expires_unfinished_trace(tmp_path) -> None:
    journal = AssignmentJournal(tmp_path / "assignments.db")
    journal.create("trace-test-001", _assignment("assignment-one"))
    journal.create("trace-test-001", _assignment("assignment-two"))
    journal.create("trace-test-002", _assignment("assignment-three"))
    journal.start("assignment-two")

    assert journal.expire_incomplete("trace-test-001") == 2
    assert journal.expire_incomplete("trace-test-001") == 0
    assert [item.state for item in journal.list_for_trace("trace-test-001")] == [
        AssignmentState.EXPIRED,
        AssignmentState.EXPIRED,
    ]
    assert journal.list_for_trace("trace-test-002")[0].state == AssignmentState.CREATED
