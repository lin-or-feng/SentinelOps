from datetime import datetime, timezone

import pytest

from sentinelops.adapters import FixtureEvidenceTool, load_fixture_cases
from sentinelops.audit import AuditLog
from sentinelops.domain import ActionType, EvidenceSource, InvestigationAction, QuerySpec
from sentinelops.gateway import EvidenceGateway, EvidenceToolError, GatewayPolicy
from sentinelops.runtime import BudgetExceeded, InvestigationBudget


def test_budget_rejects_repeated_actions() -> None:
    budget = InvestigationBudget(max_steps=4, max_queries=4, repeated_action_limit=1)
    action = InvestigationAction(
        action=ActionType.QUERY,
        source=EvidenceSource.LOGS,
        rationale="test",
    )
    budget.consume(action)
    with pytest.raises(BudgetExceeded, match="repeated"):
        budget.consume(action)


def test_budget_rejects_query_overflow() -> None:
    budget = InvestigationBudget(max_steps=4, max_queries=1)
    budget.consume(
        InvestigationAction(
            action=ActionType.QUERY,
            source=EvidenceSource.LOGS,
            rationale="first",
        )
    )
    with pytest.raises(BudgetExceeded, match="query budget"):
        budget.consume(
            InvestigationAction(
                action=ActionType.QUERY,
                source=EvidenceSource.METRICS,
                rationale="second",
            )
        )


def test_gateway_denies_non_allowlisted_source_and_audits(tmp_path) -> None:
    cases = load_fixture_cases("evals/incidents.json")
    audit = AuditLog(tmp_path / "gateway.db")
    gateway = EvidenceGateway(
        FixtureEvidenceTool(cases[0].evidence),
        audit,
        GatewayPolicy(allowed_sources=frozenset({EvidenceSource.LOGS})),
    )
    with pytest.raises(PermissionError):
        gateway.query(
            QuerySpec(
                incident_id=cases[0].task.incident_id,
                source=EvidenceSource.CHANGES,
            ),
            trace_id="trace-denied",
        )
    events = audit.list_events(trace_id="trace-denied")
    assert events[0]["status"] == "denied"


def test_gateway_retries_transient_failure(tmp_path) -> None:
    class FlakyTool:
        read_only = True
        name = "flaky"

        def __init__(self) -> None:
            self.calls = 0

        def query(self, spec):
            self.calls += 1
            if self.calls == 1:
                raise TimeoutError("temporary")
            return []

    tool = FlakyTool()
    gateway = EvidenceGateway(
        tool,
        AuditLog(tmp_path / "gateway.db"),
        GatewayPolicy(allowed_sources=frozenset({EvidenceSource.LOGS})),
    )
    assert gateway.query(
        QuerySpec(incident_id="inc-retry", source=EvidenceSource.LOGS),
        trace_id="trace-retry",
    ) == []
    assert tool.calls == 2


def test_gateway_wraps_and_audits_non_retryable_failure(tmp_path) -> None:
    class BrokenTool:
        read_only = True
        name = "broken"

        def query(self, spec):
            raise ValueError("malformed upstream payload")

    audit = AuditLog(tmp_path / "gateway.db")
    gateway = EvidenceGateway(
        BrokenTool(),
        audit,
        GatewayPolicy(allowed_sources=frozenset({EvidenceSource.LOGS})),
    )
    with pytest.raises(EvidenceToolError):
        gateway.query(
            QuerySpec(incident_id="inc-broken", source=EvidenceSource.LOGS),
            trace_id="trace-broken",
        )
    event = audit.list_events(trace_id="trace-broken")[0]
    assert event["status"] == "error"
    assert event["details"]["retryable"] is False
