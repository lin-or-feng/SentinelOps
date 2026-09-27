from datetime import datetime, timezone
import threading

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


def test_gateway_circuit_breaker_opens_and_recovers_with_one_probe(tmp_path) -> None:
    class FakeClock:
        def __init__(self) -> None:
            self.now = 100.0

        def __call__(self) -> float:
            return self.now

    class RecoveringTool:
        read_only = True
        name = "recovering"

        def __init__(self) -> None:
            self.calls = 0
            self.recovered = False
            self.probe_started = threading.Event()
            self.release_probe = threading.Event()

        def query(self, spec):
            self.calls += 1
            if not self.recovered:
                raise ConnectionError("provider unavailable")
            if self.calls == 3:
                self.probe_started.set()
                assert self.release_probe.wait(timeout=2)
            return []

    clock = FakeClock()
    tool = RecoveringTool()
    audit = AuditLog(tmp_path / "circuit.db")
    gateway = EvidenceGateway(
        tool,
        audit,
        GatewayPolicy(
            allowed_sources=frozenset({EvidenceSource.LOGS}),
            max_attempts=1,
            failure_threshold=2,
            cooldown_seconds=10,
        ),
        clock=clock,
    )
    query = QuerySpec(incident_id="inc-circuit", source=EvidenceSource.LOGS)

    for trace_id in ("trace-failure-1", "trace-failure-2"):
        with pytest.raises(EvidenceToolError):
            gateway.query(query, trace_id=trace_id)
    with pytest.raises(EvidenceToolError, match="circuit is open"):
        gateway.query(query, trace_id="trace-open")
    assert tool.calls == 2

    tool.recovered = True
    clock.now += 10
    probe_result: list[list] = []

    def run_probe() -> None:
        probe_result.append(gateway.query(query, trace_id="trace-probe"))

    probe_thread = threading.Thread(target=run_probe)
    probe_thread.start()
    assert tool.probe_started.wait(timeout=2)
    with pytest.raises(EvidenceToolError, match="circuit is open"):
        gateway.query(query, trace_id="trace-concurrent-probe")
    assert tool.calls == 3
    tool.release_probe.set()
    probe_thread.join(timeout=2)

    assert not probe_thread.is_alive()
    assert probe_result == [[]]
    assert gateway.query(query, trace_id="trace-after-recovery") == []
    assert tool.calls == 4
    open_event = audit.list_events(trace_id="trace-open")[0]
    assert open_event["status"] == "degraded"
    assert open_event["details"]["reason"] == "circuit_open"
    probe_event = audit.list_events(trace_id="trace-concurrent-probe")[0]
    assert probe_event["details"]["reason"] == "circuit_probe_in_progress"


def test_gateway_circuit_state_is_isolated_per_source(tmp_path) -> None:
    class SelectiveTool:
        read_only = True
        name = "selective"

        def query(self, spec):
            if spec.source == EvidenceSource.LOGS:
                raise ConnectionError("logs unavailable")
            return []

    gateway = EvidenceGateway(
        SelectiveTool(),
        AuditLog(tmp_path / "isolated-circuit.db"),
        GatewayPolicy(
            allowed_sources=frozenset({EvidenceSource.LOGS, EvidenceSource.METRICS}),
            max_attempts=1,
            failure_threshold=1,
        ),
    )

    with pytest.raises(EvidenceToolError):
        gateway.query(
            QuerySpec(incident_id="inc-isolated", source=EvidenceSource.LOGS),
            trace_id="trace-logs-failure",
        )
    assert gateway.query(
        QuerySpec(incident_id="inc-isolated", source=EvidenceSource.METRICS),
        trace_id="trace-metrics-ok",
    ) == []
