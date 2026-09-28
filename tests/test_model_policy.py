from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx
import pytest

from sentinelops.audit import AuditLog
from sentinelops.adapters import load_fixture_cases
from sentinelops.domain import ActionType, Evidence, EvidenceSource, IncidentTask
from sentinelops.model_policy import (
    ControlledModelPolicy,
    ModelPolicyContext,
    ModelPolicyError,
    ModelSourceProposal,
    OllamaPolicyConfig,
    OllamaSourceProposer,
    SOURCE_SELECTION_PROMPT_ID,
    SOURCE_SELECTION_SYSTEM_PROMPT,
    ollama_policy_config_from_env,
    source_selection_prompt_sha256,
)
from sentinelops.policy import InvestigationState
from sentinelops.service import create_service


def _task(*, incident_id: str = "inc-policy-001") -> IncidentTask:
    return IncidentTask(
        incident_id=incident_id,
        tenant_id="demo",
        service="checkout-service",
        started_at=datetime.now(timezone.utc),
        symptoms=["latency increased after release"],
    )


class FakeProposer:
    def __init__(self, proposal: ModelSourceProposal | Exception) -> None:
        self.proposal = proposal
        self.contexts: list[ModelPolicyContext] = []

    def propose(self, context: ModelPolicyContext) -> ModelSourceProposal:
        self.contexts.append(context)
        if isinstance(self.proposal, Exception):
            raise self.proposal
        return self.proposal


class CountingProposer:
    def __init__(self) -> None:
        self.calls = 0

    def propose(self, context: ModelPolicyContext) -> ModelSourceProposal:
        self.calls += 1
        return ModelSourceProposal(source=context.available_sources[0], rationale="unused")


def _policy(tmp_path, proposer, *, allowed_sources=None) -> ControlledModelPolicy:
    return ControlledModelPolicy(
        proposer,
        AuditLog(tmp_path / "audit.db", key="test-key"),
        allowed_sources=allowed_sources
        or frozenset(
            {
                EvidenceSource.METRICS,
                EvidenceSource.LOGS,
                EvidenceSource.TRACES,
                EvidenceSource.CHANGES,
            }
        ),
    )


def test_model_can_only_prioritize_an_available_source(tmp_path) -> None:
    proposer = FakeProposer(
        ModelSourceProposal(source=EvidenceSource.LOGS, rationale="raw model rationale marker")
    )
    policy = _policy(tmp_path, proposer)
    state = InvestigationState(task=_task())

    action = policy.decide(state, trace_id="trace-model-accepted")

    assert action.action == ActionType.QUERY
    assert action.source == EvidenceSource.LOGS
    assert action.keywords == ["checkout-service", "logs", "latency increased after release"]
    assert "raw model rationale marker" not in action.rationale
    assert proposer.contexts[0].available_sources
    event = policy.audit.list_events(trace_id="trace-model-accepted")[0]
    assert event["details"] == {
        "outcome": "accepted",
        "reason_code": "proposal_accepted",
        "source": "logs",
    }
    assert "raw model rationale marker" not in json.dumps(event, ensure_ascii=False)


def test_disallowed_or_already_queried_source_falls_back(tmp_path) -> None:
    proposer = FakeProposer(
        ModelSourceProposal(source=EvidenceSource.RUNBOOK, rationale="try an unavailable source")
    )
    policy = _policy(
        tmp_path,
        proposer,
        allowed_sources=frozenset({EvidenceSource.LOGS, EvidenceSource.METRICS}),
    )
    state = InvestigationState(task=_task(), queried_sources={EvidenceSource.METRICS})

    action = policy.decide(state, trace_id="trace-model-denied")

    assert action.source == EvidenceSource.LOGS
    event = policy.audit.list_events(trace_id="trace-model-denied")[0]
    assert event["status"] == "degraded"
    assert event["details"]["reason_code"] == "source_outside_guard"


def test_model_failure_uses_deterministic_fallback(tmp_path) -> None:
    proposer = FakeProposer(ModelPolicyError("invalid_structured_output"))
    policy = _policy(tmp_path, proposer)

    action = policy.decide(InvestigationState(task=_task()), trace_id="trace-model-fallback")

    assert action.source == EvidenceSource.CHANGES
    event = policy.audit.list_events(trace_id="trace-model-fallback")[0]
    assert event["details"] == {
        "outcome": "fallback",
        "reason_code": "invalid_structured_output",
    }


def test_adapter_contract_violation_uses_fallback(tmp_path) -> None:
    proposer = FakeProposer({"source": "logs"})  # type: ignore[arg-type]
    policy = _policy(tmp_path, proposer)

    action = policy.decide(InvestigationState(task=_task()), trace_id="trace-invalid-adapter")

    assert action.source == EvidenceSource.CHANGES
    event = policy.audit.list_events(trace_id="trace-invalid-adapter")[0]
    assert event["details"]["reason_code"] == "invalid_structured_output"


def test_private_model_output_is_rejected_without_audit_echo(tmp_path) -> None:
    private_value = "136" + "1234" + "5678"
    proposer = FakeProposer(
        ModelSourceProposal(
            source=EvidenceSource.LOGS,
            rationale=f"contact {private_value}",
        )
    )
    policy = _policy(tmp_path, proposer)

    action = policy.decide(InvestigationState(task=_task()), trace_id="trace-private-output")

    assert action.source == EvidenceSource.CHANGES
    event = policy.audit.list_events(trace_id="trace-private-output")[0]
    serialized = json.dumps(event, ensure_ascii=False)
    assert event["details"]["reason_code"] == "private_output_rejected"
    assert private_value not in serialized


def test_model_is_not_called_for_finish_or_escalate(tmp_path) -> None:
    proposer = CountingProposer()
    policy = _policy(tmp_path, proposer)
    task = _task()
    evidence = [
        Evidence(
            evidence_id=f"ev-{source.value}",
            incident_id=task.incident_id,
            service=task.service,
            source=source,
            observed_at=datetime.now(timezone.utc),
            summary="deployment release error regression rollback",
            raw_ref=f"fixture://{source.value}",
        )
        for source in (EvidenceSource.CHANGES, EvidenceSource.LOGS)
    ]

    action = policy.decide(
        InvestigationState(task=task, evidence=evidence),
        trace_id="trace-deterministic-terminal",
    )

    assert action.action == ActionType.FINISH
    assert proposer.calls == 0
    event = policy.audit.list_events(trace_id="trace-deterministic-terminal")[0]
    assert event["details"]["reason_code"] == "deterministic_terminal"


def test_multi_agent_plan_moves_only_the_proposed_source(tmp_path) -> None:
    proposer = FakeProposer(
        ModelSourceProposal(source=EvidenceSource.LOGS, rationale="logs first")
    )
    policy = _policy(tmp_path, proposer)

    plan = policy.plan_sources(
        _task(),
        allowed_sources=policy.allowed_sources,
        trace_id="trace-model-plan",
    )

    assert plan == (
        EvidenceSource.LOGS,
        EvidenceSource.CHANGES,
        EvidenceSource.METRICS,
        EvidenceSource.TRACES,
    )


def test_ollama_adapter_uses_schema_non_streaming_and_temperature_zero() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        proposal = {"source": "logs", "rationale": "inspect correlated errors"}
        return httpx.Response(
            200,
            json={
                "message": {"content": json.dumps(proposal)},
                "prompt_eval_count": 42,
                "eval_count": 9,
            },
        )

    proposer = OllamaSourceProposer(
        OllamaPolicyConfig(model="qwen3:8b"),
        transport=httpx.MockTransport(handler),
        collect_usage=True,
    )
    context = ModelPolicyContext(
        service="checkout-service",
        symptoms=["latency"],
        available_sources=[EvidenceSource.LOGS],
    )

    proposal = proposer.propose(context)
    proposer.close()

    assert proposal.source == EvidenceSource.LOGS
    assert captured["stream"] is False
    assert captured["options"] == {"temperature": 0}
    assert captured["format"] == ModelSourceProposal.model_json_schema()
    assert "finish" not in json.dumps(captured["format"])
    system_prompt = captured["messages"][0]["content"]
    assert system_prompt == SOURCE_SELECTION_SYSTEM_PROMPT
    assert SOURCE_SELECTION_PROMPT_ID == "source-selection-v1"
    assert len(source_selection_prompt_sha256()) == 64
    observations = proposer.usage_observations()
    assert len(observations) == 1
    assert observations[0].prompt_tokens == 42
    assert observations[0].completion_tokens == 9


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (httpx.Response(200, json={"message": {"content": "not-json"}}), "invalid_structured_output"),
        (httpx.Response(503, text="unavailable"), "transport_failure"),
    ],
)
def test_ollama_adapter_classifies_failures(response, reason) -> None:
    proposer = OllamaSourceProposer(
        OllamaPolicyConfig(model="qwen3:8b"),
        transport=httpx.MockTransport(lambda request: response),
    )
    context = ModelPolicyContext(
        service="checkout-service",
        symptoms=["latency"],
        available_sources=[EvidenceSource.LOGS],
    )

    with pytest.raises(ModelPolicyError, match=reason):
        proposer.propose(context)
    proposer.close()


def test_ollama_adapter_rejects_oversized_response() -> None:
    oversized = "x" * 2_000
    proposer = OllamaSourceProposer(
        OllamaPolicyConfig(model="qwen3:8b", max_response_bytes=1_024),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={"message": {"content": oversized}},
            )
        ),
    )
    context = ModelPolicyContext(
        service="checkout-service",
        symptoms=["latency"],
        available_sources=[EvidenceSource.LOGS],
    )

    with pytest.raises(ModelPolicyError, match="response_too_large"):
        proposer.propose(context)
    proposer.close()


def test_ollama_model_digest_failure_degrades_and_is_cached() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, text="unavailable")

    proposer = OllamaSourceProposer(
        OllamaPolicyConfig(model="qwen2.5:7b"),
        transport=httpx.MockTransport(handler),
    )

    assert proposer.model_digest() is None
    assert proposer.model_digest() is None
    assert calls == 1
    proposer.close()


def test_ollama_adapter_rejects_concurrent_gpu_work_without_queueing() -> None:
    entered = threading.Event()
    release = threading.Event()

    def handler(request: httpx.Request) -> httpx.Response:
        entered.set()
        assert release.wait(timeout=2)
        proposal = {"source": "logs", "rationale": "first request"}
        return httpx.Response(200, json={"message": {"content": json.dumps(proposal)}})

    proposer = OllamaSourceProposer(
        OllamaPolicyConfig(model="qwen3:8b", max_inflight=1, rate_limit_rpm=10),
        transport=httpx.MockTransport(handler),
    )
    context = ModelPolicyContext(
        service="checkout-service",
        symptoms=["latency"],
        available_sources=[EvidenceSource.LOGS],
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(proposer.propose, context)
        assert entered.wait(timeout=2)
        with pytest.raises(ModelPolicyError, match="model_busy"):
            proposer.propose(context)
        release.set()
        assert first.result(timeout=2).source == EvidenceSource.LOGS
    proposer.close()


def test_ollama_adapter_applies_sliding_window_rate_limit() -> None:
    now = [0.0]
    proposal = {"source": "logs", "rationale": "inspect errors"}
    proposer = OllamaSourceProposer(
        OllamaPolicyConfig(model="qwen3:8b", max_inflight=1, rate_limit_rpm=1),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={"message": {"content": json.dumps(proposal)}},
            )
        ),
        clock=lambda: now[0],
    )
    context = ModelPolicyContext(
        service="checkout-service",
        symptoms=["latency"],
        available_sources=[EvidenceSource.LOGS],
    )

    assert proposer.propose(context).source == EvidenceSource.LOGS
    with pytest.raises(ModelPolicyError, match="model_rate_limited"):
        proposer.propose(context)
    now[0] = 61.0
    assert proposer.propose(context).source == EvidenceSource.LOGS
    proposer.close()


@pytest.mark.parametrize(
    "url",
    [
        "https://model.example.com",
        "http://host.docker.internal:11434",
        "http://user:pass@127.0.0.1:11434",
        "http://127.0.0.1:11434/api",
    ],
)
def test_ollama_config_rejects_non_loopback_or_credentialed_urls(url) -> None:
    with pytest.raises(ValueError):
        OllamaPolicyConfig(model="qwen3:8b", base_url=url)


def test_ollama_config_requires_explicit_model() -> None:
    with pytest.raises(ValueError, match="SENTINELOPS_OLLAMA_MODEL"):
        ollama_policy_config_from_env({})


def test_ollama_config_reads_resource_limits() -> None:
    config = ollama_policy_config_from_env(
        {
            "SENTINELOPS_OLLAMA_MODEL": "qwen3:8b",
            "SENTINELOPS_OLLAMA_MAX_INFLIGHT": "2",
            "SENTINELOPS_OLLAMA_RATE_LIMIT_RPM": "12",
        }
    )

    assert config.max_inflight == 2
    assert config.rate_limit_rpm == 12


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_inflight": 0},
        {"max_inflight": 9},
        {"rate_limit_rpm": 0},
        {"rate_limit_rpm": 601},
    ],
)
def test_ollama_config_rejects_unsafe_resource_limits(overrides) -> None:
    with pytest.raises(ValueError):
        OllamaPolicyConfig(model="qwen3:8b", **overrides)


def test_service_rejects_invalid_policy_before_creating_database(tmp_path) -> None:
    database = tmp_path / "must-not-exist.db"

    with pytest.raises(ValueError, match="policy_mode"):
        create_service(db_path=database, policy_mode="autonomous")

    assert not database.exists()


def test_service_runs_controlled_policy_end_to_end(tmp_path) -> None:
    proposer = FakeProposer(
        ModelSourceProposal(source=EvidenceSource.LOGS, rationale="logs first")
    )
    service = create_service(
        dataset_path="evals/incidents.json",
        db_path=tmp_path / "service.db",
        policy_mode="ollama",
        model_proposer=proposer,
    )
    case = load_fixture_cases("evals/incidents.json")[0]

    result = service.investigate(case.task)

    assert result.trace[0].source == EvidenceSource.LOGS
    assert result.report.tool_queries <= case.task.query_budget
    events = service.audit.list_events(trace_id=result.trace_id, limit=100)
    assert any(event["action"] == "model_source_proposed" for event in events)
    rendered = service.metrics.render_prometheus()
    assert (
        'sentinelops_model_policy_decisions_total{outcome="accepted",reason_code="proposal_accepted"}'
        in rendered
    )
    assert (
        'sentinelops_model_policy_decisions_total{outcome="fallback",reason_code="source_outside_guard"}'
        in rendered
    )
    service.close()


def test_multi_agent_uses_controlled_source_plan_after_start_audit(tmp_path) -> None:
    proposer = FakeProposer(
        ModelSourceProposal(source=EvidenceSource.LOGS, rationale="logs first")
    )
    service = create_service(
        dataset_path="evals/incidents.json",
        db_path=tmp_path / "multi-service.db",
        orchestration_mode="multi",
        policy_mode="ollama",
        model_proposer=proposer,
    )
    case = load_fixture_cases("evals/incidents.json")[0]

    result = service.investigate(case.task)

    assert result.trace[0].source == EvidenceSource.LOGS
    chronological = list(
        reversed(service.audit.list_events(trace_id=result.trace_id, limit=100))
    )
    assert chronological[0]["action"] == "investigation_started"
    assert chronological[1]["action"] == "model_source_proposed"
    service.close()
