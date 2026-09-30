import json

import httpx
import pytest
from fastapi.testclient import TestClient

from sentinelops.application.assistant_preview import (
    AssistantContext,
    AssistantEvidence,
    AssistantReply,
    OllamaExplanationAssistant,
)
from sentinelops.demo_web import create_demo_app
from sentinelops.model_policy import ModelPolicyError, OllamaPolicyConfig


class FakeAssistant:
    def __init__(self):
        self.contexts = []

    def answer(self, context):
        self.contexts.append(context)
        return AssistantReply(
            decision=context.decision,
            answer="已引用证据支持现有裁决，但不能证明所有其他可能性。",
            evidence_refs=[context.evidence[0].evidence_id],
            uncertainty="只验证当前合成事故与已引用证据。",
        )


def test_assistant_is_off_by_default_even_with_model_environment(monkeypatch):
    monkeypatch.setenv("SENTINELOPS_DEMO_ASSISTANT", "ollama")
    with TestClient(create_demo_app()) as client:
        assert client.get("/api/assistant/status").json()["enabled"] is False
        report = client.post("/api/run", json={
            "case_id": "inc-deploy-001", "mode": "multi",
        }).json()
        assert report["run_id"]
        response = client.post("/api/assistant", json={
            "run_id": report["run_id"], "incident_id": "inc-deploy-001",
            "question": "为什么是这个根因？",
        })
    assert response.status_code == 503


def test_assistant_explains_selected_run_without_changing_verdict():
    assistant = FakeAssistant()
    with TestClient(create_demo_app(assistant=assistant)) as client:
        assert client.get("/api/assistant/status").json() == {
            "enabled": True, "mode": "advisory_only",
        }
        report = client.post("/api/run", json={
            "case_id": "all", "mode": "multi",
        }).json()
        original = report["results"][0]
        response = client.post("/api/assistant", json={
            "run_id": report["run_id"], "incident_id": original["incident_id"],
            "question": "为什么判断为这个根因？",
        })
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "advisory"
    assert payload["decision_unchanged"] is True
    assert payload["reply"]["decision"] == original["actual_code"]
    context = assistant.contexts[0]
    assert set(item.evidence_id for item in context.evidence) == {
        item["id"] for item in original["evidence"] if item["used"]
    }
    assert "expected_code" not in context.model_dump_json()
    assert original["actual_code"] == original["expected_code"]


def test_assistant_rejects_stale_run_other_incident_and_private_question():
    assistant = FakeAssistant()
    with TestClient(create_demo_app(assistant=assistant)) as client:
        report = client.post("/api/run", json={
            "case_id": "inc-deploy-001", "mode": "single",
        }).json()
        request = {
            "run_id": report["run_id"], "incident_id": "inc-deploy-001",
            "question": "为什么这样判断？",
        }
        assert client.post("/api/assistant", json={
            **request, "run_id": "A" * 24,
        }).status_code == 404
        assert client.post("/api/assistant", json={
            **request, "incident_id": "inc-db-001",
        }).status_code == 404
        private_marker = "139" + "12345678"
        response = client.post("/api/assistant", json={
            **request, "question": f"请解释 {private_marker}",
        })
    assert response.status_code == 422
    assert private_marker not in response.text
    assert not assistant.contexts


@pytest.mark.parametrize("fault", ["verdict", "reference"])
def test_assistant_endpoint_rejects_fake_adapter_boundary_violations(fault):
    class BadAssistant:
        def answer(self, context):
            return AssistantReply(
                decision=("cache_miss_storm" if fault == "verdict" else context.decision),
                answer="This is advisory only.",
                evidence_refs=(["not-in-context"] if fault == "reference" else [
                    context.evidence[0].evidence_id
                ]),
                uncertainty="Could be incomplete.",
            )

    with TestClient(create_demo_app(assistant=BadAssistant())) as client:
        report = client.post("/api/run", json={
            "case_id": "inc-deploy-001", "mode": "multi",
        }).json()
        response = client.post("/api/assistant", json={
            "run_id": report["run_id"], "incident_id": "inc-deploy-001",
            "question": "为什么这样判断？",
        })
    assert response.status_code == 200
    assert response.json() == {
        "status": "unavailable",
        "reason_code": (
            "verdict_mismatch" if fault == "verdict" else "unsupported_evidence_reference"
        ),
    }


def _context():
    return AssistantContext(
        service="example-service", symptoms=["error rate increased"],
        decision="deployment_regression", question="Why this verdict?",
        evidence=[
            AssistantEvidence(evidence_id="E1", source="changes", summary="new release"),
            AssistantEvidence(evidence_id="E2", source="logs", summary="errors increased"),
        ],
    )


def test_ollama_assistant_uses_local_bounded_json_without_expected_answer():
    observed = []

    def handler(request):
        observed.append(json.loads(request.content))
        return httpx.Response(200, json={"message": {"content": json.dumps({
            "decision": "deployment_regression",
            "answer": "Release timing and error logs support the recorded decision.",
            "evidence_refs": ["E1", "E2"],
            "uncertainty": "Causality is not independently proven.",
        })}})

    assistant = OllamaExplanationAssistant(
        OllamaPolicyConfig(model="test-model"),
        transport=httpx.MockTransport(handler),
    )
    try:
        reply = assistant.answer(_context())
    finally:
        assistant.close()
    assert reply.evidence_refs == ["E1", "E2"]
    assert observed[0]["stream"] is False
    assert observed[0]["format"] == AssistantReply.model_json_schema()
    assert "expected_code" not in observed[0]["messages"][1]["content"]
    assert "tools" not in observed[0]


@pytest.mark.parametrize("decision,refs,reason", [
    ("cache_miss_storm", ["E1"], "verdict_mismatch"),
    ("deployment_regression", ["E99"], "unsupported_evidence_reference"),
])
def test_ollama_assistant_fails_closed_on_verdict_or_reference_drift(
    decision, refs, reason
):
    assistant = OllamaExplanationAssistant(
        OllamaPolicyConfig(model="test-model"),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={
            "message": {"content": json.dumps({
                "decision": decision, "answer": "Explanation", "evidence_refs": refs,
                "uncertainty": "Uncertain.",
            })},
        })),
    )
    try:
        with pytest.raises(ModelPolicyError, match=reason):
            assistant.answer(_context())
    finally:
        assistant.close()
