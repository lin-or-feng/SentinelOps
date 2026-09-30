import json
import sqlite3

import httpx
import pytest
from pydantic import ValidationError

from sentinelops.adapters import FixtureEvidenceTool, load_fixture_cases
from sentinelops.cli import main
from sentinelops.domain import InvestigatorFinding, InvestigatorStatus
from sentinelops.model_policy import ModelPolicyError, OllamaPolicyConfig
from sentinelops.service import create_service
from sentinelops.specialist_shadow import (
    OllamaHypothesisProposer,
    ShadowContext,
    ShadowEvidence,
    ShadowHypothesis,
    ShadowJournal,
    ShadowModelResponse,
    ShadowSpecialist,
)


class FixedProposer:
    def __init__(self, *, ref="E1", fail=False):
        self.ref = ref
        self.fail = fail
        self.contexts = []

    def propose_hypothesis(self, context):
        self.contexts.append(context)
        if self.fail:
            raise ModelPolicyError("transport_failure")
        return ShadowModelResponse(
            hypothesis=ShadowHypothesis(
                code="deployment_regression",
                evidence_refs=[self.ref],
                confidence=0.5,
                uncertainty="Needs another independent source.",
            ),
            prompt_tokens=20,
            completion_tokens=8,
        )


def test_shadow_contract_rejects_extra_fields_and_unsupported_claims() -> None:
    with pytest.raises(ValidationError):
        ShadowHypothesis.model_validate(
            {"code": "deployment_regression", "evidence_refs": [],
             "confidence": 0.5, "uncertainty": "uncertain"}
        )
    with pytest.raises(ValidationError):
        ShadowHypothesis.model_validate(
            {"code": "unknown", "evidence_refs": ["E1"],
             "confidence": 0.5, "uncertainty": "uncertain"}
        )
    with pytest.raises(ValidationError):
        ShadowContext.model_validate(
            {"source": "logs", "evidence": [{"ref": "E1", "summary": "signal"}],
             "incident_id": "not-allowed"}
        )


def test_shadow_mode_is_opt_in_and_does_not_change_verdict(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    baseline = create_service(db_path=tmp_path / "baseline.db", orchestration_mode="multi")
    expected = baseline.investigate(case.task)
    proposer = FixedProposer()
    shadowed = create_service(
        db_path=tmp_path / "shadow.db", orchestration_mode="multi",
        shadow_mode="ollama", shadow_proposer=proposer,
    )
    actual = shadowed.investigate(case.task)

    assert actual.report == expected.report
    assert actual.degraded_components == expected.degraded_components
    assert actual.trace == expected.trace or [step.action for step in actual.trace] == [
        step.action for step in expected.trace
    ]
    assert len(proposer.contexts) == 2
    assert all(len({item.ref for item in context.evidence}) == len(context.evidence)
               for context in proposer.contexts)
    records = ShadowJournal(shadowed.store.db_path).list_for_trace(actual.trace_id)
    assert len(records) == 2
    assert all(item.reason_code == "accepted" for item in records)
    assert all(item.prompt_tokens == 20 for item in records)
    assert all("incident_id" not in context.model_dump() for context in proposer.contexts)
    assert all("raw_ref" not in context.model_dump_json() for context in proposer.contexts)
    assert ShadowJournal(baseline.store.db_path).list_for_trace(expected.trace_id) == []
    summary = ShadowJournal(shadowed.store.db_path).summary()
    assert summary["observations"] == 2
    assert summary["accepted"] == 2
    assert summary["prompt_tokens_observed"] == 40
    assert summary["baseline_agreement_rate"] is not None


@pytest.mark.parametrize("proposer", [FixedProposer(ref="E99"), FixedProposer(fail=True)])
def test_shadow_invalid_reference_or_model_failure_cannot_change_verdict(
    tmp_path, proposer
) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    service = create_service(
        db_path=tmp_path / "failure.db", orchestration_mode="multi",
        shadow_mode="ollama", shadow_proposer=proposer,
    )
    result = service.investigate(case.task)
    assert result.report.selected_code == case.expected_root_cause
    records = ShadowJournal(service.store.db_path).list_for_trace(result.trace_id)
    assert records
    assert all(item.proposed_code is None for item in records)
    assert {item.reason_code for item in records} == {
        "transport_failure" if proposer.fail else "unsupported_evidence_reference"
    }


def test_shadow_context_redacts_private_content_without_persisting_it(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    item = case.evidence[0]
    private_value = "138" + "00112233"
    changed = item.model_copy(update={"summary": f"deployment signal {private_value}"})
    finding = InvestigatorFinding(
        assignment_id="assignment-private", actor="changes-investigator",
        incident_id=item.incident_id, service=item.service, source=item.source,
        status=InvestigatorStatus.OK, evidence=[changed], duration_ms=1,
    )
    service = create_service(db_path=tmp_path / "privacy.db")
    proposer = FixedProposer()
    journal = ShadowJournal(service.store.db_path)
    shadow = ShadowSpecialist(proposer, service.audit, journal)
    shadow.observe("trace-private", finding)
    assert private_value not in proposer.contexts[0].model_dump_json()
    assert "REDACTED" in proposer.contexts[0].evidence[0].summary
    assert private_value not in journal.db_path.read_bytes().decode("utf-8", errors="ignore")


def test_shadow_requires_multi_or_auto_and_explicit_activation(tmp_path) -> None:
    with pytest.raises(ValueError, match="requires multi or auto"):
        create_service(db_path=tmp_path / "invalid.db", shadow_mode="ollama",
                       shadow_proposer=FixedProposer())
    with pytest.raises(ValueError, match="requires shadow_mode"):
        create_service(db_path=tmp_path / "invalid2.db", shadow_proposer=FixedProposer())


def test_ollama_hypothesis_proposer_uses_bounded_structured_local_call() -> None:
    observed = []

    def handler(request):
        observed.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "message": {"content": json.dumps({
                    "code": "cache_miss_storm", "evidence_refs": ["E1"],
                    "confidence": 0.65, "uncertainty": "One source only",
                })},
                "prompt_eval_count": 12,
                "eval_count": 6,
            },
        )

    adapter = OllamaHypothesisProposer(
        OllamaPolicyConfig(model="test-model"),
        transport=httpx.MockTransport(handler),
    )
    try:
        response = adapter.propose_hypothesis(
            ShadowContext(source="metrics", evidence=[
                ShadowEvidence(ref="E1", summary="cache miss rate increased")
            ])
        )
    finally:
        adapter.close()
    assert response.hypothesis.code == "cache_miss_storm"
    assert response.prompt_tokens == 12
    assert observed[0]["stream"] is False
    assert observed[0]["format"] == ShadowHypothesis.model_json_schema()
    assert "incident_id" not in observed[0]["messages"][1]["content"]


def test_ollama_shadow_rejects_malformed_structured_output() -> None:
    adapter = OllamaHypothesisProposer(
        OllamaPolicyConfig(model="test-model"),
        transport=httpx.MockTransport(lambda request: httpx.Response(
            200, json={"message": {"content": json.dumps({
                "code": "deployment_regression", "evidence_refs": ["E1"],
                "confidence": 0.7, "uncertainty": "uncertain", "tool_call": "forbidden",
            })}},
        )),
    )
    try:
        with pytest.raises(ModelPolicyError, match="invalid_structured_output"):
            adapter.propose_hypothesis(ShadowContext(
                source="changes", evidence=[ShadowEvidence(ref="E1", summary="release")]
            ))
    finally:
        adapter.close()


def test_shadow_journal_failure_cannot_revoke_persisted_verdict(tmp_path, monkeypatch) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    service = create_service(
        db_path=tmp_path / "journal-failure.db", orchestration_mode="multi",
        shadow_mode="ollama", shadow_proposer=FixedProposer(),
    )

    def fail_record(*args, **kwargs):
        raise sqlite3.OperationalError("synthetic write failure")

    monkeypatch.setattr(service.agent.shadow.journal, "record", fail_record)
    result = service.investigate(case.task)
    assert result.report.selected_code == case.expected_root_cause
    assert service.store.get(case.task.incident_id) == result
    assert service.run_journal.get(case.task.incident_id)[2] == "completed"
    assert ShadowJournal(service.store.db_path).list_for_trace(result.trace_id) == []
    assert any(
        item["details"].get("reason_code") == "shadow_recording_failure"
        for item in service.audit.list_events(trace_id=result.trace_id, limit=100)
    )


def test_shadow_is_not_called_after_evidence_identity_conflict(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[1]
    metric, log, trace = case.evidence
    tool = FixtureEvidenceTool(
        [metric, log.model_copy(update={"evidence_id": metric.evidence_id}), trace]
    )
    proposer = FixedProposer()
    service = create_service(
        db_path=tmp_path / "conflict.db", evidence_tool=tool,
        orchestration_mode="multi", shadow_mode="ollama", shadow_proposer=proposer,
    )
    result = service.investigate(case.task)
    assert proposer.contexts == []
    assert ShadowJournal(service.store.db_path).list_for_trace(result.trace_id) == []


def test_shadow_report_cli_reads_metadata_only(tmp_path, capsys) -> None:
    missing = tmp_path / "missing.db"
    assert main(["specialist-shadow-report", "--db", str(missing)]) == 2
    assert not missing.exists()
    capsys.readouterr()
    case = load_fixture_cases("evals/incidents.json")[0]
    service = create_service(
        db_path=tmp_path / "report.db", orchestration_mode="multi",
        shadow_mode="ollama", shadow_proposer=FixedProposer(),
    )
    service.investigate(case.task)
    assert main(["specialist-shadow-report", "--db", str(service.store.db_path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["observations"] == 2
    assert "accuracy" not in report
