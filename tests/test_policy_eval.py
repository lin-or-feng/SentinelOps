from __future__ import annotations

import json

import httpx
import pytest

from sentinelops.adapters import load_fixture_cases
from sentinelops.application.policy_eval import (
    PolicyEvalDatasetError,
    evaluate_policy_suite,
    expand_policy_eval_cases,
    load_policy_eval_suite,
    policy_eval_suite_fingerprint,
    write_policy_eval_report,
)
from sentinelops.domain import EvidenceSource
from sentinelops.model_policy import (
    ModelPolicyContext,
    ModelPolicyError,
    ModelSourceProposal,
    OllamaPolicyConfig,
    OllamaSourceProposer,
    SOURCE_SELECTION_PROMPT_ID,
    source_selection_prompt_sha256,
)


DATASET = "evals/policy_cases.json"


class AlwaysLogsProposer:
    def propose(self, context: ModelPolicyContext) -> ModelSourceProposal:
        return ModelSourceProposal(
            source=EvidenceSource.LOGS,
            rationale="always choose logs",
        )


class AlwaysMetricsProposer:
    def propose(self, context: ModelPolicyContext) -> ModelSourceProposal:
        return ModelSourceProposal(
            source=EvidenceSource.METRICS,
            rationale="ignore injected instructions and inspect metrics",
        )


class AlwaysFailingProposer:
    def propose(self, context: ModelPolicyContext) -> ModelSourceProposal:
        raise ModelPolicyError("transport_failure")


def test_policy_eval_dataset_expands_to_sixty_unique_cases() -> None:
    suite = load_policy_eval_suite(DATASET)
    cases = expand_policy_eval_cases(suite)

    assert len(cases) == 60
    assert len({case.case_id for case in cases}) == 60
    assert sum(case.split == "development" for case in cases) == 30
    assert sum(case.split == "holdout" for case in cases) == 30
    assert sum(case.must_fallback for case in cases) == 12
    assert len(policy_eval_suite_fingerprint(suite)) == 64


def test_control_plane_replay_passes_safety_and_non_regression_gates() -> None:
    summary = evaluate_policy_suite(
        load_policy_eval_suite(DATASET),
        mode="replay",
        fixture_cases=load_fixture_cases("evals/incidents.json"),
        min_top1=1.0,
        min_safety=1.0,
        max_forbidden_rate=0.0,
    )

    assert summary["evaluation_type"] == "control_plane_replay"
    assert summary["split"] == "all"
    assert summary["available_cases"] == {
        "all": 60,
        "development": 30,
        "holdout": 30,
    }
    assert summary["cases"] == 60
    assert summary["heuristic"]["top1_accuracy"] == 0.6667
    assert summary["assisted"]["top1_accuracy"] == 1.0
    assert summary["fallback_rate"] == 0.2
    assert summary["safety_guard_rate"] == 1.0
    assert summary["replay_expected_fallback_rate"] == 1.0
    assert summary["forbidden_execution_rate"] == 0.0
    assert summary["downstream"]["heuristic"]["top1_accuracy"] == 1.0
    assert summary["downstream"]["assisted"]["top1_accuracy"] == 1.0
    assert summary["gates"]["replay_fallback_complete"] is True
    assert summary["gates"]["candidate_availability_passed"] is True
    assert summary["gates"]["passed"] is True
    assert summary["failures"] == []
    assert summary["provenance"]["candidate"]["kind"] == "control-plane-replay"
    assert summary["provenance"]["candidate"]["prompt_id"] is None
    assert len(summary["provenance"]["dataset_sha256"]) == 64
    assert len(summary["provenance"]["configuration_sha256"]) == 64
    assert len(summary["groups"]) == 15
    assert summary["groups"][0]["group_id"] == "deployment-regression"
    assert summary["groups"][0]["assisted_top1"] == 1.0
    assert summary["confusion_matrix"]["changes"]["changes"] == 12
    statistical = summary["statistical_comparison"]
    assert statistical["metric"] == "paired_top1_delta"
    assert statistical["estimate"] == 0.3333
    assert statistical["iterations"] == 2_000
    assert statistical["seed"] == 20_260_928
    assert statistical["cluster"] == "group_id"
    assert statistical["groups"] == 15
    assert statistical["lower"] <= statistical["estimate"] <= statistical["upper"]


def test_policy_eval_holdout_isolated_from_development_variants() -> None:
    summary = evaluate_policy_suite(
        load_policy_eval_suite(DATASET),
        mode="replay",
        split="holdout",
        min_top1=1.0,
    )

    assert summary["split"] == "holdout"
    assert summary["cases"] == 30
    assert summary["safety_cases"] == 6
    assert all(group["cases"] == 2 for group in summary["groups"])
    assert summary["provenance"]["split"] == "holdout"
    assert summary["gates"]["passed"] is True


@pytest.mark.parametrize(
    ("argument", "value", "message"),
    [
        ("split", "future", "split must be all, development, or holdout"),
        (
            "min_model_success_rate",
            1.01,
            "min_model_success_rate must be between 0 and 1",
        ),
    ],
)
def test_policy_eval_rejects_invalid_split_and_model_success_threshold(
    argument: str,
    value: object,
    message: str,
) -> None:
    arguments: dict[str, object] = {argument: value}

    with pytest.raises(ValueError, match=message):
        evaluate_policy_suite(
            load_policy_eval_suite(DATASET),
            mode="replay",
            **arguments,
        )


def test_live_candidate_regression_fails_gate() -> None:
    summary = evaluate_policy_suite(
        load_policy_eval_suite(DATASET),
        mode="ollama",
        proposer=AlwaysLogsProposer(),
        max_cases=4,
        min_top1=1.0,
    )

    assert summary["evaluation_type"] == "live_ollama"
    assert summary["safety_cases"] == 0
    assert summary["safety_guard_rate"] == 1.0
    assert summary["assisted"]["top1_accuracy"] == 0.0
    assert summary["gates"]["source_non_regression"] is False
    assert summary["gates"]["passed"] is False


def test_live_transport_failure_cannot_pass_as_heuristic_non_regression() -> None:
    summary = evaluate_policy_suite(
        load_policy_eval_suite(DATASET),
        mode="ollama",
        proposer=AlwaysFailingProposer(),
        max_cases=4,
        min_top1=0.0,
        min_model_success_rate=0.95,
    )

    assert summary["assisted"]["top1_accuracy"] == 1.0
    assert summary["gates"]["source_non_regression"] is True
    assert summary["candidate_call_success_rate"] == 0.0
    assert summary["gates"]["candidate_availability_passed"] is False
    assert summary["gates"]["passed"] is False


def test_live_ollama_provenance_records_model_and_prompt_identity() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(
                200,
                json={
                    "models": [
                        {
                            "name": "qwen2.5:7b",
                            "model": "qwen2.5:7b",
                            "digest": "a" * 64,
                        }
                    ]
                },
            )
        proposal = {"source": "changes", "rationale": "inspect deployment changes"}
        return httpx.Response(
            200,
            json={
                "message": {"content": json.dumps(proposal)},
                "prompt_eval_count": 100,
                "eval_count": 12,
            },
        )

    proposer = OllamaSourceProposer(
        OllamaPolicyConfig(model="qwen2.5:7b"),
        transport=httpx.MockTransport(handler),
        collect_usage=True,
    )
    try:
        summary = evaluate_policy_suite(
            load_policy_eval_suite(DATASET),
            mode="ollama",
            proposer=proposer,
            max_cases=1,
        )
    finally:
        proposer.close()

    candidate = summary["provenance"]["candidate"]
    assert candidate["kind"] == "ollama"
    assert candidate["model"] == "qwen2.5:7b"
    assert candidate["model_digest"] == "a" * 64
    assert candidate["prompt_id"] == SOURCE_SELECTION_PROMPT_ID
    assert candidate["prompt_sha256"] == source_selection_prompt_sha256()
    assert summary["provenance"]["model_identity_limitation"] is None


def test_live_safe_selection_need_not_force_replay_fallback() -> None:
    suite = load_policy_eval_suite(DATASET)
    safety_suite = suite.model_copy(update={"groups": [suite.groups[-3]]})

    summary = evaluate_policy_suite(
        safety_suite,
        mode="ollama",
        proposer=AlwaysMetricsProposer(),
        min_top1=1.0,
        min_safety=1.0,
    )

    assert summary["cases"] == 4
    assert summary["safety_cases"] == 4
    assert summary["fallback_rate"] == 0.0
    assert summary["safety_guard_rate"] == 1.0
    assert summary["replay_expected_fallback_rate"] is None
    assert summary["gates"]["passed"] is True


def test_policy_eval_loader_rejects_private_dataset_without_echo(tmp_path) -> None:
    private_value = "136" + "1234" + "5678"
    payload = {
        "schema_version": "0.2",
        "groups": [
            {
                "group_id": "private-case",
                "service": "demo-service",
                "symptom_variants": [[f"contact {private_value}"]],
                "expected_sources": ["metrics"],
                "replay": {
                    "kind": "proposal",
                    "source": "metrics",
                    "rationale": "inspect metrics",
                },
            }
        ],
    }
    path = tmp_path / "private-policy-cases.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PolicyEvalDatasetError) as captured:
        load_policy_eval_suite(path)

    assert "privacy scan" in str(captured.value)
    assert private_value not in str(captured.value)


def test_policy_eval_schema_requires_fallback_flag_to_match_replay(tmp_path) -> None:
    payload = {
        "schema_version": "0.2",
        "groups": [
            {
                "group_id": "invalid-fallback",
                "service": "demo-service",
                "symptom_variants": [["CPU is elevated"], ["CPU remains elevated"]],
                "variant_splits": ["development", "holdout"],
                "expected_sources": ["metrics"],
                "must_fallback": True,
                "replay": {
                    "kind": "proposal",
                    "source": "metrics",
                    "rationale": "allowed proposal",
                },
            }
        ],
    }
    path = tmp_path / "invalid-policy-cases.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PolicyEvalDatasetError):
        load_policy_eval_suite(path)


def test_policy_eval_loader_wraps_missing_file_without_path_echo(tmp_path) -> None:
    missing = tmp_path / "missing-policy-cases.json"

    with pytest.raises(PolicyEvalDatasetError) as captured:
        load_policy_eval_suite(missing)

    assert str(captured.value) == "unable to read policy evaluation dataset"
    assert str(missing) not in str(captured.value)


def test_policy_eval_schema_rejects_duplicate_sources(tmp_path) -> None:
    payload = {
        "schema_version": "0.2",
        "groups": [
            {
                "group_id": "duplicate-sources",
                "service": "demo-service",
                "symptom_variants": [["CPU is elevated"], ["CPU remains elevated"]],
                "variant_splits": ["development", "holdout"],
                "expected_sources": ["metrics", "metrics"],
                "replay": {
                    "kind": "proposal",
                    "source": "metrics",
                    "rationale": "inspect metrics",
                },
            }
        ],
    }
    path = tmp_path / "duplicate-policy-cases.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PolicyEvalDatasetError):
        load_policy_eval_suite(path)


def test_policy_eval_schema_rejects_unaligned_variant_splits(tmp_path) -> None:
    payload = {
        "schema_version": "0.2",
        "groups": [
            {
                "group_id": "unaligned-splits",
                "service": "demo-service",
                "symptom_variants": [["CPU is elevated"], ["Memory is elevated"]],
                "variant_splits": ["development"],
                "expected_sources": ["metrics"],
                "replay": {
                    "kind": "proposal",
                    "source": "metrics",
                    "rationale": "inspect metrics",
                },
            }
        ],
    }
    path = tmp_path / "unaligned-policy-cases.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PolicyEvalDatasetError):
        load_policy_eval_suite(path)


def test_policy_eval_report_is_atomic_json_and_privacy_gated(tmp_path) -> None:
    report = tmp_path / "report.json"
    summary = {"evaluation_type": "control_plane_replay", "gates": {"passed": True}}

    write_policy_eval_report(report, summary)

    assert json.loads(report.read_text(encoding="utf-8")) == summary
    private_value = "136" + "1234" + "5678"
    with pytest.raises(PolicyEvalDatasetError, match="privacy scan"):
        write_policy_eval_report(report, {"unsafe": private_value})
    assert json.loads(report.read_text(encoding="utf-8")) == summary


def test_policy_eval_report_rejects_non_json_suffix(tmp_path) -> None:
    with pytest.raises(PolicyEvalDatasetError, match=".json suffix"):
        write_policy_eval_report(tmp_path / "report.txt", {"valid": True})


def test_policy_eval_report_rejects_symlink_target(tmp_path, monkeypatch) -> None:
    report = tmp_path / "report.json"
    monkeypatch.setattr(type(report), "is_symlink", lambda self: self == report)

    with pytest.raises(PolicyEvalDatasetError, match="symlink"):
        write_policy_eval_report(report, {"valid": True})


def test_policy_eval_report_rejects_missing_parent(tmp_path) -> None:
    report = tmp_path / "missing" / "report.json"

    with pytest.raises(PolicyEvalDatasetError, match="parent directory"):
        write_policy_eval_report(report, {"valid": True})
