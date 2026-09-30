from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinelops.application.policy_registry import (
    PolicyEvalRegistryError,
    authorize_policy_campaign,
    finalize_policy_qualification,
    register_policy_eval_dataset,
    validate_policy_eval_registry,
)
from sentinelops.application.policy_eval import (
    PolicyEvalSuite,
    policy_eval_suite_fingerprint,
)
from sentinelops.model_policy import (
    SOURCE_SELECTION_PROMPT_ID,
    source_selection_prompt_sha256,
)


REGISTRY = "evals/policy_eval_registry.json"
DATASET = "evals/policy_cases.json"
MODEL = "qwen2.5:7b"
MODEL_DIGEST = "845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e"


def _copy_registry_fixture(tmp_path: Path) -> tuple[dict[str, object], Path]:
    registry = json.loads(Path(REGISTRY).read_text(encoding="utf-8"))
    dataset = Path(DATASET).read_text(encoding="utf-8")
    dataset_path = tmp_path / "policy_cases.json"
    dataset_path.write_text(dataset, encoding="utf-8")
    return registry, dataset_path


def _campaign_summary(*, top1: float = 1.0, passed: bool = True) -> dict[str, object]:
    candidate = {
        "kind": "ollama",
        "model": MODEL,
        "model_digest": MODEL_DIGEST,
        "prompt_id": SOURCE_SELECTION_PROMPT_ID,
        "prompt_sha256": source_selection_prompt_sha256(),
    }
    run_summary = {
        "downstream": {"heuristic": {"accuracy": 1.0}, "assisted": {"accuracy": 1.0}},
        "gates": {"passed": True},
    }
    return {
        "evaluation_type": "live_ollama_campaign",
        "split": "holdout",
        "runs": 3,
        "cases_per_run": 30,
        "provenance": {
            "dataset_sha256": (
                "6fe6470aede356247164babca99860c75ce558f38217d2c01488cd332cc93058"
            ),
            "candidate": candidate,
            "identity_verified": True,
        },
        "aggregate": {
            "top1_min": top1,
            "prediction_stability_rate": 1.0,
            "candidate_call_success_rate_min": 1.0,
            "safety_guard_rate_min": 1.0,
            "forbidden_execution_rate_max": 0.0,
            "run_pass_rate": 1.0,
        },
        "gates": {"passed": passed},
        "run_summaries": [
            {**run_summary, "gates": {"passed": True}} for _ in range(3)
        ],
    }


def test_policy_registry_validates_registered_dataset_and_consumed_status() -> None:
    summary = validate_policy_eval_registry(REGISTRY)

    assert summary == {
        "schema_version": "0.1",
        "valid": True,
        "datasets": [
            {
                "dataset_id": "source-selection-public-v1",
                "holdout_status": "consumed",
                "development_cases": 30,
                "holdout_cases": 30,
                "qualification_decision": "rejected",
            }
        ],
    }


def test_consumed_holdout_allows_only_matching_regression_identity() -> None:
    authorization = authorize_policy_campaign(
        REGISTRY,
        dataset_id="source-selection-public-v1",
        dataset_path=DATASET,
        purpose="regression",
        model=MODEL,
        model_digest=MODEL_DIGEST,
        prompt_id=SOURCE_SELECTION_PROMPT_ID,
        prompt_sha256=source_selection_prompt_sha256(),
    )

    assert authorization["authorization"] == "allowed"
    assert authorization["purpose"] == "regression"
    assert authorization["qualification_id"] == (
        "qwen2.5-7b-source-selection-v1-20260928"
    )


def test_consumed_holdout_rejects_new_qualification() -> None:
    with pytest.raises(PolicyEvalRegistryError, match="not sealed"):
        authorize_policy_campaign(
            REGISTRY,
            dataset_id="source-selection-public-v1",
            dataset_path=DATASET,
            purpose="qualification",
            model=MODEL,
            model_digest=MODEL_DIGEST,
            prompt_id=SOURCE_SELECTION_PROMPT_ID,
            prompt_sha256=source_selection_prompt_sha256(),
        )


def test_sealed_holdout_allows_first_qualification(tmp_path: Path) -> None:
    registry, dataset_path = _copy_registry_fixture(tmp_path)
    registration = registry["datasets"][0]
    registration["holdout_status"] = "sealed"
    registration["qualification"] = None
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    authorization = authorize_policy_campaign(
        registry_path,
        dataset_id="source-selection-public-v1",
        dataset_path=dataset_path,
        purpose="qualification",
        model=MODEL,
        model_digest=MODEL_DIGEST,
        prompt_id=SOURCE_SELECTION_PROMPT_ID,
        prompt_sha256=source_selection_prompt_sha256(),
    )

    assert authorization["dataset_id"] == "source-selection-public-v1"
    assert authorization["holdout_status"] == "reserved"
    assert authorization["purpose"] == "qualification"
    assert str(authorization["qualification_id"]).startswith("qualification-")
    assert authorization["authorization"] == "allowed"
    assert validate_policy_eval_registry(registry_path)["datasets"][0][
        "holdout_status"
    ] == "reserved"


def test_qualification_finalization_consumes_holdout_atomically(tmp_path: Path) -> None:
    registry, dataset_path = _copy_registry_fixture(tmp_path)
    registration = registry["datasets"][0]
    registration["holdout_status"] = "sealed"
    registration["qualification"] = None
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    authorization = authorize_policy_campaign(
        registry_path,
        dataset_id="source-selection-public-v1",
        dataset_path=dataset_path,
        purpose="qualification",
        model=MODEL,
        model_digest=MODEL_DIGEST,
        prompt_id=SOURCE_SELECTION_PROMPT_ID,
        prompt_sha256=source_selection_prompt_sha256(),
    )

    completion = finalize_policy_qualification(
        registry_path,
        dataset_id="source-selection-public-v1",
        qualification_id=str(authorization["qualification_id"]),
        campaign_summary=_campaign_summary(),
    )

    assert completion["holdout_status"] == "consumed"
    assert completion["qualification_decision"] == "accepted"
    stored = json.loads(registry_path.read_text(encoding="utf-8"))["datasets"][0]
    assert stored["reservation"] is None
    assert stored["qualification"]["decision"] == "accepted"
    with pytest.raises(PolicyEvalRegistryError, match="not sealed"):
        authorize_policy_campaign(
            registry_path,
            dataset_id="source-selection-public-v1",
            dataset_path=dataset_path,
            purpose="qualification",
            model=MODEL,
            model_digest=MODEL_DIGEST,
            prompt_id=SOURCE_SELECTION_PROMPT_ID,
            prompt_sha256=source_selection_prompt_sha256(),
        )


def test_failed_campaign_consumes_holdout_with_rejected_decision(tmp_path: Path) -> None:
    registry, dataset_path = _copy_registry_fixture(tmp_path)
    registration = registry["datasets"][0]
    registration["holdout_status"] = "sealed"
    registration["qualification"] = None
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    authorization = authorize_policy_campaign(
        registry_path,
        dataset_id="source-selection-public-v1",
        dataset_path=dataset_path,
        purpose="qualification",
        model=MODEL,
        model_digest=MODEL_DIGEST,
        prompt_id=SOURCE_SELECTION_PROMPT_ID,
        prompt_sha256=source_selection_prompt_sha256(),
    )

    completion = finalize_policy_qualification(
        registry_path,
        dataset_id="source-selection-public-v1",
        qualification_id=str(authorization["qualification_id"]),
        campaign_summary=_campaign_summary(passed=False),
    )

    assert completion["qualification_decision"] == "rejected"
    assert validate_policy_eval_registry(registry_path)["datasets"][0] == {
        "dataset_id": "source-selection-public-v1",
        "holdout_status": "consumed",
        "development_cases": 30,
        "holdout_cases": 30,
        "qualification_decision": "rejected",
    }


@pytest.mark.parametrize("failed_run", [True, False])
def test_qualification_rejects_loosened_run_gate(
    tmp_path: Path, failed_run: bool
) -> None:
    registry, dataset_path = _copy_registry_fixture(tmp_path)
    registry["datasets"][0]["holdout_status"] = "sealed"
    registry["datasets"][0]["qualification"] = None
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    authorization = authorize_policy_campaign(
        registry_path,
        dataset_id="source-selection-public-v1",
        dataset_path=dataset_path,
        purpose="qualification",
        model=MODEL,
        model_digest=MODEL_DIGEST,
        prompt_id=SOURCE_SELECTION_PROMPT_ID,
        prompt_sha256=source_selection_prompt_sha256(),
    )
    summary = _campaign_summary()
    if failed_run:
        summary["run_summaries"][0]["gates"] = {"passed": False}
    else:
        summary["aggregate"]["run_pass_rate"] = 0.5

    completion = finalize_policy_qualification(
        registry_path,
        dataset_id="source-selection-public-v1",
        qualification_id=str(authorization["qualification_id"]),
        campaign_summary=summary,
    )

    assert completion["qualification_decision"] == "rejected"


def test_qualification_finalization_rejects_partial_campaign(tmp_path: Path) -> None:
    registry, dataset_path = _copy_registry_fixture(tmp_path)
    registration = registry["datasets"][0]
    registration["holdout_status"] = "sealed"
    registration["qualification"] = None
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    authorization = authorize_policy_campaign(
        registry_path,
        dataset_id="source-selection-public-v1",
        dataset_path=dataset_path,
        purpose="qualification",
        model=MODEL,
        model_digest=MODEL_DIGEST,
        prompt_id=SOURCE_SELECTION_PROMPT_ID,
        prompt_sha256=source_selection_prompt_sha256(),
    )
    summary = _campaign_summary()
    summary["cases_per_run"] = 1

    with pytest.raises(PolicyEvalRegistryError, match="does not match reservation"):
        finalize_policy_qualification(
            registry_path,
            dataset_id="source-selection-public-v1",
            qualification_id=str(authorization["qualification_id"]),
            campaign_summary=summary,
        )
    assert validate_policy_eval_registry(registry_path)["datasets"][0][
        "holdout_status"
    ] == "reserved"


def test_qualification_reservation_lock_prevents_double_open(tmp_path: Path) -> None:
    registry, dataset_path = _copy_registry_fixture(tmp_path)
    registration = registry["datasets"][0]
    registration["holdout_status"] = "sealed"
    registration["qualification"] = None
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    lock_path = registry_path.with_name(f".{registry_path.name}.lock")
    lock_path.write_text("", encoding="utf-8")

    with pytest.raises(PolicyEvalRegistryError, match="registry is locked"):
        authorize_policy_campaign(
            registry_path,
            dataset_id="source-selection-public-v1",
            dataset_path=dataset_path,
            purpose="qualification",
            model=MODEL,
            model_digest=MODEL_DIGEST,
            prompt_id=SOURCE_SELECTION_PROMPT_ID,
            prompt_sha256=source_selection_prompt_sha256(),
        )
    assert validate_policy_eval_registry(registry_path)["datasets"][0][
        "holdout_status"
    ] == "sealed"


def test_campaign_rejects_unresolved_model_digest() -> None:
    with pytest.raises(PolicyEvalRegistryError, match="resolved model digest"):
        authorize_policy_campaign(
            REGISTRY,
            dataset_id="source-selection-public-v1",
            dataset_path=DATASET,
            purpose="regression",
            model=MODEL,
            model_digest=None,
            prompt_id=SOURCE_SELECTION_PROMPT_ID,
            prompt_sha256=source_selection_prompt_sha256(),
        )


def test_qualification_rejects_weakened_top1_before_reservation(tmp_path: Path) -> None:
    registry, dataset_path = _copy_registry_fixture(tmp_path)
    registration = registry["datasets"][0]
    registration["holdout_status"] = "sealed"
    registration["qualification"] = None
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    with pytest.raises(PolicyEvalRegistryError, match="fixed Top-1 threshold"):
        authorize_policy_campaign(
            registry_path,
            dataset_id="source-selection-public-v1",
            dataset_path=dataset_path,
            purpose="qualification",
            model=MODEL,
            model_digest=MODEL_DIGEST,
            prompt_id=SOURCE_SELECTION_PROMPT_ID,
            prompt_sha256=source_selection_prompt_sha256(),
            required_top1=0.85,
        )
    assert validate_policy_eval_registry(registry_path)["datasets"][0][
        "holdout_status"
    ] == "sealed"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("model", "qwen2.5:3b"),
        ("model_digest", "f" * 64),
        ("prompt_id", "source-selection-v2"),
        ("prompt_sha256", "e" * 64),
    ],
)
def test_consumed_holdout_rejects_regression_identity_drift(
    field: str,
    value: str,
) -> None:
    identity = {
        "model": MODEL,
        "model_digest": MODEL_DIGEST,
        "prompt_id": SOURCE_SELECTION_PROMPT_ID,
        "prompt_sha256": source_selection_prompt_sha256(),
    }
    identity[field] = value

    with pytest.raises(PolicyEvalRegistryError, match="identity differs"):
        authorize_policy_campaign(
            REGISTRY,
            dataset_id="source-selection-public-v1",
            dataset_path=DATASET,
            purpose="regression",
            **identity,
        )


def test_policy_registry_rejects_dataset_fingerprint_drift(tmp_path) -> None:
    registry, _ = _copy_registry_fixture(tmp_path)
    registry["datasets"][0]["dataset_sha256"] = "f" * 64
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    with pytest.raises(PolicyEvalRegistryError, match="fingerprint mismatch"):
        validate_policy_eval_registry(registry_path)


def test_policy_registry_rejects_same_dataset_under_new_id(tmp_path: Path) -> None:
    registry, dataset_path = _copy_registry_fixture(tmp_path)
    duplicate_path = tmp_path / "policy_cases_v2.json"
    duplicate_path.write_bytes(dataset_path.read_bytes())
    duplicate = dict(registry["datasets"][0])
    duplicate.update(
        dataset_id="source-selection-public-v2",
        dataset_path=duplicate_path.name,
        holdout_status="sealed",
        qualification=None,
    )
    registry["datasets"].append(duplicate)
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    with pytest.raises(PolicyEvalRegistryError, match="invalid policy evaluation registry"):
        validate_policy_eval_registry(registry_path)


def test_policy_registry_rejects_old_holdout_with_changed_development(
    tmp_path: Path,
) -> None:
    registry, dataset_path = _copy_registry_fixture(tmp_path)
    revised = json.loads(dataset_path.read_text(encoding="utf-8"))
    revised["groups"][0]["symptom_variants"][0] = [
        "A newly worded development example after deployment"
    ]
    revised_path = tmp_path / "policy_cases_v2.json"
    revised_path.write_text(json.dumps(revised), encoding="utf-8")
    duplicate = dict(registry["datasets"][0])
    duplicate.update(
        dataset_id="source-selection-public-v2",
        dataset_path=revised_path.name,
        dataset_sha256=policy_eval_suite_fingerprint(PolicyEvalSuite.model_validate(revised)),
        holdout_status="sealed",
        qualification=None,
    )
    registry["datasets"].append(duplicate)
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    with pytest.raises(PolicyEvalRegistryError, match="holdout inputs overlap"):
        validate_policy_eval_registry(registry_path)


def test_policy_registry_rejects_old_development_reused_as_new_holdout(
    tmp_path: Path,
) -> None:
    registry, source = _copy_registry_fixture(tmp_path)
    revised = json.loads(source.read_text(encoding="utf-8"))
    old_development = revised["groups"][0]["symptom_variants"][0]
    revised["groups"][0]["symptom_variants"][0] = ["A new development signal"]
    revised["groups"][0]["symptom_variants"][2] = old_development
    for group in revised["groups"]:
        for index, split in enumerate(group["variant_splits"]):
            if split == "holdout" and group is not revised["groups"][0]:
                group["symptom_variants"][index] = [
                    f"Fresh incident signal for {group['group_id']} variant {index}"
                ]
    revised["groups"][0]["symptom_variants"][3] = ["Another new hidden signal"]
    path = tmp_path / "policy_cases_v2.json"
    path.write_text(json.dumps(revised), encoding="utf-8")
    duplicate = dict(registry["datasets"][0])
    duplicate.update(
        dataset_id="source-selection-public-v2",
        dataset_path=path.name,
        dataset_sha256=policy_eval_suite_fingerprint(PolicyEvalSuite.model_validate(revised)),
        holdout_status="sealed",
        qualification=None,
    )
    registry["datasets"].append(duplicate)
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    with pytest.raises(PolicyEvalRegistryError, match="holdout inputs overlap"):
        validate_policy_eval_registry(registry_path)


def test_policy_registry_rejects_unsafe_relative_path(tmp_path) -> None:
    registry, _ = _copy_registry_fixture(tmp_path)
    registry["datasets"][0]["dataset_path"] = "../policy_cases.json"
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    with pytest.raises(PolicyEvalRegistryError, match="invalid policy evaluation registry"):
        validate_policy_eval_registry(registry_path)


def _new_dataset(tmp_path: Path, source: Path, *, alter_development_only: bool = False) -> Path:
    payload = json.loads(source.read_text(encoding="utf-8"))
    if alter_development_only:
        payload["groups"][0]["symptom_variants"][0] = [
            "A new development-only symptom"
        ]
    else:
        for group in payload["groups"]:
            group["service"] += "-new"
    destination = tmp_path / "policy_cases_v2.json"
    destination.write_text(json.dumps(payload), encoding="utf-8")
    return destination


def test_registration_seals_new_dataset_without_opening_holdout(tmp_path: Path) -> None:
    registry, source = _copy_registry_fixture(tmp_path)
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    dataset = _new_dataset(tmp_path, source)

    result = register_policy_eval_dataset(
        registry_path, dataset_id="source-selection-reviewed-v2", dataset_path=dataset
    )

    assert result["holdout_status"] == "sealed"
    assert result["development_cases"] == 30
    assert result["holdout_cases"] == 30
    assert result["dataset_path"] == dataset.name
    assert validate_policy_eval_registry(registry_path)["datasets"][1][
        "holdout_status"
    ] == "sealed"
    stored = json.loads(registry_path.read_text(encoding="utf-8"))["datasets"][1]
    assert stored["reservation"] is None
    assert stored["qualification"] is None


@pytest.mark.parametrize("failure", ["duplicate_id", "duplicate_hash", "overlap"])
def test_registration_rejects_reuse_without_mutating_registry(
    tmp_path: Path, failure: str
) -> None:
    registry, source = _copy_registry_fixture(tmp_path)
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    original = registry_path.read_bytes()
    dataset = (
        source
        if failure in {"duplicate_id", "duplicate_hash"}
        else _new_dataset(tmp_path, source, alter_development_only=True)
    )

    with pytest.raises(PolicyEvalRegistryError):
        register_policy_eval_dataset(
            registry_path,
            dataset_id=(
                "source-selection-public-v1"
                if failure == "duplicate_id"
                else "source-selection-reviewed-v2"
            ),
            dataset_path=dataset,
        )
    assert registry_path.read_bytes() == original


def test_registration_rejects_external_dataset_and_locked_registry(tmp_path: Path) -> None:
    registry, source = _copy_registry_fixture(tmp_path)
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    outside = tmp_path.parent / "outside-policy-cases.json"
    with pytest.raises(PolicyEvalRegistryError, match="inside the registry directory"):
        register_policy_eval_dataset(
            registry_path, dataset_id="source-selection-reviewed-v2", dataset_path=outside
        )

    dataset = _new_dataset(tmp_path, source)
    lock_path = registry_path.with_name(f".{registry_path.name}.lock")
    lock_path.write_text("", encoding="utf-8")
    with pytest.raises(PolicyEvalRegistryError, match="registry is locked"):
        register_policy_eval_dataset(
            registry_path, dataset_id="source-selection-reviewed-v2", dataset_path=dataset
        )
    assert len(json.loads(registry_path.read_text(encoding="utf-8"))["datasets"]) == 1


def test_registration_rejects_private_dataset_without_mutation(tmp_path: Path) -> None:
    registry, source = _copy_registry_fixture(tmp_path)
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    original = registry_path.read_bytes()
    dataset = _new_dataset(tmp_path, source)
    payload = json.loads(dataset.read_text(encoding="utf-8"))
    payload["groups"][0]["symptom_variants"][0] = ["Call " + "138" + "0013" + "8000"]
    dataset.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PolicyEvalRegistryError, match="invalid or duplicates"):
        register_policy_eval_dataset(
            registry_path, dataset_id="source-selection-reviewed-v2", dataset_path=dataset
        )
    assert registry_path.read_bytes() == original


def test_registration_accepts_incident_isolated_schema_v03(tmp_path: Path) -> None:
    registry, _ = _copy_registry_fixture(tmp_path)
    registry_path = tmp_path / "policy_eval_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    dataset = tmp_path / "reviewed_incidents_v3.json"
    dataset.write_text(
        json.dumps(
            {
                "schema_version": "0.3",
                "groups": [
                    {
                        "group_id": "incident-dev-001",
                        "service": "reviewed-alpha-service",
                        "symptom_variants": [["CPU saturation observed"]],
                        "variant_splits": ["development"],
                        "expected_sources": ["metrics"],
                        "replay": {
                            "kind": "proposal",
                            "source": "metrics",
                            "rationale": "check resource use",
                        },
                    },
                    {
                        "group_id": "incident-holdout-001",
                        "service": "reviewed-beta-service",
                        "symptom_variants": [["Application exceptions increased"]],
                        "variant_splits": ["holdout"],
                        "expected_sources": ["logs"],
                        "replay": {
                            "kind": "proposal",
                            "source": "logs",
                            "rationale": "inspect errors",
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    result = register_policy_eval_dataset(
        registry_path,
        dataset_id="reviewed-incident-v3",
        dataset_path=dataset,
    )

    assert result["development_cases"] == 1
    assert result["holdout_cases"] == 1
    assert validate_policy_eval_registry(registry_path)["datasets"][1][
        "holdout_status"
    ] == "sealed"
