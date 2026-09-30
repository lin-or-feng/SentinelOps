import json
import sqlite3

import pytest

from sentinelops.adapters import load_fixture_cases
from sentinelops.application.shadow_eval import (
    ShadowEvalError,
    evaluate_shadow_development,
    load_shadow_labels,
)
from sentinelops.cli import main
from sentinelops.service import create_service
from sentinelops.specialist_shadow import ShadowHypothesis, ShadowModelResponse


DIGEST = "a" * 64


class IdentifiedProposer:
    def model_identity(self):
        return "test-model", DIGEST

    def propose_hypothesis(self, context):
        return ShadowModelResponse(
            hypothesis=ShadowHypothesis(
                code="deployment_regression", evidence_refs=["E1"],
                confidence=0.7, uncertainty="A second source is needed.",
            ),
            prompt_tokens=10, completion_tokens=5,
        )


def _labels(path, *, split="development", incident_id="inc-deploy-001"):
    path.write_text(json.dumps({
        "schema_version": "0.1", "split": split,
        "cases": [{
            "incident_id": incident_id, "group_id": "deployment-group",
            "expected_code": "deployment_regression",
        }],
    }), encoding="utf-8")
    return path


def _investigate(tmp_path):
    case = load_fixture_cases("evals/incidents.json")[0]
    db_path = tmp_path / "shadow.db"
    service = create_service(
        db_path=db_path, orchestration_mode="multi",
        shadow_mode="ollama", shadow_proposer=IdentifiedProposer(),
    )
    service.investigate(case.task)
    return db_path


def test_development_evaluation_binds_labels_model_and_prompt(tmp_path) -> None:
    db_path = _investigate(tmp_path)
    labels = _labels(tmp_path / "labels.json")
    result = evaluate_shadow_development(
        labels, db_path, model_name="test-model", model_digest=DIGEST, min_cases=1,
    )
    assert result["development_gate_passed"] is True
    assert result["production_qualified"] is False
    assert result["labelled_incidents"] == 1
    assert result["overall"]["observations"] == 2
    assert result["overall"]["model_top1_accuracy_all_attempts"] == 1.0
    assert result["prompt_tokens_observed"] == 20
    assert result["dataset_sha256"] == load_shadow_labels(labels)[1]
    assert "inc-deploy-001" not in json.dumps(result)


def test_development_gate_requires_minimum_cases_and_cli_exit_code(tmp_path, capsys) -> None:
    db_path = _investigate(tmp_path)
    labels = _labels(tmp_path / "labels.json")
    args = [
        "specialist-shadow-eval", "--labels", str(labels), "--db", str(db_path),
        "--model-name", "test-model", "--model-digest", DIGEST,
    ]
    assert main(args) == 1
    assert json.loads(capsys.readouterr().out)["development_gate_passed"] is False
    assert main([*args, "--min-cases", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["production_qualified"] is False


def test_shadow_eval_rejects_holdout_without_registry(tmp_path) -> None:
    db_path = _investigate(tmp_path)
    labels = _labels(tmp_path / "holdout.json", split="holdout")
    with pytest.raises(ShadowEvalError, match="governed registry"):
        evaluate_shadow_development(
            labels, db_path, model_name="test-model", model_digest=DIGEST,
        )


def test_shadow_eval_rejects_model_or_prompt_identity_drift(tmp_path) -> None:
    db_path = _investigate(tmp_path)
    labels = _labels(tmp_path / "labels.json")
    with pytest.raises(ShadowEvalError, match="identity does not match"):
        evaluate_shadow_development(
            labels, db_path, model_name="test-model", model_digest="b" * 64,
        )
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE specialist_shadow_provenance SET prompt_sha256 = ?",
            ("b" * 64,),
        )
    with pytest.raises(ShadowEvalError, match="identity does not match"):
        evaluate_shadow_development(
            labels, db_path, model_name="test-model", model_digest=DIGEST,
        )


def test_shadow_eval_rejects_missing_or_duplicate_labels(tmp_path) -> None:
    db_path = _investigate(tmp_path)
    labels = _labels(tmp_path / "missing.json", incident_id="inc-missing-001")
    with pytest.raises(ShadowEvalError, match="no completed investigation"):
        evaluate_shadow_development(
            labels, db_path, model_name="test-model", model_digest=DIGEST,
        )
    duplicate = {
        "schema_version": "0.1", "split": "development",
        "cases": [
            {"incident_id": "inc-deploy-001", "group_id": "group-one",
             "expected_code": "deployment_regression"},
            {"incident_id": "inc-deploy-001", "group_id": "group-two",
             "expected_code": "deployment_regression"},
        ],
    }
    labels.write_text(json.dumps(duplicate), encoding="utf-8")
    with pytest.raises(ShadowEvalError, match="invalid shadow label dataset"):
        load_shadow_labels(labels)


def test_shadow_eval_rejects_private_label_content(tmp_path) -> None:
    labels = _labels(tmp_path / "private.json")
    content = json.loads(labels.read_text(encoding="utf-8"))
    content["cases"][0]["group_id"] = "138" + "00112233"
    labels.write_text(json.dumps(content), encoding="utf-8")
    with pytest.raises(ShadowEvalError, match="privacy scan"):
        load_shadow_labels(labels)
