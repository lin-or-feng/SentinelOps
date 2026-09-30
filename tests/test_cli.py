import json
from types import SimpleNamespace

import pytest

import sentinelops.model_policy as model_policy
from sentinelops.application.policy_eval import (
    PolicyEvalDatasetError,
    write_policy_eval_report,
)
from sentinelops.cli import _is_loopback_host, main


def test_loopback_detection() -> None:
    assert _is_loopback_host("127.0.0.1") is True
    assert _is_loopback_host("::1") is True
    assert _is_loopback_host("localhost") is True
    assert _is_loopback_host("0.0.0.0") is False
    assert _is_loopback_host("public.example") is False


def test_serve_refuses_public_bind_without_token(monkeypatch, capsys) -> None:
    monkeypatch.delenv("SENTINELOPS_API_TOKEN", raising=False)

    exit_code = main(["serve", "--host", "0.0.0.0"])

    assert exit_code == 2
    assert "refusing non-loopback bind" in capsys.readouterr().err


def test_policy_eval_cli_runs_replay_gate(capsys, tmp_path) -> None:
    report = tmp_path / "policy-evaluation.json"
    exit_code = main(
        [
            "policy-eval",
            "--mode",
            "replay",
            "--min-top1",
            "1",
            "--min-safety",
            "1",
            "--max-forbidden-rate",
            "0",
            "--min-model-success-rate",
            "0.95",
            "--split",
            "holdout",
            "--output",
            str(report),
        ]
    )

    assert exit_code == 0
    assert '"evaluation_type": "control_plane_replay"' in capsys.readouterr().out
    report_text = report.read_text(encoding="utf-8")
    assert '"configuration_sha256"' in report_text
    assert '"split": "holdout"' in report_text
    assert '"cases": 30' in report_text


@pytest.mark.parametrize("split", ["all", "holdout"])
def test_live_single_run_rejects_ungoverned_holdout_before_model_call(
    monkeypatch,
    capsys,
    split: str,
) -> None:
    def unexpected_model_config():
        raise AssertionError("model must not be initialized")

    monkeypatch.setattr(
        model_policy, "ollama_policy_config_from_env", unexpected_model_config
    )

    exit_code = main(["policy-eval", "--mode", "ollama", "--split", split])

    assert exit_code == 2
    assert "requires the development split" in capsys.readouterr().out


def test_live_single_run_allows_development_diagnostics(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    class FakeProposer:
        def __init__(self, config, *, collect_usage: bool) -> None:
            captured["collect_usage"] = collect_usage

        def close(self) -> None:
            captured["closed"] = True

    def fake_evaluate(suite, **kwargs):
        captured.update(kwargs)
        return {"evaluation_type": "live_ollama", "gates": {"passed": True}}

    monkeypatch.setattr(model_policy, "OllamaSourceProposer", FakeProposer)
    monkeypatch.setattr(model_policy, "ollama_policy_config_from_env", lambda: object())
    monkeypatch.setattr("sentinelops.cli.evaluate_policy_suite", fake_evaluate)

    exit_code = main(
        ["policy-eval", "--mode", "ollama", "--split", "development", "--skip-downstream"]
    )

    assert exit_code == 0
    assert captured["split"] == "development"
    assert captured["collect_usage"] is True
    assert captured["closed"] is True
    assert '"evaluation_type": "live_ollama"' in capsys.readouterr().out


def test_policy_eval_campaign_cli_writes_auditable_report(
    monkeypatch,
    capsys,
    tmp_path,
) -> None:
    report = tmp_path / "policy-campaign.json"
    captured: dict[str, object] = {}

    class FakeProposer:
        def __init__(self, config, *, collect_usage: bool) -> None:
            captured["collect_usage"] = collect_usage
            self.config = SimpleNamespace(model="qwen2.5:7b")

        def refresh_model_digest(self) -> str:
            return "a" * 64

        def close(self) -> None:
            captured["closed"] = True

    def fake_campaign(suite, **kwargs):
        captured.update(kwargs)
        return {
            "schema_version": "0.1",
            "evaluation_type": "live_ollama_campaign",
            "split": "holdout",
            "gates": {"passed": True},
        }

    monkeypatch.setattr(model_policy, "OllamaSourceProposer", FakeProposer)
    monkeypatch.setattr(model_policy, "ollama_policy_config_from_env", lambda: object())
    monkeypatch.setattr("sentinelops.cli.evaluate_policy_campaign", fake_campaign)
    monkeypatch.setattr(
        "sentinelops.cli.authorize_policy_campaign",
        lambda *args, **kwargs: {
            "dataset_id": "source-selection-public-v1",
            "purpose": "regression",
            "authorization": "allowed",
        },
    )

    exit_code = main(
        [
            "policy-eval-campaign",
            "--runs",
            "3",
            "--purpose",
            "regression",
            "--max-top1-spread",
            "0.05",
            "--min-prediction-stability",
            "0.95",
            "--skip-downstream",
            "--output",
            str(report),
        ]
    )

    assert exit_code == 0
    assert captured["runs"] == 3
    assert captured["fixture_cases"] is None
    assert captured["collect_usage"] is True
    assert captured["closed"] is True
    assert '"evaluation_type": "live_ollama_campaign"' in capsys.readouterr().out
    assert '"split": "holdout"' in report.read_text(encoding="utf-8")


def test_policy_eval_registry_cli_validates_registered_dataset(capsys) -> None:
    exit_code = main(["policy-eval-registry-check"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert '"valid": true' in output
    assert '"holdout_status": "consumed"' in output


def test_policy_registry_register_cli_reports_sealed_dataset(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    def fake_register(registry_path, *, dataset_id, dataset_path):
        captured.update(
            registry_path=registry_path,
            dataset_id=dataset_id,
            dataset_path=dataset_path,
        )
        return {"dataset_id": dataset_id, "holdout_status": "sealed"}

    monkeypatch.setattr("sentinelops.cli.register_policy_eval_dataset", fake_register)
    exit_code = main(
        [
            "policy-eval-registry-register",
            "--dataset-id",
            "reviewed-v2",
            "--dataset",
            "evals/reviewed-v2.json",
        ]
    )

    assert exit_code == 0
    assert captured["dataset_id"] == "reviewed-v2"
    assert captured["dataset_path"].as_posix() == "evals/reviewed-v2.json"
    assert '"holdout_status": "sealed"' in capsys.readouterr().out


def test_policy_qualification_rejects_partial_holdout_before_model_call(capsys) -> None:
    exit_code = main(
        ["policy-eval-campaign", "--purpose", "qualification", "--max-cases", "1"]
    )

    assert exit_code == 2
    assert "requires the full holdout" in capsys.readouterr().out


def test_policy_qualification_requires_unused_report_path_before_model_call(
    tmp_path, capsys
) -> None:
    missing = main(["policy-eval-campaign", "--purpose", "qualification"])
    report = tmp_path / "existing.json"
    report.write_text("{}", encoding="utf-8")
    existing = main(
        [
            "policy-eval-campaign",
            "--purpose",
            "qualification",
            "--output",
            str(report),
        ]
    )

    assert missing == existing == 2
    output = capsys.readouterr().out
    assert "requires a new --output JSON evidence report" in output
    assert "report path already exists" in output
    assert report.read_text(encoding="utf-8") == "{}"


@pytest.mark.parametrize(
    "campaign_passed, decision, expected_exit",
    [(False, "rejected", 1), (True, "rejected", 1), (True, "accepted", 0)],
)
def test_policy_qualification_cli_finalizes_registry(
    monkeypatch,
    capsys,
    tmp_path,
    campaign_passed,
    decision,
    expected_exit,
) -> None:
    report = tmp_path / "qualification.json"
    captured: dict[str, object] = {}

    class FakeProposer:
        def __init__(self, config, *, collect_usage: bool) -> None:
            self.config = SimpleNamespace(model="qwen2.5:7b")

        def refresh_model_digest(self) -> str:
            return "a" * 64

        def close(self) -> None:
            captured["closed"] = True

    summary = {
        "evaluation_type": "live_ollama_campaign",
        "split": "holdout",
        "gates": {"passed": campaign_passed},
    }
    monkeypatch.setattr(model_policy, "OllamaSourceProposer", FakeProposer)
    monkeypatch.setattr(model_policy, "ollama_policy_config_from_env", lambda: object())
    monkeypatch.setattr(
        "sentinelops.cli.evaluate_policy_campaign", lambda *args, **kwargs: summary
    )
    monkeypatch.setattr(
        "sentinelops.cli.authorize_policy_campaign",
        lambda *args, **kwargs: {
            "dataset_id": "source-selection-public-v1",
            "holdout_status": "reserved",
            "purpose": "qualification",
            "qualification_id": "qualification-test",
            "authorization": "allowed",
        },
    )

    def fake_finalize(*args, **kwargs):
        preliminary = json.loads(report.read_text(encoding="utf-8"))
        assert preliminary["governance"]["holdout_status"] == "reserved"
        captured.update(kwargs)
        return {
            "holdout_status": "consumed",
            "qualification_id": "qualification-test",
            "qualification_decision": decision,
        }

    monkeypatch.setattr("sentinelops.cli.finalize_policy_qualification", fake_finalize)

    exit_code = main(
        [
            "policy-eval-campaign",
            "--purpose",
            "qualification",
            "--output",
            str(report),
        ]
    )

    assert exit_code == expected_exit
    assert captured["qualification_id"] == "qualification-test"
    assert captured["campaign_summary"] is summary
    assert captured["closed"] is True
    report_text = report.read_text(encoding="utf-8")
    assert '"holdout_status": "consumed"' in report_text
    assert f'"qualification_decision": "{decision}"' in capsys.readouterr().out


def test_policy_qualification_failure_reports_reserved_operator_action(
    monkeypatch,
    capsys,
    tmp_path,
) -> None:
    class FakeProposer:
        def __init__(self, config, *, collect_usage: bool) -> None:
            self.config = SimpleNamespace(model="qwen2.5:7b")

        def refresh_model_digest(self) -> str:
            return "a" * 64

        def close(self) -> None:
            return None

    monkeypatch.setattr(model_policy, "OllamaSourceProposer", FakeProposer)
    monkeypatch.setattr(model_policy, "ollama_policy_config_from_env", lambda: object())
    monkeypatch.setattr(
        "sentinelops.cli.authorize_policy_campaign",
        lambda *args, **kwargs: {
            "dataset_id": "source-selection-public-v1",
            "holdout_status": "reserved",
            "purpose": "qualification",
            "qualification_id": "qualification-test",
            "authorization": "allowed",
        },
    )

    def fail_campaign(*args, **kwargs):
        raise ValueError("simulated evaluation failure")

    monkeypatch.setattr("sentinelops.cli.evaluate_policy_campaign", fail_campaign)

    exit_code = main(
        [
            "policy-eval-campaign",
            "--purpose",
            "qualification",
            "--output",
            str(tmp_path / "failed-campaign.json"),
        ]
    )

    assert exit_code == 2
    output = capsys.readouterr().out
    assert '"holdout_status": "reserved"' in output
    assert "do not reset it to sealed automatically" in output


@pytest.mark.parametrize("failed_write", [1, 2])
def test_qualification_report_failure_preserves_correct_lifecycle(
    monkeypatch, capsys, tmp_path, failed_write
) -> None:
    report = tmp_path / "qualification.json"
    events: list[str] = []

    class FakeProposer:
        def __init__(self, config, *, collect_usage: bool) -> None:
            self.config = SimpleNamespace(model="qwen2.5:7b")

        def refresh_model_digest(self) -> str:
            return "a" * 64

        def close(self) -> None:
            return None

    monkeypatch.setattr(model_policy, "OllamaSourceProposer", FakeProposer)
    monkeypatch.setattr(model_policy, "ollama_policy_config_from_env", lambda: object())
    monkeypatch.setattr(
        "sentinelops.cli.authorize_policy_campaign",
        lambda *args, **kwargs: {
            "dataset_id": "source-selection-public-v1",
            "holdout_status": "reserved",
            "purpose": "qualification",
            "qualification_id": "qualification-test",
            "authorization": "allowed",
        },
    )
    monkeypatch.setattr(
        "sentinelops.cli.evaluate_policy_campaign",
        lambda *args, **kwargs: {"gates": {"passed": False}},
    )

    def fake_write(path, summary):
        events.append("write")
        if events.count("write") == failed_write:
            raise PolicyEvalDatasetError("simulated report write failure")
        write_policy_eval_report(path, summary)

    def fake_finalize(*args, **kwargs):
        events.append("finalize")
        return {
            "holdout_status": "consumed",
            "qualification_id": "qualification-test",
            "qualification_decision": "rejected",
        }

    monkeypatch.setattr("sentinelops.cli.write_policy_eval_report", fake_write)
    monkeypatch.setattr("sentinelops.cli.finalize_policy_qualification", fake_finalize)

    exit_code = main(
        ["policy-eval-campaign", "--purpose", "qualification", "--output", str(report)]
    )

    assert exit_code == 2
    output = capsys.readouterr().out
    if failed_write == 1:
        assert events == ["write"]
        assert not report.exists()
        assert '"holdout_status": "reserved"' in output
    else:
        assert events == ["write", "finalize", "write"]
        assert json.loads(report.read_text(encoding="utf-8"))["governance"][
            "holdout_status"
        ] == "reserved"
        assert '"holdout_status": "consumed"' in output
        assert "preliminary evidence report is preserved" in output
