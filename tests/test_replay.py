import json

import pytest

from sentinelops.application.replay import (
    ReplayDatasetError,
    ReplayPrivacyError,
    ReplaySuite,
    load_replay_suite,
    run_replay_suite,
    schema_fingerprint,
)
from sentinelops.cli import main


REPLAY_DATASET = "evals/observability_replays.json"


def test_curated_replay_suite_passes_all_provider_contracts() -> None:
    summary = run_replay_suite(load_replay_suite(REPLAY_DATASET))

    assert summary.valid is True
    assert summary.total == 5
    assert summary.passed == 5
    assert summary.schema_drift == 0
    assert {item.actual_outcome for item in summary.details} == {
        "success",
        "retryable_error",
        "schema_error",
    }


def test_replay_detects_unapproved_schema_drift_before_provider_execution() -> None:
    suite = load_replay_suite(REPLAY_DATASET)
    original = suite.cases[0]
    drifted = original.model_copy(
        update={"response_payload": {**original.response_payload, "newField": "added"}}
    )
    changed_suite = ReplaySuite(
        schema_version="1.0",
        privacy_policy="sentinelops-privacy-v1",
        cases=[drifted],
    )

    summary = run_replay_suite(changed_suite)

    assert summary.valid is False
    assert summary.schema_drift == 1
    assert summary.details[0].actual_outcome == "schema_drift"
    assert summary.details[0].reason == "response structure differs from the approved fingerprint"


def test_replay_loader_blocks_private_values_without_echoing_them(tmp_path) -> None:
    private_value = "138" + "0013" + "8000"
    replay_path = tmp_path / "unsafe-replay.json"
    replay_path.write_text(json.dumps({"line": private_value}), encoding="utf-8")

    with pytest.raises(ReplayPrivacyError) as error:
        load_replay_suite(replay_path)

    assert "PRC mobile number" in str(error.value)
    assert private_value not in str(error.value)


def test_replay_runner_rechecks_programmatically_constructed_suite_privacy() -> None:
    suite = load_replay_suite(REPLAY_DATASET)
    private_value = "138" + "0013" + "8000"
    original = suite.cases[0]
    unsafe_payload = {**original.response_payload, "contact": private_value}
    unsafe_case = original.model_copy(
        update={
            "response_payload": unsafe_payload,
            "expected_schema_fingerprint": schema_fingerprint(unsafe_payload),
        }
    )
    unsafe_suite = suite.model_copy(update={"cases": [unsafe_case]})

    with pytest.raises(ReplayPrivacyError) as error:
        run_replay_suite(unsafe_suite)

    assert "PRC mobile number" in str(error.value)
    assert private_value not in str(error.value)


def test_replay_schema_fingerprint_has_depth_and_node_bounds() -> None:
    payload: dict[str, object] = {}
    cursor = payload
    for index in range(22):
        child: dict[str, object] = {}
        cursor[f"level_{index}"] = child
        cursor = child

    with pytest.raises(ReplayDatasetError, match="depth limit"):
        schema_fingerprint(payload)


def test_replay_check_cli_returns_machine_readable_summary(capsys) -> None:
    exit_code = main(["replay-check", "--dataset", REPLAY_DATASET])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["valid"] is True
    assert output["passed"] == 5
