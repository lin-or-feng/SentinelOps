import json

import pytest

from sentinelops.application.policy_compare import (
    PolicyCompareError,
    compare_policy_development_reports,
)
from sentinelops.cli import main


def _report(prompt_id="v1", source="logs"):
    correct = source == "logs"
    return {
        "evaluation_type": "live_ollama",
        "split": "development",
        "cases": 1,
        "provenance": {
            "mode": "ollama", "split": "development", "evaluated_cases": 1,
            "dataset_sha256": "a" * 64,
            "sentinelops_version": "0.4.13",
            "candidate": {
                "kind": "ollama", "model": "model:7b", "model_digest": "b" * 64,
                "prompt_id": prompt_id, "prompt_sha256": "c" * 64,
            },
        },
        "case_results": [{
            "case_id": "case-01", "group_id": "group-01",
            "expected_sources": ["logs"], "heuristic_source": "metrics",
            "candidate_source": source, "candidate_correct": correct,
        }],
        "assisted": {"top1_accuracy": float(correct)},
        "safety_guard_rate": 1.0,
        "forbidden_execution_rate": 0.0,
        "candidate_call_success_rate": 1.0,
        "downstream": {"assisted": None},
    }


def _write(path, report):
    path.write_text(json.dumps(report), encoding="utf-8")


def test_development_comparison_shows_case_delta_and_is_diagnostic(tmp_path, capsys):
    base, candidate = tmp_path / "base.json", tmp_path / "candidate.json"
    _write(base, _report(source="metrics"))
    _write(candidate, _report(prompt_id="v4"))
    assert main(["policy-eval-dev-compare", "--baseline", str(base), "--candidate", str(candidate)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["improved_case_ids"] == ["case-01"]
    assert output["delta_top1"] == 1.0
    assert output["downstream_comparable"] is False
    assert output["comparison_type"] == "development_only"


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(split="holdout"),
    lambda r: r["provenance"]["candidate"].update(model_digest="other"),
    lambda r: r["provenance"].update(sentinelops_version="other"),
    lambda r: r["case_results"][0].update(case_id="different"),
    lambda r: r["case_results"][0].update(candidate_correct=False),
    lambda r: r["assisted"].update(top1_accuracy=0.0),
    lambda r: r.update(safety_guard_rate=2.0),
])
def test_development_comparison_rejects_unmatched_or_inconsistent_reports(tmp_path, mutation):
    base, candidate = tmp_path / "base.json", tmp_path / "candidate.json"
    _write(base, _report())
    changed = _report(prompt_id="v4")
    mutation(changed)
    _write(candidate, changed)
    with pytest.raises(PolicyCompareError):
        compare_policy_development_reports(base, candidate)


def test_development_comparison_rejects_private_and_oversized_input(tmp_path):
    base, candidate = tmp_path / "base.json", tmp_path / "candidate.json"
    _write(base, _report())
    changed = _report(prompt_id="v4")
    changed["private"] = "138" + "0013" + "8000"
    _write(candidate, changed)
    with pytest.raises(PolicyCompareError, match="privacy scan"):
        compare_policy_development_reports(base, candidate)
    candidate.write_bytes(b" " * 2_000_000)
    with pytest.raises(PolicyCompareError, match="size limit"):
        compare_policy_development_reports(base, candidate)


def test_downstream_comparison_requires_matching_fixture_fingerprint(tmp_path):
    base, candidate = tmp_path / "base.json", tmp_path / "candidate.json"
    before = _report()
    after = _report(prompt_id="v4")
    for report, accuracy in ((before, 0.75), (after, 1.0)):
        report["downstream"] = {
            "fixture_sha256": "d" * 64,
            "assisted": {"cases": 4, "top1_accuracy": accuracy},
        }
    _write(base, before)
    _write(candidate, after)
    summary = compare_policy_development_reports(base, candidate)
    assert summary["downstream_comparable"] is True
    assert summary["downstream_top1_delta"] == 0.25

    after["downstream"]["fixture_sha256"] = "e" * 64
    _write(candidate, after)
    summary = compare_policy_development_reports(base, candidate)
    assert summary["downstream_reports_present"] is True
    assert summary["downstream_comparable"] is False
    assert summary["downstream_top1_delta"] is None


def test_downstream_comparison_rejects_malformed_metrics(tmp_path):
    base, candidate = tmp_path / "base.json", tmp_path / "candidate.json"
    before = _report()
    after = _report(prompt_id="v4")
    before["downstream"] = {
        "fixture_sha256": "d" * 64,
        "assisted": {"cases": 4, "top1_accuracy": 1.0},
    }
    after["downstream"] = {
        "fixture_sha256": "d" * 64,
        "assisted": {"cases": 3, "top1_accuracy": 1.0},
    }
    _write(base, before)
    _write(candidate, after)
    with pytest.raises(PolicyCompareError, match="equal case counts"):
        compare_policy_development_reports(base, candidate)
