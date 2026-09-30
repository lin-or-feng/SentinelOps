"""Offline, development-only comparison of live source-selection reports."""

from __future__ import annotations

import json
from pathlib import Path

from sentinelops.privacy import MAX_SCANNABLE_BYTES, scan_content


class PolicyCompareError(ValueError):
    pass


def _load_report(path: str | Path) -> dict[str, object]:
    report_path = Path(path)
    if report_path.suffix.casefold() != ".json" or report_path.is_symlink():
        raise PolicyCompareError("comparison input must be a regular JSON report")
    try:
        with report_path.open("rb") as handle:
            payload = handle.read(MAX_SCANNABLE_BYTES + 1)
    except OSError as exc:
        raise PolicyCompareError("unable to read comparison report") from exc
    if len(payload) > MAX_SCANNABLE_BYTES:
        raise PolicyCompareError("comparison report exceeds size limit")
    if scan_content(report_path.name, payload):
        raise PolicyCompareError("comparison report failed privacy scan")
    try:
        report = json.loads(payload)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise PolicyCompareError("invalid comparison report JSON") from exc
    if not isinstance(report, dict):
        raise PolicyCompareError("comparison report must be an object")
    return report


def _validated_report(report: dict[str, object]) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    if report.get("evaluation_type") != "live_ollama" or report.get("split") != "development":
        raise PolicyCompareError("only live development reports can be compared")
    provenance = report.get("provenance")
    results = report.get("case_results")
    candidate = provenance.get("candidate") if isinstance(provenance, dict) else None
    if not isinstance(provenance, dict) or not isinstance(candidate, dict):
        raise PolicyCompareError("comparison report has invalid provenance")
    if provenance.get("mode") != "ollama" or provenance.get("split") != "development":
        raise PolicyCompareError("comparison report has inconsistent provenance")
    if candidate.get("kind") != "ollama" or not isinstance(
        provenance.get("sentinelops_version"), str
    ):
        raise PolicyCompareError("comparison report has incomplete runtime identity")
    for key in ("dataset_sha256", "model", "model_digest", "prompt_id", "prompt_sha256"):
        owner = provenance if key == "dataset_sha256" else candidate
        value = owner.get(key)
        if not isinstance(value, str) or not value:
            raise PolicyCompareError("comparison report has incomplete provenance")
    if not isinstance(results, list) or not results or type(report.get("cases")) is not int:
        raise PolicyCompareError("comparison report has invalid case results")
    if len(results) != report["cases"] or provenance.get("evaluated_cases") != len(results):
        raise PolicyCompareError("comparison report has incomplete case results")
    by_id: dict[str, dict[str, object]] = {}
    for result in results:
        if not isinstance(result, dict):
            raise PolicyCompareError("comparison report has invalid case results")
        case_id = result.get("case_id")
        expected = result.get("expected_sources")
        source = result.get("candidate_source")
        if (
            not isinstance(case_id, str)
            or not case_id
            or case_id in by_id
            or not isinstance(expected, list)
            or not expected
            or any(not isinstance(item, str) or not item for item in expected)
            or len(set(expected)) != len(expected)
            or not isinstance(source, str)
            or type(result.get("candidate_correct")) is not bool
            or result["candidate_correct"] != (source in expected)
        ):
            raise PolicyCompareError("comparison report has inconsistent case results")
        by_id[case_id] = result
    assisted = report.get("assisted")
    if not isinstance(assisted, dict):
        raise PolicyCompareError("comparison report has invalid aggregate metrics")
    top1 = sum(bool(item["candidate_correct"]) for item in by_id.values()) / len(by_id)
    if type(assisted.get("top1_accuracy")) not in (float, int) or abs(float(assisted["top1_accuracy"]) - top1) > 0.0001:
        raise PolicyCompareError("comparison report disagrees with case-level accuracy")
    for key in ("safety_guard_rate", "forbidden_execution_rate", "candidate_call_success_rate"):
        value = report.get(key)
        if type(value) not in (float, int) or not 0 <= value <= 1:
            raise PolicyCompareError("comparison report has invalid safety or availability metrics")
    return provenance, by_id


def compare_policy_development_reports(
    baseline_path: str | Path, candidate_path: str | Path
) -> dict[str, object]:
    """Compare same-cohort model runs without opening or qualifying a holdout."""
    baseline = _load_report(baseline_path)
    candidate = _load_report(candidate_path)
    base_provenance, base_cases = _validated_report(baseline)
    next_provenance, next_cases = _validated_report(candidate)
    base_model = base_provenance["candidate"]
    next_model = next_provenance["candidate"]
    assert isinstance(base_model, dict) and isinstance(next_model, dict)
    if (
        base_provenance["dataset_sha256"] != next_provenance["dataset_sha256"]
        or base_model["model"] != next_model["model"]
        or base_model["model_digest"] != next_model["model_digest"]
        or base_provenance["sentinelops_version"] != next_provenance["sentinelops_version"]
    ):
        raise PolicyCompareError("comparison requires the same dataset, model digest, and runtime version")
    if set(base_cases) != set(next_cases):
        raise PolicyCompareError("comparison requires identical case IDs")
    for case_id in base_cases:
        before, after = base_cases[case_id], next_cases[case_id]
        if any(before.get(key) != after.get(key) for key in ("group_id", "expected_sources", "heuristic_source")):
            raise PolicyCompareError("comparison requires identical case definitions")
    improved = sorted(
        case_id for case_id in base_cases
        if not base_cases[case_id]["candidate_correct"] and next_cases[case_id]["candidate_correct"]
    )
    regressed = sorted(
        case_id for case_id in base_cases
        if base_cases[case_id]["candidate_correct"] and not next_cases[case_id]["candidate_correct"]
    )
    still_failed = sorted(
        case_id for case_id in base_cases
        if not base_cases[case_id]["candidate_correct"] and not next_cases[case_id]["candidate_correct"]
    )
    total = len(base_cases)
    before_correct = sum(bool(case["candidate_correct"]) for case in base_cases.values())
    after_correct = sum(bool(case["candidate_correct"]) for case in next_cases.values())
    before_downstream = baseline.get("downstream")
    after_downstream = candidate.get("downstream")
    downstream_reports_present = (
        isinstance(before_downstream, dict)
        and isinstance(after_downstream, dict)
        and isinstance(before_downstream.get("assisted"), dict)
        and isinstance(after_downstream.get("assisted"), dict)
    )
    base_fixture = before_downstream.get("fixture_sha256") if isinstance(before_downstream, dict) else None
    next_fixture = after_downstream.get("fixture_sha256") if isinstance(after_downstream, dict) else None
    for fixture_hash in (base_fixture, next_fixture):
        if fixture_hash is not None and (
            not isinstance(fixture_hash, str)
            or len(fixture_hash) != 64
            or any(char not in "0123456789abcdef" for char in fixture_hash)
        ):
            raise PolicyCompareError("comparison report has invalid downstream fingerprint")
    downstream_comparable = (
        downstream_reports_present
        and base_fixture is not None
        and base_fixture == next_fixture
    )
    downstream_delta = None
    if downstream_comparable:
        assert isinstance(before_downstream, dict) and isinstance(after_downstream, dict)
        before_metrics = before_downstream["assisted"]
        after_metrics = after_downstream["assisted"]
        assert isinstance(before_metrics, dict) and isinstance(after_metrics, dict)
        for metrics in (before_metrics, after_metrics):
            if (
                type(metrics.get("cases")) is not int
                or metrics["cases"] < 1
                or type(metrics.get("top1_accuracy")) not in (float, int)
                or not 0 <= metrics["top1_accuracy"] <= 1
            ):
                raise PolicyCompareError("comparison report has invalid downstream metrics")
        if before_metrics["cases"] != after_metrics["cases"]:
            raise PolicyCompareError("matching downstream fingerprints require equal case counts")
        downstream_delta = round(
            after_metrics["top1_accuracy"] - before_metrics["top1_accuracy"], 4
        )
    return {
        "comparison_type": "development_only",
        "dataset_sha256": base_provenance["dataset_sha256"],
        "model": base_model["model"],
        "model_digest": base_model["model_digest"],
        "sentinelops_version": base_provenance["sentinelops_version"],
        "baseline_prompt_id": base_model["prompt_id"],
        "candidate_prompt_id": next_model["prompt_id"],
        "cases": total,
        "baseline_top1": round(before_correct / total, 4),
        "candidate_top1": round(after_correct / total, 4),
        "delta_top1": round((after_correct - before_correct) / total, 4),
        "improved_case_ids": improved,
        "regressed_case_ids": regressed,
        "still_failed_case_ids": still_failed,
        "safety": {
            key: {"baseline": baseline[key], "candidate": candidate[key]}
            for key in ("safety_guard_rate", "forbidden_execution_rate", "candidate_call_success_rate")
        },
        "downstream_reports_present": downstream_reports_present,
        "downstream_comparable": downstream_comparable,
        "downstream_fixture_sha256": base_fixture if downstream_comparable else None,
        "downstream_top1_delta": downstream_delta,
        "downstream_assisted": (
            {"baseline": before_downstream["assisted"], "candidate": after_downstream["assisted"]}
            if downstream_reports_present else None
        ),
        "candidate_has_no_case_regression": not regressed,
        "candidate_preserves_safety": (
            candidate["safety_guard_rate"] >= baseline["safety_guard_rate"]
            and candidate["forbidden_execution_rate"] <= baseline["forbidden_execution_rate"]
            and candidate["candidate_call_success_rate"] >= baseline["candidate_call_success_rate"]
        ),
        "limitation": "Development-only diagnostic; not a qualification or production-readiness claim. Safety aggregates are report-level and not independently reconstructable from case_results. Downstream comparison requires matching fixture fingerprints; legacy reports without them remain incomparable.",
    }
