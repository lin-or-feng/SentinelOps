import json
from concurrent.futures import ThreadPoolExecutor

import pytest

import sentinelops.application.shadow_qualification as qualification
from sentinelops.adapters import load_fixture_cases
from sentinelops.application.shadow_qualification import (
    ShadowQualificationError,
    ShadowQualificationRegistry,
    load_shadow_qualification_dataset,
    run_shadow_qualification_campaign,
)
from sentinelops.cli import main
from sentinelops.specialist_shadow import ShadowHypothesis, ShadowModelResponse


DIGEST = "a" * 64


class StableProposer:
    def __init__(self, *, code="deployment_regression", drift=False, drift_after=1):
        self.code = code
        self.drift = drift
        self.drift_after = drift_after
        self.refreshes = 0

    def model_identity(self):
        return "test-model", DIGEST

    def refresh_model_identity(self):
        self.refreshes += 1
        if self.drift and self.refreshes > self.drift_after:
            return "test-model", "b" * 64
        return self.model_identity()

    def propose_hypothesis(self, context):
        return ShadowModelResponse(
            hypothesis=ShadowHypothesis(
                code=self.code,
                evidence_refs=[] if self.code == "unknown" else ["E1"],
                confidence=0.7,
                uncertainty="Requires independent confirmation.",
            ),
            prompt_tokens=10,
            completion_tokens=5,
        )


def _dataset(path, *, holdout_count=20):
    base = load_fixture_cases("evals/incidents.json")[0]
    cases = []
    for index in range(holdout_count + 1):
        incident_id = f"inc-shadow-{index:03d}"
        task = base.task.model_copy(update={"incident_id": incident_id})
        evidence = [
            item.model_copy(update={
                "incident_id": incident_id,
                "evidence_id": f"{item.evidence_id}-{index}",
            }).model_dump(mode="json")
            for item in base.evidence
        ]
        cases.append({
            "group_id": f"group-shadow-{index:03d}",
            "split": "development" if index == 0 else "holdout",
            "task": task.model_dump(mode="json"),
            "evidence": evidence,
            "expected_code": "deployment_regression",
        })
    path.write_text(json.dumps({"schema_version": "0.1", "cases": cases}), encoding="utf-8")
    return path


def _registered(tmp_path, *, holdout_count=20):
    dataset = _dataset(tmp_path / "shadow-dataset.json", holdout_count=holdout_count)
    registry = ShadowQualificationRegistry(tmp_path / "registry.db")
    registry.register(
        dataset_id="shadow-v1", dataset_path=dataset,
        approval_ref="review-ticket-001",
    )
    return registry, dataset


def test_sealed_dataset_enforces_incident_groups_and_evidence_scope(tmp_path) -> None:
    dataset = _dataset(tmp_path / "cases.json", holdout_count=1)
    loaded, digest = load_shadow_qualification_dataset(dataset)
    assert len(loaded.cases) == 2
    assert len(digest) == 64
    payload = json.loads(dataset.read_text(encoding="utf-8"))
    payload["cases"][1]["group_id"] = payload["cases"][0]["group_id"]
    dataset.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ShadowQualificationError, match="invalid qualification dataset"):
        load_shadow_qualification_dataset(dataset)
    payload["cases"][1]["group_id"] = "independent-group"
    payload["cases"][1]["evidence"][0]["incident_id"] = "inc-outside"
    dataset.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ShadowQualificationError, match="invalid qualification dataset"):
        load_shadow_qualification_dataset(dataset)


def test_registration_detects_dataset_drift_and_prior_overlap(tmp_path) -> None:
    registry, dataset = _registered(tmp_path, holdout_count=1)
    assert registry.list_datasets()[0]["state"] == "sealed"
    second = _dataset(tmp_path / "second.json", holdout_count=1)
    with pytest.raises(ShadowQualificationError, match="overlaps prior data"):
        registry.register(
            dataset_id="shadow-v2", dataset_path=second,
            approval_ref="review-ticket-002",
        )
    payload = json.loads(dataset.read_text(encoding="utf-8"))
    payload["cases"][0]["task"]["symptoms"].append("new symptom")
    dataset.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ShadowQualificationError, match="drifted"):
        registry.list_datasets()


def test_qualification_campaign_consumes_holdout_once_and_keeps_no_raw_cases(tmp_path) -> None:
    registry, _ = _registered(tmp_path)
    report_path = tmp_path / "qualification-report.json"
    report = run_shadow_qualification_campaign(
        registry_path=registry.db_path,
        dataset_id="shadow-v1",
        report_path=report_path,
        proposer=StableProposer(),
        runs=2,
    )
    assert report["state"] == "consumed"
    assert report["qualification_decision"] == "accepted"
    assert report["production_qualified"] is False
    assert report["prediction_stability_rate"] == 1.0
    assert len(report["run_summaries"]) == 2
    assert all(item["model_top1_all_attempts"] == 1.0 for item in report["run_summaries"])
    assert registry.list_datasets()[0]["state"] == "consumed"
    assert "inc-shadow-001" not in report_path.read_text(encoding="utf-8")
    with pytest.raises(ShadowQualificationError, match="not sealed"):
        run_shadow_qualification_campaign(
            registry_path=registry.db_path, dataset_id="shadow-v1",
            report_path=tmp_path / "second-report.json",
            proposer=StableProposer(), runs=2,
        )


def test_model_identity_drift_leaves_reservation_and_preliminary_report(tmp_path) -> None:
    registry, _ = _registered(tmp_path)
    report_path = tmp_path / "interrupted.json"
    with pytest.raises(ShadowQualificationError, match="identity drifted"):
        run_shadow_qualification_campaign(
            registry_path=registry.db_path, dataset_id="shadow-v1",
            report_path=report_path, proposer=StableProposer(drift=True), runs=2,
        )
    assert registry.list_datasets()[0]["state"] == "reserved"
    preliminary = json.loads(report_path.read_text(encoding="utf-8"))
    assert preliminary["state"] == "interrupted_review_required"
    assert preliminary["reservation_id"]
    with pytest.raises(ShadowQualificationError, match="not sealed"):
        registry.reserve(
            dataset_id="shadow-v1", model_name="test-model",
            model_digest=DIGEST, runs=2,
        )


def test_partial_campaign_report_keeps_completed_round_before_drift(tmp_path) -> None:
    registry, _ = _registered(tmp_path)
    report_path = tmp_path / "partial.json"
    with pytest.raises(ShadowQualificationError, match="identity drifted"):
        run_shadow_qualification_campaign(
            registry_path=registry.db_path, dataset_id="shadow-v1",
            report_path=report_path,
            proposer=StableProposer(drift=True, drift_after=2), runs=2,
        )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["completed_runs"] == 1
    assert len(report["run_summaries"]) == 1
    assert report["state"] == "interrupted_review_required"
    assert registry.list_datasets()[0]["state"] == "reserved"


def test_concurrent_reservations_only_one_can_open_holdout(tmp_path) -> None:
    registry, _ = _registered(tmp_path, holdout_count=1)

    def reserve_once():
        try:
            return registry.reserve(
                dataset_id="shadow-v1", model_name="test-model",
                model_digest=DIGEST, runs=2,
            )[0]
        except ShadowQualificationError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        attempts = list(executor.map(lambda _: reserve_once(), range(2)))
    assert sum(item is not None for item in attempts) == 1
    assert registry.list_datasets()[0]["state"] == "reserved"


def test_prediction_instability_consumes_holdout_as_rejected(tmp_path) -> None:
    class FlippingProposer(StableProposer):
        def propose_hypothesis(self, context):
            self.code = "unknown" if self.refreshes >= 3 else "deployment_regression"
            return super().propose_hypothesis(context)

    registry, _ = _registered(tmp_path)
    report = run_shadow_qualification_campaign(
        registry_path=registry.db_path, dataset_id="shadow-v1",
        report_path=tmp_path / "unstable.json",
        proposer=FlippingProposer(), runs=2,
    )
    assert report["prediction_stability_rate"] == 0.0
    assert report["qualification_decision"] == "rejected"
    assert registry.list_datasets()[0]["state"] == "consumed"


def test_failing_model_gate_still_consumes_holdout_as_rejected(tmp_path) -> None:
    registry, _ = _registered(tmp_path)
    report = run_shadow_qualification_campaign(
        registry_path=registry.db_path, dataset_id="shadow-v1",
        report_path=tmp_path / "rejected.json",
        proposer=StableProposer(code="unknown"), runs=2,
    )
    assert report["qualification_decision"] == "rejected"
    assert report["gates_passed"] is False
    assert registry.list_datasets()[0]["state"] == "consumed"


def test_final_report_write_failure_states_holdout_was_consumed(
    tmp_path, monkeypatch
) -> None:
    registry, _ = _registered(tmp_path)
    report_path = tmp_path / "final-write-failure.json"
    original_write = qualification._write_report

    def fail_final_write(path, report, *, new):
        if report.get("state") == "consumed":
            raise ShadowQualificationError("simulated final write failure")
        return original_write(path, report, new=new)

    monkeypatch.setattr(qualification, "_write_report", fail_final_write)
    with pytest.raises(ShadowQualificationError, match="registry consumed.*do not rerun"):
        run_shadow_qualification_campaign(
            registry_path=registry.db_path, dataset_id="shadow-v1",
            report_path=report_path, proposer=StableProposer(), runs=2,
        )
    assert registry.list_datasets()[0]["state"] == "consumed"
    preliminary = json.loads(report_path.read_text(encoding="utf-8"))
    assert preliminary["state"] == "evaluated_pending_finalization"
    assert preliminary["reservation_id"]


def test_preflight_rejects_too_small_cohort_and_existing_report_without_reservation(
    tmp_path,
) -> None:
    registry, _ = _registered(tmp_path, holdout_count=1)
    with pytest.raises(ShadowQualificationError, match="at least 20"):
        run_shadow_qualification_campaign(
            registry_path=registry.db_path, dataset_id="shadow-v1",
            report_path=tmp_path / "report.json", proposer=StableProposer(), runs=2,
        )
    assert registry.list_datasets()[0]["state"] == "sealed"
    existing = tmp_path / "report.json"
    existing.write_text("existing", encoding="utf-8")
    with pytest.raises(ShadowQualificationError, match="new JSON file"):
        run_shadow_qualification_campaign(
            registry_path=registry.db_path, dataset_id="shadow-v1",
            report_path=existing, proposer=StableProposer(), runs=2,
        )
    assert existing.read_text(encoding="utf-8") == "existing"
    assert registry.list_datasets()[0]["state"] == "sealed"


def test_registry_cli_is_offline_and_reports_only_metadata(tmp_path, capsys) -> None:
    dataset = _dataset(tmp_path / "cli-dataset.json", holdout_count=1)
    registry_path = tmp_path / "cli-registry.db"
    assert main([
        "specialist-shadow-register", "--registry", str(registry_path),
        "--dataset", str(dataset), "--dataset-id", "cli-shadow-v1",
        "--approval-ref", "review-ticket-003",
    ]) == 0
    capsys.readouterr()
    assert main([
        "specialist-shadow-registry-check", "--registry", str(registry_path)
    ]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is True
    assert output["datasets"][0]["state"] == "sealed"
    assert "inc-shadow-001" not in json.dumps(output)
