import json

import pytest

from sentinelops.application.incident_intake import (
    IncidentIntakeError,
    load_incident_intake_manifest,
    review_incident_intake,
)
from sentinelops.cli import main


def _candidate(**updates):
    candidate = {
        "candidate_id": "example-incident-001",
        "group_id": "example-group-001",
        "source_url": "https://status.example.com/incident-001",
        "report_scope": "single_incident",
        "intended_split": "development",
        "decision_cutoff_at": "2026-01-02T12:00:00Z",
        "contemporaneous_evidence": [{
            "url": "https://status.example.com/incident-001/initial",
            "available_at": "2026-01-02T11:55:00Z",
        }],
        "label_status": "supported",
        "proposed_code": "deployment_regression",
        "license_review_ref": "review-license-001",
        "redaction_review_ref": "review-redaction-001",
        "independent_label_review_ref": "review-label-001",
    }
    candidate.update(updates)
    return candidate


def _write(tmp_path, *candidates):
    path = tmp_path / "intake.json"
    path.write_text(json.dumps({
        "schema_version": "0.1", "candidates": list(candidates),
    }), encoding="utf-8")
    return path


def test_complete_preflight_still_requires_human_review(tmp_path, capsys):
    path = _write(tmp_path, _candidate())
    manifest, digest = load_incident_intake_manifest(path)
    result = review_incident_intake(manifest, digest)
    assert len(digest) == 64
    assert result["blocked"] == 0
    assert result["manual_review_required"] == 1
    assert result["dataset_registered"] is False
    assert result["holdout_qualified"] is False
    assert main(["incident-intake-check", "--manifest", str(path)]) == 0
    assert '"status": "manual_review_required"' in capsys.readouterr().out


def test_postmortem_only_and_outside_taxonomy_are_blocked(tmp_path, capsys):
    candidate = _candidate(
        decision_cutoff_at=None,
        contemporaneous_evidence=[],
        label_status="out_of_taxonomy",
        proposed_code=None,
        license_review_ref=None,
    )
    path = _write(tmp_path, candidate)
    assert main(["incident-intake-check", "--manifest", str(path)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["blocked"] == 1
    assert result["results"][0]["blockers"] == [
        "label_out_of_taxonomy", "point_in_time_evidence_missing",
        "license_review_missing",
    ]


def test_late_evidence_is_blocked(tmp_path):
    candidate = _candidate(contemporaneous_evidence=[{
        "url": "https://status.example.com/incident-001/postmortem",
        "available_at": "2026-01-03T00:00:00Z",
    }])
    manifest, digest = load_incident_intake_manifest(_write(tmp_path, candidate))
    assert review_incident_intake(manifest, digest)["results"][0]["blockers"] == [
        "post_cutoff_evidence"
    ]


@pytest.mark.parametrize("updates", [
    {"source_url": "http://status.example.com/incident-001"},
    {"source_url": "https://localhost/incident-001"},
    {"source_url": "https://10.0.0.1/incident-001"},
    {"source_url": "https://status.example.com/incident-001?token=fake-test"},
    {"label_status": "out_of_taxonomy"},
    {"proposed_code": "unknown"},
    {"report_scope": "multiple_incidents"},
])
def test_invalid_candidate_shapes_fail_closed(tmp_path, updates, capsys):
    path = _write(tmp_path, _candidate(**updates))
    with pytest.raises(IncidentIntakeError, match="invalid intake manifest"):
        load_incident_intake_manifest(path)
    assert main(["incident-intake-check", "--manifest", str(path)]) == 2
    assert '"structurally_valid": false' in capsys.readouterr().out


def test_multi_incident_report_requires_split_and_duplicate_groups_rejected(tmp_path):
    report = _candidate(
        report_scope="multiple_incidents", group_id=None,
        decision_cutoff_at=None, contemporaneous_evidence=[],
        label_status="unreviewed", proposed_code=None,
    )
    manifest, digest = load_incident_intake_manifest(_write(tmp_path, report))
    blockers = review_incident_intake(manifest, digest)["results"][0]["blockers"]
    assert "incident_not_isolated" in blockers
    duplicate = _candidate(candidate_id="example-incident-002")
    with pytest.raises(IncidentIntakeError, match="invalid intake manifest"):
        load_incident_intake_manifest(_write(tmp_path, _candidate(), duplicate))


def test_privacy_and_oversized_manifest_fail_without_echoing_content(tmp_path):
    path = _write(tmp_path, _candidate())
    raw = path.read_text(encoding="utf-8")
    private_marker = "139" + "12345678"
    path.write_text(raw.replace("example-incident-001", private_marker), encoding="utf-8")
    with pytest.raises(IncidentIntakeError, match="privacy or size check") as exc:
        load_incident_intake_manifest(path)
    assert private_marker not in str(exc.value)
    path.write_bytes(b" " * 1_000_001)
    with pytest.raises(IncidentIntakeError, match="privacy or size check"):
        load_incident_intake_manifest(path)


def test_public_candidates_remain_blocked_and_do_not_become_holdout():
    manifest, digest = load_incident_intake_manifest(
        "evals/public_incident_candidates.json"
    )
    result = review_incident_intake(manifest, digest)
    assert result["candidates"] == result["blocked"] == 2
    assert result["holdout_qualified"] is False
    assert all(item.intended_split == "development" for item in manifest.candidates)
