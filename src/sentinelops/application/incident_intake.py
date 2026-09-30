"""Read-only preflight for public incident candidates, not dataset approval."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import AwareDatetime, Field, ValidationError, model_validator

from sentinelops.domain import StrictModel
from sentinelops.privacy import MAX_SCANNABLE_BYTES, scan_content
from sentinelops.specialist_shadow import HypothesisCode


class IncidentIntakeError(ValueError):
    pass


def _public_https_url(value: str) -> str:
    parsed = urlsplit(value)
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username
        or parsed.password
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or host.casefold() == "localhost"
        or host.casefold().endswith((".local", ".internal"))
        or any(character.isspace() for character in value)
    ):
        raise ValueError("reference must be a public HTTPS URL without credentials or query")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:
            raise ValueError("reference host must be a public domain") from None
    else:
        if not address.is_global:
            raise ValueError("reference host must not be a private address")
    return value


class IntakeEvidenceRef(StrictModel):
    url: str = Field(min_length=12, max_length=500)
    available_at: AwareDatetime

    @model_validator(mode="after")
    def valid_url(self) -> "IntakeEvidenceRef":
        _public_https_url(self.url)
        return self


class IntakeCandidate(StrictModel):
    candidate_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    group_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    source_url: str = Field(min_length=12, max_length=500)
    report_scope: Literal["single_incident", "multiple_incidents"]
    intended_split: Literal["development", "holdout"]
    decision_cutoff_at: AwareDatetime | None = None
    contemporaneous_evidence: list[IntakeEvidenceRef] = Field(default_factory=list, max_length=20)
    label_status: Literal["supported", "ambiguous", "out_of_taxonomy", "unreviewed"]
    proposed_code: HypothesisCode | None = None
    license_review_ref: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._-]{2,95}$")
    redaction_review_ref: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._-]{2,95}$")
    independent_label_review_ref: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._-]{2,95}$"
    )

    @model_validator(mode="after")
    def valid_shape(self) -> "IntakeCandidate":
        _public_https_url(self.source_url)
        if self.report_scope == "multiple_incidents" and self.group_id is not None:
            raise ValueError("multi-incident reports must be split before assigning a group")
        if self.label_status == "supported":
            if self.proposed_code is None or self.proposed_code == "unknown":
                raise ValueError("supported label requires a named in-taxonomy code")
        elif self.proposed_code is not None:
            raise ValueError("unresolved or out-of-taxonomy labels cannot have a proposed code")
        return self


class IncidentIntakeManifest(StrictModel):
    schema_version: Literal["0.1"]
    candidates: list[IntakeCandidate] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def unique_incidents(self) -> "IncidentIntakeManifest":
        ids = [item.candidate_id for item in self.candidates]
        groups = [item.group_id for item in self.candidates if item.group_id is not None]
        if len(ids) != len(set(ids)) or len(groups) != len(set(groups)):
            raise ValueError("candidate and incident group IDs must be unique")
        return self


def load_incident_intake_manifest(path: str | Path) -> tuple[IncidentIntakeManifest, str]:
    source = Path(path)
    if source.is_symlink() or source.suffix.casefold() != ".json":
        raise IncidentIntakeError("intake manifest must be a regular JSON file")
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise IncidentIntakeError("unable to read intake manifest") from exc
    if len(raw) > MAX_SCANNABLE_BYTES or scan_content(source.name, raw):
        raise IncidentIntakeError("intake manifest failed privacy or size check")
    try:
        manifest = IncidentIntakeManifest.model_validate_json(raw)
    except (ValidationError, ValueError) as exc:
        raise IncidentIntakeError("invalid intake manifest") from exc
    canonical = json.dumps(
        manifest.model_dump(mode="json"), ensure_ascii=False,
        sort_keys=True, separators=(",", ":"),
    )
    return manifest, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _blockers(candidate: IntakeCandidate) -> list[str]:
    reasons: list[str] = []
    if candidate.report_scope != "single_incident" or candidate.group_id is None:
        reasons.append("incident_not_isolated")
    if candidate.label_status != "supported":
        reasons.append(f"label_{candidate.label_status}")
    if candidate.decision_cutoff_at is None or not candidate.contemporaneous_evidence:
        reasons.append("point_in_time_evidence_missing")
    elif any(
        ref.available_at > candidate.decision_cutoff_at
        for ref in candidate.contemporaneous_evidence
    ):
        reasons.append("post_cutoff_evidence")
    if candidate.license_review_ref is None:
        reasons.append("license_review_missing")
    if candidate.redaction_review_ref is None:
        reasons.append("redaction_review_missing")
    if candidate.independent_label_review_ref is None:
        reasons.append("independent_label_review_missing")
    return reasons


def review_incident_intake(
    manifest: IncidentIntakeManifest, fingerprint: str
) -> dict[str, object]:
    results = []
    for candidate in manifest.candidates:
        blockers = _blockers(candidate)
        results.append({
            "candidate_id": candidate.candidate_id,
            "status": "blocked" if blockers else "manual_review_required",
            "blockers": blockers,
        })
    return {
        "manifest_sha256": fingerprint,
        "structurally_valid": True,
        "candidates": len(results),
        "blocked": sum(item["status"] == "blocked" for item in results),
        "manual_review_required": sum(
            item["status"] == "manual_review_required" for item in results
        ),
        "dataset_registered": False,
        "holdout_qualified": False,
        "results": results,
    }
