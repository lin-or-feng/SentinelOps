"""Development-only, read-only evaluation of recorded Specialist shadow calls."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from sentinelops.privacy import scan_content
from sentinelops.specialist_shadow import (
    SPECIALIST_PROMPT_ID,
    SPECIALIST_PROMPT_SHA256,
    ShadowJournal,
    ShadowRecord,
)
from sentinelops.storage import InvestigationStore


class ShadowEvalError(ValueError):
    pass


class ShadowLabel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    incident_id: str = Field(min_length=3, max_length=120)
    group_id: str = Field(min_length=3, max_length=120)
    expected_code: Literal[
        "deployment_regression", "database_pool_exhaustion",
        "cache_miss_storm", "downstream_timeout", "unknown",
    ]


class ShadowLabelSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.1"]
    split: Literal["development", "holdout"]
    cases: list[ShadowLabel] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def unique_incidents(self) -> "ShadowLabelSet":
        ids = [item.incident_id for item in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate incident labels")
        return self


def load_shadow_labels(path: str | Path) -> tuple[ShadowLabelSet, str]:
    source = Path(path)
    if not source.is_file():
        raise ShadowEvalError("shadow label dataset not found")
    if source.stat().st_size > 1_000_000:
        raise ShadowEvalError("shadow label dataset exceeds size limit")
    raw = source.read_bytes()
    if scan_content("shadow-labels.json", raw):
        raise ShadowEvalError("shadow label dataset failed privacy scan")
    try:
        labels = ShadowLabelSet.model_validate_json(raw)
    except (ValidationError, ValueError) as exc:
        raise ShadowEvalError("invalid shadow label dataset") from exc
    canonical = json.dumps(
        labels.model_dump(mode="json"), ensure_ascii=False,
        sort_keys=True, separators=(",", ":"),
    )
    return labels, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def evaluate_shadow_development(
    label_path: str | Path,
    db_path: str | Path,
    *,
    model_name: str,
    model_digest: str,
    min_cases: int = 20,
    min_acceptance_rate: float = 0.95,
) -> dict[str, object]:
    """Compare shadow observations with labels; never authorize production promotion."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}", model_name):
        raise ShadowEvalError("invalid model name")
    if not re.fullmatch(r"[0-9a-f]{64}", model_digest):
        raise ShadowEvalError("model digest must be a 64-character SHA-256")
    if not 1 <= min_cases <= 1000:
        raise ShadowEvalError("min_cases must be between 1 and 1000")
    if not 0 <= min_acceptance_rate <= 1:
        raise ShadowEvalError("min_acceptance_rate must be between 0 and 1")
    labels, dataset_sha256 = load_shadow_labels(label_path)
    if labels.split != "development":
        raise ShadowEvalError("holdout shadow evaluation requires a governed registry")
    if not Path(db_path).is_file():
        raise ShadowEvalError("shadow database not found")

    store = InvestigationStore(db_path)
    journal = ShadowJournal(db_path)
    observations: list[tuple[ShadowRecord, str]] = []
    for label in labels.cases:
        investigation = store.get(label.incident_id)
        if investigation is None:
            raise ShadowEvalError("labelled incident has no completed investigation")
        records = journal.list_for_trace(investigation.trace_id)
        if not records:
            raise ShadowEvalError("labelled incident has no shadow observations")
        for record in records:
            if (
                record.model_name != model_name
                or record.model_digest != model_digest
                or record.prompt_id != SPECIALIST_PROMPT_ID
                or record.prompt_sha256 != SPECIALIST_PROMPT_SHA256
            ):
                raise ShadowEvalError("shadow model or prompt identity does not match")
            observations.append((record, label.expected_code))

    by_source: dict[str, list[tuple[ShadowRecord, str]]] = defaultdict(list)
    for record, expected in observations:
        by_source[record.source].append((record, expected))

    def metrics(items: list[tuple[ShadowRecord, str]]) -> dict[str, object]:
        accepted = [(record, expected) for record, expected in items
                    if record.reason_code == "accepted"]
        model_correct = sum(record.proposed_code == expected for record, expected in items)
        baseline_correct = sum(
            (record.baseline_code or "unknown") == expected for record, expected in items
        )
        return {
            "observations": len(items),
            "acceptance_rate": _rate(len(accepted), len(items)),
            "model_top1_accuracy_all_attempts": _rate(model_correct, len(items)),
            "baseline_top1_accuracy": _rate(baseline_correct, len(items)),
            "unknown_rate": _rate(
                sum(record.proposed_code == "unknown" for record, _ in accepted),
                len(items),
            ),
            "reference_rejections": sum(
                record.reason_code == "unsupported_evidence_reference"
                for record, _ in items
            ),
        }

    overall = metrics(observations)
    reason_counts = Counter(record.reason_code for record, _ in observations)
    durations = sorted(record.duration_ms for record, _ in observations)
    accepted_rate = overall["acceptance_rate"]
    model_accuracy = overall["model_top1_accuracy_all_attempts"]
    baseline_accuracy = overall["baseline_top1_accuracy"]
    assert isinstance(accepted_rate, float)
    assert isinstance(model_accuracy, float) and isinstance(baseline_accuracy, float)
    return {
        "schema_version": "0.1",
        "evaluation_type": "specialist_shadow_development",
        "dataset_sha256": dataset_sha256,
        "labelled_incidents": len(labels.cases),
        "model_name": model_name,
        "model_digest": model_digest,
        "prompt_id": SPECIALIST_PROMPT_ID,
        "prompt_sha256": SPECIALIST_PROMPT_SHA256,
        "overall": overall,
        "by_source": {
            source: metrics(items) for source, items in sorted(by_source.items())
        },
        "reason_counts": dict(sorted(reason_counts.items())),
        "p95_shadow_call_ms": durations[(95 * len(durations) + 99) // 100 - 1],
        "prompt_tokens_observed": sum(
            record.prompt_tokens or 0 for record, _ in observations
        ),
        "completion_tokens_observed": sum(
            record.completion_tokens or 0 for record, _ in observations
        ),
        "development_gate_passed": (
            len(labels.cases) >= min_cases
            and accepted_rate >= min_acceptance_rate
            and overall["reference_rejections"] == 0
            and model_accuracy >= baseline_accuracy
        ),
        "production_qualified": False,
        "limitations": (
            "Development labels are self-attested, not independently verified. "
            "This report does not consume or qualify a holdout and cannot promote "
            "the model into the reviewer decision path."
        ),
    }
