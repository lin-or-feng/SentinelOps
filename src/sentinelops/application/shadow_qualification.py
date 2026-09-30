"""Governed, offline-only holdout campaign for Specialist shadow hypotheses."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import Field, ValidationError, model_validator

from sentinelops.adapters import FixtureEvidenceTool
from sentinelops.domain import Evidence, IncidentStatus, IncidentTask, StrictModel
from sentinelops.privacy import MAX_SCANNABLE_BYTES, scan_content
from sentinelops.specialist_shadow import (
    HypothesisCode,
    HypothesisProposer,
    SPECIALIST_PROMPT_ID,
    SPECIALIST_PROMPT_SHA256,
    ShadowJournal,
)


class ShadowQualificationError(ValueError):
    pass


class ShadowQualificationCase(StrictModel):
    group_id: str = Field(min_length=3, max_length=120)
    split: Literal["development", "holdout"]
    task: IncidentTask
    evidence: list[Evidence] = Field(min_length=1, max_length=100)
    expected_code: HypothesisCode

    @model_validator(mode="after")
    def evidence_is_scoped(self) -> "ShadowQualificationCase":
        if any(
            item.incident_id != self.task.incident_id or item.service != self.task.service
            for item in self.evidence
        ):
            raise ValueError("qualification evidence escaped its incident scope")
        ids = [item.evidence_id for item in self.evidence]
        if len(ids) != len(set(ids)):
            raise ValueError("qualification case has duplicate evidence identities")
        return self


class ShadowQualificationDataset(StrictModel):
    schema_version: Literal["0.1"]
    cases: list[ShadowQualificationCase] = Field(min_length=2, max_length=1000)

    @model_validator(mode="after")
    def independent_incident_groups(self) -> "ShadowQualificationDataset":
        ids = [item.task.incident_id for item in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("qualification incident IDs must be unique")
        splits_by_group: dict[str, set[str]] = defaultdict(set)
        for item in self.cases:
            splits_by_group[item.group_id].add(item.split)
        if any(len(splits) != 1 for splits in splits_by_group.values()):
            raise ValueError("qualification group crosses development and holdout")
        if {item.split for item in self.cases} != {"development", "holdout"}:
            raise ValueError("qualification dataset requires both splits")
        return self


def load_shadow_qualification_dataset(
    path: str | Path,
) -> tuple[ShadowQualificationDataset, str]:
    source = Path(path)
    if source.is_symlink() or source.suffix.casefold() != ".json":
        raise ShadowQualificationError("qualification dataset must be a regular JSON file")
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise ShadowQualificationError("unable to read qualification dataset") from exc
    if len(raw) > MAX_SCANNABLE_BYTES:
        raise ShadowQualificationError("qualification dataset exceeds size limit")
    if scan_content(source.name, raw):
        raise ShadowQualificationError("qualification dataset failed privacy scan")
    try:
        dataset = ShadowQualificationDataset.model_validate_json(raw)
    except (ValidationError, ValueError) as exc:
        raise ShadowQualificationError("invalid qualification dataset") from exc
    canonical = json.dumps(
        dataset.model_dump(mode="json"), ensure_ascii=False,
        sort_keys=True, separators=(",", ":"),
    )
    return dataset, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_DATASET_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")
_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ShadowQualificationRegistry:
    """SQLite lifecycle: sealed -> reserved -> consumed, with no auto-unreserve."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS shadow_qualification_datasets ("
                "dataset_id TEXT PRIMARY KEY, relative_path TEXT UNIQUE NOT NULL, "
                "dataset_sha256 TEXT UNIQUE NOT NULL, approval_ref TEXT NOT NULL, "
                "development_cases INTEGER NOT NULL, holdout_cases INTEGER NOT NULL, "
                "state TEXT NOT NULL CHECK (state IN ('sealed','reserved','consumed')), "
                "reservation_id TEXT, model_name TEXT, model_digest TEXT, "
                "prompt_sha256 TEXT, runs INTEGER, decision TEXT, "
                "summary_json TEXT, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _dataset_path(self, relative_path: str) -> Path:
        root = self.db_path.resolve().parent
        unresolved = root / relative_path
        candidate = unresolved.resolve()
        if not candidate.is_relative_to(root) or unresolved.is_symlink():
            raise ShadowQualificationError("registered dataset escapes registry directory")
        return candidate

    def _validated_registration(self, row: tuple) -> tuple[ShadowQualificationDataset, str]:
        dataset, digest = load_shadow_qualification_dataset(self._dataset_path(row[1]))
        if digest != row[2]:
            raise ShadowQualificationError("registered qualification dataset drifted")
        if (
            sum(case.split == "development" for case in dataset.cases) != row[4]
            or sum(case.split == "holdout" for case in dataset.cases) != row[5]
        ):
            raise ShadowQualificationError("registered qualification split drifted")
        return dataset, digest

    def list_datasets(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT dataset_id, relative_path, dataset_sha256, approval_ref, "
                "development_cases, holdout_cases, state, reservation_id, decision "
                "FROM shadow_qualification_datasets ORDER BY dataset_id"
            ).fetchall()
        for row in rows:
            self._validated_registration(row)
        return [
            {
                "dataset_id": row[0], "dataset_sha256": row[2],
                "development_cases": row[4], "holdout_cases": row[5],
                "state": row[6], "reservation_id": row[7], "decision": row[8],
            }
            for row in rows
        ]

    def register(
        self, *, dataset_id: str, dataset_path: str | Path, approval_ref: str
    ) -> dict[str, object]:
        if not _DATASET_ID.fullmatch(dataset_id):
            raise ShadowQualificationError("invalid qualification dataset ID")
        if not _DATASET_ID.fullmatch(approval_ref):
            raise ShadowQualificationError("approval_ref must be an external review ID")
        candidate = Path(dataset_path)
        if candidate.is_symlink():
            raise ShadowQualificationError("qualification dataset cannot be a symlink")
        root = self.db_path.resolve().parent
        resolved = candidate.resolve()
        if not resolved.is_relative_to(root):
            raise ShadowQualificationError("qualification dataset must be beside registry")
        relative = resolved.relative_to(root).as_posix()
        dataset, digest = load_shadow_qualification_dataset(resolved)
        new_inputs = {
            (case.task.service.casefold(), tuple(text.casefold() for text in case.task.symptoms))
            for case in dataset.cases
        }
        new_holdout = {
            (case.task.service.casefold(), tuple(text.casefold() for text in case.task.symptoms))
            for case in dataset.cases if case.split == "holdout"
        }
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT dataset_id, relative_path, dataset_sha256, approval_ref, "
                "development_cases, holdout_cases FROM shadow_qualification_datasets"
            ).fetchall()
            for row in prior:
                earlier, _ = self._validated_registration(row)
                earlier_inputs = {
                    (case.task.service.casefold(),
                     tuple(text.casefold() for text in case.task.symptoms))
                    for case in earlier.cases
                }
                earlier_holdout = {
                    (case.task.service.casefold(),
                     tuple(text.casefold() for text in case.task.symptoms))
                    for case in earlier.cases if case.split == "holdout"
                }
                if new_holdout & earlier_inputs or earlier_holdout & new_inputs:
                    raise ShadowQualificationError("qualification holdout overlaps prior data")
            try:
                connection.execute(
                    "INSERT INTO shadow_qualification_datasets "
                    "(dataset_id, relative_path, dataset_sha256, approval_ref, "
                    "development_cases, holdout_cases, state) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'sealed')",
                    (
                        dataset_id, relative, digest, approval_ref,
                        sum(case.split == "development" for case in dataset.cases),
                        sum(case.split == "holdout" for case in dataset.cases),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ShadowQualificationError("qualification dataset already registered") from exc
        return {"dataset_id": dataset_id, "dataset_sha256": digest, "state": "sealed"}

    def reserve(
        self, *, dataset_id: str, model_name: str, model_digest: str,
        runs: int,
    ) -> tuple[str, ShadowQualificationDataset, str]:
        if not _MODEL_NAME.fullmatch(model_name) or not _SHA256.fullmatch(model_digest):
            raise ShadowQualificationError("qualification requires resolved model identity")
        if not 2 <= runs <= 10:
            raise ShadowQualificationError("qualification runs must be between 2 and 10")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT dataset_id, relative_path, dataset_sha256, approval_ref, "
                "development_cases, holdout_cases, state "
                "FROM shadow_qualification_datasets WHERE dataset_id = ?",
                (dataset_id,),
            ).fetchone()
            if row is None:
                raise ShadowQualificationError("qualification dataset is not registered")
            dataset, digest = self._validated_registration(row)
            if row[6] != "sealed":
                raise ShadowQualificationError("holdout is not sealed; do not reuse it")
            reservation_id = f"shadow-{uuid4().hex}"
            connection.execute(
                "UPDATE shadow_qualification_datasets SET state = 'reserved', "
                "reservation_id = ?, model_name = ?, model_digest = ?, "
                "prompt_sha256 = ?, runs = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE dataset_id = ? AND state = 'sealed'",
                (
                    reservation_id, model_name, model_digest,
                    SPECIALIST_PROMPT_SHA256, runs, dataset_id,
                ),
            )
        return reservation_id, dataset, digest

    def consume(
        self, *, dataset_id: str, reservation_id: str, decision: Literal["accepted", "rejected"],
        summary: dict[str, object],
    ) -> None:
        payload = json.dumps(summary, ensure_ascii=False, sort_keys=True)
        if len(payload.encode("utf-8")) > MAX_SCANNABLE_BYTES or scan_content(
            "qualification-summary.json", payload.encode("utf-8")
        ):
            raise ShadowQualificationError("qualification summary failed privacy boundary")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT dataset_id, relative_path, dataset_sha256, approval_ref, "
                "development_cases, holdout_cases, state, reservation_id, model_name, "
                "model_digest, prompt_sha256, runs "
                "FROM shadow_qualification_datasets WHERE dataset_id = ?",
                (dataset_id,),
            ).fetchone()
            if row is None or row[6] != "reserved" or row[7] != reservation_id:
                raise ShadowQualificationError("qualification reservation identity mismatch")
            self._validated_registration(row)
            if (
                summary.get("reservation_id") != reservation_id
                or summary.get("dataset_sha256") != row[2]
                or summary.get("model_name") != row[8]
                or summary.get("model_digest") != row[9]
                or summary.get("prompt_sha256") != row[10]
                or summary.get("runs") != row[11]
                or summary.get("qualification_decision") != decision
                or summary.get("production_qualified") is not False
                or (decision == "accepted" and summary.get("gates_passed") is not True)
            ):
                raise ShadowQualificationError("qualification report does not match reservation")
            changed = connection.execute(
                "UPDATE shadow_qualification_datasets SET state = 'consumed', "
                "decision = ?, summary_json = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE dataset_id = ? AND state = 'reserved' AND reservation_id = ?",
                (decision, payload, dataset_id, reservation_id),
            ).rowcount
        if changed != 1:
            raise ShadowQualificationError("qualification reservation identity mismatch")


def _report_path(registry: ShadowQualificationRegistry, report_path: str | Path) -> Path:
    candidate = Path(report_path)
    root = registry.db_path.resolve().parent
    resolved = candidate.resolve()
    if (
        not resolved.is_relative_to(root)
        or resolved.suffix.casefold() != ".json"
        or candidate.is_symlink()
        or candidate.exists()
        or not candidate.parent.is_dir()
    ):
        raise ShadowQualificationError(
            "qualification report must be a new JSON file inside registry directory"
        )
    return resolved


def _write_report(path: Path, report: dict[str, object], *, new: bool) -> None:
    raw = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    if len(raw) > MAX_SCANNABLE_BYTES or scan_content(path.name, raw):
        raise ShadowQualificationError("qualification report failed privacy boundary")
    if new:
        try:
            with path.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise ShadowQualificationError("unable to create qualification report") from exc
        return
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise ShadowQualificationError("unable to update qualification report") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _proposer_identity(proposer: HypothesisProposer, *, refresh: bool) -> tuple[str, str]:
    resolver = getattr(proposer, "refresh_model_identity", None) if refresh else None
    if not callable(resolver):
        resolver = getattr(proposer, "model_identity", None)
    if not callable(resolver):
        raise ShadowQualificationError("qualification proposer lacks model identity")
    try:
        name, digest = resolver()
    except Exception as exc:
        raise ShadowQualificationError("unable to resolve qualification model") from exc
    if not isinstance(name, str) or not _MODEL_NAME.fullmatch(name):
        raise ShadowQualificationError("qualification model name is invalid")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ShadowQualificationError("qualification requires resolved model digest")
    return name, digest


def run_shadow_qualification_campaign(
    *,
    registry_path: str | Path,
    dataset_id: str,
    report_path: str | Path,
    proposer: HypothesisProposer,
    runs: int = 3,
) -> dict[str, object]:
    """Reserve a sealed cohort, run fresh bounded shadow calls, then consume it once."""
    registry = ShadowQualificationRegistry(registry_path)
    destination = _report_path(registry, report_path)
    entries = registry.list_datasets()
    selected = next((item for item in entries if item["dataset_id"] == dataset_id), None)
    if selected is None:
        raise ShadowQualificationError("qualification dataset is not registered")
    if selected["state"] != "sealed":
        raise ShadowQualificationError("holdout is not sealed; do not reuse it")
    if selected["holdout_cases"] < 20:
        raise ShadowQualificationError("qualification requires at least 20 holdout incidents")
    model_name, model_digest = _proposer_identity(proposer, refresh=True)
    reservation_id, dataset, dataset_sha256 = registry.reserve(
        dataset_id=dataset_id, model_name=model_name,
        model_digest=model_digest, runs=runs,
    )
    report: dict[str, object] = {
        "schema_version": "0.1",
        "evaluation_type": "specialist_shadow_holdout_campaign",
        "dataset_id": dataset_id,
        "dataset_sha256": dataset_sha256,
        "reservation_id": reservation_id,
        "model_name": model_name,
        "model_digest": model_digest,
        "prompt_id": SPECIALIST_PROMPT_ID,
        "prompt_sha256": SPECIALIST_PROMPT_SHA256,
        "runs": runs,
        "holdout_incidents": selected["holdout_cases"],
        "state": "reserved",
        "production_qualified": False,
    }
    _write_report(destination, report, new=True)

    holdout = [case for case in dataset.cases if case.split == "holdout"]
    run_summaries: list[dict[str, object]] = []
    predictions: list[dict[tuple[str, str], str | None]] = []
    try:
        with tempfile.TemporaryDirectory(
            prefix="shadow-campaign-", dir=registry.db_path.parent,
            ignore_cleanup_errors=True,
        ) as temporary:
            for run_index in range(runs):
                current_name, current_digest = _proposer_identity(proposer, refresh=True)
                if (current_name, current_digest) != (model_name, model_digest):
                    raise ShadowQualificationError("model identity drifted during campaign")
                records_by_key: dict[tuple[str, str], str | None] = {}
                reasons: Counter[str] = Counter()
                by_source: dict[str, Counter[str]] = defaultdict(Counter)
                observations = accepted = model_correct = baseline_correct = 0
                correct_verdicts = prompt_tokens = completion_tokens = 0
                durations: list[float] = []
                tokens_per_observation: list[int] = []
                for case_index, case in enumerate(holdout):
                    from sentinelops.service import create_service

                    db_path = Path(temporary) / f"run-{run_index}-case-{case_index}.db"
                    service = create_service(
                        db_path=db_path,
                        evidence_tool=FixtureEvidenceTool(case.evidence),
                        orchestration_mode="multi", policy_mode="heuristic",
                        shadow_mode="ollama", shadow_proposer=proposer,
                    )
                    try:
                        result = service.investigate(case.task)
                    finally:
                        service.close()
                    expected = case.expected_code
                    correct_verdicts += (
                        result.report.selected_code or "unknown"
                    ) == expected and (
                        expected != "unknown"
                        or result.report.status == IncidentStatus.NEEDS_HUMAN
                    )
                    shadow_records = ShadowJournal(db_path).list_for_trace(result.trace_id)
                    if not shadow_records:
                        raise ShadowQualificationError(
                            "qualification incident produced no shadow observations"
                        )
                    for record in shadow_records:
                        if (
                            record.model_name != model_name
                            or record.model_digest != model_digest
                            or record.prompt_id != SPECIALIST_PROMPT_ID
                            or record.prompt_sha256 != SPECIALIST_PROMPT_SHA256
                        ):
                            raise ShadowQualificationError(
                                "shadow identity does not match qualification reservation"
                            )
                        key = (case.task.incident_id, record.source)
                        if key in records_by_key:
                            raise ShadowQualificationError("duplicate role observation")
                        records_by_key[key] = record.proposed_code
                        reasons[record.reason_code] += 1
                        by_source[record.source]["observations"] += 1
                        observations += 1
                        accepted += record.reason_code == "accepted"
                        model_correct += record.proposed_code == expected
                        baseline_correct += (record.baseline_code or "unknown") == expected
                        by_source[record.source]["accepted"] += record.reason_code == "accepted"
                        by_source[record.source]["model_correct"] += (
                            record.proposed_code == expected
                        )
                        by_source[record.source]["baseline_correct"] += (
                            (record.baseline_code or "unknown") == expected
                        )
                        prompt_tokens += record.prompt_tokens or 0
                        completion_tokens += record.completion_tokens or 0
                        durations.append(record.duration_ms)
                        if record.prompt_tokens is None or record.completion_tokens is None:
                            reasons["missing_token_usage"] += 1
                        else:
                            tokens_per_observation.append(
                                record.prompt_tokens + record.completion_tokens
                            )
                durations.sort()
                p95 = durations[(95 * len(durations) + 99) // 100 - 1]
                run_summaries.append({
                    "run": run_index + 1,
                    "holdout_incidents": len(holdout),
                    "observations": observations,
                    "acceptance_rate": round(accepted / observations, 4),
                    "model_top1_all_attempts": round(model_correct / observations, 4),
                    "baseline_top1": round(baseline_correct / observations, 4),
                    "deterministic_verdict_accuracy": round(
                        correct_verdicts / len(holdout), 4
                    ),
                    "p95_shadow_call_ms": p95,
                    "average_tokens_per_observation": round(
                        (prompt_tokens + completion_tokens) / observations, 2
                    ),
                    "max_tokens_per_observation": max(tokens_per_observation, default=None),
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "reason_counts": dict(sorted(reasons.items())),
                    "by_source": {
                        source: {
                            "observations": counts["observations"],
                            "acceptance_rate": round(
                                counts["accepted"] / counts["observations"], 4
                            ),
                            "model_top1_all_attempts": round(
                                counts["model_correct"] / counts["observations"], 4
                            ),
                            "baseline_top1": round(
                                counts["baseline_correct"] / counts["observations"], 4
                            ),
                        }
                        for source, counts in sorted(by_source.items())
                    },
                })
                predictions.append(records_by_key)
                report["completed_runs"] = run_index + 1
                report["run_summaries"] = run_summaries
                report["state"] = "running"
                _write_report(destination, report, new=False)
        final_name, final_digest = _proposer_identity(proposer, refresh=True)
        if (final_name, final_digest) != (model_name, model_digest):
            raise ShadowQualificationError("model identity drifted after campaign")
        keys = set(predictions[0])
        stable = all(set(item) == keys for item in predictions)
        if stable:
            stable_count = sum(
                len({item[key] for item in predictions}) == 1 for key in keys
            )
            stability_rate = round(stable_count / len(keys), 4)
        else:
            stability_rate = 0.0
        gates_passed = (
            stable and stability_rate == 1.0
            and all(
                item["acceptance_rate"] == 1.0
                and item["model_top1_all_attempts"] == 1.0
                and item["deterministic_verdict_accuracy"] == 1.0
                and item["p95_shadow_call_ms"] <= 8_000
                and item["max_tokens_per_observation"] is not None
                and item["max_tokens_per_observation"] <= 2_048
                and not item["reason_counts"].get("missing_token_usage")
                and not item["reason_counts"].get("unsupported_evidence_reference")
                for item in run_summaries
            )
        )
        decision = "accepted" if gates_passed else "rejected"
        report.update({
            "state": "evaluated_pending_finalization",
            "run_summaries": run_summaries,
            "prediction_stability_rate": stability_rate,
            "gates_passed": gates_passed,
            "qualification_decision": decision,
            "limitations": (
                "Acceptance is an offline technical gate only. Human approval and "
                "independent provenance cannot be proven by this program; no production "
                "reviewer authority is granted."
            ),
        })
        _write_report(destination, report, new=False)
        registry.consume(
            dataset_id=dataset_id, reservation_id=reservation_id,
            decision=decision, summary=report,
        )
        report["state"] = "consumed"
        try:
            _write_report(destination, report, new=False)
        except ShadowQualificationError as exc:
            raise ShadowQualificationError(
                "qualification registry consumed but final report update failed; "
                "inspect the preliminary report and do not rerun"
            ) from exc
        return report
    except Exception as exc:
        if report.get("state") != "consumed":
            report["state"] = "interrupted_review_required"
            report["error_code"] = "campaign_interrupted"
            try:
                _write_report(destination, report, new=False)
            except ShadowQualificationError:
                pass
        if isinstance(exc, ShadowQualificationError):
            raise
        raise ShadowQualificationError(
            "qualification campaign interrupted; inspect reserved state and report"
        ) from exc
