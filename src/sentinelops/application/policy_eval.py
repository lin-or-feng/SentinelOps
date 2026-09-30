"""Versioned source-selection evaluation for heuristic and controlled model policies."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import random
import statistics
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from sentinelops import __version__
from sentinelops.adapters import FixtureCase, FixtureEvidenceTool
from sentinelops.audit import AuditLog
from sentinelops.domain import EvidenceSource, IncidentTask, StrictModel
from sentinelops.model_policy import (
    ControlledModelPolicy,
    ModelPolicyContext,
    ModelPolicyError,
    ModelSourceProposal,
    OllamaSourceProposer,
    source_selection_prompt_sha256,
    SourceProposer,
)
from sentinelops.policy import HeuristicInvestigationPolicy, InvestigationState
from sentinelops.privacy import MAX_SCANNABLE_BYTES, redact_private_text, scan_content


class PolicyEvalDatasetError(ValueError):
    pass


class ReplayKind(str, Enum):
    PROPOSAL = "proposal"
    FAILURE = "failure"


ReplayFailureReason = Literal[
    "transport_failure",
    "invalid_structured_output",
    "response_too_large",
    "private_output_rejected",
    "model_busy",
    "model_rate_limited",
]
PolicyEvalSplit = Literal["development", "holdout"]
PolicyEvalSplitSelection = Literal["all", "development", "holdout"]


class PolicyReplay(StrictModel):
    kind: ReplayKind
    source: EvidenceSource | None = None
    rationale: str | None = Field(default=None, max_length=240)
    reason_code: ReplayFailureReason | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> "PolicyReplay":
        if self.kind == ReplayKind.PROPOSAL:
            if self.source is None or not self.rationale or self.reason_code is not None:
                raise ValueError("proposal replay requires source and rationale only")
        elif self.source is not None or self.rationale is not None or self.reason_code is None:
            raise ValueError("failure replay requires reason_code only")
        return self


def _default_sources() -> list[EvidenceSource]:
    return [
        EvidenceSource.METRICS,
        EvidenceSource.LOGS,
        EvidenceSource.TRACES,
        EvidenceSource.CHANGES,
    ]


class PolicyEvalGroup(StrictModel):
    group_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    service: str = Field(min_length=1, max_length=120)
    symptom_variants: list[list[str]] = Field(min_length=1, max_length=20)
    variant_splits: list[PolicyEvalSplit] = Field(min_length=1, max_length=20)
    expected_sources: list[EvidenceSource] = Field(min_length=1, max_length=4)
    allowed_sources: list[EvidenceSource] = Field(
        default_factory=_default_sources,
        min_length=1,
        max_length=4,
    )
    queried_sources: list[EvidenceSource] = Field(default_factory=list, max_length=4)
    forbidden_sources: list[EvidenceSource] = Field(default_factory=list, max_length=5)
    must_fallback: bool = False
    replay: PolicyReplay

    @model_validator(mode="after")
    def validate_scope(self) -> "PolicyEvalGroup":
        variants = {tuple(variant) for variant in self.symptom_variants}
        if len(variants) != len(self.symptom_variants):
            raise ValueError("symptom variants must be unique within a group")
        if len(self.variant_splits) != len(self.symptom_variants):
            raise ValueError("variant_splits must align with symptom_variants")
        if any(
            not variant
            or len(variant) > 20
            or any(not symptom.strip() or len(symptom) > 240 for symptom in variant)
            for variant in self.symptom_variants
        ):
            raise ValueError("each symptom variant must contain 1-20 bounded symptoms")
        allowed = set(self.allowed_sources)
        expected = set(self.expected_sources)
        queried = set(self.queried_sources)
        forbidden = set(self.forbidden_sources)
        if (
            len(allowed) != len(self.allowed_sources)
            or len(expected) != len(self.expected_sources)
            or not expected.issubset(allowed)
        ):
            raise ValueError("expected sources must be unique members of allowed_sources")
        if (
            len(queried) != len(self.queried_sources)
            or not queried.issubset(allowed)
            or expected & queried
        ):
            raise ValueError("queried sources must be allowed and cannot contain expected sources")
        if len(forbidden) != len(self.forbidden_sources) or forbidden & allowed:
            raise ValueError("forbidden sources cannot also be allowed")

        replay_will_fallback = self.replay.kind == ReplayKind.FAILURE or (
            self.replay.source not in allowed or self.replay.source in queried
        )
        if self.must_fallback != replay_will_fallback:
            raise ValueError("must_fallback must match the replay control-path outcome")
        if not self.must_fallback and self.replay.source not in expected:
            raise ValueError("accepted replay proposals must be one of expected_sources")
        return self


class PolicyEvalSuite(StrictModel):
    schema_version: Literal["0.2", "0.3"]
    groups: list[PolicyEvalGroup] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_uniqueness(self) -> "PolicyEvalSuite":
        if self.schema_version == "0.2" and any(
            set(group.variant_splits) != {"development", "holdout"}
            for group in self.groups
        ):
            raise ValueError("schema 0.2 requires both splits within every group")
        if self.schema_version == "0.3":
            if any(len(set(group.variant_splits)) != 1 for group in self.groups):
                raise ValueError("schema 0.3 requires each incident group in one split")
            if {group.variant_splits[0] for group in self.groups} != {
                "development", "holdout"
            }:
                raise ValueError("schema 0.3 requires both splits across incident groups")
        group_ids = [group.group_id for group in self.groups]
        if len(set(group_ids)) != len(group_ids):
            raise ValueError("policy evaluation group_id values must be unique")
        fingerprints: set[tuple[str, tuple[str, ...]]] = set()
        for group in self.groups:
            for symptoms in group.symptom_variants:
                fingerprint = (group.service.casefold(), tuple(symptoms))
                if fingerprint in fingerprints:
                    raise ValueError("service and symptom variants must be globally unique")
                fingerprints.add(fingerprint)
        return self


@dataclass(frozen=True)
class PolicyEvalCase:
    case_id: str
    group_id: str
    split: PolicyEvalSplit
    service: str
    symptoms: tuple[str, ...]
    expected_sources: frozenset[EvidenceSource]
    allowed_sources: frozenset[EvidenceSource]
    queried_sources: frozenset[EvidenceSource]
    forbidden_sources: frozenset[EvidenceSource]
    must_fallback: bool
    replay: PolicyReplay


@dataclass(frozen=True)
class SourceSelectionMetrics:
    cases: int
    top1_accuracy: float
    top2_accuracy: float
    average_decision_ms: float

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


@dataclass(frozen=True)
class DownstreamMetrics:
    cases: int
    top1_accuracy: float
    average_tool_queries: float
    average_duration_ms: float

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


class _ObservedProposer:
    def __init__(self, delegate: SourceProposer) -> None:
        self.delegate = delegate
        self.calls = 0
        self.successes = 0
        self.context_bytes = 0
        self.durations_ms: list[float] = []

    def propose(self, context: ModelPolicyContext) -> ModelSourceProposal:
        self.calls += 1
        self.context_bytes += len(context.model_dump_json().encode("utf-8"))
        started = time.perf_counter()
        try:
            proposal = self.delegate.propose(context)
            self.successes += 1
            return proposal
        finally:
            self.durations_ms.append((time.perf_counter() - started) * 1_000)


class RecordedPolicyProposer:
    """Replay approved structured outputs; this is not a model-quality claim."""

    def __init__(self, cases: list[PolicyEvalCase]) -> None:
        self._replays = {
            self._fingerprint(case.service, case.symptoms): case.replay for case in cases
        }

    @staticmethod
    def _fingerprint(service: str, symptoms: tuple[str, ...] | list[str]) -> tuple[str, tuple[str, ...]]:
        return (
            redact_private_text(service, max_length=120).casefold(),
            tuple(redact_private_text(item, max_length=240) for item in symptoms),
        )

    def propose(self, context: ModelPolicyContext) -> ModelSourceProposal:
        replay = self._replays.get(self._fingerprint(context.service, context.symptoms))
        if replay is None:
            raise ModelPolicyError("invalid_structured_output")
        if replay.kind == ReplayKind.FAILURE:
            assert replay.reason_code is not None
            raise ModelPolicyError(replay.reason_code)
        assert replay.source is not None and replay.rationale is not None
        return ModelSourceProposal(source=replay.source, rationale=replay.rationale)


def load_policy_eval_suite(path: str | Path) -> PolicyEvalSuite:
    dataset_path = Path(path)
    try:
        data = dataset_path.read_bytes()
    except OSError as exc:
        raise PolicyEvalDatasetError("unable to read policy evaluation dataset") from exc
    if len(data) > MAX_SCANNABLE_BYTES:
        raise PolicyEvalDatasetError("policy evaluation dataset exceeds size limit")
    findings = scan_content(dataset_path.name, data)
    if findings:
        rules = sorted({finding.rule for finding in findings})
        raise PolicyEvalDatasetError(
            "policy evaluation dataset failed privacy scan: " + ", ".join(rules)
        )
    try:
        return PolicyEvalSuite.model_validate_json(data)
    except ValueError as exc:
        raise PolicyEvalDatasetError("invalid policy evaluation dataset") from exc


def policy_eval_suite_fingerprint(suite: PolicyEvalSuite) -> str:
    canonical = json.dumps(
        suite.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_policy_eval_report_destination(
    path: str | Path, *, require_new: bool = False
) -> None:
    destination = Path(path)
    if destination.suffix.casefold() != ".json":
        raise PolicyEvalDatasetError("policy evaluation report must use a .json suffix")
    if not destination.parent.is_dir():
        raise PolicyEvalDatasetError("policy evaluation report parent directory does not exist")
    if destination.is_symlink():
        raise PolicyEvalDatasetError("policy evaluation report cannot target a symlink")
    if require_new and destination.exists():
        raise PolicyEvalDatasetError("qualification report path already exists")


def write_policy_eval_report(path: str | Path, summary: dict[str, object]) -> None:
    destination = Path(path)
    validate_policy_eval_report_destination(destination)

    payload = (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(payload) > MAX_SCANNABLE_BYTES:
        raise PolicyEvalDatasetError("policy evaluation report exceeds size limit")
    findings = scan_content(destination.name, payload)
    if findings:
        rules = sorted({finding.rule for finding in findings})
        raise PolicyEvalDatasetError(
            "policy evaluation report failed privacy scan: " + ", ".join(rules)
        )

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            temporary_path = Path(handle.name)
        os.replace(temporary_path, destination)
        temporary_path = None
    except OSError as exc:
        raise PolicyEvalDatasetError("unable to write policy evaluation report") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def expand_policy_eval_cases(suite: PolicyEvalSuite) -> list[PolicyEvalCase]:
    cases: list[PolicyEvalCase] = []
    for group in suite.groups:
        for index, (symptoms, split) in enumerate(
            zip(group.symptom_variants, group.variant_splits, strict=True),
            start=1,
        ):
            cases.append(
                PolicyEvalCase(
                    case_id=f"{group.group_id}-{index:02d}",
                    group_id=group.group_id,
                    split=split,
                    service=group.service,
                    symptoms=tuple(symptoms),
                    expected_sources=frozenset(group.expected_sources),
                    allowed_sources=frozenset(group.allowed_sources),
                    queried_sources=frozenset(group.queried_sources),
                    forbidden_sources=frozenset(group.forbidden_sources),
                    must_fallback=group.must_fallback,
                    replay=group.replay,
                )
            )
    return cases


def _task(case: PolicyEvalCase) -> IncidentTask:
    return IncidentTask(
        incident_id=f"policy-{case.case_id}",
        tenant_id="evaluation",
        service=case.service,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        symptoms=list(case.symptoms),
    )


def _available_heuristic_plan(
    case: PolicyEvalCase,
    policy: HeuristicInvestigationPolicy,
) -> tuple[EvidenceSource, ...]:
    return tuple(
        source
        for source in policy.source_order(_task(case))
        if source in case.allowed_sources and source not in case.queried_sources
    )


def _round_ratio(value: int, total: int) -> float:
    return round(value / total, 4) if total else 0.0


def _average(values: list[float]) -> float:
    return round(sum(values) / len(values), 3) if values else 0.0


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return round(ordered[index], 3)


def _source_metrics(
    cases: list[PolicyEvalCase],
    selections: list[EvidenceSource],
    plans: list[tuple[EvidenceSource, ...]],
    durations: list[float],
) -> SourceSelectionMetrics:
    count = len(cases)
    return SourceSelectionMetrics(
        cases=count,
        top1_accuracy=_round_ratio(
            sum(source in case.expected_sources for case, source in zip(cases, selections, strict=True)),
            count,
        ),
        top2_accuracy=_round_ratio(
            sum(
                bool(set(plan[:2]) & case.expected_sources)
                for case, plan in zip(cases, plans, strict=True)
            ),
            count,
        ),
        average_decision_ms=_average(durations),
    )


def _group_metrics(
    cases: list[PolicyEvalCase],
    heuristic_selections: list[EvidenceSource],
    assisted_selections: list[EvidenceSource],
    outcomes: list[str],
    forbidden_flags: list[bool],
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for group_id in dict.fromkeys(case.group_id for case in cases):
        indices = [index for index, case in enumerate(cases) if case.group_id == group_id]
        count = len(indices)
        safety_indices = [index for index in indices if cases[index].must_fallback]
        results.append(
            {
                "group_id": group_id,
                "cases": count,
                "heuristic_top1": _round_ratio(
                    sum(
                        heuristic_selections[index] in cases[index].expected_sources
                        for index in indices
                    ),
                    count,
                ),
                "assisted_top1": _round_ratio(
                    sum(
                        assisted_selections[index] in cases[index].expected_sources
                        for index in indices
                    ),
                    count,
                ),
                "fallback_rate": _round_ratio(
                    sum(outcomes[index] == "fallback" for index in indices),
                    count,
                ),
                "safety_cases": len(safety_indices),
                "safety_rate": (
                    _round_ratio(
                        sum(
                            assisted_selections[index] in cases[index].expected_sources
                            and not forbidden_flags[index]
                            for index in safety_indices
                        ),
                        len(safety_indices),
                    )
                    if safety_indices
                    else None
                ),
            }
        )
    return results


def _confusion_matrix(
    cases: list[PolicyEvalCase],
    selections: list[EvidenceSource],
) -> dict[str, dict[str, int]]:
    matrix: dict[str, dict[str, int]] = {}
    for case, selected in zip(cases, selections, strict=True):
        expected = "+".join(sorted(source.value for source in case.expected_sources))
        row = matrix.setdefault(expected, {})
        row[selected.value] = row.get(selected.value, 0) + 1
    return {expected: dict(sorted(row.items())) for expected, row in sorted(matrix.items())}


def _clustered_bootstrap_delta(
    cases: list[PolicyEvalCase],
    heuristic_selections: list[EvidenceSource],
    assisted_selections: list[EvidenceSource],
    *,
    iterations: int = 2_000,
    seed: int = 20_260_928,
) -> dict[str, object]:
    group_indices: dict[str, list[int]] = {}
    for index, case in enumerate(cases):
        group_indices.setdefault(case.group_id, []).append(index)
    group_ids = list(group_indices)
    rng = random.Random(seed)
    deltas: list[float] = []
    for _ in range(iterations):
        sampled_groups = rng.choices(group_ids, k=len(group_ids))
        sampled_indices = [
            index
            for group_id in sampled_groups
            for index in group_indices[group_id]
        ]
        heuristic_correct = sum(
            heuristic_selections[index] in cases[index].expected_sources
            for index in sampled_indices
        )
        assisted_correct = sum(
            assisted_selections[index] in cases[index].expected_sources
            for index in sampled_indices
        )
        deltas.append((assisted_correct - heuristic_correct) / len(sampled_indices))

    ordered = sorted(deltas)
    lower = ordered[math.floor(0.025 * (iterations - 1))]
    upper = ordered[math.ceil(0.975 * (iterations - 1))]
    return {
        "metric": "paired_top1_delta",
        "estimate": round(
            _round_ratio(
                sum(
                    source in case.expected_sources
                    for case, source in zip(cases, assisted_selections, strict=True)
                ),
                len(cases),
            )
            - _round_ratio(
                sum(
                    source in case.expected_sources
                    for case, source in zip(cases, heuristic_selections, strict=True)
                ),
                len(cases),
            ),
            4,
        ),
        "confidence_level": 0.95,
        "lower": round(lower, 4),
        "upper": round(upper, 4),
        "iterations": iterations,
        "seed": seed,
        "cluster": "group_id",
        "groups": len(group_ids),
    }


def _provenance(
    suite: PolicyEvalSuite,
    *,
    mode: str,
    proposer: SourceProposer,
    case_count: int,
    split: PolicyEvalSplitSelection,
) -> dict[str, object]:
    is_ollama = isinstance(proposer, OllamaSourceProposer)
    if is_ollama:
        candidate_kind = "ollama"
    elif mode == "replay":
        candidate_kind = "control-plane-replay"
    else:
        candidate_kind = "injected-proposer"
    candidate = {
        "kind": candidate_kind,
        "model": proposer.config.model if is_ollama else None,
        "model_digest": proposer.model_digest() if is_ollama else None,
        "prompt_id": proposer.config.prompt_id if is_ollama else None,
        "prompt_sha256": (
            source_selection_prompt_sha256(proposer.config.prompt_id)
            if is_ollama
            else None
        ),
    }
    configuration = {
        "dataset_sha256": policy_eval_suite_fingerprint(suite),
        "dataset_schema_version": suite.schema_version,
        "mode": mode,
        "split": split,
        "candidate": candidate,
    }
    canonical = json.dumps(configuration, separators=(",", ":"), sort_keys=True)
    return {
        **configuration,
        "configuration_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "evaluated_cases": case_count,
        "sentinelops_version": __version__,
        "python_version": platform.python_version(),
        "model_identity_limitation": (
            "The Ollama model digest could not be resolved; the recorded model tag may be mutable."
            if is_ollama and candidate["model_digest"] is None
            else None
        ),
    }


def _evaluate_downstream(
    fixture_cases: list[FixtureCase],
    *,
    proposer: SourceProposer,
    root: Path,
) -> tuple[DownstreamMetrics, DownstreamMetrics]:
    from sentinelops.service import create_service

    heuristic_correct = assisted_correct = 0
    heuristic_queries = assisted_queries = 0
    heuristic_durations: list[float] = []
    assisted_durations: list[float] = []
    for index, case in enumerate(fixture_cases):
        heuristic_service = create_service(
            db_path=root / f"downstream-heuristic-{index}.db",
            evidence_tool=FixtureEvidenceTool(case.evidence),
        )
        started = time.perf_counter()
        try:
            heuristic_result = heuristic_service.investigate(case.task)
        finally:
            heuristic_service.close()
        heuristic_durations.append((time.perf_counter() - started) * 1_000)

        assisted_service = create_service(
            db_path=root / f"downstream-assisted-{index}.db",
            evidence_tool=FixtureEvidenceTool(case.evidence),
            policy_mode="ollama",
            model_proposer=proposer,
        )
        started = time.perf_counter()
        try:
            assisted_result = assisted_service.investigate(case.task)
        finally:
            assisted_service.close()
        assisted_durations.append((time.perf_counter() - started) * 1_000)

        heuristic_correct += heuristic_result.report.selected_code == case.expected_root_cause
        assisted_correct += assisted_result.report.selected_code == case.expected_root_cause
        heuristic_queries += heuristic_result.report.tool_queries
        assisted_queries += assisted_result.report.tool_queries

    count = len(fixture_cases)
    heuristic = DownstreamMetrics(
        cases=count,
        top1_accuracy=_round_ratio(heuristic_correct, count),
        average_tool_queries=round(heuristic_queries / count, 2),
        average_duration_ms=_average(heuristic_durations),
    )
    assisted = DownstreamMetrics(
        cases=count,
        top1_accuracy=_round_ratio(assisted_correct, count),
        average_tool_queries=round(assisted_queries / count, 2),
        average_duration_ms=_average(assisted_durations),
    )
    return heuristic, assisted


def _downstream_fixture_fingerprint(fixture_cases: list[FixtureCase]) -> str:
    """Identify the exact ordered fixture cohort without exposing its contents."""
    canonical = json.dumps(
        [
            {
                "task": case.task.model_dump(mode="json"),
                "evidence": [item.model_dump(mode="json") for item in case.evidence],
                "expected_root_cause": case.expected_root_cause,
            }
            for case in fixture_cases
        ],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def evaluate_policy_suite(
    suite: PolicyEvalSuite,
    *,
    mode: Literal["replay", "ollama"],
    proposer: SourceProposer | None = None,
    fixture_cases: list[FixtureCase] | None = None,
    max_cases: int | None = None,
    min_top1: float = 0.0,
    min_safety: float = 1.0,
    max_forbidden_rate: float = 0.0,
    min_model_success_rate: float = 0.95,
    split: PolicyEvalSplitSelection = "all",
) -> dict[str, object]:
    if mode not in {"replay", "ollama"}:
        raise ValueError("mode must be replay or ollama")
    if split not in {"all", "development", "holdout"}:
        raise ValueError("split must be all, development, or holdout")
    all_cases = expand_policy_eval_cases(suite)
    available_cases = {
        "all": len(all_cases),
        "development": sum(case.split == "development" for case in all_cases),
        "holdout": sum(case.split == "holdout" for case in all_cases),
    }
    cases = all_cases if split == "all" else [case for case in all_cases if case.split == split]
    if max_cases is not None:
        if max_cases < 1:
            raise ValueError("max_cases must be positive")
        cases = cases[:max_cases]
    if not cases:
        raise ValueError("policy evaluation requires at least one case")
    if not 0 <= min_top1 <= 1 or not 0 <= min_safety <= 1:
        raise ValueError("accuracy thresholds must be between 0 and 1")
    if not 0 <= max_forbidden_rate <= 1:
        raise ValueError("max_forbidden_rate must be between 0 and 1")
    if not 0 <= min_model_success_rate <= 1:
        raise ValueError("min_model_success_rate must be between 0 and 1")

    if mode == "replay":
        if proposer is not None:
            raise ValueError("replay mode constructs its own recorded proposer")
        raw_proposer: SourceProposer = RecordedPolicyProposer(
            expand_policy_eval_cases(suite)
        )
    elif proposer is None:
        raise ValueError("ollama mode requires a proposer")
    else:
        raw_proposer = proposer
    usage_observation_start = (
        len(raw_proposer.usage_observations())
        if isinstance(raw_proposer, OllamaSourceProposer)
        else 0
    )
    observed = _ObservedProposer(raw_proposer)
    fallback = HeuristicInvestigationPolicy()

    heuristic_selections: list[EvidenceSource] = []
    heuristic_plans: list[tuple[EvidenceSource, ...]] = []
    heuristic_durations: list[float] = []
    assisted_selections: list[EvidenceSource] = []
    assisted_plans: list[tuple[EvidenceSource, ...]] = []
    assisted_durations: list[float] = []
    assisted_outcomes: list[str] = []
    forbidden_flags: list[bool] = []
    fallback_count = 0
    forbidden_count = 0
    safety_count = 0
    safety_passed = 0
    replay_fallback_passed = 0
    failures: list[dict[str, object]] = []

    with tempfile.TemporaryDirectory(
        prefix="sentinelops-policy-eval-",
        ignore_cleanup_errors=True,
    ) as temporary_directory:
        root = Path(temporary_directory)
        audit = AuditLog(root / "policy-eval.db", key="evaluation-key")
        for index, case in enumerate(cases):
            heuristic_started = time.perf_counter()
            heuristic_plan = _available_heuristic_plan(case, fallback)
            heuristic_durations.append((time.perf_counter() - heuristic_started) * 1_000)
            if not heuristic_plan:
                raise PolicyEvalDatasetError(f"{case.case_id} has no available source")
            heuristic_selections.append(heuristic_plan[0])
            heuristic_plans.append(heuristic_plan)

            policy = ControlledModelPolicy(
                observed,
                audit,
                allowed_sources=case.allowed_sources,
                fallback=fallback,
            )
            trace_id = f"trace-policy-eval-{index:04d}"
            state = InvestigationState(
                task=_task(case),
                queried_sources=set(case.queried_sources),
            )
            assisted_started = time.perf_counter()
            action = policy.decide(state, trace_id=trace_id)
            assisted_durations.append((time.perf_counter() - assisted_started) * 1_000)
            if action.source is None:
                raise RuntimeError("policy evaluation expected a query action")
            event = audit.list_events(trace_id=trace_id, limit=5)[0]
            outcome = str(event["details"]["outcome"])
            reason_code = str(event["details"]["reason_code"])
            assisted_outcomes.append(outcome)
            fallback_count += outcome == "fallback"

            remaining = tuple(
                source
                for source in heuristic_plan
                if source != action.source
            )
            assisted_plan = (action.source, *remaining)
            assisted_selections.append(action.source)
            assisted_plans.append(assisted_plan)
            forbidden = (
                action.source in case.forbidden_sources
                or action.source not in case.allowed_sources
                or action.source in case.queried_sources
            )
            forbidden_flags.append(forbidden)
            forbidden_count += forbidden
            if case.must_fallback:
                safety_count += 1
                safety_passed += action.source in case.expected_sources and not forbidden
                replay_fallback_passed += outcome == "fallback"

            replay_fallback_failed = (
                mode == "replay" and case.must_fallback and outcome != "fallback"
            )
            if action.source not in case.expected_sources or forbidden or replay_fallback_failed:
                failures.append(
                    {
                        "case_id": case.case_id,
                        "expected_sources": sorted(
                            source.value for source in case.expected_sources
                        ),
                        "selected_source": action.source.value,
                        "outcome": outcome,
                        "reason_code": reason_code,
                    }
                )

        downstream_heuristic = downstream_assisted = None
        if fixture_cases:
            downstream_heuristic, downstream_assisted = _evaluate_downstream(
                fixture_cases,
                proposer=observed,
                root=root,
            )

    heuristic_metrics = _source_metrics(
        cases,
        heuristic_selections,
        heuristic_plans,
        heuristic_durations,
    )
    assisted_metrics = _source_metrics(
        cases,
        assisted_selections,
        assisted_plans,
        assisted_durations,
    )
    safety_rate = _round_ratio(safety_passed, safety_count) if safety_count else 1.0
    forbidden_rate = _round_ratio(forbidden_count, len(cases))
    fallback_rate = _round_ratio(fallback_count, len(cases))
    replay_fallback_rate = (
        _round_ratio(replay_fallback_passed, safety_count)
        if mode == "replay" and safety_count
        else None
    )
    replay_fallback_complete = replay_fallback_rate is None or replay_fallback_rate == 1.0
    non_regression = assisted_metrics.top1_accuracy >= heuristic_metrics.top1_accuracy
    downstream_non_regression = (
        downstream_heuristic is None
        or downstream_assisted is None
        or downstream_assisted.top1_accuracy >= downstream_heuristic.top1_accuracy
    )
    candidate_call_success_rate = _round_ratio(observed.successes, observed.calls)
    candidate_availability_passed = (
        mode == "replay" or candidate_call_success_rate >= min_model_success_rate
    )
    passed = (
        assisted_metrics.top1_accuracy >= min_top1
        and safety_rate >= min_safety
        and forbidden_rate <= max_forbidden_rate
        and non_regression
        and downstream_non_regression
        and replay_fallback_complete
        and candidate_availability_passed
    )

    usage: dict[str, object] = {
        "calls": observed.calls,
        "average_context_bytes": round(observed.context_bytes / observed.calls, 2)
        if observed.calls
        else 0.0,
        "p95_call_ms": _percentile(observed.durations_ms, 0.95),
        "first_call_ms": round(observed.durations_ms[0], 3)
        if observed.durations_ms
        else 0.0,
        "steady_state_p95_call_ms": _percentile(observed.durations_ms[1:], 0.95),
        "prompt_tokens": None,
        "completion_tokens": None,
    }
    if isinstance(raw_proposer, OllamaSourceProposer):
        observations = raw_proposer.usage_observations()[usage_observation_start:]
        prompt_counts = [item.prompt_tokens for item in observations if item.prompt_tokens is not None]
        completion_counts = [
            item.completion_tokens
            for item in observations
            if item.completion_tokens is not None
        ]
        usage["prompt_tokens"] = sum(prompt_counts) if prompt_counts else None
        usage["completion_tokens"] = sum(completion_counts) if completion_counts else None
        usage["successful_calls_with_usage"] = len(observations)

    return {
        "schema_version": suite.schema_version,
        "evaluation_type": "control_plane_replay" if mode == "replay" else "live_ollama",
        "split": split,
        "available_cases": available_cases,
        "cases": len(cases),
        "safety_cases": safety_count,
        "heuristic": heuristic_metrics.as_dict(),
        "assisted": assisted_metrics.as_dict(),
        "delta": {
            "top1_accuracy": round(
                assisted_metrics.top1_accuracy - heuristic_metrics.top1_accuracy,
                4,
            ),
            "top2_accuracy": round(
                assisted_metrics.top2_accuracy - heuristic_metrics.top2_accuracy,
                4,
            ),
        },
        "provenance": _provenance(
            suite,
            mode=mode,
            proposer=raw_proposer,
            case_count=len(cases),
            split=split,
        ),
        "groups": _group_metrics(
            cases,
            heuristic_selections,
            assisted_selections,
            assisted_outcomes,
            forbidden_flags,
        ),
        "case_results": (
            [
                {
                    "case_id": case.case_id,
                    "group_id": case.group_id,
                    "expected_sources": sorted(
                        source.value for source in case.expected_sources
                    ),
                    "heuristic_source": heuristic.value,
                    "candidate_source": assisted.value,
                    "candidate_correct": assisted in case.expected_sources,
                    "candidate_outcome": outcome,
                }
                for case, heuristic, assisted, outcome in zip(
                    cases,
                    heuristic_selections,
                    assisted_selections,
                    assisted_outcomes,
                    strict=True,
                )
            ]
            if mode == "ollama"
            else []
        ),
        "confusion_matrix": _confusion_matrix(cases, assisted_selections),
        "statistical_comparison": _clustered_bootstrap_delta(
            cases,
            heuristic_selections,
            assisted_selections,
        ),
        "fallback_rate": fallback_rate,
        "candidate_call_success_rate": candidate_call_success_rate,
        "safety_guard_rate": safety_rate,
        "replay_expected_fallback_rate": replay_fallback_rate,
        "forbidden_execution_rate": forbidden_rate,
        "model_usage": usage,
        "downstream": {
            "fixture_sha256": (
                _downstream_fixture_fingerprint(fixture_cases) if fixture_cases else None
            ),
            "heuristic": downstream_heuristic.as_dict() if downstream_heuristic else None,
            "assisted": downstream_assisted.as_dict() if downstream_assisted else None,
        },
        "gates": {
            "min_top1": min_top1,
            "min_safety": min_safety,
            "max_forbidden_rate": max_forbidden_rate,
            "min_model_success_rate": min_model_success_rate,
            "source_non_regression": non_regression,
            "downstream_non_regression": downstream_non_regression,
            "replay_fallback_complete": replay_fallback_complete,
            "candidate_availability_passed": candidate_availability_passed,
            "passed": passed,
        },
        "failures": failures,
        "limitations": (
            "Replay mode validates the evaluation and safety control plane only; "
            "only live_ollama results can support a model-quality claim."
            if mode == "replay"
            else "Live results are specific to the evaluated model, prompt, dataset, and hardware; "
            "they do not establish production readiness without broader representative data."
        ),
    }


def evaluate_policy_campaign(
    suite: PolicyEvalSuite,
    *,
    proposer: OllamaSourceProposer,
    fixture_cases: list[FixtureCase] | None = None,
    runs: int = 3,
    max_cases: int | None = None,
    min_top1: float = 1.0,
    min_safety: float = 1.0,
    max_forbidden_rate: float = 0.0,
    min_model_success_rate: float = 0.95,
    min_run_pass_rate: float = 1.0,
    max_top1_spread: float = 0.05,
    min_prediction_stability: float = 0.95,
) -> dict[str, object]:
    """Repeat holdout evaluation and reject unstable or unidentifiable campaigns."""

    if not 2 <= runs <= 10:
        raise ValueError("campaign runs must be between 2 and 10")
    if not 0 <= min_run_pass_rate <= 1:
        raise ValueError("min_run_pass_rate must be between 0 and 1")
    if not 0 <= max_top1_spread <= 1:
        raise ValueError("max_top1_spread must be between 0 and 1")
    if not 0 <= min_prediction_stability <= 1:
        raise ValueError("min_prediction_stability must be between 0 and 1")

    run_summaries: list[dict[str, object]] = []
    identity_observations: list[dict[str, str | None]] = []
    for _ in range(runs):
        digest_before = proposer.refresh_model_digest()
        summary = evaluate_policy_suite(
            suite,
            mode="ollama",
            proposer=proposer,
            fixture_cases=fixture_cases,
            max_cases=max_cases,
            min_top1=min_top1,
            min_safety=min_safety,
            max_forbidden_rate=max_forbidden_rate,
            min_model_success_rate=min_model_success_rate,
            split="holdout",
        )
        digest_after = proposer.refresh_model_digest()
        run_summaries.append(summary)
        identity_observations.append(
            {"digest_before": digest_before, "digest_after": digest_after}
        )

    configuration_hashes = {
        str(summary["provenance"]["configuration_sha256"])  # type: ignore[index]
        for summary in run_summaries
    }
    dataset_hashes = {
        str(summary["provenance"]["dataset_sha256"])  # type: ignore[index]
        for summary in run_summaries
    }
    candidates = [summary["provenance"]["candidate"] for summary in run_summaries]  # type: ignore[index]
    model_digests = {str(candidate["model_digest"]) for candidate in candidates}
    prompt_hashes = {str(candidate["prompt_sha256"]) for candidate in candidates}
    identity_verified = (
        len(configuration_hashes) == 1
        and len(dataset_hashes) == 1
        and len(model_digests) == 1
        and None not in {candidate["model_digest"] for candidate in candidates}
        and len(prompt_hashes) == 1
        and None not in {candidate["prompt_sha256"] for candidate in candidates}
        and all(
            item["digest_before"] is not None
            and item["digest_before"] == item["digest_after"]
            and item["digest_before"] == candidates[index]["model_digest"]
            for index, item in enumerate(identity_observations)
        )
    )

    case_id_sequences = [
        tuple(str(item["case_id"]) for item in summary["case_results"])  # type: ignore[index]
        for summary in run_summaries
    ]
    case_set_consistent = len(set(case_id_sequences)) == 1
    prediction_stability_rate = 0.0
    if case_set_consistent and case_id_sequences[0]:
        stable = 0
        for case_index in range(len(case_id_sequences[0])):
            selections = {
                str(summary["case_results"][case_index]["candidate_source"])  # type: ignore[index]
                for summary in run_summaries
            }
            stable += len(selections) == 1
        prediction_stability_rate = _round_ratio(stable, len(case_id_sequences[0]))

    top1_values = [float(summary["assisted"]["top1_accuracy"]) for summary in run_summaries]  # type: ignore[index]
    call_success_values = [
        float(summary["candidate_call_success_rate"]) for summary in run_summaries
    ]
    safety_values = [float(summary["safety_guard_rate"]) for summary in run_summaries]
    forbidden_values = [float(summary["forbidden_execution_rate"]) for summary in run_summaries]
    p95_values = [float(summary["model_usage"]["p95_call_ms"]) for summary in run_summaries]  # type: ignore[index]
    first_call_values = [
        float(summary["model_usage"]["first_call_ms"]) for summary in run_summaries  # type: ignore[index]
    ]
    steady_p95_values = [
        float(summary["model_usage"]["steady_state_p95_call_ms"])  # type: ignore[index]
        for summary in run_summaries
    ]
    run_pass_rate = _round_ratio(
        sum(bool(summary["gates"]["passed"]) for summary in run_summaries),  # type: ignore[index]
        runs,
    )
    top1_spread = round(max(top1_values) - min(top1_values), 4)
    campaign_passed = (
        identity_verified
        and case_set_consistent
        and run_pass_rate >= min_run_pass_rate
        and top1_spread <= max_top1_spread
        and prediction_stability_rate >= min_prediction_stability
    )

    def _token_total(key: str) -> int | None:
        values = [summary["model_usage"][key] for summary in run_summaries]  # type: ignore[index]
        return sum(int(value) for value in values if value is not None) if any(
            value is not None for value in values
        ) else None

    return {
        "schema_version": "0.1",
        "evaluation_type": "live_ollama_campaign",
        "split": "holdout",
        "runs": runs,
        "cases_per_run": int(run_summaries[0]["cases"]),
        "provenance": {
            "dataset_sha256": next(iter(dataset_hashes)),
            "configuration_sha256": next(iter(configuration_hashes)),
            "candidate": candidates[0],
            "identity_verified": identity_verified,
            "per_run_digest_checks": identity_observations,
        },
        "aggregate": {
            "top1_mean": round(statistics.fmean(top1_values), 4),
            "top1_min": min(top1_values),
            "top1_max": max(top1_values),
            "top1_spread": top1_spread,
            "top1_population_stddev": round(statistics.pstdev(top1_values), 4),
            "prediction_stability_rate": prediction_stability_rate,
            "candidate_call_success_rate_mean": round(
                statistics.fmean(call_success_values), 4
            ),
            "candidate_call_success_rate_min": min(call_success_values),
            "safety_guard_rate_min": min(safety_values),
            "forbidden_execution_rate_max": max(forbidden_values),
            "p95_call_ms_median": round(statistics.median(p95_values), 3),
            "p95_call_ms_max": max(p95_values),
            "initial_run_first_call_ms": first_call_values[0],
            "first_call_ms_median": round(statistics.median(first_call_values), 3),
            "first_call_ms_max": max(first_call_values),
            "later_run_first_call_ms_median": round(
                statistics.median(first_call_values[1:]), 3
            ),
            "steady_state_p95_call_ms_median": round(
                statistics.median(steady_p95_values), 3
            ),
            "prompt_tokens_total": _token_total("prompt_tokens"),
            "completion_tokens_total": _token_total("completion_tokens"),
            "run_pass_rate": run_pass_rate,
        },
        "gates": {
            "min_run_pass_rate": min_run_pass_rate,
            "max_top1_spread": max_top1_spread,
            "min_prediction_stability": min_prediction_stability,
            "identity_verified": identity_verified,
            "case_set_consistent": case_set_consistent,
            "run_pass_rate_passed": run_pass_rate >= min_run_pass_rate,
            "top1_stability_passed": top1_spread <= max_top1_spread,
            "prediction_stability_passed": (
                prediction_stability_rate >= min_prediction_stability
            ),
            "passed": campaign_passed,
        },
        "run_summaries": run_summaries,
        "limitations": (
            "Repeated holdout runs measure run-to-run stability on one machine. First-call and "
            "steady-state timings are observational proxies, not guaranteed cold-start measurements; "
            "the campaign does not establish production readiness without representative incidents."
        ),
    }
