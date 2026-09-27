"""Deterministic single-vs-multi orchestration ablation."""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from sentinelops.adapters import FixtureCase, FixtureEvidenceTool
from sentinelops.domain import OrchestrationMode


@dataclass(frozen=True)
class OrchestrationEvaluation:
    mode: str
    cases: int
    top1_accuracy: float
    evidence_validity: float
    average_tool_queries: float
    average_duration_ms: float
    synthetic_provider_delay_ms: float
    selected_multi_cases: int

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


def evaluate_orchestration(
    cases: list[FixtureCase],
    mode: OrchestrationMode,
    *,
    provider_delay_ms: float = 0.0,
) -> OrchestrationEvaluation:
    # Delayed import avoids a composition-root cycle during service startup.
    from sentinelops.service import create_service

    correct = 0
    valid = 0
    queries = 0
    durations: list[float] = []
    selected_multi_cases = 0
    with tempfile.TemporaryDirectory(
        prefix="sentinelops-orchestration-eval-",
        ignore_cleanup_errors=True,
    ) as temporary_directory:
        root = Path(temporary_directory)
        for index, case in enumerate(cases):
            tool = FixtureEvidenceTool(case.evidence)
            if provider_delay_ms > 0:
                tool = _DelayedEvidenceTool(tool, provider_delay_ms / 1_000)
            service = create_service(
                db_path=root / f"{mode.value}-{index}.db",
                evidence_tool=tool,
                orchestration_mode=mode,
            )
            started = time.perf_counter()
            try:
                result = service.investigate(case.task)
            finally:
                service.close()
            durations.append((time.perf_counter() - started) * 1_000)
            correct += result.report.selected_code == case.expected_root_cause
            known_evidence = {item.evidence_id for item in case.evidence}
            valid += set(result.report.evidence_ids).issubset(known_evidence)
            queries += result.report.tool_queries
            selected_multi_cases += result.orchestration_mode == OrchestrationMode.MULTI

    count = len(cases)
    return OrchestrationEvaluation(
        mode=mode.value,
        cases=count,
        top1_accuracy=round(correct / count, 4),
        evidence_validity=round(valid / count, 4),
        average_tool_queries=round(queries / count, 2),
        average_duration_ms=round(sum(durations) / count, 2),
        synthetic_provider_delay_ms=provider_delay_ms,
        selected_multi_cases=selected_multi_cases,
    )


class _DelayedEvidenceTool:
    """Evaluation-only wrapper for a reproducible provider-latency comparison."""

    name = "delayed-fixture-evidence"
    read_only = True

    def __init__(self, delegate: FixtureEvidenceTool, delay_seconds: float) -> None:
        self._delegate = delegate
        self._delay_seconds = delay_seconds

    def query(self, spec):
        time.sleep(self._delay_seconds)
        return self._delegate.query(spec)


def compare_orchestration(
    cases: list[FixtureCase],
    *,
    provider_delay_ms: float = 0.0,
) -> dict[str, object]:
    if not 0.0 <= provider_delay_ms <= 1_000.0:
        raise ValueError("provider_delay_ms must be between 0 and 1000")
    single = evaluate_orchestration(
        cases,
        OrchestrationMode.SINGLE,
        provider_delay_ms=provider_delay_ms,
    )
    multi = evaluate_orchestration(
        cases,
        OrchestrationMode.MULTI,
        provider_delay_ms=provider_delay_ms,
    )
    auto = evaluate_orchestration(
        cases,
        OrchestrationMode.AUTO,
        provider_delay_ms=provider_delay_ms,
    )
    return {
        "single": single.as_dict(),
        "multi": multi.as_dict(),
        "auto": auto.as_dict(),
        "delta": {
            "top1_accuracy": round(multi.top1_accuracy - single.top1_accuracy, 4),
            "evidence_validity": round(multi.evidence_validity - single.evidence_validity, 4),
            "average_tool_queries": round(
                multi.average_tool_queries - single.average_tool_queries,
                2,
            ),
            "average_duration_ms": round(
                multi.average_duration_ms - single.average_duration_ms,
                2,
            ),
        },
        "auto_delta": {
            "top1_accuracy": round(auto.top1_accuracy - single.top1_accuracy, 4),
            "evidence_validity": round(auto.evidence_validity - single.evidence_validity, 4),
            "average_tool_queries": round(
                auto.average_tool_queries - single.average_tool_queries,
                2,
            ),
            "average_duration_ms": round(
                auto.average_duration_ms - single.average_duration_ms,
                2,
            ),
        },
        "timing_note": (
            "Timing uses a deterministic fixture and optional synthetic per-query delay; "
            "it demonstrates scheduling behavior, not production provider latency."
        ),
    }
