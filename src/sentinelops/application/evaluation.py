"""Offline evaluation for the deterministic and future Agent implementations."""

from __future__ import annotations

from dataclasses import dataclass

from sentinelops.adapters import FixtureCase, FixtureEvidenceTool
from sentinelops.application.baseline import BaselineDiagnoser


@dataclass(frozen=True)
class EvaluationDetail:
    incident_id: str
    expected: str
    predicted: str | None
    top1_correct: bool
    evidence_valid: bool
    tool_queries: int


@dataclass(frozen=True)
class EvaluationSummary:
    cases: int
    top1_accuracy: float
    evidence_validity: float
    average_tool_queries: float
    details: tuple[EvaluationDetail, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "cases": self.cases,
            "top1_accuracy": self.top1_accuracy,
            "evidence_validity": self.evidence_validity,
            "average_tool_queries": self.average_tool_queries,
            "details": [detail.__dict__ for detail in self.details],
        }


def evaluate_cases(cases: list[FixtureCase]) -> EvaluationSummary:
    details: list[EvaluationDetail] = []
    for case in cases:
        tool = FixtureEvidenceTool(case.evidence)
        report = BaselineDiagnoser(tool).diagnose(case.task)
        known_evidence = {item.evidence_id for item in case.evidence}
        details.append(
            EvaluationDetail(
                incident_id=case.task.incident_id,
                expected=case.expected_root_cause,
                predicted=report.selected_code,
                top1_correct=report.selected_code == case.expected_root_cause,
                evidence_valid=set(report.evidence_ids).issubset(known_evidence),
                tool_queries=tool.query_count,
            )
        )
    count = len(details)
    return EvaluationSummary(
        cases=count,
        top1_accuracy=round(sum(item.top1_correct for item in details) / count, 4),
        evidence_validity=round(sum(item.evidence_valid for item in details) / count, 4),
        average_tool_queries=round(sum(item.tool_queries for item in details) / count, 2),
        details=tuple(details),
    )
