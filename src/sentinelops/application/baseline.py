"""Deterministic diagnosis baseline used before introducing any Agent loop."""

from __future__ import annotations

import json
from dataclasses import dataclass

from sentinelops.domain import (
    DiagnosisReport,
    Evidence,
    EvidenceSource,
    IncidentStatus,
    IncidentTask,
    QuerySpec,
    RootCauseCandidate,
)
from sentinelops.ports import EvidenceTool


@dataclass(frozen=True)
class RootCauseRule:
    code: str
    summary: str
    signals: tuple[str, ...]


RULES = (
    RootCauseRule(
        "deployment_regression",
        "A recent deployment is temporally correlated with the regression.",
        ("deployment", "release", "new version", "rollback", "版本发布"),
    ),
    RootCauseRule(
        "database_pool_exhaustion",
        "Database connection pool capacity is exhausted.",
        ("connection pool", "pool timeout", "db_waiting", "连接池耗尽"),
    ),
    RootCauseRule(
        "cache_miss_storm",
        "A cache miss storm is amplifying database load.",
        ("cache hit", "cache miss", "hit_rate", "缓存命中率"),
    ),
    RootCauseRule(
        "downstream_timeout",
        "A downstream dependency is timing out.",
        ("upstream timeout", "downstream timeout", "bank-api", "下游超时"),
    ),
)

SOURCE_WEIGHTS = {
    EvidenceSource.METRICS: 1.0,
    EvidenceSource.LOGS: 1.1,
    EvidenceSource.TRACES: 1.2,
    EvidenceSource.CHANGES: 1.25,
}


class BaselineDiagnoser:
    def __init__(self, evidence_tool: EvidenceTool) -> None:
        if not getattr(evidence_tool, "read_only", False):
            raise ValueError("baseline accepts read-only evidence tools only")
        self._tool = evidence_tool

    def diagnose(self, task: IncidentTask) -> DiagnosisReport:
        evidence: list[Evidence] = []
        queries = 0
        for source in SOURCE_WEIGHTS:
            if queries >= task.query_budget:
                break
            evidence.extend(
                self._tool.query(
                    QuerySpec(
                        incident_id=task.incident_id,
                        source=source,
                        service=task.service,
                        limit=25,
                    )
                )
            )
            queries += 1

        candidates = rank_root_causes(evidence)
        if not candidates:
            return DiagnosisReport(
                incident_id=task.incident_id,
                status=IncidentStatus.NEEDS_HUMAN,
                unresolved_questions=["No known root-cause signal matched the available evidence."],
                tool_queries=queries,
            )

        selected = candidates[0]
        return DiagnosisReport(
            incident_id=task.incident_id,
            status=IncidentStatus.DIAGNOSED,
            candidates=candidates,
            selected_code=selected.code,
            evidence_ids=sorted({item for candidate in candidates for item in candidate.evidence_ids}),
            tool_queries=queries,
        )



def rank_root_causes(evidence: list[Evidence]) -> list[RootCauseCandidate]:
    """Rank known root causes from normalized evidence without model calls."""

    ranked: list[RootCauseCandidate] = []
    for rule in RULES:
        score = 0.0
        matched_ids: list[str] = []
        for item in evidence:
            text = f"{item.summary} {json.dumps(item.attributes, ensure_ascii=False)}".casefold()
            matches = sum(signal.casefold() in text for signal in rule.signals)
            if matches:
                score += matches * SOURCE_WEIGHTS.get(item.source, 1.0) * item.reliability
                matched_ids.append(item.evidence_id)
        if score:
            ranked.append(
                RootCauseCandidate(
                    code=rule.code,
                    summary=rule.summary,
                    evidence_ids=sorted(set(matched_ids)),
                    score=min(1.0, round(score / 3.0, 4)),
                )
            )
    return sorted(ranked, key=lambda item: (-item.score, item.code))
