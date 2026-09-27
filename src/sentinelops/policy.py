"""Decision policies for the bounded investigation loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from sentinelops.application.baseline import rank_root_causes
from sentinelops.domain import (
    ActionType,
    Evidence,
    EvidenceSource,
    IncidentTask,
    InvestigationAction,
)


@dataclass
class InvestigationState:
    task: IncidentTask
    evidence: list[Evidence] = field(default_factory=list)
    queried_sources: set[EvidenceSource] = field(default_factory=set)


class InvestigationPolicy(Protocol):
    def decide(self, state: InvestigationState) -> InvestigationAction:
        """Choose the next bounded action from the current observations."""


class HeuristicInvestigationPolicy:
    """Reproducible policy used as the offline baseline for future model policies."""

    def __init__(self, min_confidence: float = 0.65, min_supporting_sources: int = 2) -> None:
        self.min_confidence = min(max(min_confidence, 0.0), 1.0)
        self.min_supporting_sources = max(1, min_supporting_sources)

    def decide(self, state: InvestigationState) -> InvestigationAction:
        candidates = rank_root_causes(state.evidence)
        if candidates:
            top = candidates[0]
            evidence_by_id = {item.evidence_id: item for item in state.evidence}
            supporting_sources = {
                evidence_by_id[evidence_id].source
                for evidence_id in top.evidence_ids
                if evidence_id in evidence_by_id
            }
            if top.score >= self.min_confidence and len(supporting_sources) >= self.min_supporting_sources:
                return InvestigationAction(
                    action=ActionType.FINISH,
                    rationale=(
                        f"candidate {top.code} reached confidence {top.score:.2f} "
                        f"across {len(supporting_sources)} evidence sources"
                    ),
                )

        for source in self._source_order(state.task):
            if source not in state.queried_sources:
                return InvestigationAction(
                    action=ActionType.QUERY,
                    source=source,
                    keywords=self._keywords(state.task, source),
                    rationale=f"collect next independent evidence domain: {source.value}",
                )

        if candidates:
            return InvestigationAction(
                action=ActionType.ESCALATE,
                rationale=(
                    "all evidence domains queried, but the leading hypothesis lacks "
                    "independent multi-source support"
                ),
            )
        return InvestigationAction(
            action=ActionType.ESCALATE,
            rationale="all evidence domains queried without a known root-cause signal",
        )

    @staticmethod
    def _source_order(task: IncidentTask) -> tuple[EvidenceSource, ...]:
        text = " ".join([*task.symptoms, task.service]).casefold()
        if any(term in text for term in ("release", "deploy", "version", "发布", "变更")):
            return (
                EvidenceSource.CHANGES,
                EvidenceSource.LOGS,
                EvidenceSource.METRICS,
                EvidenceSource.TRACES,
            )
        if any(term in text for term in ("latency", "timeout", "slow", "延迟", "超时")):
            return (
                EvidenceSource.TRACES,
                EvidenceSource.METRICS,
                EvidenceSource.LOGS,
                EvidenceSource.CHANGES,
            )
        return (
            EvidenceSource.METRICS,
            EvidenceSource.LOGS,
            EvidenceSource.TRACES,
            EvidenceSource.CHANGES,
        )

    @staticmethod
    def _keywords(task: IncidentTask, source: EvidenceSource) -> list[str]:
        words = [task.service, source.value]
        words.extend(task.symptoms[:3])
        return [word[:120] for word in words if word.strip()]
