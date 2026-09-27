"""Strict domain contracts shared by orchestration, tools and evaluation."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class EvidenceSource(str, Enum):
    METRICS = "metrics"
    LOGS = "logs"
    TRACES = "traces"
    CHANGES = "changes"
    RUNBOOK = "runbook"


class IncidentStatus(str, Enum):
    DIAGNOSED = "diagnosed"
    NEEDS_HUMAN = "needs_human"


class ActionType(str, Enum):
    QUERY = "query"
    FINISH = "finish"
    ESCALATE = "escalate"


class IncidentTask(StrictModel):
    incident_id: str = Field(min_length=3, max_length=120)
    tenant_id: str = Field(min_length=1, max_length=120)
    service: str = Field(min_length=1, max_length=120)
    started_at: AwareDatetime
    symptoms: list[str] = Field(min_length=1, max_length=20)
    deadline_seconds: int = Field(default=30, ge=1, le=300)
    query_budget: int = Field(default=12, ge=1, le=100)


class QuerySpec(StrictModel):
    incident_id: str = Field(min_length=3, max_length=120)
    source: EvidenceSource
    service: str | None = Field(default=None, max_length=120)
    keywords: list[str] = Field(default_factory=list, max_length=20)
    limit: int = Field(default=20, ge=1, le=100)
    start_time: AwareDatetime | None = None
    end_time: AwareDatetime | None = None

    @model_validator(mode="after")
    def time_window_must_be_complete_and_ordered(self) -> "QuerySpec":
        if (self.start_time is None) != (self.end_time is None):
            raise ValueError("start_time and end_time must be provided together")
        if self.start_time is not None and self.end_time is not None:
            if self.start_time >= self.end_time:
                raise ValueError("start_time must be earlier than end_time")
            if (self.end_time - self.start_time).total_seconds() > 3600:
                raise ValueError("evidence query window cannot exceed one hour")
        return self


class Evidence(StrictModel):
    evidence_id: str = Field(min_length=3, max_length=160)
    incident_id: str = Field(min_length=3, max_length=120)
    service: str = Field(min_length=1, max_length=120)
    source: EvidenceSource
    observed_at: AwareDatetime
    summary: str = Field(min_length=1, max_length=2_000)
    raw_ref: str = Field(min_length=1, max_length=500)
    reliability: float = Field(default=1.0, ge=0.0, le=1.0)
    attributes: dict[str, Any] = Field(default_factory=dict)


class RootCauseCandidate(StrictModel):
    code: str = Field(min_length=2, max_length=120)
    summary: str = Field(min_length=1, max_length=500)
    evidence_ids: list[str] = Field(default_factory=list)
    score: float = Field(ge=0.0, le=1.0)


class DiagnosisReport(StrictModel):
    incident_id: str
    status: IncidentStatus
    candidates: list[RootCauseCandidate] = Field(default_factory=list, max_length=10)
    selected_code: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    tool_queries: int = Field(ge=0)

    @model_validator(mode="after")
    def selected_candidate_must_exist(self) -> "DiagnosisReport":
        candidate_codes = {candidate.code for candidate in self.candidates}
        if self.selected_code is not None and self.selected_code not in candidate_codes:
            raise ValueError("selected_code must reference an existing candidate")
        if self.status == IncidentStatus.DIAGNOSED and self.selected_code is None:
            raise ValueError("diagnosed reports require selected_code")
        return self


class InvestigationAction(StrictModel):
    action: ActionType
    source: EvidenceSource | None = None
    keywords: list[str] = Field(default_factory=list, max_length=20)
    rationale: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def query_requires_source(self) -> "InvestigationAction":
        if self.action == ActionType.QUERY and self.source is None:
            raise ValueError("query actions require a source")
        if self.action != ActionType.QUERY and self.source is not None:
            raise ValueError("only query actions may specify a source")
        return self


class InvestigationTraceStep(StrictModel):
    step: int = Field(ge=1)
    action: ActionType
    source: EvidenceSource | None = None
    status: str = Field(min_length=1, max_length=40)
    rationale: str = Field(min_length=1, max_length=500)
    evidence_ids: list[str] = Field(default_factory=list)
    duration_ms: float = Field(ge=0)


class InvestigationResult(StrictModel):
    trace_id: str = Field(min_length=8, max_length=120)
    task: IncidentTask
    report: DiagnosisReport
    trace: list[InvestigationTraceStep]
    degraded_components: list[str] = Field(default_factory=list)
