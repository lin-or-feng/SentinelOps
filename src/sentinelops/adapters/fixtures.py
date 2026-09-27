"""Deterministic in-memory adapter used by the baseline and CI."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import TypeAdapter

from sentinelops.domain import Evidence, IncidentTask, QuerySpec


@dataclass(frozen=True)
class FixtureCase:
    task: IncidentTask
    evidence: tuple[Evidence, ...]
    expected_root_cause: str


class FixtureEvidenceTool:
    name = "fixture_evidence"
    read_only = True

    def __init__(self, evidence: list[Evidence] | tuple[Evidence, ...]) -> None:
        self._evidence = tuple(evidence)
        self.query_count = 0

    def query(self, spec: QuerySpec) -> list[Evidence]:
        self.query_count += 1
        keywords = [item.casefold() for item in spec.keywords if item.strip()]
        matches: list[Evidence] = []
        for item in self._evidence:
            if item.incident_id != spec.incident_id or item.source != spec.source:
                continue
            if spec.service and item.service != spec.service:
                continue
            searchable = f"{item.summary} {json.dumps(item.attributes, ensure_ascii=False)}".casefold()
            if keywords and not any(keyword in searchable for keyword in keywords):
                continue
            matches.append(item)
        return matches[: spec.limit]


def load_fixture_cases(path: str | Path) -> list[FixtureCase]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schema_version") != "0.1":
        raise ValueError("unsupported fixture schema_version")
    evidence_adapter = TypeAdapter(list[Evidence])
    cases: list[FixtureCase] = []
    for raw in payload.get("cases", []):
        cases.append(
            FixtureCase(
                task=IncidentTask.model_validate(raw["task"]),
                evidence=tuple(evidence_adapter.validate_python(raw["evidence"])),
                expected_root_cause=str(raw["expected_root_cause"]),
            )
        )
    if not cases:
        raise ValueError("fixture dataset must contain at least one case")
    return cases
