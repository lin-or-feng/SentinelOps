from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from sentinelops.domain import DiagnosisReport, IncidentStatus, IncidentTask


def test_incident_task_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        IncidentTask(
            incident_id="inc-1",
            tenant_id="demo",
            service="orders",
            started_at=datetime.now(timezone.utc),
            symptoms=["latency"],
            unexpected=True,
        )


def test_diagnosed_report_requires_selected_candidate() -> None:
    with pytest.raises(ValidationError):
        DiagnosisReport(
            incident_id="inc-1",
            status=IncidentStatus.DIAGNOSED,
            tool_queries=0,
        )


def test_task_rejects_empty_symptoms() -> None:
    with pytest.raises(ValidationError):
        IncidentTask(
            incident_id="inc-1",
            tenant_id="demo",
            service="orders",
            started_at=datetime.now(timezone.utc),
            symptoms=[],
        )
