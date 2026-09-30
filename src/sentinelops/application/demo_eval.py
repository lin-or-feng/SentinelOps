"""Fresh, fixture-only investigation runs for the local verification desk."""

from __future__ import annotations

import gc
import tempfile
import time
from pathlib import Path

from sentinelops.adapters import FixtureCase, FixtureEvidenceTool
from sentinelops.domain import OrchestrationMode
from sentinelops.service import create_service
from sentinelops.storage import AssignmentJournal


def evaluate_demo_cases(
    cases: list[FixtureCase], mode: OrchestrationMode,
    *, scratch_dir: str | Path = ".sentinelops/demo-temp",
) -> dict[str, object]:
    """Run each case in a fresh SQLite scope and return verifiable evidence."""
    if not cases:
        raise ValueError("demo evaluation requires at least one fixture case")
    results: list[dict[str, object]] = []
    scratch = Path(scratch_dir)
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sentinelops-demo-", dir=scratch) as directory:
        for index, case in enumerate(cases):
            database = Path(directory) / f"case-{index}.db"
            service = create_service(
                db_path=database,
                evidence_tool=FixtureEvidenceTool(case.evidence),
                orchestration_mode=mode,
                policy_mode="heuristic",
                shadow_mode="off",
            )
            started = time.perf_counter()
            try:
                result = service.investigate(case.task)
                duration_ms = round((time.perf_counter() - started) * 1000, 2)
                verification = service.audit.verify()
                events = service.audit.list_events(trace_id=result.trace_id, limit=500)
                events.reverse()
                assignments = AssignmentJournal(database).list_for_trace(result.trace_id)
                persisted = service.store.get(case.task.incident_id) == result
                run_state = service.run_journal.get(case.task.incident_id)
            finally:
                service.close()

            known_ids = {item.evidence_id for item in case.evidence}
            referenced_ids = set(result.report.evidence_ids)
            checks = {
                "expected_root_cause": result.report.selected_code == case.expected_root_cause,
                "evidence_scope": bool(referenced_ids) and referenced_ids <= known_ids,
                "audit_chain": verification.valid,
                "result_persisted": persisted,
                "run_completed": run_state is not None and run_state[2] == "completed",
            }
            results.append({
                "incident_id": case.task.incident_id,
                "service": case.task.service,
                "symptoms": case.task.symptoms,
                "expected_code": case.expected_root_cause,
                "actual_code": result.report.selected_code,
                "status": result.report.status.value,
                "requested_mode": mode.value,
                "selected_mode": result.orchestration_mode.value,
                "trace_id": result.trace_id,
                "duration_ms": duration_ms,
                "tool_queries": result.report.tool_queries,
                "degraded_components": result.degraded_components,
                "checks": checks,
                "passed": all(checks.values()),
                "audit": verification.as_dict(),
                "evidence": [
                    {
                        "id": item.evidence_id,
                        "source": item.source.value,
                        "summary": item.summary,
                        "used": item.evidence_id in referenced_ids,
                    }
                    for item in case.evidence
                ],
                "assignments": [
                    {
                        "actor": item.actor,
                        "source": item.source,
                        "state": item.state.value,
                    }
                    for item in assignments
                ],
                "trace": [step.model_dump(mode="json") for step in result.trace],
                "audit_events": [
                    {
                        "sequence": event["sequence"],
                        "actor": event["actor"],
                        "action": event["action"],
                        "resource": event["resource"],
                        "status": event["status"],
                        "details": event["details"],
                        "event_hash": event["event_hash"],
                        "previous_hash": event["previous_hash"],
                    }
                    for event in events
                ],
            })
        # sqlite3 context managers commit but do not close; let cyclic references
        # release their handles before Windows removes the temporary database.
        gc.collect()
    return {
        "evaluation_type": "fixture_only_verification_desk",
        "requested_mode": mode.value,
        "case_count": len(results),
        "passed_count": sum(item["passed"] for item in results),
        "correct_count": sum(item["checks"]["expected_root_cause"] for item in results),
        "all_passed": all(item["passed"] for item in results),
        "limitations": (
            "Synthetic local fixtures and deterministic policy only; this is not "
            "an independent model holdout or production qualification."
        ),
        "results": results,
    }
