"""The local real-data desk never reaches fixtures or upstream networks in tests."""

from __future__ import annotations

import secrets
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinelops.adapters import load_fixture_cases
from sentinelops.adapters.observability import ObservabilityEvidenceTool
from sentinelops.domain import EvidenceSource, IncidentTask
from sentinelops.gateway import EvidenceToolError
from sentinelops.operator_web import create_operator_app, main
from sentinelops.service import create_service
from sentinelops.storage import InvestigationRunJournal


TOKEN = "operator-test-token-longer-than-32-bytes"


class FakeProvider:
    def __init__(
        self, source: EvidenceSource, *, fail: bool = False,
        timeout_on_investigate: bool = False,
    ) -> None:
        self.source = source
        self.fail = fail
        self.timeout_on_investigate = timeout_on_investigate
        self.queries = []
        self.closed = False

    def query(self, spec):
        self.queries.append(spec)
        if self.fail:
            raise RuntimeError("upstream-sensitive-error")
        if self.timeout_on_investigate and spec.limit > 1:
            raise EvidenceToolError("synthetic-private-timeout")
        return []

    def close(self):
        self.closed = True


def _desk(tmp_path, *, failing_source=False, timeout_source=False):
    providers = [
        FakeProvider(EvidenceSource.METRICS),
        FakeProvider(
            EvidenceSource.LOGS, fail=failing_source,
            timeout_on_investigate=timeout_source,
        ),
    ]
    tool = ObservabilityEvidenceTool(providers)
    service = create_service(
        db_path=tmp_path / "pilot.db",
        audit_key="audit-key-very-long-for-operator-tests",
        evidence_mode="observability",
        evidence_tool=tool,
        policy_mode="heuristic",
        shadow_mode="off",
    )
    app = create_operator_app(service=service, api_token=TOKEN)
    task = load_fixture_cases("evals/incidents.json")[0].task.model_dump(mode="json")
    task["incident_id"] = "inc-operator-pilot"
    return app, providers, task


def _post(client, route, payload, **headers):
    return client.post(
        route, json=payload,
        headers={"Authorization": f"Bearer {TOKEN}", **headers},
    )


def test_operator_requires_token_and_refuses_fixture_service(tmp_path) -> None:
    app, providers, task = _desk(tmp_path)
    with TestClient(app) as client:
        assert client.get("/api/status").status_code == 401
        assert client.get("/api/status", headers={"Authorization": f"Bearer {TOKEN}"}).json()["mode"] == "real_read_only"
        assert client.post("/api/provider-check", json=task).status_code == 401
        assert not any(provider.queries for provider in providers)
    assert all(provider.closed for provider in providers)

    fixture_service = create_service(db_path=tmp_path / "fixture.db")
    try:
        try:
            create_operator_app(service=fixture_service, api_token=TOKEN)
        except ValueError as exc:
            assert "observability" in str(exc)
        else:
            raise AssertionError("fixture tool was accepted")
    finally:
        fixture_service.close()


def test_operator_requires_matching_preflight_and_confirmation(tmp_path) -> None:
    app, providers, task = _desk(tmp_path)
    with TestClient(app) as client:
        assert _post(client, "/api/investigate", {"task": task, "confirmed": True}).status_code == 409
        response = _post(client, "/api/provider-check", task)
        assert response.status_code == 200
        assert response.json()["all_reachable"] is True
        assert all(provider.queries[0].limit == 1 for provider in providers)
        assert _post(client, "/api/investigate", {"task": task, "confirmed": False}).status_code == 422
        changed = dict(task, service="different-service")
        assert _post(client, "/api/investigate", {"task": changed, "confirmed": True}).status_code == 409
        assert _post(client, "/api/provider-check", task).json()["all_reachable"] is True
        response = _post(client, "/api/investigate", {"task": task, "confirmed": True})
        assert response.status_code == 200
        data = response.json()
        assert data["result"]["task"]["incident_id"] == task["incident_id"]
        assert data["result"]["report"]["status"] == "needs_human"
        assert data["audit"]["valid"] is True
        assert data["audit_events"]
        query_counts = [len(provider.queries) for provider in providers]
        recovered = _post(client, "/api/recover", {"incident_id": task["incident_id"]})
        assert recovered.status_code == 200
        assert recovered.json()["result"]["trace_id"] == data["result"]["trace_id"]
        assert [len(provider.queries) for provider in providers] == query_counts
        assert client.post("/api/recover", json={"incident_id": task["incident_id"]}).status_code == 401
        assert _post(client, "/api/investigate", {"task": task, "confirmed": True}).status_code == 409


def test_single_agent_only_queries_configured_operator_sources(tmp_path) -> None:
    app, providers, task = _desk(tmp_path)
    with TestClient(app) as client:
        assert _post(client, "/api/provider-check", task).json()["all_reachable"] is True
        response = _post(client, "/api/investigate", {"task": task, "confirmed": True})
        assert response.status_code == 200
        report = response.json()["result"]["report"]
        assert report["status"] == "needs_human"
        assert report["tool_queries"] == 2
        assert response.json()["result"]["degraded_components"] == []
        assert all(len(provider.queries) == 2 for provider in providers)
        assert not any(event["status"] == "denied" for event in response.json()["audit_events"])


def test_operator_failed_source_blocks_run_without_leaking_error(tmp_path) -> None:
    app, _, task = _desk(tmp_path, failing_source=True)
    with TestClient(app) as client:
        response = _post(client, "/api/provider-check", task)
        assert response.status_code == 200
        assert response.json()["all_reachable"] is False
        assert "upstream-sensitive-error" not in response.text
        assert _post(client, "/api/investigate", {"task": task, "confirmed": True}).status_code == 409


def test_operator_source_timeout_degrades_to_human_without_leaking_body(tmp_path) -> None:
    app, providers, task = _desk(tmp_path, timeout_source=True)
    with TestClient(app) as client:
        assert _post(client, "/api/provider-check", task).json()["all_reachable"] is True
        response = _post(client, "/api/investigate", {"task": task, "confirmed": True})
        assert response.status_code == 200
        assert response.json()["result"]["report"]["status"] == "needs_human"
        assert response.json()["result"]["degraded_components"] == ["logs"]
        assert response.json()["audit"]["valid"] is True
        assert "synthetic-private-timeout" not in response.text
        assert [len(provider.queries) for provider in providers] == [2, 2]


def test_operator_restart_recovers_without_requery(tmp_path) -> None:
    app, providers, task = _desk(tmp_path)
    with TestClient(app) as client:
        assert _post(client, "/api/provider-check", task).json()["all_reachable"] is True
        original = _post(client, "/api/investigate", {"task": task, "confirmed": True})
        assert original.status_code == 200
    assert [len(provider.queries) for provider in providers] == [2, 2]

    restarted, new_providers, _ = _desk(tmp_path)
    with TestClient(restarted) as client:
        recovered = _post(client, "/api/recover", {"incident_id": task["incident_id"]})
        assert recovered.status_code == 200
        assert recovered.json()["result"]["trace_id"] == original.json()["result"]["trace_id"]
        assert _post(client, "/api/run-state", {"incident_id": task["incident_id"]}).json() == {
            "state": "completed",
            "result_saved": True,
            "note": "Local snapshot only; running may be stale after interruption. Never auto-retry a reserved incident.",
        }
        assert not any(provider.queries for provider in new_providers)


def test_operator_restart_preserves_unfinished_reservation_without_requery(tmp_path) -> None:
    app, providers, task = _desk(tmp_path)
    with TestClient(app):
        journal = InvestigationRunJournal(tmp_path / "pilot.db")
        journal.reserve(IncidentTask.model_validate(task), "trace-interrupted-process")
    assert not any(provider.queries for provider in providers)

    restarted, new_providers, _ = _desk(tmp_path)
    with TestClient(restarted) as client:
        assert _post(client, "/api/recover", {"incident_id": task["incident_id"]}).status_code == 404
        state = _post(client, "/api/run-state", {"incident_id": task["incident_id"]})
        assert state.status_code == 200
        assert state.json()["state"] == "running"
        assert state.json()["result_saved"] is False
        assert _post(client, "/api/provider-check", task).json()["all_reachable"] is True
        conflict = _post(client, "/api/investigate", {"task": task, "confirmed": True})
        assert conflict.status_code == 409
        assert conflict.json()["detail"] == "incident_id_conflict_or_reserved"
        assert [len(provider.queries) for provider in new_providers] == [1, 1]


def test_operator_recovery_does_not_create_or_query(tmp_path) -> None:
    app, providers, task = _desk(tmp_path)
    with TestClient(app) as client:
        response = _post(client, "/api/recover", {"incident_id": task["incident_id"]})
        assert response.status_code == 404
        assert response.json()["detail"] == "completed_investigation_not_found"
        assert not any(provider.queries for provider in providers)


def test_operator_run_state_distinguishes_missing_running_and_abandoned(tmp_path) -> None:
    app, providers, task = _desk(tmp_path)
    with TestClient(app) as client:
        missing = _post(client, "/api/run-state", {"incident_id": task["incident_id"]})
        assert missing.status_code == 200
        assert missing.json()["state"] == "not_found"
        assert missing.json()["result_saved"] is False

        # The journal is the local reservation ledger; no provider query is needed.
        journal = InvestigationRunJournal(tmp_path / "pilot.db")
        journal.reserve(IncidentTask.model_validate(task), "trace-operator-running")
        running = _post(client, "/api/run-state", {"incident_id": task["incident_id"]})
        assert running.json()["state"] == "running"
        assert running.json()["result_saved"] is False
        journal.finish(task["incident_id"], "trace-operator-running", success=False)
        abandoned = _post(client, "/api/run-state", {"incident_id": task["incident_id"]})
        assert abandoned.json()["state"] == "abandoned"
        assert abandoned.json()["result_saved"] is False
        assert not any(provider.queries for provider in providers)


def test_operator_run_state_completed_and_audit_failure(tmp_path) -> None:
    app, providers, task = _desk(tmp_path)
    with TestClient(app) as client:
        assert _post(client, "/api/provider-check", task).json()["all_reachable"] is True
        assert _post(client, "/api/investigate", {"task": task, "confirmed": True}).status_code == 200
        query_counts = [len(provider.queries) for provider in providers]
        state = _post(client, "/api/run-state", {"incident_id": task["incident_id"]})
        assert state.json()["state"] == "completed"
        assert state.json()["result_saved"] is True
        assert [len(provider.queries) for provider in providers] == query_counts
        with sqlite3.connect(tmp_path / "pilot.db") as connection:
            connection.execute(
                "UPDATE audit_events SET details_json = ? WHERE sequence = "
                "(SELECT MIN(sequence) FROM audit_events)",
                ('{"tampered":true}',),
            )
        refused = _post(client, "/api/run-state", {"incident_id": task["incident_id"]})
        assert refused.status_code == 503
        assert refused.json()["detail"] == "audit_chain_invalid"
        assert [len(provider.queries) for provider in providers] == query_counts


def test_operator_recovery_fails_closed_on_tampered_audit(tmp_path) -> None:
    app, providers, task = _desk(tmp_path)
    with TestClient(app) as client:
        assert _post(client, "/api/provider-check", task).json()["all_reachable"] is True
        assert _post(client, "/api/investigate", {"task": task, "confirmed": True}).status_code == 200
        query_counts = [len(provider.queries) for provider in providers]
        with sqlite3.connect(tmp_path / "pilot.db") as connection:
            connection.execute(
                "UPDATE audit_events SET details_json = ? WHERE sequence = "
                "(SELECT MIN(sequence) FROM audit_events)",
                ('{"tampered":true}',),
            )
        recovered = _post(client, "/api/recover", {"incident_id": task["incident_id"]})
        assert recovered.status_code == 503
        assert recovered.json()["detail"] == "audit_chain_invalid"
        assert "selected_code" not in recovered.text
        assert [len(provider.queries) for provider in providers] == query_counts


def test_operator_investigation_error_is_sanitized(
    tmp_path, monkeypatch, caplog
) -> None:
    app, _, task = _desk(tmp_path)

    def broken_investigation(self, supplied):
        raise RuntimeError("upstream-sensitive-error")

    monkeypatch.setattr("sentinelops.service.SentinelOpsService.investigate", broken_investigation)
    with TestClient(app) as client:
        assert _post(client, "/api/provider-check", task).json()["all_reachable"] is True
        response = _post(client, "/api/investigate", {"task": task, "confirmed": True})
        assert response.status_code == 503
        assert response.json()["detail"] == "investigation_failed_review_server_logs"
        assert "upstream-sensitive-error" not in response.text
        assert "upstream-sensitive-error" not in caplog.text
        assert "RuntimeError" in caplog.text


def test_operator_rejects_cross_origin_and_private_input(tmp_path) -> None:
    app, providers, task = _desk(tmp_path)
    with TestClient(app) as client:
        response = _post(client, "/api/provider-check", task, Origin="https://example.org")
        assert response.status_code == 403
        task["service"] = "138" + "0013" + "8000"
        response = _post(client, "/api/provider-check", task)
        assert response.status_code == 422
        assert "138" + "0013" + "8000" not in response.text
        assert _post(client, "/api/recover", {"incident_id": "138" + "0013" + "8000"}).status_code == 422
        assert not any(provider.queries for provider in providers)


def test_operator_assets_are_local_and_explicit(tmp_path) -> None:
    app, _, _ = _desk(tmp_path)
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "REAL DATA" in response.text
        assert response.headers["cache-control"] == "no-store"
        assert client.get("/assets/app.js").status_code == 200
        assert client.get("/assets/app.css").status_code == 200
        assert client.get("/assets/unknown.js").status_code == 422


def test_operator_startup_rejects_unsafe_config_before_storage(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.delenv("SENTINELOPS_API_TOKEN", raising=False)
    db = tmp_path / "pilot.db"
    assert main(["--db", str(db)]) == 2
    assert not db.exists()
    assert "pilot preflight failed" in capsys.readouterr().out


def test_operator_startup_refuses_database_inside_checkout() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--db", str((Path.cwd() / ".sentinelops" / "operator.db").resolve())])
    assert exc.value.code == 2


def test_operator_startup_binds_only_loopback_without_network(
    tmp_path, monkeypatch
) -> None:
    values = {
        "SENTINELOPS_API_TOKEN": secrets.token_urlsafe(32),
        "SENTINELOPS_AUDIT_KEY": secrets.token_urlsafe(32),
        "SENTINELOPS_EVIDENCE_MODE": "observability",
        "SENTINELOPS_POLICY_MODE": "heuristic",
        "SENTINELOPS_SPECIALIST_SHADOW": "off",
        "SENTINELOPS_TRUSTED_HOSTS": "127.0.0.1,localhost",
        "SENTINELOPS_CORS_ORIGINS": "",
        "SENTINELOPS_ALLOWED_OBSERVABILITY_HOSTS": "metrics.internal,logs.internal",
        "SENTINELOPS_PROMETHEUS_URL": "https://metrics.internal",
        "SENTINELOPS_LOKI_URL": "https://logs.internal",
        "SENTINELOPS_PROMETHEUS_TOKEN": secrets.token_urlsafe(32),
        "SENTINELOPS_LOKI_TOKEN": secrets.token_urlsafe(32),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    captured = {}

    def fake_run(app, **kwargs):
        captured.update(kwargs)
        with TestClient(app) as client:
            status = client.get(
                "/api/status",
                headers={"Authorization": f"Bearer {values['SENTINELOPS_API_TOKEN']}"},
            )
            assert status.status_code == 200
            assert status.json()["sources"] == ["logs", "metrics"]

    monkeypatch.setattr("uvicorn.run", fake_run)
    assert main(["--db", str(tmp_path / "pilot.db")]) == 0
    assert captured["host"] == "127.0.0.1"
    assert captured["workers"] == 1
    assert captured["access_log"] is False
