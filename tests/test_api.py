from fastapi.testclient import TestClient
from pathlib import Path

from sentinelops.adapters import load_fixture_cases
from sentinelops.api import create_app


DATASET = Path("evals/incidents.json")


def test_api_auth_investigation_persistence_and_audit(tmp_path) -> None:
    app = create_app(
        db_path=tmp_path / "api.db",
        audit_key="test-key",
        api_token="test-token",
    )
    client = TestClient(app)
    case = load_fixture_cases("evals/incidents.json")[1]

    assert client.get("/healthz").status_code == 200
    assert client.post("/v1/investigations", json=case.task.model_dump(mode="json")).status_code == 401

    headers = {"Authorization": "Bearer test-token"}
    created = client.post(
        "/v1/investigations",
        json=case.task.model_dump(mode="json"),
        headers=headers,
    )
    assert created.status_code == 201
    payload = created.json()
    assert payload["report"]["selected_code"] == case.expected_root_cause

    loaded = client.get(f"/v1/investigations/{case.task.incident_id}", headers=headers)
    assert loaded.status_code == 200
    assert loaded.json()["trace_id"] == payload["trace_id"]

    verification = client.get("/v1/audit/verify", headers=headers)
    assert verification.status_code == 200
    assert verification.json()["valid"] is True

    events = client.get(
        "/v1/audit/events",
        params={"trace_id": payload["trace_id"]},
        headers=headers,
    )
    assert events.status_code == 200
    assert len(events.json()) >= 4

    replay = client.post(
        "/v1/investigations",
        json=case.task.model_dump(mode="json"),
        headers=headers,
    )
    assert replay.status_code == 201
    assert replay.json()["trace_id"] == payload["trace_id"]

    conflicting = case.task.model_copy(update={"symptoms": ["different payload"]})
    conflict = client.post(
        "/v1/investigations",
        json=conflicting.model_dump(mode="json"),
        headers=headers,
    )
    assert conflict.status_code == 409


def test_api_returns_404_for_missing_investigation(tmp_path) -> None:
    client = TestClient(create_app(db_path=tmp_path / "api.db"))
    response = client.get("/v1/investigations/missing")
    assert response.status_code == 404


def test_api_reads_runtime_paths_from_environment(tmp_path, monkeypatch) -> None:
    database = tmp_path / "env.db"
    monkeypatch.setenv("SENTINELOPS_DATASET_PATH", str(DATASET))
    monkeypatch.setenv("SENTINELOPS_DB_PATH", str(database))

    with TestClient(create_app()) as client:
        assert client.get("/healthz").status_code == 200

    assert database.exists()
