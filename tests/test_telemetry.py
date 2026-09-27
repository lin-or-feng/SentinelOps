import json
import logging
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from sentinelops.adapters import load_fixture_cases
from sentinelops.api import create_app
from sentinelops.domain import EvidenceSource
from sentinelops.telemetry import OperationalMetrics, request_id_from_header


def test_metrics_registry_uses_fixed_low_cardinality_dimensions() -> None:
    registry = OperationalMetrics(version="test-version")
    registry.record_http(
        method="DELETE",
        route="/private/dynamic/value",
        status_code=799,
        duration_seconds=0.02,
    )
    registry.record_provider(
        source=EvidenceSource.LOGS,
        status="unexpected-status",
        duration_seconds=0.5,
    )
    registry.set_circuit(EvidenceSource.LOGS, opened=True)
    registry.record_investigation(outcome="unexpected-outcome", duration_seconds=0.1)

    rendered = registry.render_prometheus()

    assert 'method="OTHER"' in rendered
    assert 'route="unmatched"' in rendered
    assert 'status_class="unknown"' in rendered
    assert 'source="logs",status="error"' in rendered
    assert 'outcome="needs_human"' in rendered
    assert 'sentinelops_provider_circuit_open{source="logs"} 1' in rendered
    assert "/private/dynamic/value" not in rendered
    assert rendered.endswith("\n")


def test_request_id_rejects_private_or_malformed_values() -> None:
    private_value = "138" + "0013" + "8000"

    assert request_id_from_header("req-client-001") == "req-client-001"
    assert request_id_from_header(private_value) != private_value
    assert request_id_from_header("short") != "short"


def test_metrics_registry_is_thread_safe_and_renders_consistent_counts() -> None:
    registry = OperationalMetrics(version="test-version")

    def record_batch(_: int) -> None:
        for _ in range(100):
            registry.record_http(
                method="GET",
                route="/healthz",
                status_code=200,
                duration_seconds=0.01,
            )

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(record_batch, range(4)))

    rendered = registry.render_prometheus()
    assert (
        'sentinelops_http_requests_total{method="GET",route="/healthz",status_class="2xx"} 400'
        in rendered
    )
    assert (
        'sentinelops_http_request_duration_seconds_count{method="GET",route="/healthz"} 400'
        in rendered
    )


def test_api_exposes_opt_in_metrics_and_correlates_safe_request_id(tmp_path, caplog) -> None:
    caplog.set_level(logging.INFO, logger="sentinelops.http")
    app = create_app(
        db_path=tmp_path / "telemetry.db",
        api_token="test-api-token",
        metrics_enabled=True,
    )
    case = load_fixture_cases("evals/incidents.json")[0]
    headers = {
        "Authorization": "Bearer test-api-token",
        "X-Request-ID": "req-client-001",
    }

    with TestClient(app) as client:
        health = client.get("/healthz", headers={"X-Request-ID": "req-health-001"})
        created = client.post(
            "/v1/investigations",
            json=case.task.model_dump(mode="json"),
            headers=headers,
        )
        loaded = client.get(
            f"/v1/investigations/{case.task.incident_id}",
            headers=headers,
        )
        replayed = client.post(
            "/v1/investigations",
            json=case.task.model_dump(mode="json"),
            headers={**headers, "X-Request-ID": "req-replay-001"},
        )
        conflicting_task = case.task.model_copy(update={"symptoms": ["different"]})
        conflict = client.post(
            "/v1/investigations",
            json=conflicting_task.model_dump(mode="json"),
            headers={**headers, "X-Request-ID": "req-conflict-001"},
        )
        metrics = client.get("/metrics")

    assert health.headers["x-request-id"] == "req-health-001"
    assert created.status_code == 201
    assert created.headers["x-request-id"] == "req-client-001"
    assert created.headers["x-sentinelops-trace-id"] == created.json()["trace_id"]
    assert loaded.status_code == 200
    assert replayed.status_code == 201
    assert conflict.status_code == 409
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain; version=0.0.4")
    body = metrics.text
    assert (
        'sentinelops_http_requests_total{method="GET",route="/healthz",status_class="2xx"} 1'
        in body
    )
    assert 'sentinelops_investigations_total{outcome="diagnosed"} 1' in body
    assert 'sentinelops_investigations_total{outcome="idempotent_replay"} 1' in body
    assert 'sentinelops_investigations_total{outcome="conflict"} 1' in body
    assert 'sentinelops_provider_queries_total{source="logs",status="ok"}' in body
    assert case.task.incident_id not in body
    assert case.task.tenant_id not in body

    audit_events = app.state.service.audit.list_events(trace_id=created.json()["trace_id"])
    started = next(event for event in audit_events if event["action"] == "investigation_started")
    assert started["details"]["request_id"] == "req-client-001"
    replay_event = next(event for event in audit_events if event["action"] == "idempotent_replay")
    assert replay_event["details"]["request_id"] == "req-replay-001"
    conflict_event = next(event for event in audit_events if event["action"] == "idempotency_conflict")
    assert conflict_event["details"]["request_id"] == "req-conflict-001"

    structured_events = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "sentinelops.http"
    ]
    assert any(event["request_id"] == "req-client-001" for event in structured_events)
    assert all(case.task.incident_id not in record.message for record in caplog.records)


def test_metrics_endpoint_is_disabled_by_default(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("SENTINELOPS_METRICS_ENABLED", raising=False)
    with TestClient(create_app(db_path=tmp_path / "no-metrics.db")) as client:
        response = client.get("/metrics")

    assert response.status_code == 404


def test_metrics_endpoint_can_be_enabled_from_environment(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SENTINELOPS_METRICS_ENABLED", "1")

    with TestClient(create_app(db_path=tmp_path / "env-metrics.db")) as client:
        response = client.get("/metrics")

    assert response.status_code == 200
    assert "sentinelops_build_info" in response.text
