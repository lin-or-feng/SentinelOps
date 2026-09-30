"""Closed-loop and boundary tests for the loopback fixture verification desk."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinelops.audit import AuditLog, AuditVerification
from sentinelops.demo_web import create_demo_app


def test_demo_serves_local_assets_and_only_fixture_metadata() -> None:
    with TestClient(create_demo_app()) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "本地验证台" in page.text
        assert "只读 AI 助手" in page.text
        assert "script-src 'self'" in page.headers["content-security-policy"]
        assert "https://" not in page.text
        assert client.get("/assets/app.css").status_code == 200
        assert client.get("/assets/app.js").status_code == 200
        assert "assistant-form" in client.get("/assets/app.js").text
        assert client.get("/assets/unknown.js").status_code == 422
        listing = client.get("/api/cases").json()
        assert len(listing["cases"]) == 4
        assert all(item["incident_id"].startswith("inc-") for item in listing["cases"])
        assert "evidence" not in str(listing)


@pytest.mark.parametrize("mode", ["single", "multi", "auto"])
def test_demo_all_cases_complete_closed_loop_with_real_audit(
    mode, monkeypatch
) -> None:
    # The demo must ignore global live-adapter and model settings.
    monkeypatch.setenv("SENTINELOPS_EVIDENCE_MODE", "observability")
    monkeypatch.setenv("SENTINELOPS_POLICY_MODE", "ollama")
    monkeypatch.setenv("SENTINELOPS_SPECIALIST_SHADOW", "ollama")
    with TestClient(create_demo_app()) as client:
        response = client.post("/api/run", json={"case_id": "all", "mode": mode})
    assert response.status_code == 200
    report = response.json()
    assert report["case_count"] == report["passed_count"] == report["correct_count"] == 4
    assert report["all_passed"] is True
    assert report["requested_mode"] == mode
    for item in report["results"]:
        assert item["passed"] is True
        assert all(item["checks"].values())
        assert item["audit"]["valid"] is True
        assert item["audit"]["event_count"] == len(item["audit_events"])
        assert item["trace"]
        assert any(evidence["used"] for evidence in item["evidence"])
        assert item["expected_code"] == item["actual_code"]
        assert item["trace_id"].startswith("trace-")
        if mode == "multi":
            assert item["assignments"]
            assert all(assignment["state"] == "completed" for assignment in item["assignments"])
        if mode == "single":
            assert item["assignments"] == []


def test_demo_rejects_unlisted_cases_invalid_modes_and_cross_origin() -> None:
    with TestClient(create_demo_app()) as client:
        assert client.post("/api/run", json={"case_id": "missing", "mode": "multi"}).status_code == 404
        assert client.post("/api/run", json={"case_id": "all", "mode": "live"}).status_code == 422
        assert client.post("/api/run", json={"case_id": "all", "mode": "multi", "dataset_path": "other.json"}).status_code == 422
        assert client.post(
            "/api/run", json={"case_id": "all", "mode": "multi"},
            headers={"Origin": "https://example.invalid"},
        ).status_code == 403
        assert client.post(
            "/api/run", content="case_id=all&mode=multi",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ).status_code == 415
        assert client.post(
            "/api/run", content=b"x" * 4_097,
            headers={"Content-Type": "application/json"},
        ).status_code == 413
        assert client.get("/", headers={"Host": "example.invalid"}).status_code == 400


def test_demo_rejects_non_loopback_client() -> None:
    with TestClient(create_demo_app(), client=("198.51.100.25", 44321)) as client:
        response = client.get("/api/cases")
    assert response.status_code == 403


def test_demo_audit_failure_fails_closed_loop(monkeypatch) -> None:
    monkeypatch.setattr(
        AuditLog, "verify",
        lambda self: AuditVerification(False, 1, self.algorithm, 1),
    )
    with TestClient(create_demo_app()) as client:
        listing = client.get("/api/cases").json()
        case_id = listing["cases"][0]["incident_id"]
        response = client.post("/api/run", json={"case_id": case_id, "mode": "multi"})
    assert response.status_code == 200
    report = response.json()
    assert report["all_passed"] is False
    assert report["results"][0]["checks"]["audit_chain"] is False


def test_demo_repeat_uses_fresh_trace_and_cleans_temporary_database() -> None:
    scratch = Path(".sentinelops/demo-temp")
    with TestClient(create_demo_app()) as client:
        case_id = client.get("/api/cases").json()["cases"][0]["incident_id"]
        first = client.post("/api/run", json={"case_id": case_id, "mode": "multi"}).json()
        second = client.post("/api/run", json={"case_id": case_id, "mode": "multi"}).json()
    assert first["all_passed"] and second["all_passed"]
    assert first["results"][0]["trace_id"] != second["results"][0]["trace_id"]
    assert not list(scratch.glob("sentinelops-demo-*"))


def test_demo_rate_limit_is_bounded(monkeypatch) -> None:
    import sentinelops.demo_web as demo_web

    class RejectLimiter:
        def __init__(self, **kwargs):
            pass

        def allow(self):
            return type("Limit", (), {"allowed": False, "retry_after_seconds": 5})()

    monkeypatch.setattr(demo_web, "SlidingWindowLimiter", RejectLimiter)
    with TestClient(create_demo_app()) as client:
        response = client.post("/api/run", json={"case_id": "all", "mode": "multi"})
    assert response.status_code == 429
    assert response.headers["retry-after"] == "5"
