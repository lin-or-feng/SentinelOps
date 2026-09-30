"""The manual browser fixture must stay visibly separate from the real desk."""

from fastapi.testclient import TestClient

from scripts.operator_offline_smoke import create_offline_app


def test_offline_browser_fixture_is_labelled_and_local(tmp_path) -> None:
    token = "offline-test-token-longer-than-thirty-two-bytes"
    app = create_offline_app(tmp_path / "smoke.db", token)
    with TestClient(app) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "OFFLINE TEST · 假来源" in page.text
        assert "绝不连接真实监控" in page.text
        assert "REAL DATA · 非演示" not in page.text
        assert page.headers["content-security-policy"].startswith("default-src 'none'")
        script = client.get("/assets/app.js")
        assert script.status_code == 200
        assert "offlineScriptLoaded" in script.text
        status = client.get("/api/status", headers={"Authorization": f"Bearer {token}"})
        assert status.status_code == 200
        assert status.json()["sources"] == ["logs", "metrics"]
