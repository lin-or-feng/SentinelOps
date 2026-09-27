import asyncio

import pytest
from fastapi.testclient import TestClient

from sentinelops.api import create_app
from sentinelops.edge import (
    EdgeController,
    EdgePolicy,
    InflightLimiter,
    RequestBodyLimitMiddleware,
    SlidingWindowLimiter,
    edge_policy_from_env,
)


def test_edge_policy_rejects_wildcards_and_insecure_remote_origins() -> None:
    with pytest.raises(ValueError, match="trusted_hosts"):
        EdgePolicy(trusted_hosts=("*",))
    with pytest.raises(ValueError, match="cors_origins"):
        EdgePolicy(cors_origins=("*",))
    with pytest.raises(ValueError, match="cors_origins"):
        EdgePolicy(cors_origins=("http://console.example.com",))

    policy = EdgePolicy(cors_origins=("http://127.0.0.1:8501", "https://ops.example.com"))
    assert policy.cors_origins == ("http://127.0.0.1:8501", "https://ops.example.com")


def test_edge_policy_environment_is_validated() -> None:
    policy = edge_policy_from_env(
        {
            "SENTINELOPS_MAX_REQUEST_BYTES": "2048",
            "SENTINELOPS_RATE_LIMIT_RPM": "30",
            "SENTINELOPS_MAX_INFLIGHT": "4",
            "SENTINELOPS_TRUSTED_HOSTS": "localhost,api.internal",
            "SENTINELOPS_CORS_ORIGINS": "http://localhost:8501,https://ops.example.com",
        }
    )
    assert policy.max_request_bytes == 2048
    assert policy.rate_limit_requests == 30
    assert policy.max_inflight == 4
    assert policy.trusted_hosts == ("localhost", "api.internal")

    with pytest.raises(ValueError, match="SENTINELOPS_RATE_LIMIT_RPM"):
        edge_policy_from_env({"SENTINELOPS_RATE_LIMIT_RPM": "many"})


def test_sliding_window_expires_old_requests() -> None:
    now = [100.0]
    limiter = SlidingWindowLimiter(
        limit=2,
        window_seconds=10.0,
        clock=lambda: now[0],
    )

    assert limiter.allow().allowed is True
    assert limiter.allow().allowed is True
    denied = limiter.allow()
    assert denied.allowed is False
    assert denied.retry_after_seconds == 10

    now[0] = 110.0
    assert limiter.allow().allowed is True


def test_inflight_limiter_and_controller_do_not_queue_unbounded_work() -> None:
    limiter = InflightLimiter(1)
    assert limiter.acquire() is True
    assert limiter.acquire() is False
    limiter.release()
    assert limiter.acquire() is True
    limiter.release()

    controller = EdgeController(EdgePolicy(max_inflight=1))
    first = controller.admit("/v1/audit/verify")
    second = controller.admit("/v1/audit/events")
    assert first.allowed is True
    assert second.allowed is False
    assert second.status_code == 503
    controller.release(first)


def test_body_limit_checks_streamed_size_without_echoing_content() -> None:
    called = False

    async def inner(scope, receive, send) -> None:
        nonlocal called
        called = True

    middleware = RequestBodyLimitMiddleware(inner, max_request_bytes=1024)
    messages = iter(
        [
            {"type": "http.request", "body": b"private-value-" + b"a" * 690, "more_body": True},
            {"type": "http.request", "body": b"b" * 400, "more_body": False},
        ]
    )
    sent = []

    async def receive():
        return next(messages)

    async def send(message) -> None:
        sent.append(message)

    scope = {"type": "http", "method": "POST", "headers": [], "scheme": "http"}
    asyncio.run(middleware(scope, receive, send))

    assert called is False
    assert sent[0]["status"] == 413
    response_body = sent[1]["body"].decode("utf-8")
    assert "private-value" not in response_body
    assert "request body too large" in response_body


def test_api_enforces_body_rate_host_and_security_boundaries(tmp_path) -> None:
    policy = EdgePolicy(
        max_request_bytes=1024,
        rate_limit_requests=1,
        max_inflight=2,
    )
    app = create_app(db_path=tmp_path / "edge.db", edge_policy=policy)

    with TestClient(app) as client:
        first = client.get("/v1/investigations/missing")
        limited = client.get("/v1/investigations/missing-again")
        health = client.get("/healthz")

    assert first.status_code == 404
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"
    assert health.status_code == 200
    for response in (first, limited, health):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["content-security-policy"] == "frame-ancestors 'none'"
        assert response.headers["cache-control"] == "no-store"
        assert "strict-transport-security" not in response.headers

    with TestClient(
        create_app(db_path=tmp_path / "large.db", edge_policy=policy)
    ) as client:
        oversized = client.post(
            "/v1/investigations",
            content=b"x" * 1025,
            headers={"Content-Type": "application/json"},
        )
    assert oversized.status_code == 413
    assert oversized.json() == {"detail": "request body too large"}
    assert oversized.headers["x-content-type-options"] == "nosniff"

    evil_client = TestClient(
        create_app(db_path=tmp_path / "host.db", edge_policy=policy),
        base_url="http://evil.example",
    )
    assert evil_client.get("/healthz").status_code == 400


def test_api_uses_exact_cors_origins_and_https_hsts(tmp_path) -> None:
    policy = EdgePolicy(cors_origins=("https://console.example.com",))
    app = create_app(db_path=tmp_path / "cors.db", edge_policy=policy)

    with TestClient(app, base_url="https://testserver") as client:
        secure = client.get("/healthz")
        allowed = client.options(
            "/v1/investigations",
            headers={
                "Origin": "https://console.example.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        denied = client.options(
            "/v1/investigations",
            headers={
                "Origin": "https://evil.example.com",
                "Access-Control-Request-Method": "POST",
            },
        )

    assert secure.headers["strict-transport-security"].startswith("max-age=31536000")
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "https://console.example.com"
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers
