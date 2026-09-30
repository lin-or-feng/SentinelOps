"""Loopback-only operator desk for explicitly configured real, read-only sources."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from sentinelops import __version__
from sentinelops.adapters.observability import (
    ObservabilityEvidenceTool,
    observability_tool_from_env,
)
from sentinelops.application.deployment_check import check_pilot_deployment
from sentinelops.application.operator_flow import check_observability_sources
from sentinelops.domain import IncidentTask
from sentinelops.edge import RequestBodyLimitMiddleware, SlidingWindowLimiter
from sentinelops.privacy import scan_content
from sentinelops.service import IncidentConflict, SentinelOpsService, create_service


ASSETS = Path(__file__).with_name("operator_assets")
_MAX_BODY = 8_192
_LOG = logging.getLogger(__name__)


def _local_client(request: Request) -> bool:
    host = request.client.host if request.client else ""
    if host == "testclient":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


async def _task_from_request(request: Request, *, require_confirmation: bool) -> IncidentTask:
    raw = await request.body()
    if not raw or len(raw) > _MAX_BODY:
        raise HTTPException(422, "invalid_task")
    try:
        if scan_content("operator-task.json", raw):
            raise HTTPException(422, "task_failed_privacy_check")
        payload = json.loads(raw)
        if require_confirmation:
            if not isinstance(payload, dict) or payload.get("confirmed") is not True:
                raise HTTPException(422, "explicit_confirmation_required")
            if set(payload) != {"task", "confirmed"}:
                raise HTTPException(422, "invalid_task")
            payload = payload["task"]
        return IncidentTask.model_validate(payload)
    except (UnicodeDecodeError, ValueError, TypeError, ValidationError) as exc:
        raise HTTPException(422, "invalid_task") from exc


async def _incident_id_from_request(request: Request) -> str:
    raw = await request.body()
    if not raw or len(raw) > _MAX_BODY:
        raise HTTPException(422, "invalid_incident_id")
    try:
        if scan_content("operator-lookup.json", raw):
            raise HTTPException(422, "lookup_failed_privacy_check")
        payload = json.loads(raw)
        if not isinstance(payload, dict) or set(payload) != {"incident_id"}:
            raise HTTPException(422, "invalid_incident_id")
        incident_id = payload["incident_id"]
        if not isinstance(incident_id, str) or not 3 <= len(incident_id) <= 120:
            raise HTTPException(422, "invalid_incident_id")
        return incident_id
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise HTTPException(422, "invalid_incident_id") from exc


def _task_fingerprint(task: IncidentTask) -> str:
    canonical = json.dumps(task.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def create_operator_app(*, service: SentinelOpsService, api_token: str) -> FastAPI:
    """Create an isolated UI; production composition supplies only observability tools."""
    if not isinstance(service.evidence_tool, ObservabilityEvidenceTool):
        raise ValueError("operator desk requires a real observability tool")
    if not api_token or len(api_token.encode("utf-8")) < 32:
        raise ValueError("operator desk requires a strong API token")
    limiter = SlidingWindowLimiter(limit=12, window_seconds=60)
    in_flight = threading.Lock()
    preflight_lock = threading.Lock()
    checked_task: tuple[str, float] | None = None

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            service.close()

    app = FastAPI(
        title="SentinelOps 本机真实调查台", version=__version__,
        docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan,
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost", "testserver"],
        www_redirect=False,
    )
    app.add_middleware(RequestBodyLimitMiddleware, max_request_bytes=_MAX_BODY)

    @app.middleware("http")
    async def operator_boundary(request: Request, call_next):
        if not _local_client(request):
            response = JSONResponse({"detail": "loopback_clients_only"}, status_code=403)
        elif request.url.path.startswith("/api/") and not hmac.compare_digest(
            request.headers.get("authorization", ""), f"Bearer {api_token}"
        ):
            response = JSONResponse({"detail": "invalid_bearer_token"}, status_code=401)
        elif request.method == "POST" and (
            request.headers.get("origin") is not None
            and request.headers["origin"] != str(request.base_url).rstrip("/")
        ):
            response = JSONResponse({"detail": "cross_origin_denied"}, status_code=403)
        elif request.method == "POST" and (
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            response = JSONResponse({"detail": "json_required"}, status_code=415)
        else:
            response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'"
        )
        return response

    @app.get("/", include_in_schema=False)
    def home() -> FileResponse:
        return FileResponse(ASSETS / "index.html", media_type="text/html; charset=utf-8")

    @app.get("/assets/{name}", include_in_schema=False)
    def asset(name: Literal["app.css", "app.js"]) -> FileResponse:
        media_type = "text/css" if name == "app.css" else "text/javascript"
        return FileResponse(ASSETS / name, media_type=media_type)

    @app.get("/api/status")
    def status() -> dict[str, object]:
        return {
            "mode": "real_read_only",
            "ready": service.is_ready(),
            "sources": sorted(source.value for source in service.evidence_tool.sources),
            "ai_decision_enabled": False,
            "note": "Static readiness does not verify provider connectivity or evidence relevance.",
        }

    @app.post("/api/provider-check")
    async def provider_check(request: Request) -> dict[str, object]:
        nonlocal checked_task
        task = await _task_from_request(request, require_confirmation=False)
        rate = limiter.allow()
        if not rate.allowed:
            raise HTTPException(429, "operator_rate_limited")
        if not in_flight.acquire(blocking=False):
            raise HTTPException(429, "operator_busy")
        try:
            summary = await run_in_threadpool(
                check_observability_sources, service.evidence_tool, task
            )
            with preflight_lock:
                checked_task = (
                    (_task_fingerprint(task), time.monotonic())
                    if summary["all_reachable"] else None
                )
            return summary
        finally:
            in_flight.release()

    @app.post("/api/investigate")
    async def investigate(request: Request) -> dict[str, object]:
        nonlocal checked_task
        task = await _task_from_request(request, require_confirmation=True)
        rate = limiter.allow()
        if not rate.allowed:
            raise HTTPException(429, "operator_rate_limited")
        if not in_flight.acquire(blocking=False):
            raise HTTPException(429, "operator_busy")
        try:
            with preflight_lock:
                valid_check = (
                    checked_task is not None
                    and checked_task[0] == _task_fingerprint(task)
                    and time.monotonic() - checked_task[1] < 300
                )
                checked_task = None
            if not valid_check:
                raise HTTPException(409, "matching_provider_check_required")
            try:
                result = await run_in_threadpool(service.investigate, task)
                return await _render_result(result)
            except IncidentConflict as exc:
                raise HTTPException(409, "incident_id_conflict_or_reserved") from exc
            except HTTPException:
                raise
            except Exception as exc:
                _LOG.error("operator investigation or audit failed: %s", type(exc).__name__)
                raise HTTPException(503, "investigation_failed_review_server_logs") from exc
        finally:
            in_flight.release()

    async def _render_result(result) -> dict[str, object]:
        verification = await run_in_threadpool(service.audit.verify)
        if not verification.valid:
            raise HTTPException(503, "audit_chain_invalid")
        events = await run_in_threadpool(
            service.audit.list_events, trace_id=result.trace_id, limit=100
        )
        return {
            "result": result.model_dump(mode="json"),
            "audit": verification.as_dict(),
            "audit_events": events,
            "note": "Evidence bodies are not persisted or returned by this desk; verify references in the source system.",
        }

    @app.post("/api/recover")
    async def recover(request: Request) -> dict[str, object]:
        incident_id = await _incident_id_from_request(request)
        rate = limiter.allow()
        if not rate.allowed:
            raise HTTPException(429, "operator_rate_limited")
        try:
            result = await run_in_threadpool(service.store.get, incident_id)
            if result is None:
                raise HTTPException(404, "completed_investigation_not_found")
            return await _render_result(result)
        except HTTPException:
            raise
        except Exception as exc:
            _LOG.error("operator recovery or audit failed: %s", type(exc).__name__)
            raise HTTPException(503, "recovery_failed_review_server_logs") from exc

    @app.post("/api/run-state")
    async def run_state(request: Request) -> dict[str, object]:
        """Read local reservation state without reissuing any provider query."""
        incident_id = await _incident_id_from_request(request)
        rate = limiter.allow()
        if not rate.allowed:
            raise HTTPException(429, "operator_rate_limited")
        try:
            verification = await run_in_threadpool(service.audit.verify)
            if not verification.valid:
                raise HTTPException(503, "audit_chain_invalid")
            reservation = await run_in_threadpool(service.run_journal.get, incident_id)
            saved = await run_in_threadpool(service.store.get, incident_id)
            return {
                "state": reservation[2] if reservation is not None else "not_found",
                "result_saved": saved is not None,
                "note": "Local snapshot only; running may be stale after interruption. Never auto-retry a reserved incident.",
            }
        except HTTPException:
            raise
        except Exception as exc:
            _LOG.error("operator run-state lookup failed: %s", type(exc).__name__)
            raise HTTPException(503, "run_state_failed_review_server_logs") from exc

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the loopback-only real observability desk")
    parser.add_argument("--db", type=Path, required=True, help="absolute path to a controlled SQLite file")
    parser.add_argument("--port", type=int, default=8767)
    args = parser.parse_args(argv)
    if not args.db.is_absolute() or args.db.is_symlink() or not 1 <= args.port <= 65535:
        parser.error("--db must be an absolute non-symlink path and --port must be valid")
    source_checkout = Path(__file__).resolve().parents[2]
    if (source_checkout / "pyproject.toml").is_file() and args.db.resolve().is_relative_to(
        source_checkout
    ):
        parser.error("--db must be outside the source checkout")
    report = check_pilot_deployment()
    if not report["valid"]:
        print("pilot preflight failed: " + ", ".join(report["blockers"]))
        return 2
    tool = None
    try:
        tool = observability_tool_from_env()
        service = create_service(
            db_path=args.db,
            audit_key=os.environ["SENTINELOPS_AUDIT_KEY"],
            evidence_mode="observability",
            evidence_tool=tool,
            policy_mode="heuristic",
            shadow_mode="off",
        )
        app = create_operator_app(service=service, api_token=os.environ["SENTINELOPS_API_TOKEN"])
    except (ValueError, OSError, KeyError):
        if tool is not None:
            tool.close()
        print("operator configuration invalid")
        return 2
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=args.port, workers=1, access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
