"""Local-first FastAPI boundary for bounded investigations and audit verification."""

from __future__ import annotations

import hmac
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse

from sentinelops import __version__
from sentinelops.domain import IncidentTask, InvestigationResult
from sentinelops.edge import (
    EdgeController,
    EdgePolicy,
    RequestBodyLimitMiddleware,
    apply_security_headers,
    edge_policy_from_env,
)
from sentinelops.service import IncidentConflict, SentinelOpsService, create_service
from sentinelops.telemetry import (
    PROMETHEUS_CONTENT_TYPE,
    log_http_request,
    request_id_from_header,
    reset_request_id,
    set_request_id,
)


def create_app(
    *,
    dataset_path: str | Path | None = None,
    db_path: str | Path | None = None,
    audit_key: str | bytes | None = None,
    api_token: str | None = None,
    metrics_enabled: bool | None = None,
    edge_policy: EdgePolicy | None = None,
    orchestration_mode: str | None = None,
    service_instance: SentinelOpsService | None = None,
) -> FastAPI:
    resolved_dataset_path = dataset_path or os.getenv(
        "SENTINELOPS_DATASET_PATH", "evals/incidents.json"
    )
    resolved_db_path = db_path or os.getenv(
        "SENTINELOPS_DB_PATH", ".sentinelops/sentinelops.db"
    )
    service = service_instance or create_service(
        dataset_path=resolved_dataset_path,
        db_path=resolved_db_path,
        audit_key=audit_key if audit_key is not None else os.getenv("SENTINELOPS_AUDIT_KEY"),
        orchestration_mode=orchestration_mode,
    )
    configured_token = api_token if api_token is not None else os.getenv("SENTINELOPS_API_TOKEN")
    expose_metrics = (
        metrics_enabled
        if metrics_enabled is not None
        else os.getenv("SENTINELOPS_METRICS_ENABLED") == "1"
    )
    resolved_edge_policy = edge_policy or edge_policy_from_env()
    edge_controller = EdgeController(resolved_edge_policy)
    bearer = HTTPBearer(auto_error=False)

    def authorize(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> None:
        if not configured_token:
            return
        if credentials is None or not hmac.compare_digest(credentials.credentials, configured_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            service.close()

    app = FastAPI(
        title="SentinelOps API",
        version=__version__,
        description="Read-only, evidence-first incident investigation service.",
        lifespan=lifespan,
    )
    app.state.service = service
    app.state.edge_policy = resolved_edge_policy
    app.state.edge_controller = edge_controller
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(resolved_edge_policy.trusted_hosts),
        www_redirect=False,
    )
    if resolved_edge_policy.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(resolved_edge_policy.cors_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
            expose_headers=["X-Request-ID", "X-SentinelOps-Trace-ID"],
        )
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_request_bytes=resolved_edge_policy.max_request_bytes,
    )

    @app.middleware("http")
    async def observe_request(request: Request, call_next):
        request_id = request_id_from_header(request.headers.get("x-request-id"))
        token = set_request_id(request_id)
        started = time.perf_counter()
        status_code = 500
        admission = edge_controller.admit(request.url.path)
        try:
            if admission.allowed:
                response = await call_next(request)
            else:
                headers = {}
                if admission.retry_after_seconds is not None:
                    headers["Retry-After"] = str(admission.retry_after_seconds)
                response = JSONResponse(
                    {"detail": admission.detail},
                    status_code=admission.status_code or 503,
                    headers=headers,
                )
            status_code = response.status_code
            response.headers["X-Request-ID"] = request_id
            apply_security_headers(request.scope, response.headers)
            return response
        finally:
            edge_controller.release(admission)
            route = getattr(request.scope.get("route"), "path", None) or request.url.path
            duration = time.perf_counter() - started
            service.metrics.record_http(
                method=request.method,
                route=route,
                status_code=status_code,
                duration_seconds=duration,
            )
            log_http_request(
                request_id=request_id,
                method=request.method,
                route=route or "unmatched",
                status_code=status_code,
                duration_seconds=duration,
            )
            reset_request_id(token)

    @app.get("/healthz", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", tags=["system"])
    def readiness() -> dict[str, str]:
        if not service.is_ready():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="service is not ready",
            )
        return {"status": "ready"}

    if expose_metrics:
        @app.get("/metrics", tags=["system"], include_in_schema=False)
        def metrics() -> Response:
            return Response(
                content=service.metrics.render_prometheus(),
                media_type=PROMETHEUS_CONTENT_TYPE,
            )

    @app.post(
        "/v1/investigations",
        response_model=InvestigationResult,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(authorize)],
        tags=["investigations"],
    )
    def investigate(task: IncidentTask, response: Response) -> InvestigationResult:
        try:
            result = service.investigate(task)
            response.headers["X-SentinelOps-Trace-ID"] = result.trace_id
            return result
        except IncidentConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get(
        "/v1/investigations/{incident_id}",
        response_model=InvestigationResult,
        dependencies=[Depends(authorize)],
        tags=["investigations"],
    )
    def get_investigation(incident_id: str) -> InvestigationResult:
        result = service.store.get(incident_id)
        if result is None:
            raise HTTPException(status_code=404, detail="investigation not found")
        return result

    @app.get(
        "/v1/audit/verify",
        dependencies=[Depends(authorize)],
        tags=["audit"],
    )
    def verify_audit() -> dict[str, object]:
        return service.audit.verify().as_dict()

    @app.get(
        "/v1/audit/events",
        dependencies=[Depends(authorize)],
        tags=["audit"],
    )
    def audit_events(
        trace_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, object]]:
        return service.audit.list_events(trace_id=trace_id, limit=limit)

    return app
