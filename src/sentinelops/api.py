"""Local-first FastAPI boundary for bounded investigations and audit verification."""

from __future__ import annotations

import hmac
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from sentinelops import __version__
from sentinelops.domain import IncidentTask, InvestigationResult
from sentinelops.service import IncidentConflict, SentinelOpsService, create_service


def create_app(
    *,
    dataset_path: str | Path | None = None,
    db_path: str | Path | None = None,
    audit_key: str | bytes | None = None,
    api_token: str | None = None,
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
    )
    configured_token = api_token if api_token is not None else os.getenv("SENTINELOPS_API_TOKEN")
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

    @app.post(
        "/v1/investigations",
        response_model=InvestigationResult,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(authorize)],
        tags=["investigations"],
    )
    def investigate(task: IncidentTask) -> InvestigationResult:
        try:
            return service.investigate(task)
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
