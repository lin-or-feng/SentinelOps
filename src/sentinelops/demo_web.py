"""Loopback-only fixture verification desk; no live adapters or model calls."""

from __future__ import annotations

import ipaddress
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from sentinelops import __version__
from sentinelops.adapters import load_fixture_cases
from sentinelops.application.demo_eval import evaluate_demo_cases
from sentinelops.application.assistant_preview import (
    AssistantContext,
    AssistantEvidence,
    AssistantReply,
    ExplanationAssistant,
    OllamaExplanationAssistant,
)
from sentinelops.domain import OrchestrationMode, StrictModel
from sentinelops.edge import RequestBodyLimitMiddleware, SlidingWindowLimiter
from sentinelops.model_policy import ModelPolicyError, ollama_policy_config_from_env
from sentinelops.privacy import scan_content


ASSETS = Path(__file__).with_name("demo_assets")


class DemoRunRequest(StrictModel):
    case_id: str = Field(min_length=3, max_length=120)
    mode: OrchestrationMode


class AssistantRequest(StrictModel):
    run_id: str = Field(pattern=r"^[A-Za-z0-9_-]{16,64}$")
    incident_id: str = Field(min_length=3, max_length=120)
    question: str = Field(min_length=3, max_length=300)


class _RunCache:
    """Bounded, short-lived fixture results; never stores model answers."""

    def __init__(self, *, max_runs: int = 12, ttl_seconds: float = 600.0) -> None:
        self.max_runs = max_runs
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._runs: dict[str, tuple[float, dict[str, object]]] = {}

    def put(self, report: dict[str, object]) -> str:
        now = time.monotonic()
        run_id = secrets.token_urlsafe(18)
        with self._lock:
            self._prune(now)
            if len(self._runs) >= self.max_runs:
                oldest = min(self._runs, key=lambda key: self._runs[key][0])
                del self._runs[oldest]
            self._runs[run_id] = (now, report)
        return run_id

    def get(self, run_id: str) -> dict[str, object] | None:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            item = self._runs.get(run_id)
        return None if item is None else item[1]

    def _prune(self, now: float) -> None:
        for key, (created, _) in list(self._runs.items()):
            if now - created >= self.ttl_seconds:
                del self._runs[key]


def _local_client(request: Request) -> bool:
    host = request.client.host if request.client else ""
    if host == "testclient":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def create_demo_app(
    *, dataset_path: str | Path = "evals/incidents.json",
    assistant: ExplanationAssistant | None = None,
) -> FastAPI:
    cases = load_fixture_cases(dataset_path)
    if len(cases) > 20 or len({case.task.incident_id for case in cases}) != len(cases):
        raise ValueError("demo fixtures must have 1-20 unique incidents")
    by_id = {case.task.incident_id: case for case in cases}
    limiter = SlidingWindowLimiter(limit=12, window_seconds=60)
    in_flight = threading.Lock()
    assistant_limiter = SlidingWindowLimiter(limit=12, window_seconds=60)
    assistant_in_flight = threading.Lock()
    runs = _RunCache()
    app = FastAPI(
        title="SentinelOps 本地验证台",
        version=__version__,
        docs_url=None, redoc_url=None, openapi_url=None,
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost", "testserver"],
        www_redirect=False,
    )
    app.add_middleware(RequestBodyLimitMiddleware, max_request_bytes=4_096)

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        if not _local_client(request):
            return JSONResponse({"detail": "loopback clients only"}, status_code=403)
        if request.method == "POST":
            origin = request.headers.get("origin")
            if origin is not None and origin != str(request.base_url).rstrip("/"):
                return JSONResponse({"detail": "cross-origin request denied"}, status_code=403)
            if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                return JSONResponse({"detail": "JSON content type required"}, status_code=415)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
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

    @app.get("/api/cases")
    def list_cases() -> dict[str, object]:
        return {
            "version": __version__,
            "cases": [
                {
                    "incident_id": case.task.incident_id,
                    "service": case.task.service,
                    "symptoms": case.task.symptoms,
                    "expected_code": case.expected_root_cause,
                }
                for case in cases
            ],
        }

    @app.post("/api/run")
    def run_demo(payload: DemoRunRequest) -> dict[str, object]:
        if payload.case_id == "all":
            selected = cases
        elif payload.case_id in by_id:
            selected = [by_id[payload.case_id]]
        else:
            selected = None
        if selected is None:
            raise HTTPException(status_code=404, detail="fixture incident not found")
        rate = limiter.allow()
        if not rate.allowed:
            raise HTTPException(
                status_code=429, detail="demo rate limit reached",
                headers={"Retry-After": str(rate.retry_after_seconds)},
            )
        if not in_flight.acquire(blocking=False):
            raise HTTPException(status_code=429, detail="demo run already in progress")
        try:
            report = evaluate_demo_cases(list(selected), payload.mode)
            report["run_id"] = runs.put(report)
            return report
        finally:
            in_flight.release()

    @app.get("/api/assistant/status")
    def assistant_status() -> dict[str, object]:
        return {"enabled": assistant is not None, "mode": "advisory_only"}

    @app.post("/api/assistant")
    def explain(payload: AssistantRequest) -> dict[str, object]:
        if assistant is None:
            raise HTTPException(status_code=503, detail="local assistant is disabled")
        if scan_content("assistant-question.txt", payload.question.encode("utf-8")):
            raise HTTPException(status_code=422, detail="question failed privacy check")
        report = runs.get(payload.run_id)
        if report is None:
            raise HTTPException(status_code=404, detail="run expired or not found")
        matching = [
            item for item in report["results"]
            if item["incident_id"] == payload.incident_id
        ]
        if not matching:
            raise HTTPException(status_code=404, detail="incident not in run")
        item = matching[0]
        used = [evidence for evidence in item["evidence"] if evidence["used"]][:8]
        if not used:
            raise HTTPException(status_code=409, detail="no cited evidence for explanation")
        rate = assistant_limiter.allow()
        if not rate.allowed:
            raise HTTPException(
                status_code=429, detail="assistant rate limit reached",
                headers={"Retry-After": str(rate.retry_after_seconds)},
            )
        if not assistant_in_flight.acquire(blocking=False):
            raise HTTPException(status_code=429, detail="assistant already in progress")
        try:
            context = AssistantContext(
                service=item["service"], symptoms=item["symptoms"],
                decision=item["actual_code"] or "needs_human",
                question=payload.question,
                evidence=[
                    AssistantEvidence(
                        evidence_id=evidence["id"], source=evidence["source"],
                        summary=evidence["summary"],
                    )
                    for evidence in used
                ],
            )
            reply = assistant.answer(context)
            reply = AssistantReply.model_validate(reply)
            allowed_refs = {evidence.evidence_id for evidence in context.evidence}
            if reply.decision != context.decision:
                raise ModelPolicyError("verdict_mismatch")
            if (
                len(reply.evidence_refs) != len(set(reply.evidence_refs))
                or not set(reply.evidence_refs).issubset(allowed_refs)
            ):
                raise ModelPolicyError("unsupported_evidence_reference")
        except ModelPolicyError as exc:
            return {"status": "unavailable", "reason_code": exc.reason_code}
        finally:
            assistant_in_flight.release()
        return {
            "status": "advisory",
            "decision_unchanged": True,
            "reply": reply.model_dump(mode="json"),
        }

    return app


if __name__ == "__main__":
    import uvicorn
    preview = None
    if os.getenv("SENTINELOPS_DEMO_ASSISTANT", "off").casefold() == "ollama":
        preview = OllamaExplanationAssistant(ollama_policy_config_from_env())
    try:
        uvicorn.run(create_demo_app(assistant=preview), host="127.0.0.1", port=8765, workers=1)
    finally:
        if preview is not None:
            preview.close()
