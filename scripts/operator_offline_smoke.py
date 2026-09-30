"""Temporary loopback-only browser smoke fixture; never contacts a real provider.

Run only for manual offline acceptance. The generated token and database are
discarded when this process exits; do not use this entrypoint for real incidents.
"""

from __future__ import annotations

import argparse
import secrets
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import Request
from fastapi.responses import HTMLResponse, Response

from sentinelops.adapters.observability import ObservabilityEvidenceTool
from sentinelops.domain import EvidenceSource, QuerySpec
from sentinelops.operator_web import ASSETS, create_operator_app
from sentinelops.service import create_service


OFFLINE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    ),
}


class OfflineProvider:
    """Deterministic empty source; no sockets, credentials, or remote requests."""

    def __init__(self, source: EvidenceSource, *, query_delay_seconds: float = 0) -> None:
        self.source = source
        self.query_delay_seconds = query_delay_seconds

    def query(self, spec: QuerySpec) -> list:
        if spec.limit > 1 and self.query_delay_seconds:
            time.sleep(self.query_delay_seconds)
        return []

    def close(self) -> None:
        pass


def create_offline_app(db_path: Path, token: str, *, query_delay_seconds: float = 0):
    tool = ObservabilityEvidenceTool([
        OfflineProvider(EvidenceSource.METRICS, query_delay_seconds=query_delay_seconds),
        OfflineProvider(EvidenceSource.LOGS, query_delay_seconds=query_delay_seconds),
    ])
    service = create_service(
        db_path=db_path,
        audit_key=secrets.token_urlsafe(32),
        evidence_mode="observability",
        evidence_tool=tool,
        policy_mode="heuristic",
        shadow_mode="off",
    )
    app = create_operator_app(service=service, api_token=token)

    @app.middleware("http")
    async def offline_label(request: Request, call_next):
        if request.url.path == "/":
            html = (ASSETS / "index.html").read_text(encoding="utf-8")
            html = html.replace("本机真实调查台", "离线假来源验收台")
            html = html.replace("REAL DATA · 非演示", "OFFLINE TEST · 假来源")
            html = html.replace("只读 Pilot", "离线测试")
            html = html.replace(
                "此页面只连接已配置的只读监控来源。",
                "此页面只连接本进程内的假来源，绝不连接真实监控。",
            )
            html = html.replace("开始真实只读调查", "开始离线模拟调查")
            html = html.replace(
                "我已确认这是获批的只读调查，且任务字段准确。",
                "我已确认这是离线假来源测试，且任务字段准确。",
            )
            html = html.replace(
                "本机单实例 Pilot · 不构成生产上线批准",
                "离线假来源测试 · 不构成生产验收",
            )
            return HTMLResponse(html, headers=OFFLINE_HEADERS)
        if request.url.path == "/assets/app.js":
            script = (ASSETS / "app.js").read_text(encoding="utf-8")
            script = script.replace("真实只读", "离线假来源")
            script = script.replace("本机数据库", "临时测试数据库")
            script = script.replace("请填写获批事故", "请填写合成事故")
            script = "document.documentElement.dataset.offlineScriptLoaded = 'yes';\n" + script
            return Response(
                script, media_type="text/javascript",
                headers=OFFLINE_HEADERS,
            )
        return await call_next(request)

    return app


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="Run a loopback-only offline operator fixture")
    parser.add_argument("--query-delay-seconds", type=float, default=0)
    args = parser.parse_args()
    if not 0 <= args.query_delay_seconds <= 10:
        parser.error("--query-delay-seconds must be between 0 and 10")
    token = secrets.token_urlsafe(32)
    checkout = Path(__file__).resolve().parents[1]
    scratch = checkout / ".sentinelops"
    scratch.mkdir(exist_ok=True)
    if not scratch.resolve().is_relative_to(checkout):
        parser.error("offline scratch directory must stay within the checkout")
    with TemporaryDirectory(prefix="offline-", dir=scratch) as directory:
        app = create_offline_app(
            Path(directory) / "smoke.db", token,
            query_delay_seconds=args.query_delay_seconds,
        )
        print("OFFLINE TEST ONLY: http://127.0.0.1:8768/", flush=True)
        print(f"Temporary test token: {token}", flush=True)
        uvicorn.run(app, host="127.0.0.1", port=8768, workers=1, access_log=False)


if __name__ == "__main__":
    main()
