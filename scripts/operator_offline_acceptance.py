"""One-command, loopback-only acceptance harness for the OFFLINE TEST desk.

This does not read real provider configuration or grant release qualification.
It starts two disposable fake-provider servers, drives the installed Edge browser,
then writes an ignored JSON report and screenshots without persisting test tokens.
"""

from __future__ import annotations

import json
import gc
import secrets
import socket
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, Iterator

import uvicorn

from scripts.operator_offline_smoke import create_offline_app


HOST = "127.0.0.1"
PORT = 8768
REPORT_NAME = "operator-offline-acceptance.json"


def _scratch_directory() -> Path:
    checkout = Path(__file__).resolve().parents[1]
    scratch = checkout / ".sentinelops"
    scratch.mkdir(exist_ok=True)
    if not scratch.resolve().is_relative_to(checkout):
        raise RuntimeError("offline output directory must stay within the checkout")
    return scratch


@contextmanager
def _offline_server(db_path: Path, token: str, *, delay_seconds: float) -> Iterator[None]:
    # Never connect to an existing listener: that could be a real local service.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((HOST, PORT))
    app = create_offline_app(db_path, token, query_delay_seconds=delay_seconds)
    server = uvicorn.Server(uvicorn.Config(
        app, host=HOST, port=PORT, workers=1, access_log=False, log_config=None,
    ))
    worker = threading.Thread(target=server.run, name="offline-acceptance-server", daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            if not worker.is_alive() or time.monotonic() >= deadline:
                raise RuntimeError("offline fixture did not start")
            time.sleep(0.05)
        yield
    finally:
        server.should_exit = True
        worker.join(timeout=10)
        if worker.is_alive():
            raise RuntimeError("offline fixture did not stop cleanly")


def _stage(
    name: str,
    *,
    delay_seconds: float,
    browser_check: Callable[..., Path],
    scratch: Path,
    screenshot_name: str,
) -> dict[str, object]:
    token = secrets.token_urlsafe(32)
    screenshot = scratch / screenshot_name
    started = time.monotonic()
    try:
        with TemporaryDirectory(prefix="acceptance-", dir=scratch) as directory:
            with _offline_server(Path(directory) / "fixture.db", token, delay_seconds=delay_seconds):
                result = browser_check(token, screenshot=screenshot)
            # SQLite context managers commit but do not close connections; after
            # the server thread exits, collect its request-scoped objects before
            # Windows attempts to remove the temporary fixture database.
            gc.collect()
    except Exception as exc:
        raise RuntimeError(str(exc).replace(token, "[TEMP_TOKEN]")) from None
    if result != screenshot or not screenshot.is_file():
        raise AssertionError("browser check did not produce its expected screenshot")
    return {
        "name": name,
        "status": "passed",
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "screenshot": str(screenshot),
    }


def main(
    checks: tuple[tuple[str, float, Callable[..., Path], str], ...] | None = None,
) -> int:
    scratch = _scratch_directory()
    stages: list[dict[str, object]] = []
    if checks is None:
        try:
            from scripts.operator_browser_acceptance import run as browser_acceptance
            from scripts.operator_browser_interruption import run as browser_interruption
        except ModuleNotFoundError as exc:
            if exc.name != "playwright":
                raise
            print("Browser acceptance requires Playwright Python and installed Microsoft Edge.")
            return 2
        checks = (
            ("browser_flow", 0.0, browser_acceptance, "operator-harness-browser.png"),
            ("browser_disconnect_recovery", 3.0, browser_interruption,
             "operator-harness-interruption.png"),
        )
    for name, delay, check, screenshot_name in checks:
        print(f"OFFLINE TEST ONLY: {name}", flush=True)
        try:
            stages.append(_stage(
                name, delay_seconds=delay, browser_check=check,
                scratch=scratch, screenshot_name=screenshot_name,
            ))
        except Exception as exc:
            # _stage scrubs its temporary token before propagating browser errors.
            detail = str(exc)
            stages.append({
                "name": name, "status": "failed", "error_type": type(exc).__name__,
                "error_excerpt": detail[:1200],
            })
            break
    status = "passed" if len(stages) == len(checks) and all(
        stage["status"] == "passed" for stage in stages
    ) else "failed"
    report = {
        "schema_version": 1,
        "mode": "OFFLINE TEST - fake in-process providers only",
        "status": status,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "stages": stages,
        "release_qualification": False,
        "limits": [
            "No real provider or approved incident was used.",
            "No independent accuracy or production deployment claim follows from this run.",
        ],
    }
    report_path = scratch / REPORT_NAME
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"OFFLINE TEST {status.upper()}: {report_path}", flush=True)
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
