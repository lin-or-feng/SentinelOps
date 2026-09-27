"""Fail-fast local release gate shared with CI."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(*args: str) -> None:
    command = [sys.executable, *args]
    print(f"\n> {' '.join(command)}", flush=True)
    environment = os.environ.copy()
    source_path = str(ROOT / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, environment.get("PYTHONPATH", "")) if part
    )
    subprocess.run(command, cwd=ROOT, check=True, env=environment)


def main() -> int:
    run("-m", "compileall", "-q", "src", "tests", "scripts")
    run(str(ROOT / "scripts" / "privacy_guard.py"), "--tracked")
    run(str(ROOT / "scripts" / "static_audit.py"))
    run(
        "-m",
        "pytest",
        "--cov=sentinelops",
        "--cov-report=term-missing",
        "--cov-fail-under=80",
    )
    run("-m", "sentinelops", "baseline", "--min-top1", "1.0")
    print("\nSentinelOps release gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
