"""Install repository-owned privacy hooks without copying files into .git."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    subprocess.run(
        ["git", "config", "--local", "core.hooksPath", ".githooks"],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        ["git", "config", "--local", "sentinelops.pythonPath", sys.executable],
        cwd=ROOT,
        check=True,
    )
    print("Installed privacy hooks and pinned their interpreter to the current Python.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
