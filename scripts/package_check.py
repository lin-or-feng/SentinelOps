"""Build and import a wheel outside the checkout; never publish it automatically."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]


def _run(arguments: list[str], *, cwd: Path, environment: dict[str, str]) -> None:
    subprocess.run(
        [sys.executable, *arguments],
        cwd=cwd,
        env=environment,
        check=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and verify an isolated SentinelOps wheel")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--index-url", help="optional package index for isolated build dependencies")
    args = parser.parse_args(argv)
    with ExitStack() as stack:
        if args.output_dir is None:
            wheel_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(
                prefix="sentinelops-wheel-"
            )))
        else:
            wheel_dir = args.output_dir.resolve()
            wheel_dir.mkdir(parents=True, exist_ok=True)
            if any(wheel_dir.iterdir()):
                raise ValueError("wheel output directory must be empty")
        install_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(
            prefix="sentinelops-install-"
        )))
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        if args.index_url is not None:
            parsed = urlsplit(args.index_url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("index URL must be HTTPS and contain no credentials or query")
            environment["PIP_INDEX_URL"] = args.index_url
        _run(
            ["-m", "pip", "wheel", "--disable-pip-version-check", "--no-deps",
             "--wheel-dir", str(wheel_dir), str(ROOT)],
            cwd=install_dir,
            environment=environment,
        )
        wheels = list(wheel_dir.glob("sentinelops-*.whl"))
        if len(wheels) != 1:
            raise RuntimeError("expected exactly one SentinelOps wheel")
        _run(
            ["-m", "pip", "install", "--disable-pip-version-check", "--no-deps",
             "--target", str(install_dir), str(wheels[0])],
            cwd=install_dir,
            environment=environment,
        )
        environment["PYTHONPATH"] = str(install_dir)
        environment["SENTINELOPS_INSTALL_TARGET"] = str(install_dir)
        smoke = (
            "import os; from pathlib import Path; import sentinelops; "
            "from importlib.resources import files; "
            "from sentinelops.api import create_app; "
            "from sentinelops.demo_web import create_demo_app; "
            "from sentinelops.operator_web import create_operator_app; "
            "assert Path(sentinelops.__file__).resolve().is_relative_to("
            "Path(os.environ['SENTINELOPS_INSTALL_TARGET']).resolve()), "
            "'wheel import resolved outside isolated target'; "
            "assets = files('sentinelops').joinpath('demo_assets'); "
            "assert all(assets.joinpath(name).is_file() for name in "
            "('index.html', 'app.css', 'app.js')), 'wheel is missing demo assets'; "
            "operator_assets = files('sentinelops').joinpath('operator_assets'); "
            "assert all(operator_assets.joinpath(name).is_file() for name in "
            "('index.html', 'app.css', 'app.js')), 'wheel is missing operator assets'; "
            "print('isolated wheel import and packaged assets passed')"
        )
        _run(["-c", smoke], cwd=install_dir, environment=environment)
        print(f"Package smoke passed: {wheels[0].name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
