from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinelops.adapters import load_fixture_cases
from sentinelops.application import evaluate_cases


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the SentinelOps deterministic baseline")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("evals/incidents.json"),
        help="Path to a schema_version=0.1 fixture dataset",
    )
    parser.add_argument("--min-top1", type=float, default=1.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = evaluate_cases(load_fixture_cases(args.dataset))
    print(json.dumps(summary.as_dict(), ensure_ascii=False, indent=2))
    return 0 if summary.top1_accuracy >= args.min_top1 and summary.evidence_validity == 1.0 else 1
