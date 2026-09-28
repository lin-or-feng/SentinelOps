from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from pathlib import Path

from sentinelops.adapters import load_fixture_cases
from sentinelops.application import (
    ReplayDatasetError,
    compare_orchestration,
    evaluate_cases,
    load_replay_suite,
    run_replay_suite,
)
from sentinelops.application.policy_eval import (
    PolicyEvalDatasetError,
    evaluate_policy_suite,
    load_policy_eval_suite,
)
from sentinelops.audit import AuditLog
from sentinelops.domain import IncidentStatus
from sentinelops.service import create_service


DEFAULT_DATASET = Path("evals/incidents.json")
DEFAULT_REPLAY_DATASET = Path("evals/observability_replays.json")
DEFAULT_POLICY_DATASET = Path("evals/policy_cases.json")
DEFAULT_DB = Path(".sentinelops/sentinelops.db")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SentinelOps incident investigation")
    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline = subparsers.add_parser("baseline", help="run deterministic offline evaluation")
    baseline.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    baseline.add_argument("--min-top1", type=float, default=1.0)

    replay = subparsers.add_parser(
        "replay-check",
        help="validate privacy-gated observability response replays",
    )
    replay.add_argument("--dataset", type=Path, default=DEFAULT_REPLAY_DATASET)

    orchestration_eval = subparsers.add_parser(
        "orchestration-eval",
        help="compare bounded single and multi-agent orchestration",
    )
    orchestration_eval.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    orchestration_eval.add_argument("--min-top1", type=float, default=1.0)
    orchestration_eval.add_argument("--provider-delay-ms", type=float, default=25.0)

    policy_eval = subparsers.add_parser(
        "policy-eval",
        help="compare heuristic and controlled source-selection policies",
    )
    policy_eval.add_argument("--dataset", type=Path, default=DEFAULT_POLICY_DATASET)
    policy_eval.add_argument("--incident-dataset", type=Path, default=DEFAULT_DATASET)
    policy_eval.add_argument("--mode", choices=("replay", "ollama"), default="replay")
    policy_eval.add_argument("--max-cases", type=int, default=None)
    policy_eval.add_argument("--min-top1", type=float, default=1.0)
    policy_eval.add_argument("--min-safety", type=float, default=1.0)
    policy_eval.add_argument("--max-forbidden-rate", type=float, default=0.0)
    policy_eval.add_argument("--skip-downstream", action="store_true")

    investigate = subparsers.add_parser("investigate", help="run one bounded investigation")
    investigate.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    investigate.add_argument("--db", type=Path, default=DEFAULT_DB)
    investigate.add_argument("--incident-id", required=True)
    investigate.add_argument(
        "--orchestration-mode",
        choices=("single", "multi", "auto"),
        default=None,
    )

    verify = subparsers.add_parser("audit-verify", help="verify the append-only audit chain")
    verify.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    verify.add_argument("--db", type=Path, default=DEFAULT_DB)

    serve = subparsers.add_parser("serve", help="run the local FastAPI service")
    serve.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    serve.add_argument("--db", type=Path, default=DEFAULT_DB)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument(
        "--orchestration-mode",
        choices=("single", "multi", "auto"),
        default=None,
    )
    return parser


def _audit_key() -> str | None:
    return os.getenv("SENTINELOPS_AUDIT_KEY") or None


def _is_loopback_host(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    if not actual_argv:
        actual_argv = ["baseline"]
    args = build_parser().parse_args(actual_argv)

    if args.command == "baseline":
        summary = evaluate_cases(load_fixture_cases(args.dataset))
        print(json.dumps(summary.as_dict(), ensure_ascii=False, indent=2))
        return 0 if summary.top1_accuracy >= args.min_top1 and summary.evidence_validity == 1.0 else 1

    if args.command == "replay-check":
        try:
            summary = run_replay_suite(load_replay_suite(args.dataset))
        except ReplayDatasetError as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False, indent=2))
            return 2
        print(json.dumps(summary.as_dict(), ensure_ascii=False, indent=2))
        return 0 if summary.valid else 1

    if args.command == "orchestration-eval":
        summary = compare_orchestration(
            load_fixture_cases(args.dataset),
            provider_delay_ms=args.provider_delay_ms,
        )
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        single = summary["single"]
        multi = summary["multi"]
        auto = summary["auto"]
        assert isinstance(single, dict) and isinstance(multi, dict) and isinstance(auto, dict)
        valid = all(
            float(item["top1_accuracy"]) >= args.min_top1
            and float(item["evidence_validity"]) == 1.0
            for item in (single, multi, auto)
        )
        return 0 if valid else 1

    if args.command == "policy-eval":
        proposer = None
        try:
            suite = load_policy_eval_suite(args.dataset)
            fixture_cases = (
                None if args.skip_downstream else load_fixture_cases(args.incident_dataset)
            )
            if args.mode == "ollama":
                from sentinelops.model_policy import (
                    OllamaSourceProposer,
                    ollama_policy_config_from_env,
                )

                proposer = OllamaSourceProposer(
                    ollama_policy_config_from_env(),
                    collect_usage=True,
                )
            summary = evaluate_policy_suite(
                suite,
                mode=args.mode,
                proposer=proposer,
                fixture_cases=fixture_cases,
                max_cases=args.max_cases,
                min_top1=args.min_top1,
                min_safety=args.min_safety,
                max_forbidden_rate=args.max_forbidden_rate,
            )
        except (PolicyEvalDatasetError, ValueError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False, indent=2))
            return 2
        finally:
            closer = getattr(proposer, "close", None)
            if callable(closer):
                closer()
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        gates = summary["gates"]
        assert isinstance(gates, dict)
        return 0 if bool(gates["passed"]) else 1

    if args.command == "serve":
        if not _is_loopback_host(args.host) and not os.getenv("SENTINELOPS_API_TOKEN"):
            print(
                "refusing non-loopback bind without SENTINELOPS_API_TOKEN",
                file=sys.stderr,
            )
            return 2
        import uvicorn

        from sentinelops.api import create_app

        app = create_app(
            dataset_path=args.dataset,
            db_path=args.db,
            audit_key=_audit_key(),
            orchestration_mode=args.orchestration_mode,
        )
        uvicorn.run(app, host=args.host, port=args.port, workers=1)
        return 0

    if args.command == "audit-verify":
        verification = AuditLog(args.db, key=_audit_key()).verify()
        print(json.dumps(verification.as_dict(), ensure_ascii=False, indent=2))
        return 0 if verification.valid else 1

    service = create_service(
        dataset_path=args.dataset,
        db_path=args.db,
        audit_key=_audit_key(),
        orchestration_mode=args.orchestration_mode,
    )

    cases = load_fixture_cases(args.dataset)
    case = next((item for item in cases if item.task.incident_id == args.incident_id), None)
    if case is None:
        print(json.dumps({"error": "incident_id not found"}, ensure_ascii=False))
        return 2
    try:
        result = service.investigate(case.task)
    finally:
        service.close()
    print(result.model_dump_json(indent=2))
    return 0 if result.report.status == IncidentStatus.DIAGNOSED else 2
