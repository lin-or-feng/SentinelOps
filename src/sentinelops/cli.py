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
    evaluate_policy_campaign,
    evaluate_policy_suite,
    load_policy_eval_suite,
    validate_policy_eval_report_destination,
    write_policy_eval_report,
)
from sentinelops.application.policy_compare import (
    PolicyCompareError,
    compare_policy_development_reports,
)
from sentinelops.application.incident_intake import (
    IncidentIntakeError,
    load_incident_intake_manifest,
    review_incident_intake,
)
from sentinelops.application.operator_flow import (
    OperatorInputError,
    check_observability_sources,
    load_operator_task,
)
from sentinelops.application.backup_drill import BackupDrillError, backup_and_restore_drill
from sentinelops.application.deployment_check import check_pilot_deployment
from sentinelops.application.shadow_eval import ShadowEvalError, evaluate_shadow_development
from sentinelops.application.shadow_qualification import (
    ShadowQualificationError,
    ShadowQualificationRegistry,
    run_shadow_qualification_campaign,
)
from sentinelops.application.policy_registry import (
    PolicyEvalRegistryError,
    authorize_policy_campaign,
    finalize_policy_qualification,
    register_policy_eval_dataset,
    validate_policy_eval_registry,
)
from sentinelops.audit import AuditLog
from sentinelops.adapters.observability import observability_tool_from_env
from sentinelops.domain import IncidentStatus
from sentinelops.service import create_service
from sentinelops.specialist_shadow import ShadowJournal


DEFAULT_DATASET = Path("evals/incidents.json")
DEFAULT_REPLAY_DATASET = Path("evals/observability_replays.json")
DEFAULT_POLICY_DATASET = Path("evals/policy_cases.json")
DEFAULT_POLICY_REGISTRY = Path("evals/policy_eval_registry.json")
DEFAULT_DB = Path(".sentinelops/sentinelops.db")
DEFAULT_SHADOW_REGISTRY = Path(".sentinelops/shadow-registry.db")
DEFAULT_INTAKE_MANIFEST = Path("evals/public_incident_candidates.json")


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

    intake = subparsers.add_parser(
        "incident-intake-check",
        help="read-only preflight of public incident metadata; never approves a dataset",
    )
    intake.add_argument("--manifest", type=Path, default=DEFAULT_INTAKE_MANIFEST)

    orchestration_eval = subparsers.add_parser(
        "orchestration-eval",
        help="compare bounded single and multi-agent orchestration",
    )
    orchestration_eval.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    orchestration_eval.add_argument("--min-top1", type=float, default=1.0)
    orchestration_eval.add_argument("--provider-delay-ms", type=float, default=25.0)

    shadow_report = subparsers.add_parser(
        "specialist-shadow-report",
        help="summarize metadata-only shadow observations without model calls",
    )
    shadow_report.add_argument("--db", type=Path, default=DEFAULT_DB)

    shadow_eval = subparsers.add_parser(
        "specialist-shadow-eval",
        help="compare recorded shadow specialists against development labels only",
    )
    shadow_eval.add_argument("--labels", type=Path, required=True)
    shadow_eval.add_argument("--db", type=Path, default=DEFAULT_DB)
    shadow_eval.add_argument("--model-name", required=True)
    shadow_eval.add_argument("--model-digest", required=True)
    shadow_eval.add_argument("--min-cases", type=int, default=20)

    shadow_registry = subparsers.add_parser(
        "specialist-shadow-registry-check",
        help="validate registered Specialist shadow datasets without model calls",
    )
    shadow_registry.add_argument("--registry", type=Path, default=DEFAULT_SHADOW_REGISTRY)

    shadow_register = subparsers.add_parser(
        "specialist-shadow-register",
        help="register a manually reviewed offline dataset as sealed",
    )
    shadow_register.add_argument("--registry", type=Path, default=DEFAULT_SHADOW_REGISTRY)
    shadow_register.add_argument("--dataset", type=Path, required=True)
    shadow_register.add_argument("--dataset-id", required=True)
    shadow_register.add_argument("--approval-ref", required=True)

    shadow_campaign = subparsers.add_parser(
        "specialist-shadow-campaign",
        help="run fresh repeated offline holdout shadow evaluation once",
    )
    shadow_campaign.add_argument("--registry", type=Path, default=DEFAULT_SHADOW_REGISTRY)
    shadow_campaign.add_argument("--dataset-id", required=True)
    shadow_campaign.add_argument("--report", type=Path, required=True)
    shadow_campaign.add_argument("--runs", type=int, default=3)

    policy_eval = subparsers.add_parser(
        "policy-eval",
        help="compare heuristic and controlled source-selection policies",
    )
    policy_eval.add_argument("--dataset", type=Path, default=DEFAULT_POLICY_DATASET)
    policy_eval.add_argument("--incident-dataset", type=Path, default=DEFAULT_DATASET)
    policy_eval.add_argument("--mode", choices=("replay", "ollama"), default="replay")
    policy_eval.add_argument("--max-cases", type=int, default=None)
    policy_eval.add_argument(
        "--split",
        choices=("all", "development", "holdout"),
        default="all",
    )
    policy_eval.add_argument("--min-top1", type=float, default=1.0)
    policy_eval.add_argument("--min-safety", type=float, default=1.0)
    policy_eval.add_argument("--max-forbidden-rate", type=float, default=0.0)
    policy_eval.add_argument("--min-model-success-rate", type=float, default=0.95)
    policy_eval.add_argument("--skip-downstream", action="store_true")
    policy_eval.add_argument("--output", type=Path, default=None)

    policy_compare = subparsers.add_parser(
        "policy-eval-dev-compare",
        help="compare two live development reports without accessing holdout",
    )
    policy_compare.add_argument("--baseline", type=Path, required=True)
    policy_compare.add_argument("--candidate", type=Path, required=True)

    policy_campaign = subparsers.add_parser(
        "policy-eval-campaign",
        help="repeat live Ollama holdout evaluation and enforce stability gates",
    )
    policy_campaign.add_argument("--dataset", type=Path, default=DEFAULT_POLICY_DATASET)
    policy_campaign.add_argument("--registry", type=Path, default=DEFAULT_POLICY_REGISTRY)
    policy_campaign.add_argument(
        "--dataset-id",
        default="source-selection-public-v1",
    )
    policy_campaign.add_argument(
        "--purpose",
        choices=("qualification", "regression"),
        default="qualification",
    )
    policy_campaign.add_argument("--incident-dataset", type=Path, default=DEFAULT_DATASET)
    policy_campaign.add_argument("--runs", type=int, default=3)
    policy_campaign.add_argument("--max-cases", type=int, default=None)
    policy_campaign.add_argument("--min-top1", type=float, default=1.0)
    policy_campaign.add_argument("--min-safety", type=float, default=1.0)
    policy_campaign.add_argument("--max-forbidden-rate", type=float, default=0.0)
    policy_campaign.add_argument("--min-model-success-rate", type=float, default=0.95)
    policy_campaign.add_argument("--min-run-pass-rate", type=float, default=1.0)
    policy_campaign.add_argument("--max-top1-spread", type=float, default=0.05)
    policy_campaign.add_argument("--min-prediction-stability", type=float, default=0.95)
    policy_campaign.add_argument("--skip-downstream", action="store_true")
    policy_campaign.add_argument("--output", type=Path, default=None)

    policy_registry = subparsers.add_parser(
        "policy-eval-registry-check",
        help="validate registered evaluation cohorts and lifecycle metadata",
    )
    policy_registry.add_argument("--registry", type=Path, default=DEFAULT_POLICY_REGISTRY)

    policy_register = subparsers.add_parser(
        "policy-eval-registry-register",
        help="validate and atomically register a new sealed evaluation dataset",
    )
    policy_register.add_argument("--registry", type=Path, default=DEFAULT_POLICY_REGISTRY)
    policy_register.add_argument("--dataset-id", required=True)
    policy_register.add_argument("--dataset", type=Path, required=True)

    investigate = subparsers.add_parser("investigate", help="run one bounded investigation")
    investigate.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    investigate.add_argument("--db", type=Path, default=DEFAULT_DB)
    incident_input = investigate.add_mutually_exclusive_group(required=True)
    incident_input.add_argument("--incident-id")
    incident_input.add_argument("--task-file", type=Path)
    investigate.add_argument(
        "--orchestration-mode",
        choices=("single", "multi", "auto"),
        default=None,
    )

    provider_check = subparsers.add_parser(
        "provider-check", help="explicitly query configured read-only sources without saving evidence"
    )
    provider_check.add_argument("--task-file", type=Path, required=True)

    backup_drill = subparsers.add_parser(
        "backup-drill", help="snapshot SQLite and verify an isolated restore without overwriting"
    )
    backup_drill.add_argument("--db", type=Path, default=DEFAULT_DB)
    backup_drill.add_argument("--output", type=Path, required=True)

    subparsers.add_parser(
        "deployment-check", help="validate the offline read-only pilot deployment profile"
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

    if args.command == "incident-intake-check":
        try:
            manifest, fingerprint = load_incident_intake_manifest(args.manifest)
        except IncidentIntakeError as exc:
            print(json.dumps({"structurally_valid": False, "error": str(exc)}, ensure_ascii=False))
            return 2
        result = review_incident_intake(manifest, fingerprint)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["blocked"] == 0 else 1

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

    if args.command == "specialist-shadow-report":
        if not args.db.is_file():
            print(json.dumps({"valid": False, "error": "shadow database not found"}))
            return 2
        print(json.dumps(ShadowJournal(args.db).summary(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "specialist-shadow-eval":
        try:
            summary = evaluate_shadow_development(
                args.labels, args.db,
                model_name=args.model_name,
                model_digest=args.model_digest,
                min_cases=args.min_cases,
            )
        except ShadowEvalError as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False))
            return 2
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary["development_gate_passed"] else 1

    if args.command == "specialist-shadow-registry-check":
        try:
            datasets = ShadowQualificationRegistry(args.registry).list_datasets()
        except ShadowQualificationError as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False))
            return 2
        print(json.dumps({"valid": True, "datasets": datasets}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "specialist-shadow-register":
        try:
            result = ShadowQualificationRegistry(args.registry).register(
                dataset_id=args.dataset_id,
                dataset_path=args.dataset,
                approval_ref=args.approval_ref,
            )
        except ShadowQualificationError as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "specialist-shadow-campaign":
        from sentinelops.model_policy import ollama_policy_config_from_env
        from sentinelops.specialist_shadow import OllamaHypothesisProposer

        proposer = None
        try:
            proposer = OllamaHypothesisProposer(ollama_policy_config_from_env())
            result = run_shadow_qualification_campaign(
                registry_path=args.registry,
                dataset_id=args.dataset_id,
                report_path=args.report,
                proposer=proposer,
                runs=args.runs,
            )
        except (ShadowQualificationError, ValueError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False))
            return 2
        finally:
            if proposer is not None:
                proposer.close()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["qualification_decision"] == "accepted" else 1

    if args.command == "policy-eval-registry-check":
        try:
            summary = validate_policy_eval_registry(args.registry)
        except PolicyEvalRegistryError as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False, indent=2))
            return 2
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if args.command == "policy-eval-registry-register":
        try:
            summary = register_policy_eval_dataset(
                args.registry,
                dataset_id=args.dataset_id,
                dataset_path=args.dataset,
            )
        except PolicyEvalRegistryError as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False, indent=2))
            return 2
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if args.command == "policy-eval-dev-compare":
        try:
            summary = compare_policy_development_reports(args.baseline, args.candidate)
        except PolicyCompareError as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False, indent=2))
            return 2
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if args.command == "policy-eval":
        proposer = None
        try:
            if args.mode == "ollama" and args.split != "development":
                raise PolicyEvalDatasetError(
                    "live single-run evaluation requires the development split; "
                    "use policy-eval-campaign for governed holdout evaluation"
                )
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
                min_model_success_rate=args.min_model_success_rate,
                split=args.split,
            )
            if args.output is not None:
                write_policy_eval_report(args.output, summary)
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

    if args.command == "policy-eval-campaign":
        proposer = None
        authorization: dict[str, object] | None = None
        try:
            from sentinelops.model_policy import (
                OllamaSourceProposer,
                SOURCE_SELECTION_PROMPT_ID,
                ollama_policy_config_from_env,
                source_selection_prompt_sha256,
            )

            if args.purpose == "qualification" and (
                args.max_cases is not None or args.skip_downstream
            ):
                raise PolicyEvalRegistryError(
                    "qualification requires the full holdout and downstream regression set"
                )
            if args.purpose == "qualification":
                if args.output is None:
                    raise PolicyEvalRegistryError(
                        "qualification requires a new --output JSON evidence report"
                    )
                validate_policy_eval_report_destination(args.output, require_new=True)
                if args.output.resolve() in {
                    args.dataset.resolve(),
                    args.incident_dataset.resolve(),
                    args.registry.resolve(),
                }:
                    raise PolicyEvalRegistryError(
                        "qualification report cannot replace an input or registry"
                    )
            suite = load_policy_eval_suite(args.dataset)
            fixture_cases = (
                None if args.skip_downstream else load_fixture_cases(args.incident_dataset)
            )
            proposer = OllamaSourceProposer(
                ollama_policy_config_from_env(),
                collect_usage=True,
            )
            prompt_id = getattr(proposer.config, "prompt_id", SOURCE_SELECTION_PROMPT_ID)
            authorization = authorize_policy_campaign(
                args.registry,
                dataset_id=args.dataset_id,
                dataset_path=args.dataset,
                purpose=args.purpose,
                model=proposer.config.model,
                model_digest=proposer.refresh_model_digest(),
                prompt_id=prompt_id,
                prompt_sha256=source_selection_prompt_sha256(prompt_id),
                runs=args.runs,
                required_top1=args.min_top1,
            )
            summary = evaluate_policy_campaign(
                suite,
                proposer=proposer,
                fixture_cases=fixture_cases,
                runs=args.runs,
                max_cases=args.max_cases,
                min_top1=args.min_top1,
                min_safety=args.min_safety,
                max_forbidden_rate=args.max_forbidden_rate,
                min_model_success_rate=args.min_model_success_rate,
                min_run_pass_rate=args.min_run_pass_rate,
                max_top1_spread=args.max_top1_spread,
                min_prediction_stability=args.min_prediction_stability,
            )
            if args.purpose == "qualification":
                summary["governance"] = authorization
                assert args.output is not None
                write_policy_eval_report(args.output, summary)
                completion = finalize_policy_qualification(
                    args.registry,
                    dataset_id=args.dataset_id,
                    qualification_id=str(authorization["qualification_id"]),
                    campaign_summary=summary,
                )
                authorization = {**authorization, **completion}
            summary["governance"] = authorization
            if args.output is not None:
                write_policy_eval_report(args.output, summary)
        except (PolicyEvalDatasetError, PolicyEvalRegistryError, ValueError) as exc:
            error: dict[str, object] = {"valid": False, "error": str(exc)}
            if args.purpose == "qualification" and authorization is not None:
                consumed = authorization.get("holdout_status") == "consumed"
                error["governance"] = {
                    **authorization,
                    "operator_action": (
                        "The holdout is consumed. The preliminary evidence report is preserved; "
                        "inspect the registry and report before any follow-up."
                        if consumed
                        else "The holdout remains reserved. Review whether inference began; "
                        "do not reset it to sealed automatically."
                    ),
                }
            print(json.dumps(error, ensure_ascii=False, indent=2))
            return 2
        finally:
            closer = getattr(proposer, "close", None)
            if callable(closer):
                closer()
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        gates = summary["gates"]
        assert isinstance(gates, dict)
        if args.purpose == "qualification":
            assert authorization is not None
            return 0 if authorization["qualification_decision"] == "accepted" else 1
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

        try:
            app = create_app(
                dataset_path=args.dataset,
                db_path=args.db,
                audit_key=_audit_key(),
                orchestration_mode=args.orchestration_mode,
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        uvicorn.run(app, host=args.host, port=args.port, workers=1)
        return 0

    if args.command == "deployment-check":
        summary = check_pilot_deployment()
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary["valid"] else 2

    if args.command == "audit-verify":
        verification = AuditLog(args.db, key=_audit_key()).verify()
        print(json.dumps(verification.as_dict(), ensure_ascii=False, indent=2))
        return 0 if verification.valid else 1

    if args.command == "backup-drill":
        try:
            summary = backup_and_restore_drill(
                args.db, args.output, audit_key=_audit_key()
            )
        except BackupDrillError as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False))
            return 2
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if args.command == "provider-check":
        try:
            task = load_operator_task(args.task_file)
            tool = observability_tool_from_env()
        except OperatorInputError as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False))
            return 2
        except ValueError:
            print(json.dumps({"valid": False, "error": "provider configuration invalid"}))
            return 2
        try:
            summary = check_observability_sources(tool, task)
        finally:
            tool.close()
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary["all_reachable"] else 1

    if args.task_file is not None:
        try:
            task = load_operator_task(args.task_file)
        except OperatorInputError as exc:
            print(json.dumps({"error": str(exc)}, ensure_ascii=False))
            return 2
        evidence_mode = "observability"
    else:
        cases = load_fixture_cases(args.dataset)
        case = next((item for item in cases if item.task.incident_id == args.incident_id), None)
        if case is None:
            print(json.dumps({"error": "incident_id not found"}, ensure_ascii=False))
            return 2
        task = case.task
        evidence_mode = "fixture"

    try:
        service = create_service(
            dataset_path=args.dataset,
            db_path=args.db,
            audit_key=_audit_key(),
            orchestration_mode=args.orchestration_mode,
            evidence_mode=evidence_mode,
        )
    except ValueError:
        if evidence_mode != "observability":
            raise
        print(json.dumps({"error": "provider configuration invalid"}))
        return 2
    try:
        result = service.investigate(task)
    finally:
        service.close()
    print(result.model_dump_json(indent=2))
    return 0 if result.report.status == IncidentStatus.DIAGNOSED else 2
