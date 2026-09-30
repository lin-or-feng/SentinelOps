"""Offline, secret-free preflight for the single-instance read-only pilot profile."""

from __future__ import annotations

import os
from collections.abc import Mapping

from sentinelops.adapters.observability import observability_tool_from_env
from sentinelops.edge import edge_policy_from_env


def _usable_secret(value: str | None) -> bool:
    if not value or len(value.encode("utf-8")) < 32:
        return False
    normalized = value.casefold().strip()
    return not normalized.startswith(("replace-", "change-", "example-", "your-"))


def check_pilot_deployment(
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Check static pilot configuration without DNS, HTTP, or printing credentials."""
    values = os.environ if environment is None else environment
    blockers: list[str] = []
    api_token = values.get("SENTINELOPS_API_TOKEN")
    audit_key = values.get("SENTINELOPS_AUDIT_KEY")
    if not _usable_secret(api_token):
        blockers.append("api_token_missing_or_weak")
    if not _usable_secret(audit_key):
        blockers.append("audit_key_missing_or_weak")
    if api_token and audit_key and api_token == audit_key:
        blockers.append("api_and_audit_keys_reused")

    if values.get("SENTINELOPS_EVIDENCE_MODE", "fixture").casefold() != "observability":
        blockers.append("observability_mode_required")
    if values.get("SENTINELOPS_POLICY_MODE", "heuristic").casefold() != "heuristic":
        blockers.append("deterministic_policy_required")
    if values.get("SENTINELOPS_SPECIALIST_SHADOW", "off").casefold() != "off":
        blockers.append("shadow_model_must_be_off")
    if values.get("SENTINELOPS_ALLOW_INSECURE_HTTP") == "1":
        blockers.append("insecure_provider_http_forbidden")

    try:
        edge = edge_policy_from_env(values)
    except ValueError:
        blockers.append("edge_policy_invalid")
    else:
        if not set(edge.trusted_hosts) <= {"127.0.0.1", "localhost", "::1"}:
            blockers.append("pilot_trusted_hosts_must_be_loopback")
        if edge.cors_origins:
            blockers.append("pilot_cors_must_be_disabled")

    configured_sources: list[str] = []
    if values.get("SENTINELOPS_EVIDENCE_MODE", "fixture").casefold() == "observability":
        try:
            tool = observability_tool_from_env(values)
        except ValueError:
            blockers.append("provider_configuration_invalid")
        else:
            try:
                configured_sources = sorted(source.value for source in tool.sources)
            finally:
                tool.close()
            if len(configured_sources) < 2:
                blockers.append("two_independent_sources_required")
        for name in ("PROMETHEUS", "LOKI", "TEMPO"):
            if values.get(f"SENTINELOPS_{name}_URL") and not _usable_secret(
                values.get(f"SENTINELOPS_{name}_TOKEN")
            ):
                blockers.append(f"{name.casefold()}_token_missing_or_weak")

    return {
        "profile": "pilot",
        "valid": not blockers,
        "blockers": blockers,
        "configured_sources": configured_sources,
        "network_probe_performed": False,
        "note": "Static checks cannot prove token scope, TLS termination, firewall policy, or real provider reachability.",
    }
