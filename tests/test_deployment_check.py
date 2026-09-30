import json
import secrets

import pytest

from sentinelops.api import create_app
from sentinelops.application.deployment_check import check_pilot_deployment
from sentinelops.cli import main


def _pilot_values() -> dict[str, str]:
    return {
        "SENTINELOPS_API_TOKEN": secrets.token_urlsafe(32),
        "SENTINELOPS_AUDIT_KEY": secrets.token_urlsafe(32),
        "SENTINELOPS_EVIDENCE_MODE": "observability",
        "SENTINELOPS_POLICY_MODE": "heuristic",
        "SENTINELOPS_SPECIALIST_SHADOW": "off",
        "SENTINELOPS_TRUSTED_HOSTS": "127.0.0.1,localhost",
        "SENTINELOPS_CORS_ORIGINS": "",
        "SENTINELOPS_ALLOWED_OBSERVABILITY_HOSTS": "metrics.internal,logs.internal",
        "SENTINELOPS_PROMETHEUS_URL": "https://metrics.internal",
        "SENTINELOPS_LOKI_URL": "https://logs.internal",
        "SENTINELOPS_PROMETHEUS_TOKEN": secrets.token_urlsafe(32),
        "SENTINELOPS_LOKI_TOKEN": secrets.token_urlsafe(32),
    }


def test_pilot_preflight_accepts_two_https_sources_without_network() -> None:
    values = _pilot_values()
    result = check_pilot_deployment(values)
    assert result["valid"] is True
    assert result["configured_sources"] == ["logs", "metrics"]
    assert result["network_probe_performed"] is False
    assert not any(value in json.dumps(result) for value in values.values() if len(value) > 32)


def test_pilot_preflight_rejects_placeholder_reuse_and_unsafe_network() -> None:
    values = _pilot_values()
    values["SENTINELOPS_API_TOKEN"] = "replace-with-a-long-random-token"
    values["SENTINELOPS_AUDIT_KEY"] = values["SENTINELOPS_API_TOKEN"]
    values["SENTINELOPS_TRUSTED_HOSTS"] = "public.example"
    values["SENTINELOPS_CORS_ORIGINS"] = "https://public.example"
    values["SENTINELOPS_ALLOW_INSECURE_HTTP"] = "1"
    values["SENTINELOPS_POLICY_MODE"] = "ollama"
    result = check_pilot_deployment(values)
    assert result["valid"] is False
    assert set(result["blockers"]) >= {
        "api_token_missing_or_weak",
        "audit_key_missing_or_weak",
        "api_and_audit_keys_reused",
        "pilot_trusted_hosts_must_be_loopback",
        "pilot_cors_must_be_disabled",
        "insecure_provider_http_forbidden",
        "deterministic_policy_required",
    }


def test_pilot_preflight_requires_two_authenticated_sources() -> None:
    values = _pilot_values()
    values.pop("SENTINELOPS_LOKI_URL")
    values.pop("SENTINELOPS_LOKI_TOKEN")
    values["SENTINELOPS_PROMETHEUS_TOKEN"] = "replace-with-read-only-token"
    result = check_pilot_deployment(values)
    assert result["valid"] is False
    assert "two_independent_sources_required" in result["blockers"]
    assert "prometheus_token_missing_or_weak" in result["blockers"]


def test_pilot_api_fails_before_creating_storage_with_unsafe_config(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("SENTINELOPS_DEPLOYMENT_PROFILE", "pilot")
    monkeypatch.setenv("SENTINELOPS_API_TOKEN", "replace-with-a-long-random-token")
    db_path = tmp_path / "must-not-exist.db"
    with pytest.raises(ValueError, match="pilot deployment preflight failed"):
        create_app(db_path=db_path)
    assert not db_path.exists()


def test_deployment_check_cli_emits_only_reason_codes(monkeypatch, capsys) -> None:
    values = _pilot_values()
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    assert main(["deployment-check"]) == 0
    output = capsys.readouterr().out
    assert '"valid": true' in output
    assert values["SENTINELOPS_API_TOKEN"] not in output
    assert values["SENTINELOPS_AUDIT_KEY"] not in output


def test_pilot_api_rejects_unchecked_credential_override(tmp_path, monkeypatch) -> None:
    values = _pilot_values()
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SENTINELOPS_DEPLOYMENT_PROFILE", "pilot")
    db_path = tmp_path / "must-not-exist.db"
    with pytest.raises(ValueError, match="audit key must match"):
        create_app(db_path=db_path, audit_key="unchecked-key")
    with pytest.raises(ValueError, match="API token must match"):
        create_app(db_path=db_path, api_token="unchecked-token")
    assert not db_path.exists()
