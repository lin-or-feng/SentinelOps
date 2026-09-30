import json

import pytest

from sentinelops.adapters import load_fixture_cases
from sentinelops.application.operator_flow import (
    OperatorInputError,
    check_observability_sources,
    load_operator_task,
)
from sentinelops.cli import main
from sentinelops.domain import EvidenceSource
from sentinelops.adapters.observability import (
    ProviderAuthorizationError,
    ProviderPayloadError,
    ProviderRateLimitError,
    ResponseTooLarge,
)


def _task_file(tmp_path):
    task = load_fixture_cases("evals/incidents.json")[0].task
    path = tmp_path / "incident.json"
    path.write_text(task.model_dump_json(), encoding="utf-8")
    return path, task


def test_operator_task_validates_json_privacy_and_size(tmp_path) -> None:
    path, task = _task_file(tmp_path)
    assert load_operator_task(path) == task
    path.write_text(task.model_dump_json().replace("order-service", "138" + "0013" + "8000"))
    try:
        load_operator_task(path)
    except OperatorInputError as exc:
        assert "privacy" in str(exc)
    else:
        raise AssertionError("private task was accepted")
    path.write_bytes(b"x" * (64 * 1024 + 1))
    try:
        load_operator_task(path)
    except OperatorInputError as exc:
        assert "size" in str(exc)
    else:
        raise AssertionError("oversized task was accepted")


def test_provider_check_uses_bounded_reads_and_reports_no_evidence(tmp_path) -> None:
    _, task = _task_file(tmp_path)

    class FakeTool:
        sources = frozenset({EvidenceSource.METRICS, EvidenceSource.LOGS})

        def query(self, spec):
            assert spec.service == task.service
            assert spec.limit == 1
            assert (spec.end_time - spec.start_time).total_seconds() == 20 * 60
            if spec.source == EvidenceSource.LOGS:
                raise RuntimeError("sensitive provider response")
            return []

    summary = check_observability_sources(FakeTool(), task)
    assert summary["all_reachable"] is False
    assert summary["checks"] == [
        {
            "source": "logs", "status": "failed",
            "reason_code": "unexpected_provider_error", "error_type": "RuntimeError",
        },
        {"source": "metrics", "status": "ok", "evidence_count": 0},
    ]
    assert "sensitive provider response" not in json.dumps(summary)


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (ProviderAuthorizationError("private body"), "authorization_denied"),
        (ProviderRateLimitError("private body"), "rate_limited"),
        (TimeoutError("private body"), "timeout"),
        (ResponseTooLarge("private body"), "response_too_large"),
        (ProviderPayloadError("private body"), "invalid_response"),
        (PermissionError("private body"), "source_not_allowed"),
        (ConnectionError("private body"), "network_or_server_error"),
    ],
)
def test_source_failure_codes_are_stable_and_do_not_include_body(
    tmp_path, error, code
) -> None:
    _, task = _task_file(tmp_path)

    class FailingTool:
        sources = frozenset({EvidenceSource.METRICS})

        def query(self, spec):
            raise error

    result = check_observability_sources(FailingTool(), task)
    assert result["checks"][0]["reason_code"] == code
    assert "private body" not in json.dumps(result)


def test_cli_provider_check_closes_tool(tmp_path, monkeypatch, capsys) -> None:
    path, _ = _task_file(tmp_path)

    class FakeTool:
        sources = frozenset({EvidenceSource.METRICS})
        closed = False

        def query(self, spec):
            return []

        def close(self):
            self.closed = True

    tool = FakeTool()
    monkeypatch.setattr("sentinelops.cli.observability_tool_from_env", lambda: tool)
    assert main(["provider-check", "--task-file", str(path)]) == 0
    assert tool.closed
    assert '"all_reachable": true' in capsys.readouterr().out


def test_cli_real_task_never_falls_back_to_fixture(tmp_path, monkeypatch, capsys) -> None:
    path, task = _task_file(tmp_path)
    captured = {}

    class FakeService:
        def investigate(self, supplied):
            captured["task"] = supplied
            raise RuntimeError("stopped before querying")

        def close(self):
            captured["closed"] = True

    def fake_create_service(**kwargs):
        captured["mode"] = kwargs["evidence_mode"]
        return FakeService()

    monkeypatch.setattr("sentinelops.cli.create_service", fake_create_service)
    try:
        main(["investigate", "--task-file", str(path)])
    except RuntimeError as exc:
        assert "stopped before querying" in str(exc)
    else:
        raise AssertionError("the fake service did not stop the run")
    assert captured == {"mode": "observability", "task": task, "closed": True}
    assert capsys.readouterr().out == ""


def test_cli_real_task_fails_closed_without_provider_configuration(
    tmp_path, monkeypatch, capsys
) -> None:
    path, _ = _task_file(tmp_path)
    monkeypatch.delenv("SENTINELOPS_ALLOWED_OBSERVABILITY_HOSTS", raising=False)
    assert main(["investigate", "--task-file", str(path)]) == 2
    assert "provider configuration invalid" in capsys.readouterr().out
