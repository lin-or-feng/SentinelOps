"""The offline harness must fail closed and never persist its temporary token."""

from contextlib import contextmanager
from pathlib import Path

import pytest

from scripts import operator_offline_acceptance as harness


def test_stage_redacts_token_from_local_failure(monkeypatch, tmp_path: Path) -> None:
    @contextmanager
    def failing_server(_db_path, token, *, delay_seconds):
        raise RuntimeError(f"fixture error included {token}")
        yield

    monkeypatch.setattr(harness, "_offline_server", failing_server)
    with pytest.raises(RuntimeError, match=r"\[TEMP_TOKEN\]") as captured:
        harness._stage(
            "synthetic", delay_seconds=0, browser_check=lambda *_args, **_kwargs: tmp_path,
            scratch=tmp_path, screenshot_name="synthetic.png",
        )
    assert "fixture error included [TEMP_TOKEN]" in str(captured.value)


def test_failed_stage_writes_non_qualifying_report_and_nonzero_exit(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(harness, "_scratch_directory", lambda: tmp_path)

    def failing_stage(*_args, **_kwargs):
        raise AssertionError("synthetic offline failure")

    monkeypatch.setattr(harness, "_stage", failing_stage)
    checks = (("browser_flow", 0.0, lambda *_args, **_kwargs: tmp_path, "browser.png"),)
    assert harness.main(checks=checks) == 1
    report = (tmp_path / harness.REPORT_NAME).read_text(encoding="utf-8")
    assert '"status": "failed"' in report
    assert '"release_qualification": false' in report
    assert "synthetic offline failure" in report


def test_report_does_not_persist_temporary_token(monkeypatch, tmp_path: Path) -> None:
    marker = "this-is-only-a-synthetic-offline-token"
    monkeypatch.setattr(harness, "_scratch_directory", lambda: tmp_path)
    monkeypatch.setattr(harness.secrets, "token_urlsafe", lambda _length: marker)

    @contextmanager
    def failing_server(_db_path, token, *, delay_seconds):
        raise RuntimeError(f"failed with {token}")
        yield

    monkeypatch.setattr(harness, "_offline_server", failing_server)
    checks = (("browser_flow", 0.0, lambda *_args, **_kwargs: tmp_path, "browser.png"),)
    assert harness.main(checks=checks) == 1
    report = (tmp_path / harness.REPORT_NAME).read_text(encoding="utf-8")
    assert marker not in report
    assert "[TEMP_TOKEN]" in report
