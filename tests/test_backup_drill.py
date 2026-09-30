import sqlite3

import pytest

from sentinelops.adapters import load_fixture_cases
from sentinelops.application.backup_drill import BackupDrillError, backup_and_restore_drill
from sentinelops.audit import AuditLog
from sentinelops.cli import main
from sentinelops.service import create_service


def test_backup_drill_restores_result_and_audit_without_overwriting(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    source = tmp_path / "active.db"
    backup = tmp_path / "snapshot.db"
    service = create_service(db_path=source, audit_key="backup-test-key")
    result = service.investigate(case.task)
    summary = backup_and_restore_drill(source, backup, audit_key="backup-test-key")

    assert summary["valid"] is True
    assert summary["snapshot_restored"] is True
    assert summary["counts"]["investigations"] == 1
    assert AuditLog(backup, key="backup-test-key").verify().valid
    with sqlite3.connect(backup) as connection:
        saved = connection.execute(
            "SELECT trace_id FROM investigations WHERE incident_id = ?",
            (case.task.incident_id,),
        ).fetchone()
    assert saved == (result.trace_id,)
    original = backup.read_bytes()
    with pytest.raises(BackupDrillError, match="already exists"):
        backup_and_restore_drill(source, backup, audit_key="backup-test-key")
    assert backup.read_bytes() == original


def test_backup_drill_rejects_wrong_key_and_tampered_audit(tmp_path) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    source = tmp_path / "active.db"
    service = create_service(db_path=source, audit_key="correct-key")
    service.investigate(case.task)
    with pytest.raises(BackupDrillError, match="audit chain"):
        backup_and_restore_drill(
            source, tmp_path / "wrong-key.db", audit_key="incorrect-key"
        )
    assert not (tmp_path / "wrong-key.db").exists()

    with sqlite3.connect(source) as connection:
        connection.execute(
            "UPDATE audit_events SET action = 'forged' WHERE sequence = "
            "(SELECT MAX(sequence) FROM audit_events)"
        )
    with pytest.raises(BackupDrillError, match="audit chain"):
        backup_and_restore_drill(
            source, tmp_path / "tampered.db", audit_key="correct-key"
        )
    assert not (tmp_path / "tampered.db").exists()


def test_backup_drill_cli_returns_verified_counts(tmp_path, monkeypatch, capsys) -> None:
    case = load_fixture_cases("evals/incidents.json")[0]
    source = tmp_path / "cli-active.db"
    service = create_service(db_path=source, audit_key="cli-backup-key")
    service.investigate(case.task)
    monkeypatch.setenv("SENTINELOPS_AUDIT_KEY", "cli-backup-key")
    destination = tmp_path / "cli-backup.db"
    assert main([
        "backup-drill", "--db", str(source), "--output", str(destination)
    ]) == 0
    assert '"snapshot_restored": true' in capsys.readouterr().out
    assert destination.is_file()
