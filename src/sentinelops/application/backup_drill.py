"""Explicit SQLite snapshot and isolated restore verification; never overwrite a DB."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from sentinelops.audit import AuditLog


class BackupDrillError(ValueError):
    pass


def _validate_copy(path: Path, audit_key: str | bytes | None) -> dict[str, int]:
    with closing(sqlite3.connect(path)) as connection:
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise BackupDrillError("SQLite integrity check failed")
        required = {"investigations", "investigation_runs", "audit_events"}
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not required <= tables:
            raise BackupDrillError("source is not a SentinelOps investigation database")
        counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in sorted(required)
        }
    verification = AuditLog(path, key=audit_key).verify()
    if not verification.valid:
        raise BackupDrillError("audit chain verification failed")
    return counts


def backup_and_restore_drill(
    source: str | Path,
    destination: str | Path,
    *,
    audit_key: str | bytes | None = None,
) -> dict[str, object]:
    """Snapshot a live DB, restore to scratch, verify both; keep only the backup."""
    source_path = Path(source)
    target_path = Path(destination)
    if source_path.is_symlink() or not source_path.is_file():
        raise BackupDrillError("source must be an existing regular database")
    if target_path.is_symlink() or target_path.exists():
        raise BackupDrillError("backup destination already exists")
    if source_path.resolve() == target_path.resolve():
        raise BackupDrillError("backup destination must differ from source")
    if not target_path.parent.is_dir():
        raise BackupDrillError("backup destination directory does not exist")

    scratch: list[Path] = []
    try:
        for label in ("snapshot", "restore"):
            handle, name = tempfile.mkstemp(
                prefix=f".sentinelops-{label}-", suffix=".db", dir=target_path.parent
            )
            os.close(handle)
            scratch.append(Path(name))
        snapshot, restored = scratch
        with closing(sqlite3.connect(source_path)) as live, closing(
            sqlite3.connect(snapshot)
        ) as copy:
            live.backup(copy)
        snapshot_counts = _validate_copy(snapshot, audit_key)
        with closing(sqlite3.connect(snapshot)) as copy, closing(
            sqlite3.connect(restored)
        ) as recovery:
            copy.backup(recovery)
        restore_counts = _validate_copy(restored, audit_key)
        if snapshot_counts != restore_counts:
            raise BackupDrillError("restored database row counts differ from backup")
        try:
            os.link(snapshot, target_path)
        except FileExistsError as exc:
            raise BackupDrillError("backup destination already exists") from exc
        return {
            "valid": True,
            "snapshot_restored": True,
            "counts": snapshot_counts,
            "destination": str(target_path),
            "note": "Store this backup in an access-controlled location; the file may contain incident data.",
        }
    except (sqlite3.Error, OSError) as exc:
        raise BackupDrillError("backup or restore verification failed") from exc
    finally:
        for path in scratch:
            path.unlink(missing_ok=True)
