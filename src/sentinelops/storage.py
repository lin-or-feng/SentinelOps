"""SQLite persistence for completed and degraded investigations."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from sentinelops.domain import InvestigationResult


class InvestigationStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS investigations ("
                "incident_id TEXT PRIMARY KEY, trace_id TEXT UNIQUE NOT NULL, "
                "status TEXT NOT NULL, result_json TEXT NOT NULL, "
                "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def save(self, result: InvestigationResult) -> None:
        payload = result.model_dump_json()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO investigations (incident_id, trace_id, status, result_json) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(incident_id) DO UPDATE SET "
                "trace_id = excluded.trace_id, status = excluded.status, "
                "result_json = excluded.result_json, updated_at = CURRENT_TIMESTAMP",
                (
                    result.task.incident_id,
                    result.trace_id,
                    result.report.status.value,
                    payload,
                ),
            )

    def get(self, incident_id: str) -> InvestigationResult | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM investigations WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        return InvestigationResult.model_validate_json(row[0]) if row else None
