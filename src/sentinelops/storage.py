"""SQLite persistence for completed and degraded investigations."""

from __future__ import annotations

import sqlite3
import hashlib
import json
from typing import Any
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from sentinelops.domain import (
    Evidence,
    IncidentTask,
    InvestigatorAssignment,
    InvestigatorStatus,
    InvestigationResult,
)
from sentinelops.audit import AuditLog


class EvidenceIdentityError(RuntimeError):
    pass


@dataclass(frozen=True)
class EvidenceRecord:
    trace_id: str
    evidence_key_sha256: str
    payload_sha256: str
    source: str


class EvidenceJournal:
    """Persist approved evidence identities and hashes, never evidence text."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS agent_evidence ("
                "trace_id TEXT NOT NULL, evidence_key_sha256 TEXT NOT NULL, "
                "payload_sha256 TEXT NOT NULL, source TEXT NOT NULL, "
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                "PRIMARY KEY (trace_id, evidence_key_sha256))"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def record_batch(self, trace_id: str, evidence: list[Evidence]) -> None:
        with self._connect() as connection:
            for item in evidence:
                identity = self._hash(item.evidence_id)
                canonical = json.dumps(
                    item.model_dump(mode="json"), ensure_ascii=False,
                    sort_keys=True, separators=(",", ":"),
                )
                payload_hash = self._hash(canonical)
                existing = connection.execute(
                    "SELECT payload_sha256 FROM agent_evidence "
                    "WHERE trace_id = ? AND evidence_key_sha256 = ?",
                    (trace_id, identity),
                ).fetchone()
                if existing is not None:
                    if existing[0] != payload_hash:
                        raise EvidenceIdentityError(
                            "evidence identity has conflicting contents"
                        )
                    continue
                connection.execute(
                    "INSERT INTO agent_evidence "
                    "(trace_id, evidence_key_sha256, payload_sha256, source) "
                    "VALUES (?, ?, ?, ?)",
                    (trace_id, identity, payload_hash, item.source.value),
                )

    def list_for_trace(self, trace_id: str) -> list[EvidenceRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT trace_id, evidence_key_sha256, payload_sha256, source "
                "FROM agent_evidence WHERE trace_id = ? ORDER BY evidence_key_sha256",
                (trace_id,),
            ).fetchall()
        return [EvidenceRecord(*row) for row in rows]


class RunReservationError(RuntimeError):
    pass


class InvestigationRunJournal:
    """Reserve an incident before any external query; never auto-retry abandoned runs."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS investigation_runs ("
                "incident_id TEXT PRIMARY KEY, trace_id TEXT UNIQUE NOT NULL, "
                "task_sha256 TEXT NOT NULL, "
                "state TEXT NOT NULL CHECK (state IN ('running','completed','abandoned')), "
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @staticmethod
    def task_fingerprint(task: IncidentTask) -> str:
        canonical = json.dumps(
            task.model_dump(mode="json"), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def reserve(self, task: IncidentTask, trace_id: str) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO investigation_runs "
                    "(incident_id, trace_id, task_sha256, state) VALUES (?, ?, ?, 'running')",
                    (task.incident_id, trace_id, self.task_fingerprint(task)),
                )
        except sqlite3.IntegrityError as exc:
            raise RunReservationError("incident investigation is already reserved") from exc

    def finish(self, incident_id: str, trace_id: str, *, success: bool) -> None:
        destination = "completed" if success else "abandoned"
        with self._connect() as connection:
            updated = connection.execute(
                "UPDATE investigation_runs SET state = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE incident_id = ? AND trace_id = ? AND state = 'running'",
                (destination, incident_id, trace_id),
            ).rowcount
        if updated != 1:
            raise RunReservationError("invalid investigation run transition")

    def reconcile_completed(self, result: InvestigationResult) -> None:
        """Repair a result-first crash window without ever rerunning the provider."""
        with self._connect() as connection:
            connection.execute(
                "UPDATE investigation_runs SET state = 'completed', "
                "updated_at = CURRENT_TIMESTAMP WHERE incident_id = ? AND trace_id = ? "
                "AND task_sha256 = ? AND state IN ('running', 'abandoned')",
                (
                    result.task.incident_id,
                    result.trace_id,
                    self.task_fingerprint(result.task),
                ),
            )

    def get(self, incident_id: str) -> tuple[str, str, str] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT trace_id, task_sha256, state FROM investigation_runs "
                "WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        return tuple(row) if row is not None else None


class AssignmentState(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class AssignmentStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class AssignmentRecord:
    assignment_id: str
    trace_id: str
    incident_id: str
    actor: str
    source: str
    state: AssignmentState


class AssignmentJournal:
    """Durable, metadata-only lifecycle for one role-scoped assignment."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS agent_assignments ("
                "assignment_id TEXT PRIMARY KEY, trace_id TEXT NOT NULL, "
                "incident_id TEXT NOT NULL, actor TEXT NOT NULL, source TEXT NOT NULL, "
                "state TEXT NOT NULL CHECK (state IN "
                "('created','running','completed','failed','expired')), "
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_assignments_trace "
                "ON agent_assignments(trace_id)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def create(self, trace_id: str, assignment: InvestigatorAssignment) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO agent_assignments "
                    "(assignment_id, trace_id, incident_id, actor, source, state) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        assignment.assignment_id,
                        trace_id,
                        assignment.query.incident_id,
                        assignment.actor,
                        assignment.query.source.value,
                        AssignmentState.CREATED.value,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise AssignmentStateError("assignment identity already exists") from exc

    def start(self, assignment_id: str) -> None:
        self._transition(assignment_id, AssignmentState.CREATED, AssignmentState.RUNNING)

    def finish(self, assignment_id: str, status: InvestigatorStatus) -> None:
        destination = {
            InvestigatorStatus.OK: AssignmentState.COMPLETED,
            InvestigatorStatus.ERROR: AssignmentState.FAILED,
            InvestigatorStatus.TIMEOUT: AssignmentState.EXPIRED,
        }[status]
        self._transition(assignment_id, AssignmentState.RUNNING, destination)

    def _transition(
        self, assignment_id: str, expected: AssignmentState, destination: AssignmentState
    ) -> None:
        with self._connect() as connection:
            updated = connection.execute(
                "UPDATE agent_assignments SET state = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE assignment_id = ? AND state = ?",
                (destination.value, assignment_id, expected.value),
            ).rowcount
        if updated != 1:
            raise AssignmentStateError("invalid assignment state transition")

    def expire_incomplete(self, trace_id: str) -> int:
        """Explicit recovery action; never replays external queries automatically."""
        with self._connect() as connection:
            return connection.execute(
                "UPDATE agent_assignments SET state = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE trace_id = ? AND state IN (?, ?)",
                (
                    AssignmentState.EXPIRED.value,
                    trace_id,
                    AssignmentState.CREATED.value,
                    AssignmentState.RUNNING.value,
                ),
            ).rowcount

    def list_for_trace(self, trace_id: str) -> list[AssignmentRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT assignment_id, trace_id, incident_id, actor, source, state "
                "FROM agent_assignments WHERE trace_id = ? ORDER BY rowid",
                (trace_id,),
            ).fetchall()
        return [
            AssignmentRecord(*row[:-1], AssignmentState(row[-1])) for row in rows
        ]


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
            self._save_on_connection(connection, result, payload)

    @staticmethod
    def _save_on_connection(
        connection: sqlite3.Connection, result: InvestigationResult, payload: str
    ) -> None:
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

    def save_with_completion_audit(
        self,
        result: InvestigationResult,
        audit: AuditLog,
        *,
        actor: str,
        details: dict[str, Any],
    ) -> None:
        """Commit result and its completion event together in the shared SQLite DB."""
        if self.db_path.resolve() != audit.db_path.resolve():
            raise ValueError("result and audit must use the same SQLite database")
        payload = result.model_dump_json()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._save_on_connection(connection, result, payload)
            audit.append_in_transaction(
                connection,
                trace_id=result.trace_id,
                actor=actor,
                action="investigation_completed",
                resource=result.task.incident_id,
                status=result.report.status.value,
                details=details,
            )

    def get(self, incident_id: str) -> InvestigationResult | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM investigations WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        return InvestigationResult.model_validate_json(row[0]) if row else None

    def healthcheck(self) -> bool:
        try:
            with self._connect() as connection:
                return connection.execute("SELECT 1").fetchone() == (1,)
        except sqlite3.Error:
            return False
