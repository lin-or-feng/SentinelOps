"""Append-only, redacted and hash-chained audit events."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SENSITIVE_FRAGMENTS = ("token", "password", "secret", "authorization", "cookie", "api_key")


def redact_details(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if any(part in str(key).casefold() for part in SENSITIVE_FRAGMENTS)
            else redact_details(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_details(item) for item in value]
    if isinstance(value, tuple):
        return [redact_details(item) for item in value]
    if isinstance(value, str) and (value.casefold().startswith("bearer ") or value.startswith("sk-")):
        return "[REDACTED]"
    return value


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    event_count: int
    algorithm: str
    first_invalid_sequence: int | None = None

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


class AuditLog:
    def __init__(self, db_path: str | Path, key: str | bytes | None = None) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._key = key.encode("utf-8") if isinstance(key, str) else key
        self.algorithm = "hmac-sha256" if self._key else "sha256-development"
        self._lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS audit_events ("
                "sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, "
                "created_at TEXT NOT NULL, trace_id TEXT NOT NULL, actor TEXT NOT NULL, "
                "action TEXT NOT NULL, resource TEXT NOT NULL, status TEXT NOT NULL, "
                "details_json TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL, "
                "algorithm TEXT NOT NULL)"
            )

    def _digest(self, payload: str) -> str:
        encoded = payload.encode("utf-8")
        if self._key:
            return hmac.new(self._key, encoded, hashlib.sha256).hexdigest()
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _canonical(fields: dict[str, Any]) -> str:
        return json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def append(
        self,
        *,
        trace_id: str,
        actor: str,
        action: str,
        resource: str,
        status: str,
        details: dict[str, Any] | None = None,
    ) -> str:
        event_id = f"audit-{uuid.uuid4().hex}"
        created_at = datetime.now(timezone.utc).isoformat()
        safe_details = redact_details(details or {})
        details_json = self._canonical(safe_details)
        with self._lock, self._connect() as connection:
            previous = connection.execute(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous[0] if previous else "GENESIS"
            fields = {
                "event_id": event_id,
                "created_at": created_at,
                "trace_id": trace_id,
                "actor": actor,
                "action": action,
                "resource": resource,
                "status": status,
                "details_json": details_json,
                "previous_hash": previous_hash,
                "algorithm": self.algorithm,
            }
            event_hash = self._digest(self._canonical(fields))
            connection.execute(
                "INSERT INTO audit_events "
                "(event_id, created_at, trace_id, actor, action, resource, status, "
                "details_json, previous_hash, event_hash, algorithm) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id, created_at, trace_id, actor, action, resource, status,
                    details_json, previous_hash, event_hash, self.algorithm,
                ),
            )
        return event_id

    def verify(self) -> AuditVerification:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT sequence, event_id, created_at, trace_id, actor, action, resource, "
                "status, details_json, previous_hash, event_hash, algorithm "
                "FROM audit_events ORDER BY sequence"
            ).fetchall()
        previous_hash = "GENESIS"
        for row in rows:
            sequence, event_id, created_at, trace_id, actor, action, resource, status, details_json, stored_previous, stored_hash, algorithm = row
            fields = {
                "event_id": event_id,
                "created_at": created_at,
                "trace_id": trace_id,
                "actor": actor,
                "action": action,
                "resource": resource,
                "status": status,
                "details_json": details_json,
                "previous_hash": stored_previous,
                "algorithm": algorithm,
            }
            expected = self._digest(self._canonical(fields))
            if stored_previous != previous_hash or stored_hash != expected or algorithm != self.algorithm:
                return AuditVerification(False, len(rows), self.algorithm, sequence)
            previous_hash = stored_hash
        return AuditVerification(True, len(rows), self.algorithm)

    def list_events(self, trace_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        sql = (
            "SELECT sequence, event_id, created_at, trace_id, actor, action, resource, "
            "status, details_json, previous_hash, event_hash, algorithm FROM audit_events"
        )
        params: tuple[Any, ...]
        if trace_id:
            sql += " WHERE trace_id = ? ORDER BY sequence DESC LIMIT ?"
            params = (trace_id, max(1, min(limit, 500)))
        else:
            sql += " ORDER BY sequence DESC LIMIT ?"
            params = (max(1, min(limit, 500)),)
        with self._connect() as connection:
            rows = connection.execute(sql, params).fetchall()
        keys = (
            "sequence", "event_id", "created_at", "trace_id", "actor", "action",
            "resource", "status", "details_json", "previous_hash", "event_hash", "algorithm",
        )
        events = [dict(zip(keys, row, strict=True)) for row in rows]
        for event in events:
            event["details"] = json.loads(str(event.pop("details_json")))
        return events
