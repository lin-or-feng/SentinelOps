import sqlite3

from concurrent.futures import ThreadPoolExecutor

from sentinelops.audit import AuditLog, redact_details


def test_separate_audit_instances_serialize_hash_chain(tmp_path) -> None:
    db_path = tmp_path / "parallel-audit.db"
    logs = [AuditLog(db_path, key="shared-test-key") for _ in range(4)]

    def append_one(index: int) -> None:
        logs[index % len(logs)].append(
            trace_id=f"trace-{index}",
            actor="test",
            action="parallel_append",
            resource=f"resource-{index}",
            status="ok",
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(append_one, range(40)))
    verification = logs[0].verify()
    assert verification.valid
    assert verification.event_count == 40


def test_redaction_is_recursive() -> None:
    value = redact_details(
        {
            "password": "unsafe",
            "nested": {"api_key": "sk-example", "safe": "ok"},
            "items": ["Bearer token-value", "visible"],
        }
    )
    assert value == {
        "password": "[REDACTED]",
        "nested": {"api_key": "[REDACTED]", "safe": "ok"},
        "items": ["[REDACTED]", "visible"],
    }


def test_hmac_audit_chain_verifies_and_hides_secrets(tmp_path) -> None:
    db_path = tmp_path / "audit.db"
    audit = AuditLog(db_path, key="test-audit-key")
    audit.append(
        trace_id="trace-test",
        actor="tester",
        action="query",
        resource="logs",
        status="ok",
        details={"authorization": "Bearer should-not-survive", "count": 2},
    )
    audit.append(
        trace_id="trace-test",
        actor="tester",
        action="finish",
        resource="incident-1",
        status="ok",
    )

    verification = audit.verify()
    assert verification.valid is True
    assert verification.event_count == 2
    assert verification.algorithm == "hmac-sha256"
    events = audit.list_events(trace_id="trace-test")
    assert events[-1]["details"]["authorization"] == "[REDACTED]"


def test_audit_chain_detects_database_tampering(tmp_path) -> None:
    db_path = tmp_path / "audit.db"
    audit = AuditLog(db_path, key="test-audit-key")
    audit.append(
        trace_id="trace-test",
        actor="tester",
        action="query",
        resource="metrics",
        status="ok",
        details={"count": 1},
    )
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE audit_events SET details_json = ? WHERE sequence = 1",
            ('{"count":999}',),
        )
    verification = audit.verify()
    assert verification.valid is False
    assert verification.first_invalid_sequence == 1
