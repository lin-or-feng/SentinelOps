import sqlite3

from sentinelops.audit import AuditLog, redact_details


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
