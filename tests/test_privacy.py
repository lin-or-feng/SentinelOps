import hashlib

import pytest

from sentinelops.privacy import redact_private_text, scan_content


def rules(path: str, data: bytes) -> set[str]:
    return {finding.rule for finding in scan_content(path, data)}


@pytest.mark.parametrize(
    ("payload", "expected_rule"),
    [
        (("138" + "0013" + "8000").encode(), "PRC mobile number"),
        (("110105" + "19491231" + "002X").encode(), "PRC identity number"),
        (("private.user" + "@" + "corp.internal").encode(), "email address"),
        (("C:" + "\\Users\\private-user\\file.txt").encode(), "local user home path"),
        (
            ("-----BEGIN " + "PRIVATE KEY-----").encode(),
            "private key material",
        ),
        (("ghp_" + "A" * 36).encode(), "GitHub token"),
        (
            (("pass" + "word") + " = \"production-value\"").encode(),
            "credential-like literal",
        ),
    ],
)
def test_detects_private_text_without_exposing_match(payload: bytes, expected_rule: str) -> None:
    findings = scan_content("notes.txt", payload)

    assert expected_rule in {finding.rule for finding in findings}
    assert payload.decode() not in "\n".join(finding.display() for finding in findings)


def test_allows_known_non_secret_examples() -> None:
    payload = b"dev@example.com\napi_token = \"test-token\"\n.env.example"

    assert scan_content("example.txt", payload) == []


def test_blocks_sensitive_paths_and_unreviewed_binary() -> None:
    assert "forbidden sensitive filename" in rules(".env", b"SAFE=value")
    assert "forbidden sensitive file type" in rules("certificates/client.p12", b"text")
    assert "unreviewed binary file; allow by exact SHA-256 only" in rules(
        "diagram.png", b"\x89PNG\x00private"
    )


def test_binary_allowlist_is_bound_to_exact_content_hash() -> None:
    binary = b"\x89PNG\x00reviewed"
    digest = hashlib.sha256(binary).hexdigest()

    assert scan_content("diagram.png", binary, allowed_binary_sha256=frozenset({digest})) == []
    assert scan_content(
        "diagram.png",
        binary + b"changed",
        allowed_binary_sha256=frozenset({digest}),
    )


def test_blocks_oversized_unscannable_content() -> None:
    findings = scan_content("large.txt", b"a" * 1_000_001)

    assert {finding.rule for finding in findings} == {"file exceeds privacy scan size limit"}


def test_redacts_private_text_before_persistence() -> None:
    phone = "138" + "0013" + "8000"
    email = "private" + "@" + "corp.internal"

    redacted = redact_private_text(f"phone={phone} email={email}")

    assert phone not in redacted
    assert email not in redacted
    assert redacted.count("[REDACTED:") == 2
