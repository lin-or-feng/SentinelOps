"""Privacy leak detection shared by local Git hooks and CI."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath


MAX_SCANNABLE_BYTES = 1_000_000
SAFE_EMAIL_DOMAINS = {"example.com", "users.noreply.github.com"}
FORBIDDEN_FILENAMES = {
    ".env",
    "credentials.json",
    "service-account.json",
    "id_rsa",
    "id_ed25519",
}
FORBIDDEN_SUFFIXES = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".kdbx",
}


@dataclass(frozen=True)
class PrivacyFinding:
    path: str
    rule: str
    line: int | None = None

    def display(self) -> str:
        location = f"{self.path}:{self.line}" if self.line is not None else self.path
        return f"{location}: {self.rule}"


TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "PRC identity number",
        re.compile(
            r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])"
            r"(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"
        ),
    ),
    ("PRC mobile number", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    (
        "email address",
        re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}(?![\w.-])", re.I),
    ),
    (
        "local user home path",
        re.compile(
            r"(?:[A-Za-z]:\\" r"Users\\[^\\\s]+|/Us" r"ers/[^/\s]+|/ho" r"me/[^/\s]+)"
        ),
    ),
    ("private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b")),
)

CREDENTIAL_LITERAL = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\b"
    r"\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
)
SAFE_LITERAL_PREFIXES = ("test-", "fake-", "dummy-", "example-", "replace-")


def _normalized_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _path_findings(path: str) -> list[PrivacyFinding]:
    normalized = _normalized_path(path)
    pure_path = PurePosixPath(normalized)
    filename = pure_path.name.casefold()
    findings: list[PrivacyFinding] = []
    if filename in FORBIDDEN_FILENAMES or (
        filename.startswith(".env.") and filename != ".env.example"
    ):
        findings.append(PrivacyFinding(normalized, "forbidden sensitive filename"))
    if pure_path.suffix.casefold() in FORBIDDEN_SUFFIXES:
        findings.append(PrivacyFinding(normalized, "forbidden sensitive file type"))
    return findings


def _looks_binary(data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _is_safe_email(value: str) -> bool:
    domain = value.rsplit("@", 1)[-1].casefold()
    return domain in SAFE_EMAIL_DOMAINS


def scan_content(
    path: str,
    data: bytes,
    *,
    allowed_binary_sha256: frozenset[str] = frozenset(),
) -> list[PrivacyFinding]:
    """Return privacy findings without returning or printing matched values."""

    normalized = _normalized_path(path)
    findings = _path_findings(normalized)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) > MAX_SCANNABLE_BYTES:
        findings.append(PrivacyFinding(normalized, "file exceeds privacy scan size limit"))
        return findings
    if _looks_binary(data):
        if digest not in allowed_binary_sha256:
            findings.append(
                PrivacyFinding(normalized, "unreviewed binary file; allow by exact SHA-256 only")
            )
        return findings

    text = data.decode("utf-8")
    seen: set[tuple[str, int | None]] = set()
    for rule, pattern in TEXT_PATTERNS:
        for match in pattern.finditer(text):
            if rule == "email address" and _is_safe_email(match.group(0)):
                continue
            line = _line_number(text, match.start())
            marker = (rule, line)
            if marker not in seen:
                findings.append(PrivacyFinding(normalized, rule, line))
                seen.add(marker)
    for match in CREDENTIAL_LITERAL.finditer(text):
        value = match.group(1).casefold()
        if value.startswith(SAFE_LITERAL_PREFIXES) or "${" in value:
            continue
        line = _line_number(text, match.start())
        marker = ("credential-like literal", line)
        if marker not in seen:
            findings.append(PrivacyFinding(normalized, marker[0], line))
            seen.add(marker)
    return findings
