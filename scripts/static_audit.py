"""Small dependency-free audit for prohibited runtime calls and committed secrets."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
PROHIBITED_CALLS = {
    "eval",
    "exec",
    "compile",
    "os.system",
    "os.popen",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "pickle.load",
    "pickle.loads",
    "marshal.loads",
}
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "OpenAI-style key": re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b"),
}
TEXT_SUFFIXES = {".py", ".md", ".yml", ".yaml", ".toml", ".json", ".example"}


def call_name(node: ast.Call) -> str:
    parts: list[str] = []
    target: ast.expr = node.func
    while isinstance(target, ast.Attribute):
        parts.append(target.attr)
        target = target.value
    if isinstance(target, ast.Name):
        parts.append(target.id)
    return ".".join(reversed(parts))


def audit_runtime_calls() -> list[str]:
    findings: list[str] = []
    for path in SOURCE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and call_name(node) in PROHIBITED_CALLS:
                findings.append(f"{path.relative_to(ROOT)}:{node.lineno}: {call_name(node)}")
    return findings


def audit_committed_text() -> list[str]:
    findings: list[str] = []
    excluded_parts = {".git", ".venv", ".pytest_cache", ".sentinelops", "__pycache__"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in excluded_parts for part in path.parts):
            continue
        if path.suffix.casefold() not in TEXT_SUFFIXES and path.name not in {"Dockerfile"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for label, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{path.relative_to(ROOT)}:{line}: suspected {label}")
    return findings


def main() -> int:
    findings = audit_runtime_calls() + audit_committed_text()
    if findings:
        print("Static audit failed:")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print("Static audit passed: no prohibited runtime calls or known secret formats found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
