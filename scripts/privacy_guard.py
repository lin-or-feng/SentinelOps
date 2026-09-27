"""Scan staged, tracked, or about-to-be-pushed Git content for privacy leaks."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
sys.path.insert(0, str(SOURCE))

from sentinelops.privacy import PrivacyFinding, scan_content  # noqa: E402


ZERO_SHA = "0" * 40
NOREPLY_SUFFIX = "@users.noreply.github.com"


def git_bytes(*args: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git command failed: {message}")
    return completed.stdout


def load_binary_allowlist() -> frozenset[str]:
    path = ROOT / ".privacy-allowlist"
    if not path.exists():
        return frozenset()
    hashes: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip().casefold()
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", line):
            raise ValueError(".privacy-allowlist accepts only full SHA-256 hashes")
        hashes.add(line)
    return frozenset(hashes)


def split_null(payload: bytes) -> list[str]:
    return [item.decode("utf-8", errors="surrogateescape") for item in payload.split(b"\0") if item]


def scan_index(paths: list[str], allowed_hashes: frozenset[str]) -> list[PrivacyFinding]:
    findings: list[PrivacyFinding] = []
    for path in paths:
        try:
            data = git_bytes("show", f":{path}")
        except RuntimeError:
            continue
        findings.extend(scan_content(path, data, allowed_binary_sha256=allowed_hashes))
    return findings


def scan_worktree(
    paths: list[str],
    allowed_hashes: frozenset[str],
    *,
    root: Path = ROOT,
) -> list[PrivacyFinding]:
    findings: list[PrivacyFinding] = []
    for path in paths:
        candidate = root / path
        if candidate.is_symlink():
            findings.append(PrivacyFinding(path, "unreviewed symbolic link"))
            continue
        if not candidate.is_file():
            continue
        try:
            data = candidate.read_bytes()
        except OSError:
            findings.append(PrivacyFinding(path, "worktree file could not be scanned"))
            continue
        findings.extend(scan_content(path, data, allowed_binary_sha256=allowed_hashes))
    return findings


def scan_commit(commit: str, allowed_hashes: frozenset[str]) -> list[PrivacyFinding]:
    findings: list[PrivacyFinding] = []
    metadata = git_bytes("show", "-s", "--format=%ae%n%ce", commit).decode(
        "utf-8", errors="replace"
    )
    for role, email in zip(("author", "committer"), metadata.splitlines(), strict=False):
        if email and not email.casefold().endswith(NOREPLY_SUFFIX):
            findings.append(PrivacyFinding(f"commit:{commit[:12]}", f"non-private {role} email"))

    paths = split_null(
        git_bytes(
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-only",
            "--diff-filter=ACMR",
            "-r",
            "-z",
            commit,
        )
    )
    for path in paths:
        try:
            data = git_bytes("show", f"{commit}:{path}")
        except RuntimeError:
            continue
        findings.extend(scan_content(path, data, allowed_binary_sha256=allowed_hashes))
    return findings


def current_identity_finding() -> list[PrivacyFinding]:
    completed = subprocess.run(
        ["git", "var", "GIT_AUTHOR_IDENT"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode:
        return [PrivacyFinding("git-config", "author identity is not configured")]
    identity = completed.stdout.decode("utf-8", errors="replace")
    match = re.search(r"<([^>]+)>", identity)
    if match is None or not match.group(1).casefold().endswith(NOREPLY_SUFFIX):
        return [PrivacyFinding("git-config", "Git author email is not a GitHub noreply address")]
    return []


def commits_for_pre_push(remote_name: str, stdin_text: str) -> list[str]:
    commits: set[str] = set()
    for line in stdin_text.splitlines():
        fields = line.split()
        if len(fields) != 4:
            continue
        _, local_sha, _, remote_sha = fields
        if local_sha == ZERO_SHA:
            continue
        if remote_sha != ZERO_SHA:
            revision_args = [f"{remote_sha}..{local_sha}"]
        else:
            revision_args = [local_sha, "--not", f"--remotes={remote_name}"]
        payload = git_bytes("rev-list", *revision_args).decode("ascii", errors="strict")
        commits.update(item for item in payload.splitlines() if item)
    return sorted(commits)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Block private data before Git commit or push")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="scan the staged Git index")
    mode.add_argument("--tracked", action="store_true", help="scan all tracked Git index files")
    mode.add_argument(
        "--worktree",
        action="store_true",
        help="scan tracked and untracked non-ignored worktree files",
    )
    mode.add_argument("--pre-push", metavar="REMOTE", help="scan commits received on stdin")
    parser.add_argument("--check-identity", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        allowed_hashes = load_binary_allowlist()
        if args.staged:
            paths = split_null(
                git_bytes("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
            )
            findings = scan_index(paths, allowed_hashes)
        elif args.worktree:
            paths = split_null(
                git_bytes("ls-files", "-z", "--cached", "--others", "--exclude-standard")
            )
            findings = scan_worktree(paths, allowed_hashes)
        elif args.tracked:
            findings = scan_index(split_null(git_bytes("ls-files", "-z")), allowed_hashes)
        else:
            commits = commits_for_pre_push(args.pre_push, sys.stdin.read())
            findings = [
                finding
                for commit in commits
                for finding in scan_commit(commit, allowed_hashes)
            ]
        if args.check_identity:
            findings.extend(current_identity_finding())
    except (RuntimeError, ValueError) as exc:
        print(f"Privacy guard could not complete: {exc}", file=sys.stderr)
        return 2

    if findings:
        print("Privacy guard blocked this operation:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding.display()}", file=sys.stderr)
        print("Matched values are intentionally hidden. Remove or replace the data, then retry.", file=sys.stderr)
        return 1
    print("Privacy guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
