# Security and privacy policy

## Supported version

Only the latest `main` revision receives security fixes.

## Reporting

Do not open a public issue containing credentials, personal information, exploit payloads or private logs. Use GitHub Private Vulnerability Reporting when it is enabled for this repository. Until a private channel is configured, remove sensitive values and provide only a minimal redacted reproduction.

## Repository privacy controls

- `.gitignore` excludes common environment, database, key and credential files;
- repository-owned `pre-commit` and `pre-push` hooks run `scripts/privacy_guard.py`;
- CI scans every tracked file independently of local hooks;
- findings disclose only path, line and detector name, never the matched value;
- unreviewed binary files are blocked; approvals are bound to an exact SHA-256 in `.privacy-allowlist`;
- new commits must use a GitHub noreply author and committer address.

These controls reduce accidental disclosure but are not a DLP product. OCR, steganography, encrypted archives, novel token formats and intentionally bypassed hooks may evade detection.

## If a secret was committed

1. Revoke or rotate it immediately; assume cloning and caching already occurred.
2. Remove it from current files.
3. Coordinate before rewriting Git history because force-push invalidates existing clones and open work.
4. Re-run the privacy guard and security tests.
5. Review audit/provider logs for unauthorized use.
