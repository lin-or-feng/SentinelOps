# Change log

This file records implemented scope, not release approval. The current package version remains `0.11.0`; no 1.0 tag or publication has been created.

## Unreleased — pre-1.0 readiness work

- Added a one-command, loopback-only offline browser acceptance harness with disposable fake providers, interrupted-browser recovery, redacted local reports and screenshots. This verifies UI workflow, not real incident accuracy or release qualification.

- Classified read-only provider preflight failures with fixed codes for authorization, rate limiting, timeout, invalid/oversized responses and network errors; rejected tampered audit chains when recovering a completed investigation instead of returning an apparently successful result.

- Added a separate loopback-only real observability operator desk. It requires the pilot static preflight, bearer token, bounded provider check for the exact task and explicit confirmation before a read-only investigation; results show references, Trace and audit, with read-only recovery of a completed result. No evidence bodies or AI authority are exposed. Offline fake-provider tests do not constitute real-data validation.

- Added explicit real-incident task input and bounded read-only Provider preflight; neither silently switches to fixture evidence.
- Committed final investigation results and completion audit events atomically in SQLite; serialized audit-chain appends.
- Added online SQLite snapshot and isolated restore verification, Provider timeout regressions, and documented soft-deadline behavior.
- Added an opt-in pilot deployment configuration preflight that rejects unsafe settings before application state is created.
- Added isolated wheel build/install smoke verification and a manual-only release-readiness CI workflow; no artifact is published.
- Remaining blockers: authorized independent incident data, real read-only Provider acceptance, target-environment security and recovery drills, Docker runtime smoke, dependency/image locking, license decision, and release approval.

## 0.11.0 — existing local version

- Added an optional, read-only local AI explanation preview for completed synthetic investigations. It cannot change the deterministic verdict or execute tools.
