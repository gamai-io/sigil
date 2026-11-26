# Changelog

## [0.22.2] - 2026-11-26

### Added
- `sigil-conformance --offline`: 12 library-only checks (JCS, hashes, sign/verify, tamper,
  chain truncation, suffix proof, path prefix, HMAC downgrade, P-256, ctx/handoff lifecycle,
  vectors) that need no services and no `/data`.
- A CI job that starts the full stack (gate, verifier, anchor + TSA, KMS, replica, three
  lease witnesses, MCP proxy, A2A, context gateway) with generated keys and runs the
  conformance suite: 46 pass, 0 fail, 3 skipped with reasons.
- `deploy/build.sh` and a multi-stage `deploy/Dockerfile`; `docker build` now works from a
  fresh clone instead of expecting `dist/*.whl`.

### Fixed
- The offline checks failed on a machine without `/data` because `sigil.ctx`/`handoff`
  build their paths from `SIGIL_DATA` at import time.
- Two tamper mutations in the conformance suite could self-collide (1/64) and pass a
  tampered receipt.
- `__version__` said 0.22.0 while the package was 0.22.1 (a test now keeps them equal).
- The README implied a 49/49 conformance run was CI-verified; it now states exactly what
  CI runs and which three checks need infrastructure this repository does not ship.
