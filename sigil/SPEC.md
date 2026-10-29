# SIGIL/1 — Signed Intent, Grant, and Invariant Ledger
**Version:** 1.0 (profile over MCP / A2A / HTTP)  
**Status:** reference implementation + conformance suite

## 1. Scope

SIGIL/1 defines a semantic contract for agent actions:
**intent → grant → decision → effect → receipt → anchor**.

It does **not** define a new wire protocol. The envelope is carried in existing
metadata:
- MCP: `params._meta.sigil` / `result._meta.sigil`
- A2A: `Message.metadata.sigil` / `Artifact.metadata.sigil`
- HTTP: `SIGIL-Intent` / `SIGIL-Receipt` headers (base64url JCS)

## 2. Canonicalization and hashes

- JSON Canonicalization Scheme (RFC 8785 / JCS); UTF-8.
- `intent_hash = SHA-256(JCS(intent + contract))`
- `route_hash = SHA-256(JCS(decision_trace))`
- `result_digest = SHA-256(JCS(result))`
- `receipt_hash = SHA-256(JCS(receipt − sig − anchor))`
- Chain: `prev_hash` of first receipt is `"GENESIS"`.

## 3. Envelope

```json
{
  "sigil": "1",
  "id": "uuid",
  "idem": "string",
  "parent": "uuid|null",
  "issued_at": 0, "expires_at": 0,
  "actor": {"id": "string", "kind": "human|agent|service", "key_id": "string"},
  "target": {"kind": "tool|agent|executor", "id": "string", "version": "string"},
  "intent": {"op": "string", "args": {}, "schema_ref": "string"},
  "contract": {"contract_id": "string", "version": "string", "equivalence_domain": "string"},
  "caps_required": ["capability_id"],
  "determinism": {"mode": "strict|seeded|best_effort", "seed": null},
  "policy": {"profile": "string", "grant_id": "string|null", "approval_id": "string|null"},
  "evidence": {"level": "none|digest|signed|anchored", "chain_id": "string", "prev_hash": "string"}
}
```

## 4. Grant (capability authorization)

A grant is **bound to one intent hash**; it is not a bearer token.

```json
{"grant_id":"uuid","subject":"string","issuer":"string",
 "capabilities":[{"id":"capability","scope":"string","constraints":{"path_prefix":"/ok"}}],
 "bound_to":"<intent_hash>","not_before":0,"not_after":0,"max_uses":10,"nonce":"hex",
 "sig":{"alg":"ed25519","key_id":"gate-ed25519-1","value":"base64"}}
```

Rules: deny-by-default; signature; `bound_to` equality; expiry; capability presence;
constraint checks (e.g. `path_prefix`); single-use approval.

## 5. Approval

```json
{"approval_id":"uuid","intent_hash":"...","policy_hash":"...","approver":"human:...",
 "not_after":0,"nonce":"hex","sig":{...}}
```

An approval is valid only for the exact `intent_hash` + `policy_hash`, before expiry,
and once. Mutating any bound field invalidates it.

## 6. Lease and fencing (single writer)

A writer must hold a valid lease from a witness:

```json
{"lease_id":"uuid","holder":"gate-primary","fencing_token":7,
 "issuer":"remote-lease","not_after":0,
 "sig":{"alg":"ed25519","key_id":"remote-lease-1","value":"base64"}}
```

- Lease TTL 6s, renew every 2s (reference values).
- Every write (`execute`, `record`) requires a valid lease; otherwise `503 E_LEASE_LOST`.
- `fencing_token` is monotonic; it is included in the receipt.
- On primary loss, a standby acquires a **higher** fencing token before writing.
- **Quorum mode:** acquire/renew from N witnesses; require Q (reference 3 witnesses, Q=2).
  Each witness signs its own token; the receipt carries the max `fencing_token` and
  `quorum: {required, acquired, witnesses}`. One witness may fail without losing the lease;
  with only one witness left, writes fail closed (`E_LEASE_LOST`).
- A single witness is a SPOF; quorum mode removes that SPOF but the reference witness
  implementation is not a consensus protocol (no Raft/Paxos).

## 7. Receipt

```json
{"v":"1","receipt_id":"uuid","intent_id":"...","intent_hash":"...","route_hash":"...",
 "grant_id":"...","lease":{"holder":"...","fencing_token":7},
 "policy":{"decision":"allow|deny|require_approval","rule_ids":[],"policy_hash":"..."},
 "executor":{"kind":"local|mcp|a2a","id":"...","version":"...","sandbox":"..."},
 "effects":[{"kind":"fs.write|tool.call|mcp.tools.call|a2a.message","target":"...",
             "before_digest":null,"after_digest":"...","bytes":0}],
 "result":{},"result_digest":"...","status":"ok|denied|error",
 "nondet_used":[],"chain_id":"...","prev_hash":"...",
 "sig":{"alg":"ed25519","key_id":"gate-ed25519-1","value":"base64"},
 "anchor":null}
```

Denials are receipts too: `status="denied"`, `effects=[]`, fail-closed.

## 8. Determinism

- `strict`: only deterministic executors (`echo`, `read_file`, `increment_counter`,
  `sql`, `skill`, `fastpath`); LLM executors fail `E_CONTRACT_VIOLATION`.
- `seeded`: nondeterministic fields are declared and recorded; replay substitutes
  recorded values.
- `best_effort`: no replay guarantee.
- Determinism applies to intent, route, policy, and effects — **not** to model tokens.

## 9. Idempotency and crash recovery

- `idem` key + `intent_hash` uniqueness.
- Same key + same intent → stored receipt, `replayed: true`.
- Same key + different intent → `409 E_IDEMPOTENCY_CONFLICT`, no effect.
- Effects use a journal written before execution; on restart, a matching effect
  digest finalizes the receipt without re-applying (`recovered: true`).

## 10. Anchoring and timestamps

- Local chain is tamper-evident only after anchoring.
- Remote anchor (reference: Oracle) signs `chain root + seq` with Ed25519.
- RFC3161 timestamp token is bound to the chain root; public FreeTSA and a local
  TSA are supported.
- `verify` recomputes all hashes/signatures and validates local + remote + TSA.

## 11. Errors

Transport (retryable): `E_TRANSPORT`, `E_TIMEOUT`, `E_UNAVAILABLE`.  
Semantic (terminal): `E_POLICY_DENIED`, `E_CAPABILITY_MISSING`, `E_CAPABILITY_SCOPE`,
`E_APPROVAL_REQUIRED`, `E_APPROVAL_INVALID`, `E_IDEMPOTENCY_CONFLICT`,
`E_REPLAY_DIVERGENCE`, `E_EVIDENCE_INVALID`, `E_CONTRACT_VIOLATION`,
`E_UNSUPPORTED_FEATURE`, `E_LEASE_LOST`, `E_GRANT_*`, `E_TSA`, `E_REMOTE_ANCHOR`.

## 12. Signatures / KMS

- Ed25519 (`ed25519`) is the reference local algorithm.
- ECDSA P-256 (`ecdsa-p256-sha256`) is supported for cloud KMS/HSM compatibility.
- Adapters: AWS KMS (`ECDSA_SHA_256`), GCP KMS (`EC_SIGN_P256_SHA256`),
  Azure Key Vault (`ES256`); credentials are external and not part of the repo.
- The local P-256 backend is tested (`kms.p256_cloud_compatible`); cloud adapters
  require credentials and are not tested live in this lab.

## 13. Conformance (30 tests)

Canonical JCS · cross-transport intent hash · route hash · strict rejection ·
idem same/conflict/crash · replay/tamper/truncation · local+public RFC3161 ·
remote anchor · Ed25519 · KMS isolation · MCP tools/resources/prompts ·
A2A metadata · replica read failover · replica auto-sync · write failover with
lease fencing · lease witness token · **quorum lease (3 witnesses, Q=2)** ·
**P-256 cloud-KMS-compatible signature**.

Reference implementation: `sigil-profile` wheel; conformance: `sigil-conformance`.
