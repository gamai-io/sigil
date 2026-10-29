# SIGIL/1.1 — lab profile (normative changes over 1.0)

Status: lab profile. This is not a claim of production HA or independent certification.

## 1. Control plane

- `POST /grant`, `/route`, `/authorize`, `/abort`, `/execute`, `/record`, `/debug/reset` require `X-SIGIL-Token` matching `SIGIL_CONTROL_TOKEN_FILE`.
- `POST /approve` requires a distinct `SIGIL_APPROVER_TOKEN_FILE`.
- Missing/empty token file fails closed with `401 E_UNAUTHENTICATED`.
- `/health`, `/receipts`, `/chain/verify`, `/chain/proof/*` are read-only.

## 2. Claims and execution

- `/authorize` validates policy, grant and approval, then reserves the grant use and approval before any effect. It returns `claim_id` (the idempotency key).
- `/abort` releases a claim if the external effect did not complete.
- `/record` with `claim_id` finalizes a receipt for an external effect without re-consuming the grant/approval.
- MCP metered calls MUST follow `grant -> authorize -> upstream -> record`; a deny happens before the upstream call.
- MCP `tools/call` arguments MUST validate against the upstream `tools/list` JSON schema. Invalid arguments return `-32602` with `E_TOOL_SCHEMA` and no effect.

## 3. Idempotency and lease

- `inflight` reserves an idempotency key atomically; concurrent duplicates receive `409 E_IDEMPOTENCY_IN_PROGRESS`.
- `finalize` runs under `BEGIN IMMEDIATE`, writes the chain and idem atomically, and requires a valid lease.
- Lease loss is fail-closed (`503 E_LEASE_LOST`).
- Witness fencing is persisted (`state.json`, `0600`) and MUST NOT reset on restart.

## 4. Anchor

- `POST /anchor` requires the root to equal the current gate chain root (`409 E_ROOT_NOT_IN_CHAIN`).
- Root MUST be 64 lowercase hex.
- With `SIGIL_ANCHOR_STRICT_SEQ=1`, `seq` MUST be greater than the previous anchor (`409 E_ANCHOR_ROLLBACK`).
- Append is serialized and fsynced.

## 5. Proof of inclusion

- `GET /chain/proof/{receipt_hash}` returns a suffix from the target receipt to the current root.
- `POST /verify/proof` verifies the target hash, `prev_hash` links, signatures and root (`E_PROOF_TARGET`, `E_PROOF_ROOT`).

## 6. ACP bridge and context

- ACP `_meta["dev.gama.sigil"]` carries `ctx_id`, `handoff_id`, `step`, `idem_key`, `replay`, `receipt_hash`.
- Context ids are content-addressed (`ctx1:`); blobs are `sha256:`.
- Handoff manifests bind a context, expected receipts and an `idem_prefix`.
- Replay MUST reuse the same idempotency keys and MUST NOT create a new chain receipt.
- `POST /prune` (control token) removes old contexts/handoffs; live manifest references are preserved.

## 7. Fixed vectors

`sigil-vectors` verifies `sigil/vectors.json` (JCS, policy hash, path boundaries, normalization, receipt hash, JSON schema cases) without running any service.

## 8. Key rotation

- `sigil-rotate <gate|anchor> <role>-ed25519-N --kms-dir ... --pub-dir ...` generates a new private key (`0600`) and public key (`<key_id>_public.pem`, `0644`).
- KMS accepts `gate-ed25519-N` and `anchor-ed25519-N` key ids with existing key files.
- Old public keys remain published so old receipts keep verifying; switch the signer by setting `SIGIL_KEY_ID` and restarting that service.


## 9. Quorum lease certificate

- A receipt's `lease.quorum` includes `proofs`: the individually signed witness lease tokens.
- Each proof MUST verify against the witness public key and MUST bind the same holder.
- The receipt `fencing_token` MUST equal the maximum proof fencing token.
- A tampered or missing proof invalidates the quorum certificate.
