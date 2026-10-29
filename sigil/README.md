# SIGIL/1 — proof-carrying execution profile (reference implementation)

A profile over existing transports (MCP/A2A/HTTP), not a new wire protocol.
Core idea: **intent → grant → decision → effect → receipt → anchor**.

Install (wheel in `dist/`):

```bash
pip install sigil_profile-0.3.0-py3-none-any.whl
# console scripts: sigil-gate, sigil-verify, sigil-anchor, sigil-mcp-proxy
```

SDK:

```python
from sigil import SigilClient
c = SigilClient()                       # gate/verify/anchor defaults
i = {"id": "1", "op": "echo", "args": {"text": "hi"},
     "contract": {"id": "echo/v1", "version": "1"}}
g = c.grant(i, [{"id": "echo", "constraints": {}}])
r = c.execute(i, g, "idem-1")
assert c.verify(r["receipt"])["valid"]
a = c.anchor_root(r["receipt_hash"], 1)
```

Reusable middleware: `sigil.mcp.create_proxy_app(gate_url, upstream_url)` meters `tools/call`,
`resources/read`, `prompts/get` and attaches `_meta.sigil` receipts.
A2A helpers: `sigil.a2a.agent_extension()`, `sigil.a2a.record_echo()`, `sigil.a2a.attach_receipt()`.

## Services

| Service | Port | Role |
|---|---|---|
| `sigil.gate` | 18100 | grants, approvals, policy, idempotency, effects, receipts, chain |
| `sigil.verify` | 18101 | canonicalization, receipt/grant/chain/anchor verification, replay check |
| `sigil.anchor` | 18102 | append-only anchor log, anchor tokens |

Run (lab pattern, no Docker build):

```bash
docker run -d --name sigil-gate -p 127.0.0.1:18100:18100 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cap-drop ALL \
  --security-opt no-new-privileges --user 65534:65534 \
  -v /tmp/gama_proto_lab/sigil:/sigil:ro -v /tmp/gama_proto_lab/deps:/deps:ro \
  -v /tmp/sigil_lab/data:/data:rw -v /tmp/sigil_lab/effects:/effects:rw \
  -e PYTHONPATH=/sigil:/deps -e SIGIL_TEST=1 \
  python:3.12-slim python -m sigil.gate
# same for sigil.verify (18101) and sigil.anchor (18102)
```

## Envelope (carried in `_meta.sigil` / `metadata.sigil` / header)

```json
{
  "sigil": "1",
  "id": "uuid",
  "idem": "key",
  "actor": {"id": "lab", "kind": "agent"},
  "target": {"kind": "executor", "id": "local"},
  "intent": {"op": "echo", "args": {"text": "zdravo"}, "schema_ref": "echo/v1"},
  "contract": {"contract_id": "echo/v1", "version": "1"},
  "determinism": {"mode": "strict|seeded|best_effort", "seed": null},
  "evidence": {"level": "signed|anchored", "chain_id": "lab-chain"}
}
```

Hashes: `intent_hash = SHA-256(JCS(intent + contract))`, `route_hash = SHA-256(JCS(decision_trace))`,
`result_digest = SHA-256(JCS(result))`, `receipt_hash = SHA-256(JCS(receipt − sig − anchor))`.

## Grant (bound to intent, not a bearer token)

```json
{"grant_id":"uuid","subject":"lab","issuer":"sigil-gate",
 "capabilities":[{"id":"write_file","constraints":{"path_prefix":"/ok"}}],
 "bound_to":"<intent_hash>","not_before":0,"not_after":0,"max_uses":10,"nonce":"hex",
 "sig":{"alg":"hmac-sha256","key_id":"lab-hmac-1","value":"hex"}}
```

## Approval

```json
{"approval_id":"uuid","intent_hash":"...","policy_hash":"...","approver":"human:lab",
 "not_after":0,"nonce":"hex","sig":{...}}
```

## Receipt

```json
{"v":"1","receipt_id":"uuid","intent_id":"...","intent_hash":"...","route_hash":"...",
 "grant_id":"...","policy":{"decision":"allow|deny|require_approval","rule_ids":[],"policy_hash":"..."},
 "executor":{"kind":"local","id":"echo","version":"1.0","sandbox":"lab-container"},
 "effects":[{"kind":"fs.write","target":"/effects/x","before_digest":null,"after_digest":"...","bytes":1}],
 "result":{},"result_digest":"...","status":"ok|denied|error","nondet_used":[],
 "chain_id":"lab-chain","prev_hash":"...","sig":{...},"anchor":null}
```

## API

- `POST /grant {intent, capabilities?, ttl_ms?, max_uses?}`
- `POST /approve {intent, approver?}`
- `POST /execute {intent, grant, approval?, idem_key, transport?}` → receipt or error
- `POST /route {intent}` → decision trace + route_hash
- `GET /receipts`, `GET /chain/verify`
- verify: `POST /canonical`, `POST /verify {receipt,intent?,grant?,chain?,anchor?}`, `POST /replay {receipt,recorded}`
- anchor: `POST /anchor {root,seq}`, `GET /latest`, `POST /verify {anchor}`

## Errors

`E_GRANT_SIGNATURE`, `E_GRANT_BINDING`, `E_GRANT_EXPIRED`, `E_CAPABILITY_MISSING`,
`E_CAPABILITY_SCOPE`, `E_APPROVAL_REQUIRED`, `E_APPROVAL_INVALID`, `E_IDEMPOTENCY_CONFLICT`,
`E_CONTRACT_VIOLATION`, `E_UNKNOWN_OP`, plus receipts with `status=denied`.

## Signatures / keys

- Ed25519: **gate** `gate-ed25519-1`, **anchor** `anchor-ed25519-1`.
- **KMS (`:18103`) holds both private keys**; gate/anchor call `POST /sign` with a token. Gate/anchor containers have **no private keys**, verify has public keys only.
- HMAC-SHA256 accepted only for legacy receipts (`lab-hmac-1`).
- Remote anchor (node B `127.0.0.1:18102`) has its own Ed25519 key; its public key is `/data/keys/remote_anchor_pub.pem`; requests are token-gated (`/data/remote_token`).
- Local anchor **fails closed** (502 `E_REMOTE_ANCHOR`) if the remote anchor is unreachable.

## Conformance

`python -m sigil.conformance` → **30/30** (twice, plus packaged wheel run). Import-safe API: `from sigil.conformance import run; run(verbose=False)`.
Tests 16–30 cover Ed25519, remote Oracle anchor, MCP tools/resources/prompts, A2A metadata, local + public RFC3161, KMS isolation, replica read failover/auto-sync, write failover with lease fencing, and the lease witness.
Spec: `SIGIL_SPEC_1.0.md` (also shipped as `sigil/SPEC.md`); report `docs/SPEC.md`.

## Limits (honest)

- Lab HMAC key, single-node SQLite, local append-only anchor (not a public transparency log).
- Effects implemented locally (`echo`, `read_file`, `write_file`, `increment_counter`); external executors need adapters.
- RFC3161: **public FreeTSA** (`https://freetsa.org/tsr`) by default; local self-signed TSA remains as fallback (`SIGIL_TSA_MODE=local`).
- Public TSA depends on network/third party; local mode is deterministic/offline.
- Remote anchor is our Oracle service, not a public transparency log.
- KMS is a local signing daemon, not a cloud HSM; keys are readable inside its container.
- Oracle FS does not allow `chattr +a` (append-only flag unavailable); log is append-only by code.
- MCP middleware covers `tools/call`, `resources/read`, `prompts/get`; A2A covers card extension + message metadata.
- The wheel bundles the conformance script as a module; it is a script, not an import-time side effect.
