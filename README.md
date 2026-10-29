# SIGIL/1 — Proof-Carrying Execution for AI Agents

SIGIL/1 is a **profile over existing transports** (MCP, A2A, HTTP), not a new wire protocol.
It makes every consequential agent action answerable with a verifiable receipt:

```
intent -> grant -> decision -> effect -> receipt -> anchor
```

If an action cannot be granted, executed, or proven, it is **denied by default**.
The reference implementation ships a gate, a verifier, an append-only anchor log,
an MCP middleware, A2A helpers, quorum leases, and a conformance suite.

## Why

Agent frameworks log *traces*. Traces show what the agent said it did.
SIGIL produces a *receipt*: canonicalized intent, policy decision, effect hash,
idempotency key, lease fencing token, and an inclusion proof against an anchor root.
A verifier can reject a receipt without trusting the agent, the model, or the log store.

## Components

| Component | Role |
|---|---|
| `sigil-gate` | grants, policy, approvals, idempotency, effects, receipts, hash chain |
| `sigil-verify` | canonicalization, receipt/grant/chain/anchor verification, replay check |
| `sigil-anchor` | append-only anchor log, inclusion proofs, anchor tokens |
| `sigil-mcp-proxy` | meters `tools/call`, `resources/read`, `prompts/get`; attaches `_meta.sigil` |
| `sigil-lease-witness` | quorum lease witnesses (fencing tokens) |
| `sigil-conformance` | end-to-end conformance suite |

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

Optional A2A helpers: `pip install -e '.[a2a]'`.

## Quickstart (in-process SDK)

```python
from sigil import SigilClient

c = SigilClient()
intent = {
    "id": "1",
    "op": "echo",
    "args": {"text": "hi"},
    "contract": {"id": "echo/v1", "version": "1"},
}
grant = c.grant(intent, [{"id": "echo", "constraints": {}}])
result = c.execute(intent, grant, "idem-1")
assert c.verify(result["receipt"])["valid"]
anchor = c.anchor_root(result["receipt_hash"], 1)
```

## Run services (lab)

```bash
sigil-gate      --port 18100
sigil-verify    --port 18101
sigil-anchor    --port 18102
sigil-conformance --base http://127.0.0.1:18100
```

Each service is a small FastAPI app; see `deploy/` for Docker and compose examples.

## Security model (what it does and does not do)

- **Does**: canonical JSON (RFC 8785), Ed25519 signatures, hash-chained receipts,
  idempotency keys, lease fencing, quorum witnesses, replay rejection,
  tamper detection, inclusion proofs.
- **Does not**: sandbox the workload. Pair SIGIL with a sandbox
  (bubblewrap, gVisor, containers) for isolation. SIGIL proves *what happened*;
  it does not prevent a compromised runtime from trying.
- **Trust boundary**: the KMS/keys and the anchor log are the roots of trust.
  Protect them; rotate keys with `sigil-rotate`.

## Invoice-to-ERP demo (proof, not a claim)

`examples/invoice_erp_demo.py` is a self-contained synthetic workflow:

```
invoice math -> capability grant -> idempotent claim -> ERP write
             -> signed receipt -> anchor -> independent verify -> replay/tamper
```

Run it with services started in a temporary runtime:

```bash
python3 examples/invoice_erp_demo.py --start
```

Measured output on 2026-10-29 (Python 3.12, Contabo):

```text
[1] invoice MOCK-2026-001: net=64.50 vat=10.97 total=75.47 -> math ok
[2] grant ... bound to intent, max_uses=1
[3] idempotent claim reserved: invoice-MOCK-2026-001
[4] ERP write: /tmp/sigil-erp-.../MOCK-2026-001.json
[5] receipt 57e5836ccf38c642... recorded
[6] independent verify: valid=True errors=[]
[7] anchor ... verify={'valid': True, ...}
[8] same idempotency key -> replayed=True (no second effect)
[9] tampered receipt -> valid=False errors=['E_SIGNATURE', 'E_RESULT_DIGEST']
RESULT: PASS
```

It uses synthetic data and a temporary JSON "ERP"; it does not connect to a
production ERP and does not claim OCR accuracy. The point is the trust path:
the same invoice cannot be posted twice, the result is signed, and a changed
receipt is rejected.

## Conformance

`sigil-conformance` exercises grants, idempotency, replay, tampering, chain breaks,
anchor inclusion, remote anchor verification, and lease/quorum behaviour.
The reference run used in development reports 49/49 checks passing against the
0.22.0 package (see `docs/` and the conformance output).

## Status

Reference implementation, actively hardened. Interfaces may change before 1.0.
Two specs are included:

- `SIGIL_SPEC_1.0.md` — core receipt/grant/anchor model
- `SIGIL_SPEC_1.1.md` — quorum lease, context gateway, A2A/MCP profile

## License

Apache-2.0. See `LICENSE`.
