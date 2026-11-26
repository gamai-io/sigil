[![PyPI](https://img.shields.io/pypi/v/sigil-profile.svg)](https://pypi.org/project/sigil-profile/)
[![CI](https://github.com/gamai-io/sigil/actions/workflows/ci.yml/badge.svg)](https://github.com/gamai-io/sigil/actions/workflows/ci.yml)

> **Live evidence dashboard:** https://gamai-io.github.io/demo/
> **Install:** `pip install sigil-profile`

# SIGIL/1 — Proof-Carrying Execution for AI Agents

> **ProofGate Runtime v0.1** is the local claim/receipt core: [`proofgate-runtime`](https://github.com/gamai-io/proofgate-runtime). SIGIL remains the grant/anchor/MCP middleware service.

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

## Docker image

The image is self-contained: `deploy/Dockerfile` is a multi-stage build that
packages the wheel **inside** the image from the checkout, so a fresh clone
needs no prebuilt `dist/*.whl` (and no version is hard-coded in the Dockerfile).
The base image is pinned by digest and the runtime runs as uid `65534`.

```bash
# build + smoke test (read-only rootfs, non-root, waits for /health)
bash deploy/build.sh

# or just build
docker build -f deploy/Dockerfile -t sigil:0.22 .
```

CI runs the same build and smoke test in the `docker` job (5-minute cap).
Deployment details: `deploy/PRODUCTION.md`.

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

Measured output on 2026-10-29 (Python 3.12, Linux x86_64):

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

`sigil-conformance` runs 49 numbered checks: grants, idempotency, replay,
tampering, chain breaks, anchor inclusion, MCP/A2A receipts, TSA, replica
failover and lease/quorum behaviour.

There are two honest, separately reported suites:

| Command | What it runs | Needs | Result CI reproduces |
|---|---|---|---|
| `pytest -q tests/ --ignore=tests/test_conformance_stack.py` | 7 unit tests + `run_offline()` | nothing (temp dir) | **8 passed** (7 unit + 1 offline test); CI matrix runs it on 3.10 and 3.12 |
| `python -m sigil.conformance --offline` | 12 library checks `O1`–`O12` | nothing (temp dir) | **12/12 passed** |
| `sigil-vectors` | 13 fixed vectors | nothing | **13/13 passed** |
| `pytest -q tests/test_conformance_stack.py -s` | stack checks `1`–`49` | gate/verify/anchor/KMS/replica/3 lease witnesses/MCP middleware/A2A/context gateway | **46 passed, 0 failed, 3 skipped** of 49 (~60 s, Python 3.12) |

Measured on 2026-11-26 with Python 3.12.3, Linux x86_64, in a fresh clone
(`SIGIL_CI_PORT_BASE=18300` was used locally because a host service already
held :18100; CI uses the defaults). The 3.10 leg is the CI matrix only — it was
not re-run on the machine where these numbers were taken. The stack job
generates all Ed25519/P-256 keys, control/approver/lease tokens and a
throw-away RFC3161 TSA certificate in the job — **no repository secrets and no
pre-existing `/tmp/sigil_lab`**.

The three skips are explicit, not silent passes:

| # | Check | Why it cannot run in CI |
|---|---|---|
| 17 | `anchor.remote_anchor` | The development lab pointed the anchor at an Oracle-hosted second anchor that stamps `node: "remote"`. That service is not in this repo and not in `deploy/docker-compose.yml`. Enable with `SIGIL_CONFORMANCE_REMOTE_ANCHOR` + a matching anchor. |
| 21 | `keys.isolation` | Asserts gate/anchor/verify cannot see private keys through container mounts. A process runner cannot prove container isolation, so it is skipped rather than faked. It runs under the docker lab driver. |
| 24 | `anchor.public_rfc3161` | Third-party FreeTSA (`https://freetsa.org/tsr`) needs network and CA/cert files that are not in the repo. Enable with `SIGIL_CONFORMANCE_PUBLIC_TSA=1` after installing those files. |

### What needs what

| Service (default port) | Checks that need it | CI-feasible |
|---|---|---|
| gate :18100 | 3–16, 18–20, 22–23, 25–29, 31–45, 47–49 | **yes** (uvicorn, generated keys) |
| verify :18101 | 1, 2, 8–11, 15, 16, 36, 43 | **yes** |
| anchor :18102 + local TSA | 11, 17, 20, 24, 41, 42 | **yes** for local TSA; **no** for 17/24 |
| KMS :18103 | signing for every executed receipt; 47 rotation; 21 isolation | **yes** for signing/rotation; **no** for isolation without containers |
| replica :18104 | 25, 26 | **yes** |
| lease witnesses :18106–18108 | 27–29, 40, 48 | **yes** |
| MCP middleware :18110 + upstream :18080 | 18, 22, 23, 39, 45 | **yes** (small upstream fixture in the test) |
| A2A endpoint :18082 | 19 | **yes** (fixture uses `sigil.a2a`) |
| context gateway :18120 | 44 | **yes** |
| P-256 key file (no service) | 30 | **yes** (generated in job) |
| external Oracle anchor | 17 | **no** — service not in repo |
| public FreeTSA | 24 | **no** — third party + missing CA files |
| container key isolation | 21 | **no** — requires mount namespaces/`docker exec` |

Files the suite needs are generated per run under a temp dir
(`SIGIL_CONFORMANCE_KEYS/EFFECTS/DATA`): gate/anchor Ed25519 keys, a P-256
signer, a lease witness key shared by the three witnesses, control/approver/
lease/KMS tokens, `lease_public.pem`, `p256_cloud_public.pem`, and a local TSA
cert+config. The docker driver still uses the original `/tmp/sigil_lab` and
`/tmp/gama_proto_lab/{sigil,deps}` layout.

`deploy/docker-compose.yml` is **not** sufficient for conformance: it defines
only `kms`, `gate`, `verify`, `anchor` and `context` (no replica, no lease
witnesses, no MCP middleware/A2A upstream), builds the image from the checkout
during `docker compose build` (the wheel is packaged inside the image — a fresh
clone needs no `dist/` artefact), maps services to 191xx, and sets
`SIGIL_TSA_ENABLE=0` with no remote anchor — so checks 17, 20, 24, 25–29, 40,
48 and the MCP/A2A ones cannot pass from compose alone. That is why the CI job
starts uvicorn processes directly instead.

Checks 7, 25, 27, 29 and 40 are timing-sensitive by nature: they stop/restart
gate or witness processes and wait for lease expiry (check 29 alone is ~30 s
because `execute()` retries 503 for up to 12 s). The suite waits on health
endpoints rather than fixed sleeps where possible, but these five are the ones
to suspect first if the job flakes; they are not reported green unless the
observed state matches. The stack job runs on Python 3.12 only to keep CI
under ~5 minutes; the offline suite runs on 3.10 and 3.12.

## Status

Reference implementation, actively hardened. Interfaces may change before 1.0.
Two specs are included:

- `SIGIL_SPEC_1.0.md` — core receipt/grant/anchor model
- `SIGIL_SPEC_1.1.md` — quorum lease, context gateway, A2A/MCP profile

## License

Apache-2.0. See `LICENSE`.
## Sold on its own, or inside the suite? (asked on AI Lounge, 24 Nov 2026)

Both, deliberately: receipts are the unit a customer can adopt alone (a verifier is 30 lines), while
the fleet audit is what they buy once the receipts exist. Selling only the suite would hide the one
artefact that proves the claim; selling only receipts leaves the replay and the audit unsold.
