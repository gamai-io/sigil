from __future__ import annotations
import json, os, sqlite3, sys, uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
import uvicorn
from . import common as C
from .lease import Lease, LeaseLost
from .quorum_lease import QuorumLease, QuorumLeaseLost

DESTRUCTIVE = {"rm_rf", "format_disk", "drop_table", "delete_all"}
ALLOWED = {"echo", "read_file", "write_file", "increment_counter"}
DETERMINISTIC = {"echo", "read_file", "increment_counter", "sql", "skill", "fastpath"}
CRASH = os.environ.get("SIGIL_CRASH_AFTER_EFFECT") == "1"
LEASE = None
_lease_urls = [u for u in os.environ.get("SIGIL_LEASE_URLS", "").split(",") if u.strip()]
if _lease_urls:
    LEASE = QuorumLease(_lease_urls,
                        os.environ.get("SIGIL_LEASE_TOKEN_FILE", "/run/sigil-lease-token"),
                        os.environ.get("SIGIL_LEASE_HOLDER", "gate-primary"),
                        os.environ.get("SIGIL_LEASE_PUB", "/pub/lease_public.pem"),
                        quorum=int(os.environ.get("SIGIL_LEASE_QUORUM", "2")))
elif os.environ.get("SIGIL_LEASE_URL"):
    LEASE = Lease(os.environ["SIGIL_LEASE_URL"],
                  os.environ.get("SIGIL_LEASE_TOKEN_FILE", "/run/sigil-lease-token"),
                  os.environ.get("SIGIL_LEASE_HOLDER", "gate-primary"),
                  os.environ.get("SIGIL_LEASE_PUB", "/pub/lease_public.pem"))

def policy_for(intent: dict) -> dict:
    op = intent.get("op")
    args = intent.get("args") or {}
    if op in DESTRUCTIVE:
        return {"decision": "deny", "rule_ids": ["destructive_deny"]}
    if str(op or "").startswith("mcp.") and args.get("tool") in DESTRUCTIVE:
        return {"decision": "deny", "rule_ids": ["mcp_destructive_tool_deny"]}
    if op not in ALLOWED and not str(op or "").startswith("mcp."):
        return {"decision": "deny", "rule_ids": ["unknown_op_deny"]}
    if op == "write_file":
        return {"decision": "require_approval", "rule_ids": ["write_requires_approval"]}
    return {"decision": "allow", "rule_ids": ["allow_read_echo_counter"]}

def policy_hash(policy: dict) -> str:
    return C.sha({"decision": policy["decision"], "rule_ids": policy["rule_ids"]})

def server_caps(intent: dict) -> list[dict] | None:
    op = intent.get("op")
    if op == "write_file":
        return [{"id": op, "constraints": {"path_prefix": C.WRITE_PREFIX}}]
    if op in ALLOWED or str(op or "").startswith("mcp."):
        return [{"id": op, "constraints": {}}]
    return None

def route_trace(intent: dict) -> list[dict]:
    return [
        {"stage": "reflex", "rule_id": "intent_hash", "outcome": "ok",
         "inputs_digest": C.sha(intent)},
        {"stage": "policy", "rule_id": ",".join(policy_for(intent)["rule_ids"]),
         "outcome": policy_for(intent)["decision"]},
    ]

def error(code: str, msg: str, status: int = 400, **extra):
    return JSONResponse({"error": {"code": code, "message": msg, **extra}}, status_code=status)

def validate_grant(con, grant: dict, intent_hash: str, op: str, intent: dict) -> tuple[bool, str]:
    core = {k: v for k, v in grant.items() if k != "sig"}
    if not C.verify_sig(core, grant.get("sig", {})):
        return False, "E_GRANT_SIGNATURE"
    if grant.get("bound_to") != intent_hash:
        return False, "E_GRANT_BINDING"
    now = C.now_ms()
    if grant.get("not_before", 0) > now:
        return False, "E_GRANT_NOT_YET_VALID"
    if grant.get("not_after", 0) <= now:
        return False, "E_GRANT_EXPIRED"
    row = con.execute("SELECT uses,max_uses FROM grants WHERE grant_id=? AND intent_hash=?",
                      (grant.get("grant_id"), intent_hash)).fetchone()
    if row is None:
        return False, "E_GRANT_UNKNOWN"
    if row["uses"] >= row["max_uses"]:
        return False, "E_GRANT_EXHAUSTED"
    caps = grant.get("capabilities") or []
    cap = next((c for c in caps if c.get("id") == op), None)
    if cap is None:
        return False, "E_CAPABILITY_MISSING"
    prefix = (cap.get("constraints") or {}).get("path_prefix", "")
    if op == "write_file" and not prefix:
        return False, "E_CAPABILITY_SCOPE"
    if prefix:
        path = (intent.get("args") or {}).get("path", "")
        if not path or not C.within_prefix(prefix, path):
            return False, "E_CAPABILITY_SCOPE"
    return True, ""

def validate_approval(con, approval: dict, intent_hash: str, pol_hash: str) -> tuple[bool, str]:
    if not approval:
        return False, "E_APPROVAL_REQUIRED"
    core = {k: v for k, v in approval.items() if k != "sig"}
    if not C.verify_sig(core, approval.get("sig", {})):
        return False, "E_APPROVAL_INVALID"
    if approval.get("intent_hash") != intent_hash:
        return False, "E_APPROVAL_INVALID"
    if approval.get("policy_hash") != pol_hash:
        return False, "E_APPROVAL_INVALID"
    now = C.now_ms()
    if approval.get("not_before", 0) > now:
        return False, "E_APPROVAL_NOT_YET_VALID"
    if approval.get("not_after", 0) <= now:
        return False, "E_APPROVAL_INVALID"
    row = con.execute("SELECT used FROM approvals WHERE approval_id=?", (approval.get("approval_id"),)).fetchone()
    if row is None or row["used"]:
        return False, "E_APPROVAL_INVALID"
    return True, ""

def build_receipt(intent, intent_hash, route_hash, grant_id, policy, effects, result, status="ok", **extra):
    rec = {
        "v": "1", "receipt_id": str(uuid.uuid4()), "intent_id": intent.get("id"),
        "intent_hash": intent_hash, "route_hash": route_hash, "grant_id": grant_id,
        "policy": {"decision": policy["decision"], "rule_ids": policy["rule_ids"],
                   "policy_hash": policy_hash(policy)},
        "executor": {"kind": "local", "id": intent.get("op"), "version": "1.0",
                     "sandbox": "lab-container"},
        "effects": effects, "result": result, "result_digest": C.sha(result),
        "status": status, "nondet_used": intent.get("nondet", []),
        "chain_id": C.CHAIN_ID, "prev_hash": "",
    }
    rec.update(extra)
    return rec

class ClaimError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.message = message or code
        super().__init__(self.message)

def reserve_idem(con, key: str, intent_hash: str):
    try:
        con.execute("INSERT INTO inflight(key,intent_hash,created_at) VALUES(?,?,?)",
                    (key, intent_hash, C.now_ms()))
    except sqlite3.IntegrityError:
        raise ClaimError("E_IDEMPOTENCY_IN_PROGRESS", "same idem_key is already in flight")

def claim_grant(con, grant_id: str, now: int):
    cur = con.execute("UPDATE grants SET uses=uses+1 WHERE grant_id=? AND uses<max_uses AND not_after>?",
                      (grant_id, now))
    if cur.rowcount != 1:
        raise ClaimError("E_GRANT_EXHAUSTED", "grant exhausted or expired")

def claim_approval(con, approval: dict, now: int):
    cur = con.execute(
        "UPDATE approvals SET used=1 WHERE approval_id=? AND used=0 AND not_after>? AND "
        "COALESCE(json_extract(approval_json,'$.not_before'),0)<=?",
        (approval.get("approval_id"), now, now))
    if cur.rowcount != 1:
        raise ClaimError("E_APPROVAL_INVALID", "approval already used or expired")

def reserve_claims(con, key: str, intent_hash: str, grant: dict,
                   approval: dict | None, need_approval: bool):
    con.execute("BEGIN IMMEDIATE")
    try:
        reserve_idem(con, key, intent_hash)
        if need_approval:
            claim_approval(con, approval or {}, C.now_ms())
        claim_grant(con, grant.get("grant_id"), C.now_ms())
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise

def finalize(con, receipt, receipt_hash, idem_key=None):
    lease_info = None
    if LEASE:
        t = LEASE.require()
        lease_info = {"holder": t.get("holder"), "fencing_token": t.get("fencing_token")}
        if "quorum" in t: lease_info["quorum"] = t["quorum"]
        receipt["lease"] = lease_info
    con.execute("BEGIN IMMEDIATE")
    try:
        prev = C.last_hash(con)
        receipt["prev_hash"] = prev
        core = {k: v for k, v in receipt.items() if k not in ("sig", "anchor")}
        receipt["sig"] = C.sign(core)
        rh = C.receipt_hash(receipt)
        con.execute("INSERT INTO chain(receipt_hash, prev_hash, receipt_json, created_at) VALUES(?,?,?,?)",
                    (rh, prev, json.dumps(receipt, ensure_ascii=False), C.now_ms()))
        if idem_key:
            con.execute("INSERT INTO idem(key,intent_hash,receipt_json,created_at) VALUES(?,?,?,?)",
                        (idem_key, receipt["intent_hash"], json.dumps(receipt, ensure_ascii=False), C.now_ms()))
            con.execute("DELETE FROM inflight WHERE key=?", (idem_key,))
        con.execute("COMMIT")
        return receipt, rh
    except Exception:
        con.execute("ROLLBACK")
        raise

def recover(con):
    if LEASE and not LEASE.valid():
        return
    rows = con.execute("SELECT * FROM journal").fetchall()
    for r in rows:
        key = r["key"]
        con.execute("BEGIN IMMEDIATE")
        try:
            if con.execute("SELECT 1 FROM idem WHERE key=?", (key,)).fetchone():
                con.execute("DELETE FROM journal WHERE key=?", (key,))
                con.execute("DELETE FROM inflight WHERE key=?", (key,))
                con.execute("COMMIT")
                continue
            payload = json.loads(r["payload"])
            target = r["target"]
            if C.file_digest(target) != r["after_digest"]:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w") as f: f.write(str(payload["counter"]))
            receipt = payload["receipt"]
            receipt["recovered"] = True
            receipt["prev_hash"] = C.last_hash(con)
            core = {k: v for k, v in receipt.items() if k not in ("sig", "anchor")}
            receipt["sig"] = C.sign(core)
            rh = C.receipt_hash(receipt)
            con.execute("INSERT INTO chain(receipt_hash, prev_hash, receipt_json, created_at) VALUES(?,?,?,?)",
                        (rh, receipt["prev_hash"], json.dumps(receipt, ensure_ascii=False), C.now_ms()))
            con.execute("INSERT OR REPLACE INTO idem(key,intent_hash,receipt_json,created_at) VALUES(?,?,?,?)",
                        (key, receipt["intent_hash"], json.dumps(receipt, ensure_ascii=False), C.now_ms()))
            con.execute("DELETE FROM journal WHERE key=?", (key,))
            con.execute("DELETE FROM inflight WHERE key=?", (key,))
            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            raise

@asynccontextmanager
async def lifespan(app: FastAPI):
    if LEASE:
        LEASE.start()
    if LEASE is None or LEASE.valid():
        con = C.db(); recover(con); con.close()
    try:
        yield
    finally:
        if LEASE: LEASE.release()

app = FastAPI(title="sigil-gate", lifespan=lifespan, docs_url=None, redoc_url=None)
METRICS = {"requests": 0, "errors": 0}

@app.middleware("http")
async def metrics_mw(request: Request, call_next):
    METRICS["requests"] += 1
    try:
        resp = await call_next(request)
    except Exception:
        METRICS["errors"] += 1
        raise
    if resp.status_code >= 500:
        METRICS["errors"] += 1
    return resp

@app.middleware("http")
async def control_auth(request: Request, call_next):
    path = request.url.path
    if path == "/health":
        return await call_next(request)
    got = request.headers.get("X-SIGIL-Token")
    if path == "/approve":
        ok = C.token_ok(got, C.read_token(C.APPROVER_TOKEN_FILE))
    elif path in {"/grant", "/route", "/authorize", "/abort", "/execute", "/record", "/debug/reset"}:
        ok = C.token_ok(got, C.read_token(C.CONTROL_TOKEN_FILE))
    else:
        ok = True
    if not ok:
        return JSONResponse({"error": {"code": "E_UNAUTHENTICATED",
                                       "message": "control token required"}}, status_code=401)
    return await call_next(request)

@app.get("/metrics")
def metrics():
    con = C.db()
    try:
        count = con.execute("SELECT COUNT(*) FROM chain").fetchone()[0]
    finally:
        con.close()
    lease = 1 if (LEASE and LEASE.valid()) else 0
    body = "\n".join([
        "# TYPE sigil_chain_receipts gauge",
        f"sigil_chain_receipts {count}",
        "# TYPE sigil_requests_total counter",
        f"sigil_requests_total {METRICS['requests']}",
        "# TYPE sigil_errors_total counter",
        f"sigil_errors_total {METRICS['errors']}",
        "# TYPE sigil_lease_valid gauge",
        f"sigil_lease_valid {lease}",
    ]) + "\n"
    return PlainTextResponse(body)

@app.get("/health")
def health():
    out = {"ok": True, "role": "gate", "chain_id": C.CHAIN_ID}
    if LEASE:
        out["lease"] = LEASE.valid()
        try:
            t = LEASE.require(); out["lease_holder"] = t.get("holder"); out["fencing_token"] = t.get("fencing_token")
        except Exception:
            pass
    return out

@app.post("/grant")
async def grant(req: Request):
    body = await req.json()
    intent = body.get("intent") or {}
    ih = C.sha(intent)
    caps = server_caps(intent)
    if caps is None:
        return error("E_CAPABILITY_MISSING", "no server capability for op", 403)
    requested = body.get("capabilities")
    if requested is not None:
        allowed = {(c.get("id"), json.dumps(c.get("constraints") or {}, sort_keys=True)) for c in caps}
        if any((c.get("id"), json.dumps(c.get("constraints") or {}, sort_keys=True)) not in allowed
               for c in requested):
            return error("E_CAPABILITY_ESCALATION", "requested capability not allowed", 403)
    ttl = min(max(int(body.get("ttl_ms", 300000)), 1), 600000)
    max_uses = min(max(int(body.get("max_uses", 10)), 1), C.MAX_USES_CAP)
    g = {"grant_id": str(uuid.uuid4()), "subject": C.PRINCIPAL,
         "issuer": "sigil-gate", "capabilities": caps, "bound_to": ih,
         "not_before": C.now_ms(), "not_after": C.now_ms() + ttl,
         "max_uses": max_uses, "nonce": uuid.uuid4().hex}
    g["sig"] = C.sign(g)
    con = C.db()
    con.execute("INSERT INTO grants(grant_id,intent_hash,grant_json,uses,max_uses,not_after) VALUES(?,?,?,?,?,?)",
                (g["grant_id"], ih, json.dumps(g), 0, g["max_uses"], g["not_after"]))
    con.close()
    return {"grant": g, "intent_hash": ih}

@app.post("/approve")
async def approve(req: Request):
    body = await req.json()
    intent = body.get("intent") or {}
    ih = C.sha(intent)
    policy = policy_for(intent)
    ph = policy_hash(policy)
    a = {"approval_id": str(uuid.uuid4()), "intent_hash": ih, "policy_hash": ph,
         "approver": C.APPROVER_ID,
         "not_before": C.now_ms(),
         "not_after": C.now_ms() + min(max(int(body.get("ttl_ms", 300000)), 1), 600000),
         "nonce": uuid.uuid4().hex}
    a["sig"] = C.sign(a)
    con = C.db()
    con.execute("INSERT INTO approvals(approval_id,intent_hash,policy_hash,approval_json,used,not_after) VALUES(?,?,?,?,0,?)",
                (a["approval_id"], ih, ph, json.dumps(a), a["not_after"]))
    con.close()
    return {"approval": a, "intent_hash": ih, "policy_hash": ph}

@app.post("/route")
async def route(req: Request):
    body = await req.json()
    intent = body.get("intent") or {}
    trace = route_trace(intent)
    return {"trace": trace, "route_hash": C.sha(trace), "intent_hash": C.sha(intent)}

def _lease_or_503():
    if LEASE is None:
        return None
    try:
        return LEASE.require()
    except (LeaseLost, QuorumLeaseLost):
        return JSONResponse({"error": {"code": "E_LEASE_LOST", "message": "writer lease lost"}}, status_code=503)

@app.post("/authorize")
async def authorize(req: Request):
    ltok = _lease_or_503()
    if isinstance(ltok, JSONResponse): return ltok
    body = await req.json()
    intent = body.get("intent") or {}
    grant = body.get("grant") or {}
    approval = body.get("approval")
    key = body.get("idem_key")
    if not key:
        return error("E_IDEMPOTENCY_KEY_REQUIRED", "idem_key is required", 422)
    ih = C.sha(intent)
    policy = policy_for(intent)
    ph = policy_hash(policy)
    rh = C.sha(route_trace(intent))
    con = C.db()
    try:
        row = con.execute("SELECT intent_hash, receipt_json FROM idem WHERE key=?", (key,)).fetchone()
        if row:
            if row["intent_hash"] != ih:
                return error("E_IDEMPOTENCY_CONFLICT", "same key, different intent", 409)
            rec = json.loads(row["receipt_json"])
            rh = C.receipt_hash(rec)
            rec["replayed"] = True
            return {"authorized": True, "replayed": True, "claim_id": key,
                    "receipt": rec, "receipt_hash": rh,
                    "result": rec.get("result")}
        if policy["decision"] == "deny":
            con.execute("BEGIN IMMEDIATE")
            try:
                reserve_idem(con, key, ih)
                con.execute("COMMIT")
            except Exception:
                con.execute("ROLLBACK"); raise
            rec = build_receipt(intent, ih, rh, grant.get("grant_id"), policy, [], None, status="denied")
            rec, _ = finalize(con, rec, None, key)
            return JSONResponse({"receipt": rec, "denied": True}, status_code=403)
        ok, why = validate_grant(con, grant, ih, intent.get("op"), intent)
        if not ok:
            return error(why, "grant rejected", 403)
        if policy["decision"] == "require_approval":
            ok, why = validate_approval(con, approval, ih, ph)
            if not ok:
                return error(why, "approval rejected", 403)
        try:
            reserve_claims(con, key, ih, grant, approval, policy["decision"] == "require_approval")
        except ClaimError as e:
            return error(e.code, e.message, 409 if e.code == "E_IDEMPOTENCY_IN_PROGRESS" else 403)
        return {"authorized": True, "claim_id": key, "intent_hash": ih,
                "grant_id": grant.get("grant_id"),
                "approval_id": approval.get("approval_id") if approval else None}
    finally:
        con.close()


@app.post("/abort")
async def abort(req: Request):
    ltok = _lease_or_503()
    if isinstance(ltok, JSONResponse): return ltok
    body = await req.json()
    key = body.get("claim_id") or body.get("idem_key")
    grant_id = body.get("grant_id")
    approval_id = body.get("approval_id")
    if not key:
        return error("E_CLAIM_REQUIRED", "claim_id is required", 422)
    con = C.db()
    try:
        con.execute("BEGIN IMMEDIATE")
        con.execute("DELETE FROM inflight WHERE key=?", (key,))
        if grant_id:
            con.execute("UPDATE grants SET uses=CASE WHEN uses>0 THEN uses-1 ELSE 0 END WHERE grant_id=?", (grant_id,))
        if approval_id:
            con.execute("UPDATE approvals SET used=0 WHERE approval_id=?", (approval_id,))
        con.execute("COMMIT")
        return {"aborted": True, "claim_id": key}
    except Exception:
        con.execute("ROLLBACK"); raise
    finally:
        con.close()


@app.post("/execute")
async def execute(req: Request):
    ltok = _lease_or_503()
    if isinstance(ltok, JSONResponse): return ltok
    body = await req.json()
    intent = body.get("intent") or {}
    grant = body.get("grant") or {}
    approval = body.get("approval")
    key = body.get("idem_key")
    if not key:
        return error("E_IDEMPOTENCY_KEY_REQUIRED", "idem_key is required", 422)
    ih = C.sha(intent)
    policy = policy_for(intent)
    ph = policy_hash(policy)
    route = route_trace(intent)
    rh = C.sha(route)

    con = C.db()
    try:
        row = con.execute("SELECT intent_hash, receipt_json FROM idem WHERE key=?", (key,)).fetchone()
        if row:
            if row["intent_hash"] != ih:
                return error("E_IDEMPOTENCY_CONFLICT", "same key, different intent", 409)
            rec = json.loads(row["receipt_json"]); rec["replayed"] = True
            return {"receipt": rec, "replayed": True, "result": rec.get("result")}

        if policy["decision"] == "deny":
            con.execute("BEGIN IMMEDIATE")
            try:
                reserve_idem(con, key, ih)
                con.execute("COMMIT")
            except Exception:
                con.execute("ROLLBACK")
                raise
            rec = build_receipt(intent, ih, rh, grant.get("grant_id"), policy, [], None, status="denied")
            rec, _ = finalize(con, rec, None, key)
            return JSONResponse({"receipt": rec, "denied": True}, status_code=403)

        ok, why = validate_grant(con, grant, ih, intent.get("op"), intent)
        if not ok:
            return error(why, "grant rejected", 403)
        if policy["decision"] == "require_approval":
            ok, why = validate_approval(con, approval, ih, ph)
            if not ok:
                return error(why, "approval rejected", 403)
        mode = (intent.get("determinism") or {}).get("mode", "best_effort")
        executor = intent.get("executor", intent.get("op"))
        if mode == "strict" and executor not in DETERMINISTIC:
            return error("E_CONTRACT_VIOLATION", "strict mode rejects non-deterministic executor", 422)

        try:
            reserve_claims(con, key, ih, grant, approval, policy["decision"] == "require_approval")
        except ClaimError as e:
            return error(e.code, e.message, 409 if e.code == "E_IDEMPOTENCY_IN_PROGRESS" else 403)

        op = intent.get("op")
        result = None
        effects = []
        if op == "echo":
            result = {"echo": intent.get("args", {}).get("text", "")}
        elif op == "read_file":
            rel = intent.get("args", {}).get("path", "")
            p = C.effect_path(rel)
            result = {"content": open(p).read() if os.path.exists(p) else None}
        elif op == "write_file":
            rel = intent.get("args", {}).get("path", "")
            content = intent.get("args", {}).get("content", "")
            p = C.effect_path(rel)
            before = C.file_digest(p)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f: f.write(content)
            after = C.file_digest(p)
            effects = [{"kind": "fs.write", "target": p, "before_digest": before,
                        "after_digest": after, "bytes": len(content.encode())}]
            result = {"path": p, "bytes": len(content.encode())}
        elif op == "increment_counter":
            rel = intent.get("args", {}).get("path", "counter.txt")
            p = C.effect_path(rel)
            before = C.file_digest(p)
            n = int(open(p).read()) if os.path.exists(p) else 0
            nxt = n + 1
            rec_template = build_receipt(intent, ih, rh, grant.get("grant_id"), policy,
                [{"kind": "fs.write", "target": p, "before_digest": before,
                  "after_digest": C.raw_sha(str(nxt)), "bytes": len(str(nxt))}],
                {"counter": nxt})
            con.execute("INSERT OR REPLACE INTO journal(key,intent_hash,target,before_digest,after_digest,payload,created_at) VALUES(?,?,?,?,?,?,?)",
                        (key, ih, p, before, C.raw_sha(str(nxt)),
                         json.dumps({"counter": nxt, "receipt": rec_template}), C.now_ms()))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f: f.write(str(nxt))
            if CRASH:
                os._exit(1)
            effects = [{"kind": "fs.write", "target": p, "before_digest": before,
                        "after_digest": C.raw_sha(str(nxt)), "bytes": len(str(nxt))}]
            result = {"counter": nxt}
        else:
            con.execute("DELETE FROM inflight WHERE key=?", (key,))
            return error("E_UNKNOWN_OP", "unknown op", 422)

        rec = build_receipt(intent, ih, rh, grant.get("grant_id"), policy, effects, result)
        try:
            rec, rhash = finalize(con, rec, None, key)
        except (LeaseLost, QuorumLeaseLost):
            return error("E_LEASE_LOST", "writer lease lost after effect", 503)
        return {"receipt": rec, "receipt_hash": rhash, "result": result}
    finally:
        con.close()

@app.post("/record")
async def record(req: Request):
    ltok = _lease_or_503()
    if isinstance(ltok, JSONResponse): return ltok
    """Record a receipt for an effect executed by an external executor (e.g. MCP tool)."""
    body = await req.json()
    intent = body.get("intent") or {}
    grant = body.get("grant") or {}
    approval = body.get("approval")
    key = body.get("idem_key")
    result = body.get("result")
    if not key:
        return error("E_IDEMPOTENCY_KEY_REQUIRED", "idem_key is required", 422)
    ih = C.sha(intent)
    policy = policy_for(intent)
    ph = policy_hash(policy)
    rh = C.sha(route_trace(intent))
    con = C.db()
    try:
        row = con.execute("SELECT intent_hash, receipt_json FROM idem WHERE key=?", (key,)).fetchone()
        if row:
            if row["intent_hash"] != ih:
                return error("E_IDEMPOTENCY_CONFLICT", "same key, different intent", 409)
            rec = json.loads(row["receipt_json"]); rec["replayed"] = True
            return {"receipt": rec, "replayed": True, "result": rec.get("result")}
        claim_id = body.get("claim_id")
        if claim_id:
            claim = con.execute("SELECT intent_hash FROM inflight WHERE key=?", (claim_id,)).fetchone()
            if claim is None or claim["intent_hash"] != ih:
                return error("E_CLAIM_NOT_FOUND", "authorization claim missing or mismatched", 409)
            effects = body.get("effects") or [{"kind": "tool.call", "target": intent.get("op"),
                                               "result_digest": C.sha(result)}]
            rec = build_receipt(intent, ih, rh, grant.get("grant_id"), policy, effects, result)
            if body.get("executor"):
                rec["executor"].update(body["executor"])
            try:
                rec, rhash = finalize(con, rec, None, claim_id)
            except (LeaseLost, QuorumLeaseLost):
                return error("E_LEASE_LOST", "writer lease lost after effect", 503)
            return {"receipt": rec, "receipt_hash": rhash, "result": result}
        if policy["decision"] == "deny":
            con.execute("BEGIN IMMEDIATE")
            try:
                reserve_idem(con, key, ih)
                con.execute("COMMIT")
            except Exception:
                con.execute("ROLLBACK")
                raise
            rec = build_receipt(intent, ih, rh, grant.get("grant_id"), policy, [], result, status="denied")
            rec, _ = finalize(con, rec, None, key)
            return JSONResponse({"receipt": rec, "denied": True}, status_code=403)
        ok, why = validate_grant(con, grant, ih, intent.get("op"), intent)
        if not ok:
            return error(why, "grant rejected", 403)
        if policy["decision"] == "require_approval":
            ok, why = validate_approval(con, approval, ih, ph)
            if not ok:
                return error(why, "approval rejected", 403)
        try:
            reserve_claims(con, key, ih, grant, approval, policy["decision"] == "require_approval")
        except ClaimError as e:
            return error(e.code, e.message, 409 if e.code == "E_IDEMPOTENCY_IN_PROGRESS" else 403)
        effects = body.get("effects") or [{"kind": "tool.call", "target": intent.get("op"),
                                           "result_digest": C.sha(result)}]
        rec = build_receipt(intent, ih, rh, grant.get("grant_id"), policy, effects, result)
        if body.get("executor"):
            rec["executor"].update(body["executor"])
        try:
            rec, rhash = finalize(con, rec, None, key)
        except (LeaseLost, QuorumLeaseLost):
            return error("E_LEASE_LOST", "writer lease lost after effect", 503)
        return {"receipt": rec, "receipt_hash": rhash, "result": result}
    finally:
        con.close()

@app.get("/chain/proof/{receipt_hash}")
def chain_proof(receipt_hash: str):
    con = C.db()
    try:
        row = con.execute("SELECT seq FROM chain WHERE receipt_hash=?", (receipt_hash,)).fetchone()
        if row is None:
            return error("E_RECEIPT_NOT_FOUND", "receipt is not in chain", 404)
        rows = [dict(r) for r in con.execute(
            "SELECT seq, receipt_hash, prev_hash, receipt_json FROM chain WHERE seq>=? ORDER BY seq",
            (row["seq"],))]
        if not rows:
            return error("E_RECEIPT_NOT_FOUND", "receipt is not in chain", 404)
        return {"receipt_hash": receipt_hash, "seq": row["seq"],
                "root": rows[-1]["receipt_hash"], "count": len(rows),
                "receipts": [json.loads(r["receipt_json"]) for r in rows]}
    finally:
        con.close()


@app.get("/receipts")
def receipts(limit: int = 100):
    con = C.db()
    rows = C.chain_rows(con, limit)
    con.close()
    return {"chain_id": C.CHAIN_ID, "count": len(rows), "receipts": rows}

@app.get("/chain/verify")
def chain_verify():
    con = C.db()
    rows = C.chain_rows(con)
    con.close()
    recs = [json.loads(r["receipt_json"]) for r in rows]
    ok, errs = C.verify_chain(recs)
    return {"ok": ok, "errors": errs, "count": len(recs),
            "root": rows[-1]["receipt_hash"] if rows else "GENESIS"}

@app.post("/debug/reset")
def debug_reset():
    if os.environ.get("SIGIL_TEST") != "1":
        return error("E_FORBIDDEN", "reset disabled", 403)
    con = C.db()
    for t in ("chain", "idem", "journal", "grants", "approvals", "inflight"):
        con.execute(f"DELETE FROM {t}")
    con.close()
    return {"ok": True}

def main():
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("SIGIL_PORT", "18100")), log_level="warning")

if __name__ == "__main__":
    main()
