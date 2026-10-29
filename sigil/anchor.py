from __future__ import annotations
import json, os, re, threading, uuid
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
from . import common as C
from . import tsa as T

LOG = os.path.join(C.DATA, "anchor.log")
GATE = os.environ.get("SIGIL_GATE", "").rstrip("/")
REMOTE = os.environ.get("SIGIL_REMOTE_ANCHOR", "").rstrip("/")
STRICT_SEQ = os.environ.get("SIGIL_ANCHOR_STRICT_SEQ", "0") == "1"
LOCK = threading.Lock()
REMOTE_TOKEN_FILE = os.environ.get("SIGIL_REMOTE_TOKEN_FILE", os.path.join(C.DATA, "remote_token"))
TSA_ENABLE = os.environ.get("SIGIL_TSA_ENABLE", "0") == "1"
TSA_REQUIRED = os.environ.get("SIGIL_TSA_REQUIRED", "0") == "1"
app = FastAPI(title="sigil-anchor")

@app.middleware("http")
async def anchor_auth(request: Request, call_next):
    if request.url.path == "/anchor":
        got = request.headers.get("X-SIGIL-Token")
        if not C.token_ok(got, C.read_token(C.CONTROL_TOKEN_FILE)):
            return JSONResponse({"error": {"code": "E_UNAUTHENTICATED",
                                           "message": "control token required"}}, status_code=401)
    return await call_next(request)

def remote_token() -> str:
    try: return open(REMOTE_TOKEN_FILE).read().strip()
    except Exception: return ""

def remote_anchor(root: str, seq: int):
    if not REMOTE:
        return None
    import httpx
    tok = remote_token()
    r = httpx.post(REMOTE + "/anchor", json={"root": root, "seq": seq, "chain_id": C.CHAIN_ID},
                   headers={"X-SIGIL-Token": tok}, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"remote anchor failed: {r.status_code} {r.text[:200]}")
    return r.json()["anchor"]

def last() -> dict | None:
    if not os.path.exists(LOG):
        return None
    lines = [l for l in open(LOG) if l.strip()]
    return json.loads(lines[-1]) if lines else None

def append(entry: dict):
    os.makedirs(C.DATA, exist_ok=True)
    with open(LOG, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())

def verify_chain_root(root: str, seq: int):
    if not GATE:
        return
    import httpx
    r = httpx.get(GATE + "/chain/verify", timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"gate chain unavailable: {r.status_code}")
    d = r.json()
    if not d.get("ok"):
        raise RuntimeError("gate chain invalid")
    if root != d.get("root"):
        raise RuntimeError("root is not the current chain root")
    if seq < 0:
        raise RuntimeError("negative seq")

@app.get("/health")
def health():
    return {"ok": True, "role": "anchor", "log": LOG}

@app.post("/anchor")
async def anchor(req: Request):
    body = await req.json()
    root = body.get("root")
    if not root or not re.fullmatch(r"[0-9a-f]{64}", str(root)):
        return JSONResponse({"error": {"code": "E_ROOT_INVALID"}}, status_code=422)
    seq = int(body.get("seq", 0))
    try:
        verify_chain_root(root, seq)
    except Exception as e:
        return JSONResponse({"error": {"code": "E_ROOT_NOT_IN_CHAIN", "message": str(e)}}, status_code=409)
    prev = last()
    if STRICT_SEQ and prev and seq <= int(prev.get("seq", 0)):
        return JSONResponse({"error": {"code": "E_ANCHOR_ROLLBACK",
                                       "message": "seq must be greater than previous anchor"}}, status_code=409)
    try:
        rem = remote_anchor(root, seq)
    except Exception as e:
        if os.environ.get("SIGIL_ANCHOR_ALLOW_LOCAL") == "1":
            rem = None
        else:
            return JSONResponse({"error": {"code": "E_REMOTE_ANCHOR", "message": str(e)}}, status_code=502)
    tok = {"anchor_id": str(uuid.uuid4()), "chain_id": body.get("chain_id", C.CHAIN_ID),
           "root": root, "seq": seq,
           "prev_anchor": prev["anchor_hash"] if prev else "GENESIS",
           "at": C.now_ms()}
    if rem is not None:
        tok["remote"] = rem
    if TSA_ENABLE:
        try:
            tok["rfc3161"] = T.make(root)
        except Exception as e:
            if TSA_REQUIRED:
                return JSONResponse({"error": {"code": "E_TSA", "message": str(e)}}, status_code=502)
    core = dict(tok)
    tok["sig"] = C.sign(core)
    tok["anchor_hash"] = C.sha({k: v for k, v in tok.items() if k not in ("sig", "anchor_hash")})
    with LOCK:
        append(tok)
    return {"anchor": tok}

@app.get("/latest")
def latest():
    l = last()
    return {"anchor": l} if l else {"anchor": None}

@app.post("/verify")
async def verify(req: Request):
    body = await req.json()
    tok = body.get("anchor") or {}
    core = {k: v for k, v in tok.items() if k not in ("sig", "anchor_hash")}
    ok = C.verify_sig(core, tok.get("sig", {}))
    ok = ok and tok.get("anchor_hash") == C.sha(core)
    rem = tok.get("remote")
    remote_ok = None
    if rem:
        rc = {k: v for k, v in rem.items() if k not in ("sig", "anchor_hash")}
        remote_ok = C.verify_sig(rc, rem.get("sig", {}), C.REMOTE_PUB_PATH) and rem.get("anchor_hash") == C.sha(rc)
        remote_ok = remote_ok and rem.get("root") == tok.get("root")
    tsa_ok = None
    if tok.get("rfc3161"):
        tsa_ok = T.verify(tok.get("root", ""), tok["rfc3161"])
    return {"valid": bool(ok and (remote_ok is not False) and (tsa_ok is not False)), "root": tok.get("root"),
            "remote": remote_ok, "rfc3161": tsa_ok}

def main():
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("SIGIL_PORT", "18102")), log_level="warning")

if __name__ == "__main__":
    main()
