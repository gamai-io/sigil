from __future__ import annotations
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
from . import common as C
from . import tsa as T

app = FastAPI(title="sigil-verify")

def err(code, msg):
    return JSONResponse({"valid": False, "error": {"code": code, "message": msg}}, status_code=200)

@app.get("/health")
def health():
    return {"ok": True, "role": "verify"}

@app.post("/canonical")
async def canonical(req: Request):
    body = await req.json()
    obj = body.get("obj")
    return {"canonical": C.canon(obj).decode(), "sha256": C.sha(obj)}

@app.post("/verify")
async def verify(req: Request):
    body = await req.json()
    rec = body.get("receipt") or {}
    errors = []
    core = {k: v for k, v in rec.items() if k not in ("sig", "anchor")}
    if not C.verify_sig(core, rec.get("sig", {})):
        errors.append("E_SIGNATURE")
    if rec.get("result_digest") != C.sha(rec.get("result")):
        errors.append("E_RESULT_DIGEST")
    if rec.get("policy", {}).get("policy_hash") != C.sha({
            "decision": rec.get("policy", {}).get("decision"),
            "rule_ids": rec.get("policy", {}).get("rule_ids")}):
        errors.append("E_POLICY_HASH")
    ih = rec.get("intent_hash")
    if body.get("intent") is not None and C.sha(body["intent"]) != ih:
        errors.append("E_INTENT_HASH")
    if body.get("grant") is not None:
        g = body["grant"]; gc = {k: v for k, v in g.items() if k != "sig"}
        if not C.verify_sig(gc, g.get("sig", {})):
            errors.append("E_GRANT_SIGNATURE")
        if g.get("bound_to") != ih:
            errors.append("E_GRANT_BINDING")
    if body.get("chain"):
        ok, chain_errs = C.verify_chain(body["chain"])
        if not ok:
            errors.extend(chain_errs)
    if body.get("anchor"):
        tok = body["anchor"]; tc = {k: v for k, v in tok.items() if k not in ("sig", "anchor_hash")}
        if not C.verify_sig(tc, tok.get("sig", {})):
            errors.append("E_ANCHOR_SIGNATURE")
        if tok.get("root") != rec.get("receipt_hash") and tok.get("root") != C.receipt_hash(rec):
            errors.append("E_ANCHOR_BINDING")
        rem = tok.get("remote")
        if rem:
            rc = {k: v for k, v in rem.items() if k not in ("sig", "anchor_hash")}
            if not (C.verify_sig(rc, rem.get("sig", {}), C.REMOTE_PUB_PATH)
                    and rem.get("anchor_hash") == C.sha(rc)
                    and rem.get("root") == tok.get("root")):
                errors.append("E_REMOTE_ANCHOR")
        if tok.get("rfc3161") and not T.verify(tok.get("root", ""), tok["rfc3161"]):
            errors.append("E_TSA")
    return {"valid": not errors, "errors": errors, "receipt_hash": C.receipt_hash(rec)}

@app.post("/proof")
async def proof(req: Request):
    body = await req.json()
    p = body.get("proof") or {}
    receipts = p.get("receipts") or []
    ok, errs = C.verify_suffix(receipts, p.get("receipt_hash", ""), p.get("root", ""))
    return {"valid": ok, "errors": errs, "receipt_hash": p.get("receipt_hash"),
            "root": p.get("root"), "count": len(receipts)}


@app.post("/replay")
async def replay(req: Request):
    body = await req.json()
    rec = body.get("receipt") or {}
    recorded = body.get("recorded") or {}
    result = recorded.get("result", rec.get("result"))
    got = C.sha(result)
    return {"equal": got == rec.get("result_digest"), "recorded_digest": got,
            "receipt_digest": rec.get("result_digest")}

def main():
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("SIGIL_PORT", "18101")), log_level="warning")

if __name__ == "__main__":
    main()
