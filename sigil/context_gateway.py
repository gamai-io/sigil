"""Stateless HTTP context gateway for ACP<->MCP shared context."""
from __future__ import annotations
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
import uvicorn
from . import common as C
from . import ctx, handoff

app = FastAPI(title="sigil-context-gateway", docs_url=None, redoc_url=None)


@app.post("/prune")
async def prune(req: Request):
    got = req.headers.get("X-SIGIL-Token")
    if not C.token_ok(got, C.read_token(C.CONTROL_TOKEN_FILE)):
        return JSONResponse({"error": {"code": "E_UNAUTHENTICATED"}}, status_code=401)
    body = await req.json()
    age = int(body.get("max_age_ms", 7 * 86400000))
    dry = bool(body.get("dry_run", False))
    return {"ctx": ctx.prune(age, dry), "handoff": handoff.prune(age, dry)}


@app.get("/health")
def health():
    return {"ok": True, "role": "sigil-context-gateway", "stateless": True,
            "root": ctx.ROOT}


@app.post("/ctx/ingest")
async def ingest(req: Request):
    body = await req.json()
    entries = body.get("entries")
    if not isinstance(entries, list):
        return JSONResponse({"error": {"code": "E_ENTRIES_REQUIRED"}}, status_code=422)
    norm = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        if e.get("text") is not None and not e.get("b"):
            blob = ctx.put_blob(str(e["text"]).encode(), e.get("t", "text/plain"))
            e = {k: v for k, v in e.items() if k != "text"}
            e["b"] = blob["blob"]
            e.setdefault("t", "text/plain")
        norm.append(e)
    try:
        cid = ctx.build_ctx(norm, parents=body.get("parents") or [],
                            labels=body.get("labels") or {})
    except Exception as e:
        return JSONResponse({"error": {"code": "E_CTX", "message": str(e)}}, status_code=400)
    return {"ctx_id": cid, "manifest": ctx.get_manifest(cid)}


@app.get("/ctx/{ctx_id}")
def manifest(ctx_id: str):
    try:
        return ctx.get_manifest(ctx_id)
    except FileNotFoundError:
        return JSONResponse({"error": {"code": "E_CTX_NOT_FOUND"}}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": {"code": "E_CTX", "message": str(e)}}, status_code=400)


@app.post("/handoff")
async def create_handoff(req: Request):
    body = await req.json()
    try:
        h = handoff.create(
            from_session=body.get("from_session", "unknown"),
            to_agent=body.get("to_agent"),
            ctx_id=body.get("ctx_id", ""),
            caps=body.get("caps") or [],
            expected=body.get("expected") or [],
            parent_handoff_id=body.get("parent_handoff_id"),
            ttl_ms=int(body.get("ttl_ms", 3600000)),
            labels=body.get("labels") or {},
            idem_prefix=body.get("idem_prefix"),
        )
        return {"handoff": h}
    except Exception as e:
        return JSONResponse({"error": {"code": "E_HANDOFF", "message": str(e)}}, status_code=400)


@app.get("/handoff/{handoff_id}")
def get_handoff(handoff_id: str):
    try:
        return {"handoff": handoff.get(handoff_id)}
    except FileNotFoundError:
        return JSONResponse({"error": {"code": "E_HANDOFF_NOT_FOUND"}}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": {"code": "E_HANDOFF", "message": str(e)}}, status_code=400)


@app.get("/handoff/{handoff_id}/replay")
def replay_handoff(handoff_id: str):
    try:
        return {"plan": handoff.replay_plan(handoff_id)}
    except FileNotFoundError:
        return JSONResponse({"error": {"code": "E_HANDOFF_NOT_FOUND"}}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": {"code": "E_HANDOFF", "message": str(e)}}, status_code=400)


@app.get("/blob/{blob_id}")
def blob(blob_id: str):
    try:
        return Response(ctx.get_blob(blob_id), media_type="application/octet-stream")
    except FileNotFoundError:
        return JSONResponse({"error": {"code": "E_BLOB_NOT_FOUND"}}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": {"code": "E_BLOB", "message": str(e)}}, status_code=400)


def main():
    uvicorn.run(app, host=os.environ.get("SIGIL_BIND", "0.0.0.0"),
                port=int(os.environ.get("SIGIL_PORT", "18120")), log_level="warning")


if __name__ == "__main__":
    main()
