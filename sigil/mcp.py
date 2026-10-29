"""Reusable MCP Streamable HTTP middleware: adds SIGIL grants + receipts to metered methods."""
from __future__ import annotations
import copy, hashlib, json, os, uuid
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

CONTROL_TOKEN_FILE = os.environ.get("SIGIL_CONTROL_TOKEN_FILE", "/run/sigil-control-token")

def _gate_headers() -> dict:
    try:
        tok = open(CONTROL_TOKEN_FILE, encoding="utf-8").read().strip()
    except OSError:
        tok = ""
    return {"X-SIGIL-Token": tok} if tok else {}

DEFAULT_METERED = {
    "tools/call": "mcp.tools.call",
    "resources/read": "mcp.resources.read",
    "prompts/get": "mcp.prompts.get",
}

def _parse(resp: httpx.Response):
    ct = resp.headers.get("content-type", "")
    if "text/event-stream" in ct:
        for line in resp.text.splitlines():
            if line.startswith("data: "):
                return json.loads(line[6:])
        return {"error": "empty sse"}
    return resp.json()

def create_proxy_app(gate_url: str, upstream_url: str,
                     metered: dict[str, str] | None = None,
                     timeout: float = 20.0) -> FastAPI:
    app = FastAPI(title="sigil-mcp-middleware")
    metered = metered or DEFAULT_METERED
    schemas: dict[str, dict] = {}

    async def tool_schema(client, headers, name: str):
        if name in schemas:
            return schemas[name]
        r = await client.post(upstream_url, json={
            "jsonrpc": "2.0", "id": "sigil-tools", "method": "tools/list", "params": {}},
            headers=headers)
        if r.status_code >= 400 or not r.content:
            return None
        data = _parse(r)
        for t in data.get("result", {}).get("tools", []):
            if t.get("name"):
                schemas[t["name"]] = t.get("inputSchema") or {}
        return schemas.get(name)

    @app.get("/health")
    def health():
        return {"ok": True, "role": "sigil-mcp-middleware", "upstream": upstream_url}

    @app.post("/mcp")
    async def mcp(req: Request):
        raw = await req.body()
        body = json.loads(raw or b"{}")
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        sid = req.headers.get("mcp-session-id")
        if sid: headers["mcp-session-id"] = sid
        method = body.get("method")
        if method not in metered:
            async with httpx.AsyncClient(timeout=timeout) as client:
                up = await client.post(upstream_url, content=raw, headers=headers)
                if up.status_code in (202, 204) or not up.content:
                    return JSONResponse({}, status_code=202,
                                        headers={"mcp-session-id": up.headers.get("mcp-session-id", "")})
                out_headers = {}
                if up.headers.get("mcp-session-id"):
                    out_headers["mcp-session-id"] = up.headers["mcp-session-id"]
                return JSONResponse(_parse(up), headers=out_headers)

        params = body.get("params") or {}

        def rpc_error(message: str, data: dict, code: int = -32000):
            return JSONResponse({"jsonrpc": "2.0", "id": body.get("id"),
                                 "error": {"code": code, "message": message, "data": data}})

        op = metered[method]
        target = params.get("name") or params.get("uri") or op
        call_args = params.get("arguments") or {}
        args = {"tool": target, "arguments": call_args}
        if method == "tools/call":
            async with httpx.AsyncClient(timeout=timeout) as schema_client:
                schema = await tool_schema(schema_client, headers, target)
            if schema is not None:
                try:
                    import jsonschema
                    jsonschema.validate(instance=call_args, schema=schema)
                except ImportError:
                    return rpc_error("SIGIL schema validator unavailable",
                                     {"sigil": {"code": "E_TOOL_SCHEMA", "tool": target}}, -32602)
                except Exception as e:
                    return rpc_error("SIGIL tool schema rejected arguments",
                                     {"sigil": {"code": "E_TOOL_SCHEMA", "tool": target, "error": str(e)}}, -32602)
        intent = {"id": str(uuid.uuid4()), "op": op, "args": args,
                  "contract": {"id": f"{op}/v1", "version": "1"},
                  "determinism": {"mode": "seeded"}}
        sig_meta = (params.get("_meta") or {}).get("sigil") or {}
        idem = sig_meta.get("idem_key") or ("mcp:" + intent["id"])
        if sig_meta.get("idem_key"):
            intent["id"] = idem

        async with httpx.AsyncClient(timeout=timeout) as client:
            gr = await client.post(gate_url + "/grant", json={
                "intent": intent, "capabilities": [{"id": op, "constraints": {}}]},
                headers=_gate_headers())
            if gr.status_code != 200:
                return rpc_error("SIGIL grant unavailable", {"status": gr.status_code, "body": gr.text[:300]}, -32001)
            g = gr.json()["grant"]
            az = await client.post(gate_url + "/authorize", json={
                "intent": intent, "grant": g, "idem_key": idem}, headers=_gate_headers())
            if az.status_code != 200:
                data = az.json() if az.content else {}
                return rpc_error("SIGIL denied before effect", {"sigil": data, "status": az.status_code}, -32002)
            azd = az.json()
            if azd.get("replayed"):
                rec = azd.get("receipt") or {}
                result = copy.deepcopy(rec.get("result"))
                if result is None:
                    return rpc_error("SIGIL replay without result", {"sigil": azd}, -32003)
                result.setdefault("_meta", {})["sigil"] = {
                    "profile": "1", "ctx_id": sig_meta.get("ctx_id"),
                    "receipt": rec, "receipt_hash": azd.get("receipt_hash") or rec.get("receipt_hash"),
                    "replayed": True,
                }
                out_headers = {"mcp-session-id": sid} if sid else {}
                return JSONResponse({"jsonrpc": "2.0", "id": body.get("id"), "result": result},
                                    headers=out_headers)

            up = await client.post(upstream_url, content=raw, headers=headers)
            out_headers = {}
            if up.headers.get("mcp-session-id"):
                out_headers["mcp-session-id"] = up.headers["mcp-session-id"]
            if up.status_code in (202, 204) or not up.content:
                await client.post(gate_url + "/abort", json={
                    "claim_id": idem, "grant_id": g.get("grant_id")}, headers=_gate_headers())
                return JSONResponse({}, status_code=202, headers=out_headers)
            data = _parse(up)
            result = data.get("result")
            if data.get("error") or result is None:
                await client.post(gate_url + "/abort", json={
                    "claim_id": idem, "grant_id": g.get("grant_id")}, headers=_gate_headers())
                return JSONResponse(data, headers=out_headers)

            digest = hashlib.sha256(json.dumps(result, sort_keys=True,
                                               separators=(",", ":")).encode()).hexdigest()
            rec = (await client.post(gate_url + "/record", json={
                "claim_id": idem,
                "intent": intent, "grant": g, "idem_key": idem,
                "result": result,
                "effects": [{"kind": op, "target": target, "result_digest": digest}],
                "executor": {"kind": "mcp", "id": op, "version": "1.0", "sandbox": "docker"},
            }, headers=_gate_headers())).json()
            if "receipt" not in rec:
                return rpc_error("SIGIL receipt unavailable; result withheld",
                                 {"sigil": rec}, -32004)
            result.setdefault("_meta", {})["sigil"] = {
                "profile": "1", "ctx_id": (params.get("_meta", {}).get("sigil", {}) or {}).get("ctx_id"),
                "receipt": rec["receipt"], "receipt_hash": rec.get("receipt_hash"),
            }
            return JSONResponse(data, headers=out_headers)

    return app
