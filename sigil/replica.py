"""Read-only hot-standby replica of the SIGIL receipt chain (SQLite)."""
from __future__ import annotations
import asyncio, json, os, sqlite3, time
import httpx
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
from . import common as C

GATE = os.environ.get("SIGIL_GATE", "http://127.0.0.1:18100").rstrip("/")
DB = os.environ.get("SIGIL_REPLICA_DB", os.path.join(C.DATA, "replica.db"))
STATE = {"last_sync": 0, "valid": None, "error": None}
SYNC_INTERVAL = float(os.environ.get("SIGIL_REPLICA_INTERVAL", "5"))

async def _loop():
    while True:
        try:
            await asyncio.to_thread(sync)
        except Exception:
            pass
        await asyncio.sleep(SYNC_INTERVAL)

@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(_loop())
    try:
        yield
    finally:
        task.cancel()

app = FastAPI(title="sigil-replica", lifespan=lifespan)

@app.middleware("http")
async def replica_auth(request: Request, call_next):
    if request.url.path in {"/sync", "/debug/reset"}:
        got = request.headers.get("X-SIGIL-Token")
        if not C.token_ok(got, C.read_token(C.CONTROL_TOKEN_FILE)):
            return JSONResponse({"error": {"code": "E_UNAUTHENTICATED",
                                           "message": "control token required"}}, status_code=401)
    return await call_next(request)

def con():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB, timeout=10, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("""CREATE TABLE IF NOT EXISTS chain(
      seq INTEGER PRIMARY KEY, receipt_hash TEXT NOT NULL, prev_hash TEXT NOT NULL,
      receipt_json TEXT NOT NULL, created_at INTEGER NOT NULL)""")
    return c

def rows(limit=1000):
    c = con()
    out = [dict(r) for r in c.execute(
        "SELECT seq,receipt_hash,prev_hash,receipt_json,created_at FROM chain ORDER BY seq LIMIT ?", (limit,))]
    c.close(); return out

def root():
    c = con(); r = c.execute("SELECT receipt_hash FROM chain ORDER BY seq DESC LIMIT 1").fetchone(); c.close()
    return r["receipt_hash"] if r else "GENESIS"

def sync() -> dict:
    try:
        data = httpx.get(GATE + "/receipts", params={"limit": 1000}, timeout=10).json()
        rs = data.get("receipts", [])
        c = con()
        for r in rs:
            c.execute("INSERT OR REPLACE INTO chain(seq,receipt_hash,prev_hash,receipt_json,created_at) VALUES(?,?,?,?,?)",
                      (r["seq"], r["receipt_hash"], r["prev_hash"], r["receipt_json"], r.get("created_at", 0)))
        recs = [json.loads(x["receipt_json"]) for x in rows(1000)]
        ok, errs = C.verify_chain(recs)
        STATE.update(last_sync=int(time.time()), valid=ok, error="; ".join(errs) or None)
        c.close()
        return {"ok": ok, "count": len(rs), "root": root(), "errors": errs}
    except Exception as e:
        STATE.update(last_sync=int(time.time()), valid=False, error=str(e))
        return {"ok": False, "error": str(e)}

@app.get("/health")
def health():
    return {"ok": True, "role": "replica", "gate": GATE, "db": DB}

@app.post("/sync")
def do_sync():
    return sync()

@app.post("/debug/reset")
def debug_reset():
    if os.environ.get("SIGIL_TEST") != "1":
        return {"ok": False, "error": "disabled"}
    c = con(); c.execute("DELETE FROM chain"); c.close()
    STATE.update(last_sync=0, valid=None, error=None)
    return {"ok": True}

@app.get("/status")
def status():
    c = con(); n = c.execute("SELECT COUNT(*) AS n FROM chain").fetchone()["n"]; c.close()
    return {"count": n, "root": root(), **STATE}

@app.get("/receipts")
def receipts(limit: int = 1000):
    return {"count": len(rows(limit)), "root": root(), "receipts": rows(limit)}

@app.post("/verify")
def verify():
    recs = [json.loads(x["receipt_json"]) for x in rows(1000)]
    ok, errs = C.verify_chain(recs)
    return {"valid": ok, "errors": errs, "count": len(recs), "root": root()}

def main():
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("SIGIL_PORT", "18104")), log_level="warning")

if __name__ == "__main__":
    main()
