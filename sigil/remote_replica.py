#!/usr/bin/env python3
"""Remote SIGIL read replica: pull gate receipts, verify chain/signatures, store SQLite."""
import base64, hashlib, json, os, sqlite3, sys, time, urllib.request
from cryptography.hazmat.primitives import serialization

BASE = os.environ.get("SIGIL_REPLICA_BASE", "./data/sigil_replica")
DB = os.path.join(BASE, "replica.db")
PUB = os.path.join(BASE, "gate_ed25519_public.pem")
GATE = os.environ.get("SIGIL_GATE", "http://127.0.0.1:18100").rstrip("/")

def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def sha(o):
    return hashlib.sha256(canon(o)).hexdigest()

def verify_sig(obj, sig):
    try:
        pub = serialization.load_pem_public_key(open(PUB, "rb").read())
        pub.verify(base64.b64decode(sig["value"]), canon(obj))
        return True
    except Exception:
        return False

def db():
    os.makedirs(BASE, exist_ok=True)
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS chain(
      seq INTEGER PRIMARY KEY, receipt_hash TEXT, prev_hash TEXT,
      receipt_json TEXT, created_at INTEGER)""")
    c.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
    return c

def sync():
    with urllib.request.urlopen(GATE + "/receipts?limit=1000", timeout=15) as r:
        data = json.loads(r.read().decode())
    rows = data.get("receipts", [])
    c = db()
    c.execute("DELETE FROM chain")
    for x in rows:
        c.execute("INSERT OR REPLACE INTO chain(seq,receipt_hash,prev_hash,receipt_json,created_at) VALUES(?,?,?,?,?)",
                  (x["seq"], x["receipt_hash"], x["prev_hash"], x["receipt_json"], x.get("created_at", 0)))
    recs = [json.loads(x["receipt_json"]) for x in c.execute("SELECT * FROM chain ORDER BY seq")]
    errs = []; prev = "GENESIS"
    for i, rec in enumerate(recs):
        core = {k: v for k, v in rec.items() if k not in ("sig", "anchor")}
        h = sha(core)
        expected = rows[i]["receipt_hash"] if i < len(rows) else h
        if rec.get("prev_hash", "GENESIS") != prev: errs.append(f"seq {i}: prev")
        if h != expected: errs.append(f"seq {i}: hash")
        if not verify_sig(core, rec.get("sig", {})): errs.append(f"seq {i}: sig")
        prev = expected
    root = rows[-1]["receipt_hash"] if rows else "GENESIS"
    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('last_sync',?)", (str(int(time.time())),))
    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('root',?)", (root,))
    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('valid',?)", (str(not errs).lower(),))
    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('errors',?)", ("; ".join(errs),))
    c.commit(); c.close()
    return {"ok": not errs, "count": len(recs), "root": root, "errors": errs}

def status():
    if not os.path.exists(DB): return {"count": 0, "root": "GENESIS", "valid": None}
    c = db(); n = c.execute("SELECT COUNT(*) AS n FROM chain").fetchone()["n"]
    m = {r["k"]: r["v"] for r in c.execute("SELECT * FROM meta")}; c.close()
    return {"count": n, **m}

def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        print(json.dumps(status(), ensure_ascii=False))
    else:
        print(json.dumps(sync(), ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
