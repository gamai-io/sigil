#!/usr/bin/env python3
"""Oracle SIGIL lease witness: single writer lease with fencing tokens."""
import base64, hashlib, hmac, json, os, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives import serialization

BASE = os.environ.get("SIGIL_LEASE_BASE", "./data/sigil_lease")
KEYS = os.path.join(BASE, "keys")
TOKEN_FILE = os.path.join(BASE, "token")
STATE_FILE = os.environ.get("SIGIL_LEASE_STATE", os.path.join(BASE, "state.json"))
PORT = int(os.environ.get("SIGIL_LEASE_PORT", "18106"))
LOCK = threading.Lock()
STATE = {"holder": None, "lease_id": None, "fencing": 0, "not_after": 0}
os.makedirs(KEYS, exist_ok=True)

def _load_fencing() -> int:
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return int(json.load(f).get("fencing", 0))
    except Exception:
        return 0

def _persist():
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp." + str(os.getpid())
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"fencing": STATE["fencing"]}, f, sort_keys=True, separators=(",", ":"))
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)

STATE["fencing"] = _load_fencing()

def priv():
    with open(os.path.join(KEYS, "ed25519_private.pem"), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def token(): 
    try: return open(TOKEN_FILE).read().strip()
    except Exception: return ""

def issue(holder, fencing, ttl_ms):
    tok = {"lease_id": str(uuid.uuid4()), "holder": holder, "fencing_token": fencing,
           "issuer": "remote-lease", "not_after": int(time.time()*1000) + ttl_ms}
    sig = priv().sign(canon(tok))
    tok["sig"] = {"alg": "ed25519", "key_id": "remote-lease-1",
                  "value": base64.b64encode(sig).decode()}
    return tok

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _j(self, code, obj):
        b=json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path == "/health": return self._j(200, {"ok": True, "role": "lease-witness", "node": "remote"})
        if self.path == "/status":
            with LOCK: return self._j(200, dict(STATE, now=int(time.time()*1000)))
        self._j(404, {"error":"not found"})
    def do_POST(self):
        expected = token()
        got = self.headers.get("X-SIGIL-Token","")
        if not expected or not hmac.compare_digest(got.encode(), expected.encode()):
            return self._j(403, {"error":"forbidden"})
        n=int(self.headers.get("Content-Length",0)); raw=self.rfile.read(n).decode() if n else "{}"
        try: b=json.loads(raw)
        except Exception: return self._j(400, {"error":"bad json"})
        now=int(time.time()*1000)
        if self.path == "/acquire":
            holder=b.get("holder"); ttl=int(b.get("ttl_ms",6000))
            with LOCK:
                if STATE["holder"] and now < STATE["not_after"] and STATE["holder"] != holder:
                    return self._j(409, {"error":"lease_held","holder":STATE["holder"],
                                         "not_after":STATE["not_after"],
                                         "fencing_token":STATE["fencing"]})
                STATE["fencing"] += 1
                _persist()
                tok=issue(holder, STATE["fencing"], ttl)
                STATE.update(holder=holder, lease_id=tok["lease_id"], not_after=tok["not_after"])
                return self._j(200, {"lease": tok, "fencing_token": STATE["fencing"]})
        if self.path == "/renew":
            lid=b.get("lease_id"); holder=b.get("holder"); ttl=int(b.get("ttl_ms",6000))
            with LOCK:
                if lid != STATE["lease_id"] or holder != STATE["holder"] or now >= STATE["not_after"]:
                    return self._j(410, {"error":"lease_lost"})
                tok=issue(holder, STATE["fencing"], ttl)
                STATE.update(lease_id=tok["lease_id"], not_after=tok["not_after"])
                return self._j(200, {"lease": tok, "fencing_token": STATE["fencing"]})
        if self.path == "/release":
            with LOCK:
                if b.get("lease_id") == STATE["lease_id"]:
                    STATE.update(holder=None, lease_id=None, not_after=0)
                return self._j(200, {"ok": True})
        self._j(404, {"error":"not found"})

def main():
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()

if __name__ == "__main__":
    main()
