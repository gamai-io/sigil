"""RFC3161 timestamp adapter (openssl ts, local lab TSA)."""
from __future__ import annotations
import base64, hashlib, os, subprocess, tempfile, time
from . import common as C

TSA_DIR = os.environ.get("SIGIL_TSA_DIR", "/data/tsa")
TSA_CONF = os.path.join(TSA_DIR, "tsa.cnf")
MODE = os.environ.get("SIGIL_TSA_MODE", "local")
PUBLIC_URL = os.environ.get("SIGIL_TSA_PUBLIC_URL", "https://freetsa.org/tsr")
PUBLIC_CA = os.environ.get("SIGIL_TSA_PUBLIC_CA", "/pub/freetsa-cacert.pem")
PUBLIC_CERT = os.environ.get("SIGIL_TSA_PUBLIC_CERT", "/pub/freetsa-tsa.crt")

def _run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=20)
    return p.returncode, (p.stdout or "") + (p.stderr or "")

def make(root_hex: str) -> dict:
    with tempfile.TemporaryDirectory() as td:
        data = os.path.join(td, "root.bin"); q = os.path.join(td, "q.tsq"); r = os.path.join(td, "r.tsr")
        open(data, "w").write(root_hex)
        rc, out = _run(["openssl", "ts", "-query", "-data", data, "-sha256", "-cert", "-out", q])
        if rc != 0: raise RuntimeError("ts query failed: " + out)
        if MODE == "public":
            import httpx
            resp = httpx.post(PUBLIC_URL, content=open(q, "rb").read(),
                              headers={"Content-Type": "application/timestamp-query"}, timeout=20)
            if resp.status_code != 200:
                raise RuntimeError(f"public TSA HTTP {resp.status_code}")
            blob = resp.content
            open(r, "wb").write(blob)
            cert = open(PUBLIC_CERT, "rb").read()
            return {"mode": "public", "url": PUBLIC_URL,
                    "token_b64": base64.b64encode(blob).decode(),
                    "tsa_cert_sha256": hashlib.sha256(cert).hexdigest(),
                    "at": C.now_ms()}
        rc, out = _run(["openssl", "ts", "-reply", "-config", TSA_CONF, "-queryfile", q, "-out", r])
        if rc != 0: raise RuntimeError("ts reply failed: " + out)
        blob = open(r, "rb").read()
        cert = open(C.TSA_CERT, "rb").read()
        return {"mode": "local", "token_b64": base64.b64encode(blob).decode(),
                "tsa_cert_sha256": hashlib.sha256(cert).hexdigest(),
                "at": C.now_ms()}

def verify(root_hex: str, token: dict) -> bool:
    try:
        with tempfile.TemporaryDirectory() as td:
            data = os.path.join(td, "root.bin"); r = os.path.join(td, "r.tsr")
            open(data, "w").write(root_hex)
            open(r, "wb").write(base64.b64decode(token["token_b64"]))
            if token.get("mode") == "public":
                rc, out = _run(["openssl", "ts", "-verify", "-in", r, "-data", data,
                                "-CAfile", PUBLIC_CA, "-untrusted", PUBLIC_CERT])
                if rc != 0 or "Verification: OK" not in out:
                    return False
                cert = open(PUBLIC_CERT, "rb").read()
            else:
                rc, out = _run(["openssl", "ts", "-verify", "-in", r, "-data", data, "-CAfile", C.TSA_CERT])
                if rc != 0 or "Verification: OK" not in out:
                    return False
                cert = open(C.TSA_CERT, "rb").read()
            return hashlib.sha256(cert).hexdigest() == token.get("tsa_cert_sha256")
    except Exception:
        return False
