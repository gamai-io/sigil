"""Local KMS-like signing daemon: private keys never leave this container."""
from __future__ import annotations
import base64, hmac, os, re, stat
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
from cryptography.hazmat.primitives import serialization

BASE = os.environ.get("SIGIL_KMS_DIR", "/kms")
TOKEN_FILE = os.environ.get("SIGIL_KMS_TOKEN_FILE", os.path.join(BASE, "token"))
ALLOWED = {"gate-ed25519-1", "anchor-ed25519-1"}
KEY_RE = re.compile(r"^(gate|anchor)-ed25519-[0-9]+$")
app = FastAPI(title="sigil-kms")

def token() -> str:
    try: return open(TOKEN_FILE).read().strip()
    except Exception: return ""

def key(key_id: str):
    if key_id not in ALLOWED and not KEY_RE.match(str(key_id)):
        raise KeyError(key_id)
    path = os.path.join(BASE, key_id + ".pem")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise PermissionError(f"insecure key mode {oct(mode)}: {path}")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

@app.get("/health")
def health():
    return {"ok": True, "role": "kms", "keys": sorted(ALLOWED)}

@app.post("/sign")
async def sign(req: Request):
    expected = token()
    got = req.headers.get("X-SIGIL-Token", "")
    if not expected or not hmac.compare_digest(got.encode(), expected.encode()):
        return JSONResponse({"error": {"code": "E_FORBIDDEN"}}, status_code=403)
    b = await req.json()
    key_id = b.get("key_id")
    try:
        payload = base64.b64decode(b["payload_b64"])
        sig = key(key_id).sign(payload)
        return {"alg": "ed25519", "key_id": key_id,
                "value": base64.b64encode(sig).decode()}
    except Exception as e:
        return JSONResponse({"error": {"code": "E_SIGN", "message": str(e)}}, status_code=400)

def main():
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("SIGIL_PORT", "18103")), log_level="warning")

if __name__ == "__main__":
    main()
