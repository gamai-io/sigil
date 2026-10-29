"""SIGIL/1 lab core: canonicalization, hashes, signatures, receipts, chain."""
from __future__ import annotations
import hashlib, hmac, json, os, sqlite3, time, uuid
from typing import Any
import rfc8785

DATA = os.environ.get("SIGIL_DATA", "/data")
EFFECTS = os.environ.get("SIGIL_EFFECTS", "/effects")
CHAIN_ID = os.environ.get("SIGIL_CHAIN_ID", "lab-chain")

KEY = os.environ.get("SIGIL_KEY", "").encode()
HMAC_KEY_ID = os.environ.get("SIGIL_HMAC_KEY_ID", "lab-hmac-1")
ALLOW_HMAC = os.environ.get("SIGIL_ALLOW_HMAC", "0") == "1"
KEY_ID = os.environ.get("SIGIL_KEY_ID", "gate-ed25519-1")
RECEIPT_KEY_ID = os.environ.get("SIGIL_RECEIPT_KEY_ID", "gate-ed25519-1")
ANCHOR_KEY_ID = os.environ.get("SIGIL_ANCHOR_KEY_ID", "anchor-ed25519-1")
PRIV_PATH = os.environ.get("SIGIL_PRIV_PATH", "/keys/ed25519_private.pem")
PUB_DIR = os.environ.get("SIGIL_PUB_DIR", "/pub")
CONTROL_TOKEN_FILE = os.environ.get("SIGIL_CONTROL_TOKEN_FILE", "/run/sigil-control-token")
APPROVER_TOKEN_FILE = os.environ.get("SIGIL_APPROVER_TOKEN_FILE", "/run/sigil-approver-token")
READ_TOKEN_FILE = os.environ.get("SIGIL_READ_TOKEN_FILE", CONTROL_TOKEN_FILE)
APPROVER_ID = os.environ.get("SIGIL_APPROVER_ID", "human:approver")
PRINCIPAL = os.environ.get("SIGIL_PRINCIPAL", "gate-client")
WRITE_PREFIX = os.environ.get("SIGIL_WRITE_PREFIX", "/ok")
MAX_USES_CAP = int(os.environ.get("SIGIL_MAX_USES_CAP", "100"))
REMOTE_PUB_PATH = os.environ.get("SIGIL_REMOTE_PUB", os.path.join(PUB_DIR, "remote_anchor_public.pem"))
TSA_CERT = os.environ.get("SIGIL_TSA_CERT", os.path.join(PUB_DIR, "tsa.crt"))
PUB_FILES = {
    "gate-ed25519-1": "gate_ed25519_public.pem",
    "anchor-ed25519-1": "anchor_ed25519_public.pem",
    "anchor-1": "remote_anchor_public.pem",
    "p256-cloud-1": "p256_cloud_public.pem",
    "gcp-p256-1": "p256_cloud_public.pem",
    "azure-p256-1": "p256_cloud_public.pem",
}

def canon(obj: Any) -> bytes:
    return rfc8785.dumps(obj)

def sha(obj: Any) -> str:
    return hashlib.sha256(canon(obj)).hexdigest()

def raw_sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def _priv():
    from cryptography.hazmat.primitives import serialization
    with open(PRIV_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def pub_path_for(key_id: str) -> str:
    if key_id in PUB_FILES:
        return os.path.join(PUB_DIR, PUB_FILES[key_id])
    candidate = os.path.join(PUB_DIR, str(key_id).replace("-", "_") + "_public.pem")
    if os.path.exists(candidate):
        return candidate
    return os.path.join(PUB_DIR, "gate_ed25519_public.pem")

def _pub(path: str | None = None):
    from cryptography.hazmat.primitives import serialization
    if path is None:
        path = os.path.join(PUB_DIR, "gate_ed25519_public.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

KMS_URL = os.environ.get("SIGIL_KMS_URL", "")
KMS_TOKEN_FILE = os.environ.get("SIGIL_KMS_TOKEN_FILE", "/kms/token")

def _kms_token() -> str:
    try: return open(KMS_TOKEN_FILE).read().strip()
    except Exception: return ""

def sign(obj: Any) -> dict:
    if KMS_URL:
        import base64, httpx
        r = httpx.post(KMS_URL.rstrip("/") + "/sign",
                       json={"key_id": KEY_ID,
                             "payload_b64": base64.b64encode(canon(obj)).decode()},
                       headers={"X-SIGIL-Token": _kms_token()}, timeout=10)
        if r.status_code != 200:
            raise RuntimeError(f"KMS sign failed: {r.status_code} {r.text[:200]}")
        return r.json()
    if os.path.exists(PRIV_PATH):
        import base64
        sig = _priv().sign(canon(obj))
        return {"alg": "ed25519", "key_id": KEY_ID,
                "value": base64.b64encode(sig).decode()}
    if ALLOW_HMAC and KEY:
        return {"alg": "hmac-sha256", "key_id": HMAC_KEY_ID,
                "value": hmac.new(KEY, canon(obj), hashlib.sha256).hexdigest()}
    raise RuntimeError("no signing key available (KMS/private key required)")

def verify_sig(obj: Any, sig: dict, pub_path: str | None = None) -> bool:
    if not sig:
        return False
    if sig.get("alg") == "ed25519":
        try:
            import base64
            path = pub_path or pub_path_for(sig.get("key_id", ""))
            _pub(path).verify(base64.b64decode(sig.get("value", "")), canon(obj))
            return True
        except Exception:
            return False
    if sig.get("alg") == "ecdsa-p256-sha256":
        try:
            import base64
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            path = pub_path or pub_path_for(sig.get("key_id", ""))
            if not os.path.exists(path):
                path = os.path.join(PUB_DIR, "p256_cloud_public.pem")
            _pub(path).verify(base64.b64decode(sig.get("value", "")), canon(obj), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
    if sig.get("alg") == "hmac-sha256" and sig.get("key_id") == HMAC_KEY_ID:
        return bool(ALLOW_HMAC and KEY) and hmac.compare_digest(
            sig.get("value", ""), hmac.new(KEY, canon(obj), hashlib.sha256).hexdigest())
    return False

def now_ms() -> int:
    return int(time.time() * 1000)

def read_token(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""

def token_ok(got: str | None, expected: str) -> bool:
    return bool(expected) and hmac.compare_digest((got or "").encode(), expected.encode())

def db() -> sqlite3.Connection:
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "sigil.db"), timeout=10, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript("""
    CREATE TABLE IF NOT EXISTS chain(
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      receipt_hash TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      receipt_json TEXT NOT NULL,
      created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS idem(
      key TEXT PRIMARY KEY,
      intent_hash TEXT NOT NULL,
      receipt_json TEXT NOT NULL,
      created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS journal(
      key TEXT PRIMARY KEY,
      intent_hash TEXT NOT NULL,
      target TEXT NOT NULL,
      before_digest TEXT,
      after_digest TEXT NOT NULL,
      payload TEXT NOT NULL,
      created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS grants(
      grant_id TEXT PRIMARY KEY,
      intent_hash TEXT NOT NULL,
      grant_json TEXT NOT NULL,
      uses INTEGER NOT NULL DEFAULT 0,
      max_uses INTEGER NOT NULL,
      not_after INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS approvals(
      approval_id TEXT PRIMARY KEY,
      intent_hash TEXT NOT NULL,
      policy_hash TEXT NOT NULL,
      approval_json TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      not_after INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS inflight(
      key TEXT PRIMARY KEY,
      intent_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL);
    """)
    return con

def last_hash(con: sqlite3.Connection) -> str:
    r = con.execute("SELECT receipt_hash FROM chain ORDER BY seq DESC LIMIT 1").fetchone()
    return r["receipt_hash"] if r else "GENESIS"

def chain_rows(con: sqlite3.Connection, limit: int = 1000) -> list[dict]:
    return [dict(r) for r in con.execute(
        "SELECT seq, receipt_hash, prev_hash, receipt_json, created_at FROM chain ORDER BY seq LIMIT ?", (limit,))]

def append_receipt(con: sqlite3.Connection, receipt: dict, receipt_hash: str) -> dict:
    prev = last_hash(con)
    con.execute("INSERT INTO chain(receipt_hash, prev_hash, receipt_json, created_at) VALUES(?,?,?,?)",
                (receipt_hash, prev, json.dumps(receipt, ensure_ascii=False), now_ms()))
    rid = con.execute("SELECT last_insert_rowid() AS s").fetchone()["s"]
    return {"seq": rid, "prev_hash": prev, "receipt_hash": receipt_hash}

def receipt_hash(receipt: dict) -> str:
    core = {k: v for k, v in receipt.items() if k not in ("sig", "anchor")}
    return sha(core)

def verify_chain(receipts: list[dict]) -> tuple[bool, list[str]]:
    errs = []
    prev = "GENESIS"
    for i, r in enumerate(receipts):
        h = receipt_hash(r)
        if r.get("prev_hash", "GENESIS") != prev:
            errs.append(f"seq {i}: prev_hash mismatch")
        if not verify_sig({k: v for k, v in r.items() if k not in ("sig", "anchor")}, r.get("sig", {})):
            errs.append(f"seq {i}: bad signature")
        prev = h
    return (not errs), errs

def verify_suffix(receipts: list[dict], target_hash: str, root: str) -> tuple[bool, list[str]]:
    errs = []
    if not receipts:
        return False, ["E_PROOF_EMPTY"]
    if receipt_hash(receipts[0]) != target_hash:
        errs.append("E_PROOF_TARGET")
    prev = target_hash
    for i, r in enumerate(receipts):
        h = receipt_hash(r)
        if i > 0 and r.get("prev_hash") != prev:
            errs.append(f"seq {i}: prev_hash mismatch")
        if not verify_sig({k: v for k, v in r.items() if k not in ("sig", "anchor")}, r.get("sig", {})):
            errs.append(f"seq {i}: bad signature")
        prev = h
    if prev != root:
        errs.append("E_PROOF_ROOT")
    return (not errs), errs

def _under(root: str, p: str) -> bool:
    root, p = os.path.realpath(root), os.path.realpath(p)
    try:
        return os.path.commonpath([root, p]) == root
    except ValueError:
        return False

def within_prefix(prefix: str, rel: str) -> bool:
    root = os.path.realpath(EFFECTS)
    p = os.path.realpath(os.path.join(root, rel.lstrip("/")))
    pre = os.path.realpath(os.path.join(root, prefix.lstrip("/")))
    return _under(root, p) and _under(pre, p)

def effect_path(rel: str) -> str:
    root = os.path.realpath(EFFECTS)
    p = os.path.realpath(os.path.join(root, rel.lstrip("/")))
    if not _under(root, p):
        raise ValueError("path outside effects root")
    return p

def file_digest(path: str) -> str | None:
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()
