"""A2A (Agent2Agent) helpers for the SIGIL/1 profile."""
from __future__ import annotations
import hashlib, json, os, uuid
import httpx

EXTENSION_URI = "https://sigil.dev/1"
CONTROL_TOKEN_FILE = os.environ.get("SIGIL_CONTROL_TOKEN_FILE", "/run/sigil-control-token")

def _gate_headers() -> dict:
    try:
        tok = open(CONTROL_TOKEN_FILE, encoding="utf-8").read().strip()
    except OSError:
        tok = ""
    return {"X-SIGIL-Token": tok} if tok else {}

def agent_extension() -> dict:
    return {"uri": EXTENSION_URI,
            "description": "SIGIL/1 proof-carrying execution profile",
            "required": False}

def record_echo(gate_url: str, text: str, message_id: str) -> dict | None:
    """Issue a grant and record a receipt for an A2A echo message."""
    intent = {"id": str(uuid.uuid4()), "op": "echo", "args": {"text": text},
              "contract": {"id": "a2a/echo/v1", "version": "1"},
              "determinism": {"mode": "seeded"}}
    try:
        with httpx.Client(timeout=10) as c:
            g = c.post(gate_url + "/grant", json={
                "intent": intent, "capabilities": [{"id": "echo", "constraints": {}}]},
                headers=_gate_headers()).json()["grant"]
            digest = hashlib.sha256(json.dumps({"text": f"echo:{text}"}, sort_keys=True,
                                               separators=(",", ":")).encode()).hexdigest()
            rec = c.post(gate_url + "/record", json={
                "intent": intent, "grant": g, "idem_key": "a2a:" + message_id,
                "result": {"text": f"echo:{text}"},
                "effects": [{"kind": "a2a.message", "target": "echo", "result_digest": digest}],
                "executor": {"kind": "a2a", "id": "echo", "version": "1.0", "sandbox": "docker"},
            }, headers=_gate_headers()).json()
        return rec if "receipt" in rec else None
    except Exception:
        return None

def attach_receipt(message, rec: dict) -> bool:
    """Attach SIGIL metadata to an A2A protobuf Message or a dict."""
    payload = {"sigil": {"profile": "1", "receipt": rec["receipt"],
                         "receipt_hash": rec.get("receipt_hash")}}
    try:
        from google.protobuf.struct_pb2 import Struct
        st = Struct(); st.update(payload)
        message.metadata.CopyFrom(st)
        return True
    except Exception:
        if isinstance(message, dict):
            message.setdefault("metadata", {}).update(payload)
            return True
        return False
