"""Durable ACP handoff manifests bound to a SIGIL context id."""
from __future__ import annotations
import json, os, time, uuid
from . import common as C

ROOT = os.environ.get("SIGIL_HANDOFF_DIR", os.path.join(C.DATA, "handoffs"))


def _ensure():
    os.makedirs(ROOT, exist_ok=True)


def _path(handoff_id: str) -> str:
    if not handoff_id.startswith("ho1:") or len(handoff_id) != 68:
        raise ValueError("invalid handoff id")
    return os.path.join(ROOT, handoff_id[4:] + ".json")


def create(from_session: str, to_agent: str | None, ctx_id: str,
           caps: list[dict] | None = None, expected: list[dict] | None = None,
           parent_handoff_id: str | None = None, ttl_ms: int = 3600000,
           labels: dict | None = None, idem_prefix: str | None = None) -> dict:
    _ensure()
    now = C.now_ms()
    core = {
        "v": 1,
        "parent_handoff_id": parent_handoff_id,
        "from": {"session_id": from_session},
        "to": {"agent": to_agent},
        "ctx_id": ctx_id,
        "caps": caps or [],
        "expected": expected or [],
        "idem_prefix": idem_prefix or ("ho:" + str(uuid.uuid4()) + ":"),
        "labels": labels or {},
        "created_at": now,
        "not_after": now + max(1, int(ttl_ms)),
    }
    handoff_id = "ho1:" + C.sha(core)
    h = {"handoff_id": handoff_id, **core}
    p = _path(handoff_id)
    tmp = p + ".tmp." + str(os.getpid())
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(h, f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)
    return h


def get(handoff_id: str) -> dict:
    with open(_path(handoff_id), encoding="utf-8") as f:
        return json.load(f)


def replay_plan(handoff_id: str) -> dict:
    h = get(handoff_id)
    if h.get("not_after", 0) <= C.now_ms():
        raise ValueError("handoff expired")
    return {"handoff_id": handoff_id, "ctx_id": h["ctx_id"], "caps": h.get("caps", []),
            "expected": h.get("expected", []), "idem_prefix": h.get("idem_prefix"),
            "replayable": True}


def check_replay(handoff_id: str, step: int, result_digest: str) -> bool:
    h = get(handoff_id)
    for e in h.get("expected", []):
        if int(e.get("step", -1)) == int(step):
            return e.get("result_digest") == result_digest
    return False


def prune(max_age_ms: int = 7 * 86400000, dry_run: bool = False) -> dict:
    _ensure()
    cutoff = time.time() - max(0, int(max_age_ms)) / 1000.0
    old = [os.path.join(ROOT, n) for n in os.listdir(ROOT)
           if os.path.isfile(os.path.join(ROOT, n)) and os.path.getmtime(os.path.join(ROOT, n)) < cutoff]
    if not dry_run:
        for p in old:
            try: os.remove(p)
            except FileNotFoundError: pass
    return {"handoffs": len(old), "dry_run": dry_run}
