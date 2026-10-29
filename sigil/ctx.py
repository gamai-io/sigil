"""Content-addressed context store (SIGIL/1 ACP-MCP bridge primitive)."""
from __future__ import annotations
import hashlib, json, os, time
from . import common as C

ROOT = os.environ.get("SIGIL_CTX_DIR", os.path.join(C.DATA, "ctx"))
BLOBS = os.path.join(ROOT, "blobs")
MANIFESTS = os.path.join(ROOT, "manifests")
ENTRY_KEYS = ("k", "t", "b", "n")


def _ensure():
    os.makedirs(BLOBS, exist_ok=True)
    os.makedirs(MANIFESTS, exist_ok=True)


def blob_id(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _blob_path(blob: str) -> str:
    if not blob.startswith("sha256:") or len(blob) != 71:
        raise ValueError("invalid blob id")
    return os.path.join(BLOBS, blob[7:])


def put_blob(data: bytes, media_type: str = "application/octet-stream") -> dict:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    _ensure()
    b = blob_id(bytes(data))
    p = _blob_path(b)
    deduped = os.path.exists(p)
    if not deduped:
        tmp = p + ".tmp." + str(os.getpid())
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    return {"blob": b, "media_type": media_type, "bytes": len(data), "deduped": deduped}


def get_blob(blob: str) -> bytes:
    with open(_blob_path(blob), "rb") as f:
        return f.read()


def normalize_entry(entry: dict) -> dict:
    out = {k: entry.get(k) for k in ENTRY_KEYS if entry.get(k) is not None}
    if "b" in out and out["b"] is not None and not str(out["b"]).startswith("sha256:"):
        raise ValueError("entry b must be a blob id")
    return out


def _manifest_path(ctx_id: str) -> str:
    if not ctx_id.startswith("ctx1:") or len(ctx_id) != 69:
        raise ValueError("invalid ctx id")
    return os.path.join(MANIFESTS, ctx_id[5:] + ".json")


def build_ctx(entries: list[dict], parents: list[str] | None = None,
              labels: dict | None = None) -> str:
    _ensure()
    norm = sorted((normalize_entry(e) for e in entries), key=lambda e: str(e.get("k", "")))
    manifest = {"v": 1, "parents": sorted(parents or []), "entries": norm,
                "labels": labels or {}}
    cid = "ctx1:" + C.sha(manifest)
    p = _manifest_path(cid)
    if not os.path.exists(p):
        tmp = p + ".tmp." + str(os.getpid())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    return cid


def get_manifest(ctx_id: str) -> dict:
    with open(_manifest_path(ctx_id), encoding="utf-8") as f:
        m = json.load(f)
    return {"ctx_id": ctx_id, **m}


def merge(base_ctx: str, entries: list[dict], labels: dict | None = None) -> str:
    base = get_manifest(base_ctx)
    merged = {str(e.get("k", "")): e for e in base.get("entries", [])}
    for e in entries:
        ne = normalize_entry(e)
        merged[str(ne.get("k", ""))] = ne
    return build_ctx(list(merged.values()), parents=[base_ctx], labels=labels or base.get("labels"))


def diff(a_ctx: str, b_ctx: str) -> dict:
    a = {str(e.get("k", "")): e for e in get_manifest(a_ctx).get("entries", [])}
    b = {str(e.get("k", "")): e for e in get_manifest(b_ctx).get("entries", [])}
    return {"added": sorted(set(b) - set(a)), "removed": sorted(set(a) - set(b)),
            "changed": sorted(k for k in set(a) & set(b) if a[k] != b[k])}


def prune(max_age_ms: int = 7 * 86400000, dry_run: bool = False) -> dict:
    _ensure()
    cutoff = time.time() - max(0, int(max_age_ms)) / 1000.0
    old_manifests = []
    for name in os.listdir(MANIFESTS):
        p = os.path.join(MANIFESTS, name)
        if os.path.isfile(p) and os.path.getmtime(p) < cutoff:
            old_manifests.append(p)
    referenced = set()
    for name in os.listdir(MANIFESTS):
        p = os.path.join(MANIFESTS, name)
        if p in old_manifests or not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8") as f:
                for e in json.load(f).get("entries", []):
                    if e.get("b"):
                        referenced.add(e["b"])
        except Exception:
            pass
    old_blobs = []
    for name in os.listdir(BLOBS):
        p = os.path.join(BLOBS, name)
        b = "sha256:" + name
        if os.path.isfile(p) and os.path.getmtime(p) < cutoff and b not in referenced:
            old_blobs.append(p)
    if not dry_run:
        for p in old_manifests + old_blobs:
            try: os.remove(p)
            except FileNotFoundError: pass
    return {"manifests": len(old_manifests), "blobs": len(old_blobs), "dry_run": dry_run}
