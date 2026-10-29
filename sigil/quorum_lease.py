"""Quorum lease client: acquire/renew a writer lease from N witnesses, require Q."""
from __future__ import annotations
import threading, time
import httpx
from . import common as C

class QuorumLeaseLost(RuntimeError):
    pass

class QuorumLease:
    def __init__(self, urls: list[str], token_file: str, holder: str, pub_path: str,
                 quorum: int = 2, ttl_ms: int = 6000, renew_ms: int = 2000):
        self.urls = [u.rstrip("/") for u in urls if u.strip()]
        self.token_file = token_file; self.holder = holder; self.pub_path = pub_path
        self.quorum = quorum; self.ttl_ms = ttl_ms; self.renew_ms = renew_ms
        self._tokens: list[tuple[str, dict]] = []
        self._lock = threading.Lock(); self._stop = False; self._thread = None

    def _token(self):
        try: return open(self.token_file).read().strip()
        except Exception: return ""

    def _verify(self, tok):
        core = {k: v for k, v in tok.items() if k != "sig"}
        return C.verify_sig(core, tok.get("sig", {}), self.pub_path)

    def _post(self, url, path, body):
        try:
            r = httpx.post(url + path, json=body, headers={"X-SIGIL-Token": self._token()}, timeout=5)
            return r
        except Exception:
            return None

    def acquire(self) -> bool:
        got = []
        for u in self.urls:
            r = self._post(u, "/acquire", {"holder": self.holder, "ttl_ms": self.ttl_ms})
            if r is not None and r.status_code == 200:
                tok = r.json()["lease"]
                if self._verify(tok): got.append((u, tok))
        if len(got) < self.quorum:
            for u, tok in got:
                self._post(u, "/release", {"lease_id": tok["lease_id"]})
            with self._lock: self._tokens = []
            return False
        with self._lock: self._tokens = got
        return True

    def renew(self) -> bool:
        with self._lock: toks = list(self._tokens)
        if not toks: return False
        got = []
        for u, tok in toks:
            r = self._post(u, "/renew", {"lease_id": tok["lease_id"], "holder": self.holder, "ttl_ms": self.ttl_ms})
            if r is not None and r.status_code == 200:
                nt = r.json()["lease"]
                if self._verify(nt): got.append((u, nt))
        if len(got) < self.quorum:
            with self._lock: self._tokens = []
            return False
        with self._lock: self._tokens = got
        return True

    def _loop(self):
        while not self._stop:
            with self._lock:
                toks = list(self._tokens)
            if not toks:
                self.acquire()
            else:
                exp = min(t.get("not_after", 0) for _, t in toks)
                if exp - C.now_ms() < 1500 and not self.renew():
                    self.acquire()
            time.sleep(self.renew_ms / 1000)

    def start(self, sync: bool = True):
        if not self.valid() and sync:
            deadline = time.time() + 30
            while time.time() < deadline and not self.acquire():
                time.sleep(0.5)
        if not self._thread:
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        return self.valid()

    def valid(self) -> bool:
        with self._lock:
            toks = list(self._tokens)
        if len(toks) < self.quorum: return False
        return all(t.get("not_after", 0) > C.now_ms() + 500 for _, t in toks)

    def require(self) -> dict:
        with self._lock:
            toks = list(self._tokens)
        if len(toks) < self.quorum or not all(t.get("not_after", 0) > C.now_ms() + 500 for _, t in toks):
            raise QuorumLeaseLost("quorum lease lost")
        fence = max(t.get("fencing_token", 0) for _, t in toks)
        return {"holder": self.holder, "fencing_token": fence,
                "quorum": {"required": self.quorum, "acquired": len(toks),
                           "witnesses": [u for u, _ in toks],
                           "proofs": [t for _, t in toks]}}

    def release(self):
        self._stop = True
        with self._lock: toks = list(self._tokens)
        for u, t in toks:
            self._post(u, "/release", {"lease_id": t["lease_id"]})
        with self._lock: self._tokens = []
