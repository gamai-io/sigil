"""Client for the Oracle lease witness (single-writer fencing)."""
from __future__ import annotations
import os, threading, time
import httpx
from . import common as C

class LeaseLost(RuntimeError):
    pass

class Lease:
    def __init__(self, url: str, token_file: str, holder: str, pub_path: str,
                 ttl_ms: int = 6000, renew_ms: int = 2000):
        self.url = url.rstrip("/"); self.token_file = token_file; self.holder = holder
        self.pub_path = pub_path; self.ttl_ms = ttl_ms; self.renew_ms = renew_ms
        self._tok = None; self._fencing = 0; self._expires = 0
        self._lock = threading.Lock(); self._stop = False; self._thread = None

    def _token(self) -> str:
        try: return open(self.token_file).read().strip()
        except Exception: return ""

    def _verify(self, tok: dict) -> bool:
        core = {k: v for k, v in tok.items() if k != "sig"}
        return C.verify_sig(core, tok.get("sig", {}), self.pub_path)

    def _set(self, tok: dict):
        with self._lock:
            self._tok = tok; self._fencing = tok.get("fencing_token", 0)
            self._expires = tok.get("not_after", 0)

    def acquire(self) -> bool:
        try:
            r = httpx.post(self.url + "/acquire", json={"holder": self.holder, "ttl_ms": self.ttl_ms},
                           headers={"X-SIGIL-Token": self._token()}, timeout=10)
            if r.status_code != 200: return False
            tok = r.json()["lease"]
            if not self._verify(tok): return False
            self._set(tok); return True
        except Exception:
            return False

    def renew(self) -> bool:
        with self._lock:
            tok = self._tok
        if not tok: return False
        try:
            r = httpx.post(self.url + "/renew", json={"lease_id": tok["lease_id"],
                           "holder": self.holder, "ttl_ms": self.ttl_ms},
                           headers={"X-SIGIL-Token": self._token()}, timeout=10)
            if r.status_code != 200:
                with self._lock: self._tok = None
                return False
            nt = r.json()["lease"]
            if not self._verify(nt): return False
            self._set(nt); return True
        except Exception:
            return False

    def _loop(self):
        while not self._stop:
            with self._lock:
                exp = self._expires
            if not exp:
                self.acquire()
            elif exp - C.now_ms() < 1500 and not self.renew():
                self.acquire()
            time.sleep(self.renew_ms / 1000)

    def start(self, sync: bool = True) -> bool:
        if self.valid():
            pass
        elif sync:
            deadline = time.time() + 30
            while time.time() < deadline and not self.acquire():
                time.sleep(0.5)
        if not self._thread:
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        return self.valid()

    def valid(self) -> bool:
        with self._lock:
            return bool(self._tok) and self._expires > C.now_ms() + 500

    def require(self) -> dict:
        with self._lock:
            if not self._tok or self._expires <= C.now_ms() + 500:
                raise LeaseLost("lease lost")
            return dict(self._tok)

    def release(self):
        self._stop = True
        with self._lock:
            tok = self._tok
        if tok:
            try:
                httpx.post(self.url + "/release", json={"lease_id": tok["lease_id"]},
                           headers={"X-SIGIL-Token": self._token()}, timeout=5)
            except Exception:
                pass
        with self._lock:
            self._tok = None
