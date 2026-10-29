from __future__ import annotations
from typing import Any
import httpx

class SigilError(RuntimeError):
    def __init__(self, code: str, message: str, status: int = 0, payload: Any = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status
        self.payload = payload

class SigilClient:
    """Small client for SIGIL/1 gate/verify/anchor services."""
    def __init__(self, gate="http://127.0.0.1:18100", verify="http://127.0.0.1:18101",
                 anchor="http://127.0.0.1:18102", timeout=15.0,
                 control_token: str | None = None,
                 control_token_file: str = "/run/sigil-control-token"):
        self.gate_url = gate.rstrip("/"); self.verify_url = verify.rstrip("/"); self.anchor_url = anchor.rstrip("/")
        if control_token is None:
            try:
                control_token = open(control_token_file, encoding="utf-8").read().strip()
            except OSError:
                control_token = ""
        headers = {"X-SIGIL-Token": control_token} if control_token else {}
        self._c = httpx.Client(timeout=timeout, headers=headers)

    def _post(self, url: str, body: dict) -> dict:
        r = self._c.post(url, json=body)
        try: data = r.json()
        except Exception: data = {"raw": r.text}
        if r.status_code >= 400:
            err = data.get("error", {}) if isinstance(data, dict) else {}
            raise SigilError(err.get("code", "E_HTTP"), err.get("message", r.text[:200]),
                             r.status_code, data)
        return data

    def grant(self, intent: dict, capabilities: list[dict] | None = None,
              ttl_ms: int = 300000, max_uses: int = 10) -> dict:
        body = {"intent": intent, "ttl_ms": ttl_ms, "max_uses": max_uses}
        if capabilities is not None: body["capabilities"] = capabilities
        return self._post(self.gate_url + "/grant", body)["grant"]

    def approve(self, intent: dict, approver: str = "human:lab", ttl_ms: int = 300000) -> dict:
        return self._post(self.gate_url + "/approve",
                          {"intent": intent, "approver": approver, "ttl_ms": ttl_ms})["approval"]

    def execute(self, intent: dict, grant: dict, idem_key: str,
                approval: dict | None = None, **extra) -> dict:
        body = {"intent": intent, "grant": grant, "idem_key": idem_key, **extra}
        if approval is not None: body["approval"] = approval
        return self._post(self.gate_url + "/execute", body)

    def record(self, intent: dict, grant: dict, idem_key: str, result: Any,
               effects: list[dict] | None = None, executor: dict | None = None,
               approval: dict | None = None) -> dict:
        body = {"intent": intent, "grant": grant, "idem_key": idem_key, "result": result}
        if effects is not None: body["effects"] = effects
        if executor is not None: body["executor"] = executor
        if approval is not None: body["approval"] = approval
        return self._post(self.gate_url + "/record", body)

    def route(self, intent: dict) -> dict:
        return self._post(self.gate_url + "/route", {"intent": intent})

    def verify(self, receipt: dict, **extra) -> dict:
        return self._post(self.verify_url + "/verify", {"receipt": receipt, **extra})

    def canonical(self, obj: Any) -> dict:
        return self._post(self.verify_url + "/canonical", {"obj": obj})

    def replay(self, receipt: dict, recorded: dict) -> dict:
        return self._post(self.verify_url + "/replay", {"receipt": receipt, "recorded": recorded})

    def anchor_root(self, root: str, seq: int = 0) -> dict:
        return self._post(self.anchor_url + "/anchor", {"root": root, "seq": seq})["anchor"]

    def verify_anchor(self, anchor: dict) -> dict:
        return self._post(self.anchor_url + "/verify", {"anchor": anchor})

    def receipts(self, limit: int = 100) -> dict:
        return self._c.get(self.gate_url + "/receipts", params={"limit": limit}).json()

    def chain_verify(self) -> dict:
        return self._c.get(self.gate_url + "/chain/verify").json()

    def close(self):
        self._c.close()
