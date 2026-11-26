"""Run the conformance suite against a stack that CI itself starts.

No docker, no secrets, no pre-existing key material: every key and token is
generated into a temporary directory for this test, and every service is a
uvicorn subprocess (the MCP upstream and the A2A endpoint are small fixtures
written to the temp dir, because the repo does not ship lab instances of
them).

Checks that cannot be reproduced this way are reported as *skipped*, never as
passing:

* 17 anchor.remote_anchor  - the development lab pointed the anchor at an
  Oracle-hosted second anchor that stamps ``node: "remote"``; no such service
  exists in this repo or in deploy/docker-compose.yml.
* 21 keys.isolation       - asserts that gate/anchor/verify cannot see private
  keys via container mounts. A process runner cannot prove container
  isolation, so it is skipped instead of faked.
* 24 anchor.public_rfc3161 - third-party FreeTSA over the network; the CA/cert
  files are not in the repo.

Checks 20 (local RFC3161 TSA) runs: the test generates a throw-away TSA cert
and openssl config in the temp dir.
"""
from __future__ import annotations

import os
import pathlib
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import httpx
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

EXPECTED_SKIPS = {
    "17 anchor.remote_anchor",
    "21 keys.isolation",
    "24 anchor.public_rfc3161",
}

MCP_UPSTREAM = '''
import os
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
SID = "upstream-session-1"
TOOLS = [
    {"name": "echo", "description": "echo text", "inputSchema": {
        "type": "object", "properties": {"text": {"type": "string"}},
        "required": ["text"], "additionalProperties": False}},
    {"name": "drop_table", "description": "destructive", "inputSchema": {
        "type": "object", "properties": {}, "additionalProperties": False}},
]

def out(obj, code=200):
    return JSONResponse(obj, status_code=code, headers={"mcp-session-id": SID})

@app.get("/health")
def health():
    return {"ok": True, "role": "lab-mcp-upstream"}

@app.post("/mcp")
async def mcp(req: Request):
    body = await req.json()
    m, rid = body.get("method"), body.get("id")
    if m == "initialize":
        return out({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "lab-upstream", "version": "0"}}})
    if m == "notifications/initialized":
        return JSONResponse({}, status_code=202, headers={"mcp-session-id": SID})
    if m == "tools/list":
        return out({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    if m == "tools/call":
        p = body.get("params") or {}
        if p.get("name") == "echo":
            text = str((p.get("arguments") or {}).get("text", ""))
            return out({"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": text}]}})
        return out({"jsonrpc": "2.0", "id": rid, "error": {
            "code": -32601, "message": "unknown tool"}})
    if m == "resources/read":
        return out({"jsonrpc": "2.0", "id": rid, "result": {"contents": [
            {"uri": "lab://info", "mimeType": "text/plain", "text": "sigil lab info"}]}})
    if m == "prompts/get":
        return out({"jsonrpc": "2.0", "id": rid, "result": {
            "description": "lab prompt",
            "messages": [{"role": "user", "content": {"type": "text", "text": "sigil"}}]}})
    return out({"jsonrpc": "2.0", "id": rid, "error": {
        "code": -32601, "message": "method not found"}})

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("SIGIL_PORT", "18080")),
                log_level="warning")
'''

A2A_AGENT = '''
import os
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sigil import a2a

GATE = os.environ["SIGIL_GATE"]
app = FastAPI()

@app.get("/health")
def health():
    return {"ok": True, "role": "lab-a2a"}

@app.get("/.well-known/agent-card.json")
def card():
    return {"name": "sigil-lab-agent", "capabilities": {
        "extensions": [a2a.agent_extension()]}}

@app.post("/")
async def rpc(req: Request):
    body = await req.json()
    if body.get("method") != "SendMessage":
        return JSONResponse({"jsonrpc": "2.0", "id": body.get("id"), "error": {
            "code": -32601, "message": "method not found"}})
    m = (body.get("params") or {}).get("message") or {}
    text = "".join(p.get("text", "") for p in (m.get("parts") or []) if isinstance(p, dict))
    mid = str(m.get("messageId") or "a2a-1")
    rec = a2a.record_echo(GATE, text, mid)
    msg = {"messageId": mid, "role": "ROLE_AGENT", "parts": [{"text": "echo:" + text}]}
    if rec:
        a2a.attach_receipt(msg, rec)
    return {"jsonrpc": "2.0", "id": body.get("id"), "result": {"message": msg}}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("SIGIL_PORT", "18082")),
                log_level="warning")
'''


def _free_ports(start: int, count: int) -> list[int]:
    out: list[int] = []
    p = start
    while len(out) < count:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", p))
            out.append(p)
        except OSError:
            pass
        finally:
            s.close()
        p += 1
        if p > start + 500:
            raise RuntimeError("no free ports")
    return out


def _write_keypair(priv: pathlib.Path, pub: pathlib.Path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    priv.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    pub.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    os.chmod(priv, 0o600)
    os.chmod(pub, 0o644)


class Stack:
    def __init__(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="sigil-ci-stack-"))
        self.procs: dict[str, tuple[subprocess.Popen, object]] = {}
        self.envs: dict[str, dict] = {}
        self._prepare()
        self._start_all()

    # -- layout -------------------------------------------------------------
    def _prepare(self):
        base = int(os.environ.get("SIGIL_CI_PORT_BASE", "18100"))
        (p_gate, p_verify, p_anchor, p_kms, p_replica,
         p_w1, p_w2, p_w3, p_proxy, p_up, p_a2a, p_ctx) = _free_ports(base, 12)
        self.ports = {
            "gate": p_gate, "verify": p_verify, "anchor": p_anchor, "kms": p_kms,
            "replica": p_replica, "w1": p_w1, "w2": p_w2, "w3": p_w3,
            "proxy": p_proxy, "upstream": p_up, "a2a": p_a2a, "ctx": p_ctx,
        }
        r = self.root
        self.data = r / "data"; self.effects = r / "effects"; self.logdir = r / "logs"
        self.keys = r / "keys"; self.kms_dir = self.keys / "kms"; self.pub_dir = self.keys / "public"
        self.p256_dir = self.keys / "p256"; self.tsa_dir = r / "tsa"; self.tsa_data = self.tsa_dir / "data"
        for d in (self.data, self.effects, self.logdir, self.kms_dir, self.pub_dir,
                  self.p256_dir, self.tsa_data):
            d.mkdir(parents=True, exist_ok=True)
        os.chmod(self.keys, 0o700); os.chmod(self.kms_dir, 0o700)

        _write_keypair(self.kms_dir / "gate-ed25519-1.pem", self.pub_dir / "gate_ed25519_public.pem")
        _write_keypair(self.kms_dir / "anchor-ed25519-1.pem", self.pub_dir / "anchor_ed25519_public.pem")

        for name in ("control_token", "approver_token", "lease_token"):
            p = self.keys / name
            p.write_text(secrets.token_hex(32) + "\n")
            os.chmod(p, 0o600)
        kms_token = secrets.token_hex(32) + "\n"
        (self.kms_dir / "token").write_text(kms_token)
        os.chmod(self.kms_dir / "token", 0o600)
        self.control_token = (self.keys / "control_token").read_text().strip()
        self.approver_token = (self.keys / "approver_token").read_text().strip()
        self.lease_token = (self.keys / "lease_token").read_text().strip()

        # P-256 signer used by the cloud-KMS-compatible backend check.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        p256 = ec.generate_private_key(ec.SECP256R1())
        (self.p256_dir / "private.pem").write_bytes(p256.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        os.chmod(self.p256_dir / "private.pem", 0o600)
        (self.pub_dir / "p256_cloud_public.pem").write_bytes(p256.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

        # One keypair shared by all lease witnesses (the gate verifies with a single pub file).
        lease_priv = r / "lease-key.pem"
        _write_keypair(lease_priv, self.pub_dir / "lease_public.pem")
        self.witness_bases = {}
        for i, name in enumerate(("w1", "w2", "w3")):
            wb = r / name
            (wb / "keys").mkdir(parents=True)
            (wb / "token").write_text(self.lease_token + "\n")
            os.chmod(wb / "token", 0o600)
            (wb / "keys" / "ed25519_private.pem").write_bytes(lease_priv.read_bytes())
            os.chmod(wb / "keys" / "ed25519_private.pem", 0o600)
            self.witness_bases[i] = wb

        # Local RFC3161 TSA (self-signed, generated in the job).
        self.tsa_crt = self.tsa_dir / "tsa.crt"
        self.tsa_key = self.tsa_dir / "tsa.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/CN=SIGIL CI TSA",
            "-addext", "extendedKeyUsage=critical,timeStamping",
            "-addext", "keyUsage=critical,digitalSignature,nonRepudiation",
            "-keyout", str(self.tsa_key), "-out", str(self.tsa_crt),
        ], check=True, capture_output=True)
        (self.tsa_dir / "serial").write_text("01\n")
        (self.tsa_dir / "tsa.cnf").write_text(f"""\
[ tsa ]
default_tsa = tsa_config1

[ tsa_config1 ]
dir = {self.tsa_data}
serial = {self.tsa_dir / 'serial'}
crypto_device = builtin
signer_cert = {self.tsa_crt}
certs = {self.tsa_crt}
signer_key = {self.tsa_key}
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.2
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
""")
        shutil.copyfile(self.tsa_crt, self.pub_dir / "tsa.crt")

        fixtures = r / "fixtures"; fixtures.mkdir()
        (fixtures / "mcp_upstream.py").write_text(MCP_UPSTREAM)
        (fixtures / "a2a_agent.py").write_text(A2A_AGENT)
        self.fixtures = fixtures

        self.url = {k: f"http://127.0.0.1:{v}" for k, v in self.ports.items()}
        self.common = {
            "PYTHONPATH": str(ROOT),
            "PYTHONDONTWRITEBYTECODE": "1",
            "SIGIL_DATA": str(self.data),
            "SIGIL_EFFECTS": str(self.effects),
            "SIGIL_PUB_DIR": str(self.pub_dir),
            "SIGIL_CONTROL_TOKEN_FILE": str(self.keys / "control_token"),
            "SIGIL_APPROVER_TOKEN_FILE": str(self.keys / "approver_token"),
            "SIGIL_CHAIN_ID": "lab-chain",
            "SIGIL_TEST": "1",
            "SIGIL_ALLOW_HMAC": "0",
            "SIGIL_KMS_URL": self.url["kms"],
            "SIGIL_KMS_TOKEN_FILE": str(self.kms_dir / "token"),
            "SIGIL_TSA_ENABLE": "1",
            "SIGIL_TSA_MODE": "local",
            "SIGIL_TSA_DIR": str(self.tsa_dir),
            "SIGIL_TSA_CERT": str(self.tsa_crt),
            "SIGIL_ANCHOR_STRICT_SEQ": "1",
            "SIGIL_ANCHOR_ALLOW_LOCAL": "1",
            "SIGIL_GATE": self.url["gate"],
            "SIGIL_REPLICA_DB": str(self.data / "replica.db"),
            "SIGIL_REPLICA_INTERVAL": "1",
            "SIGIL_CTX_DIR": str(self.data / "ctx"),
            "SIGIL_HANDOFF_DIR": str(self.data / "handoffs"),
            "SIGIL_MCP_UPSTREAM": self.url["upstream"] + "/mcp",
            "SIGIL_LEASE_URLS": ",".join(self.url[f"w{i}"] for i in (1, 2, 3)),
            "SIGIL_LEASE_QUORUM": "2",
            "SIGIL_LEASE_TOKEN_FILE": str(self.keys / "lease_token"),
            "SIGIL_LEASE_PUB": str(self.pub_dir / "lease_public.pem"),
        }
        self.gate_env = dict(self.common, SIGIL_PORT=str(self.ports["gate"]),
                             SIGIL_KEY_ID="gate-ed25519-1", SIGIL_LEASE_HOLDER="gate-primary")
        self.standby_env = dict(self.gate_env, SIGIL_LEASE_HOLDER="gate-standby")
        self.service_env = {
            "verify": dict(self.common, SIGIL_PORT=str(self.ports["verify"])),
            "anchor": dict(self.common, SIGIL_PORT=str(self.ports["anchor"]),
                           SIGIL_KEY_ID="anchor-ed25519-1"),
            "kms": dict(self.common, SIGIL_PORT=str(self.ports["kms"]),
                        SIGIL_KMS_DIR=str(self.kms_dir)),
            "replica": dict(self.common, SIGIL_PORT=str(self.ports["replica"])),
            "ctx": dict(self.common, SIGIL_PORT=str(self.ports["ctx"])),
            "proxy": dict(self.common, SIGIL_PORT=str(self.ports["proxy"])),
            "a2a": dict(self.common, SIGIL_PORT=str(self.ports["a2a"])),
            "upstream": dict(self.common, SIGIL_PORT=str(self.ports["upstream"])),
        }
        for i in (1, 2, 3):
            self.envs[f"w{i}"] = dict(
                self.common, SIGIL_LEASE_BASE=str(self.witness_bases[i - 1]),
                SIGIL_LEASE_PORT=str(self.ports[f"w{i}"]))

    # -- processes ----------------------------------------------------------
    @staticmethod
    def _cmd(mod: str) -> list[str]:
        return [sys.executable, mod] if mod.endswith(".py") else [sys.executable, "-m", mod]

    def _spawn(self, name: str, cmd: list[str], env: dict):
        log = open(self.logdir / f"{name}.log", "ab", buffering=0)
        p = subprocess.Popen(cmd, cwd=str(ROOT), env={**os.environ, **env},
                             stdout=log, stderr=subprocess.STDOUT)
        self.procs[name] = (p, log)

    def _stop(self, name: str, grace: float = 5.0):
        entry = self.procs.pop(name, None)
        if not entry:
            return
        p, log = entry
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                p.kill(); p.wait(timeout=5)
        try:
            log.close()
        except Exception:
            pass

    def _tail(self, name: str, lines: int = 40) -> str:
        p = self.logdir / f"{name}.log"
        try:
            return "\n".join(p.read_text(errors="replace").splitlines()[-lines:])
        except OSError:
            return ""

    def _wait(self, name: str, timeout: float = 90.0):
        url = self.url[name] + "/health"
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if httpx.get(url, timeout=1).status_code == 200:
                    return
            except Exception:
                pass
            proc = self.procs.get(name, (None,))[0]
            if proc is not None and proc.poll() is not None:
                raise RuntimeError(f"{name} exited early\n{self._tail(name)}")
            time.sleep(0.2)
        raise RuntimeError(f"{name} did not become healthy\n{self._tail(name)}")

    def _start_all(self):
        for i in (1, 2, 3):
            self._spawn(f"w{i}", [sys.executable, "-m", "sigil.lease_witness"], self.envs[f"w{i}"])
        for name, mod in [("kms", "sigil.kms"), ("verify", "sigil.verify"),
                          ("upstream", str(self.fixtures / "mcp_upstream.py"))]:
            self._spawn(name, self._cmd(mod), self.service_env[name])
            self._wait(name)
        self._spawn("gate", [sys.executable, "-m", "sigil.gate"], self.gate_env)
        self._wait("gate")
        for name, mod in [("anchor", "sigil.anchor"), ("replica", "sigil.replica"),
                          ("ctx", "sigil.context_gateway"), ("proxy", "sigil.mcp_proxy"),
                          ("a2a", str(self.fixtures / "a2a_agent.py"))]:
            self._spawn(name, self._cmd(mod), self.service_env[name])
            self._wait(name)
        for i in (1, 2, 3):
            self._wait(f"w{i}")

    # -- driver surface -----------------------------------------------------
    def start_gate(self, crash: bool = False):
        self._stop("gate")
        env = dict(self.gate_env)
        if crash:
            env["SIGIL_CRASH_AFTER_EFFECT"] = "1"
        self._spawn("gate", [sys.executable, "-m", "sigil.gate"], env)
        self._wait("gate")

    def stop_gate(self):
        self._stop("gate")

    def start_standby(self):
        self._stop("standby")
        self._spawn("standby", [sys.executable, "-m", "sigil.standby"], self.standby_env)
        time.sleep(1)

    def stop_standby(self):
        self._stop("standby")

    def witness(self, index: int, action: str):
        name = f"w{index + 1}"
        if action in ("stop", "restart"):
            self._stop(name)
        if action in ("start", "restart"):
            self._spawn(name, [sys.executable, "-m", "sigil.lease_witness"], self.envs[name])
            self._wait(name)

    # -- conformance client config -----------------------------------------
    def conformance_env(self) -> dict:
        return {
            "SIGIL_CONFORMANCE_GATE": self.url["gate"],
            "SIGIL_CONFORMANCE_VERIFY": self.url["verify"],
            "SIGIL_CONFORMANCE_ANCHOR": self.url["anchor"],
            "SIGIL_CONFORMANCE_KMS": self.url["kms"],
            "SIGIL_CONFORMANCE_REPLICA": self.url["replica"],
            "SIGIL_CONFORMANCE_MCP": self.url["proxy"],
            "SIGIL_CONFORMANCE_A2A": self.url["a2a"],
            "SIGIL_CONFORMANCE_CTX": self.url["ctx"],
            "SIGIL_CONFORMANCE_WITNESSES": ",".join(self.url[f"w{i}"] for i in (1, 2, 3)),
            "SIGIL_CONFORMANCE_DATA": str(self.data),
            "SIGIL_CONFORMANCE_EFFECTS": str(self.effects),
            "SIGIL_CONFORMANCE_KEYS": str(self.keys),
            "SIGIL_CONTROL_TOKEN_FILE": str(self.keys / "control_token"),
            "SIGIL_APPROVER_TOKEN_FILE": str(self.keys / "approver_token"),
            "SIGIL_CONFORMANCE_TSA": "1",
            # Remote anchor and public FreeTSA are deliberately not set.
        }

    def dump_logs(self) -> str:
        out = []
        for name in sorted(self.procs) + ["gate"]:
            tail = self._tail(name, 20)
            if tail:
                out.append(f"--- {name} ---\n{tail}")
        return "\n".join(out)

    def close(self):
        for name in list(self.procs):
            self._stop(name)
        shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class ProcessDriver:
    name = "process"
    managed = True
    can_restart_gate = True
    can_standby = True
    can_witness = True
    can_isolation = False

    def __init__(self, stack: Stack):
        self.stack = stack

    def start_gate(self, crash: bool = False):
        self.stack.start_gate(crash=crash)

    def stop_gate(self):
        self.stack.stop_gate()

    def start_standby(self):
        self.stack.start_standby()

    def stop_standby(self):
        self.stack.stop_standby()

    def witness(self, index: int, action: str):
        self.stack.witness(index, action)


def test_conformance_stack():
    st = Stack()
    try:
        from sigil import conformance
        conformance.configure(st.conformance_env())
        out = conformance.run(verbose=True, driver=ProcessDriver(st))
    except BaseException:
        print("\n" + st.dump_logs())
        st.close()
        raise
    try:
        summary = conformance.format_summary(out)
        print("\n" + summary)
        assert out["failed"] == 0, summary
        skipped = {r["test"] for r in out["results"] if r.get("skipped")}
        assert skipped == EXPECTED_SKIPS, f"unexpected skips: {skipped}"
        assert out["passed"] >= 45, summary
    finally:
        st.close()
