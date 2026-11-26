"""SIGIL/1 conformance suite.

Default mode exercises a *running* stack: gate, verifier, anchor, KMS, replica,
three lease witnesses, the MCP middleware, an A2A endpoint and the context
gateway.  Who starts/stops those services is delegated to a *driver*:

* ``DockerDriver`` (default) reproduces the original lab layout: containers
  named ``sigil-gate``, ``sigil-verify``, ``sigil-anchor``, ``sigil-kms``,
  ``sigil-w2``/``sigil-w3``, with host networking and key material under
  ``/tmp/sigil_lab`` (overridable, see the module constants below).
* A process driver (see ``tests/test_conformance_stack.py``) starts uvicorn
  subprocesses on a CI runner with keys generated in the job.  It cannot
  claim container key isolation, so check 21 is reported as skipped.

``--offline`` runs only checks that need the library plus a temp directory:
canonicalization, hashing, signing/verification, tamper rejection, chain and
suffix-proof verification, path-prefix safety, ctx/handoff lifecycle and the
fixed vectors.  It needs no ports, containers or key material.

Every check that cannot run is recorded as ``skipped`` with a reason; a run
only fails on an actual failed check (exit code 1).  Nothing is silently
counted as passing.
"""
from __future__ import annotations
import argparse, base64, copy, json, os, shutil, subprocess, time
from contextlib import contextmanager
import httpx, rfc8785
from sigil import common as C


def _url(name: str, default: str) -> str:
    return os.environ.get(name, default).rstrip("/")


# ---- configuration --------------------------------------------------------
# Service endpoints and the lab filesystem layout are read from the
# environment so the same checks can run against the docker lab or against a
# CI-managed runtime.  `configure()` re-reads them (also used by tests).

def _read_token(env_name: str, default_path: str) -> str:
    """Read an optional lab token; never fail at import time."""
    try:
        return open(os.environ.get(env_name, default_path), encoding="utf-8").read().strip()
    except OSError:
        return ""


def configure(env: dict | None = None) -> None:
    global GATE, VERIFY, ANCHOR, KMS, REPLICA, PROXY, A2A, CTX, WITNESSES
    global LAB, DATA, EFFECTS, KEYS, KMS_DIR, PUB_DIR, P256_PRIV, P256_PUB, LEASE_PUB
    global CONTROL_TOKEN, APPROVER_TOKEN, CLIENT, ACLIENT
    global REMOTE_EXPECTED, TSA_EXPECTED, PUBLIC_TSA_EXPECTED
    if env:
        os.environ.update({str(k): str(v) for k, v in env.items()})
    GATE = _url("SIGIL_CONFORMANCE_GATE", "http://127.0.0.1:18100")
    VERIFY = _url("SIGIL_CONFORMANCE_VERIFY", "http://127.0.0.1:18101")
    ANCHOR = _url("SIGIL_CONFORMANCE_ANCHOR", "http://127.0.0.1:18102")
    KMS = _url("SIGIL_CONFORMANCE_KMS", "http://127.0.0.1:18103")
    REPLICA = _url("SIGIL_CONFORMANCE_REPLICA", "http://127.0.0.1:18104")
    PROXY = _url("SIGIL_CONFORMANCE_MCP", "http://127.0.0.1:18110")
    A2A = _url("SIGIL_CONFORMANCE_A2A", "http://127.0.0.1:18082")
    CTX = _url("SIGIL_CONFORMANCE_CTX", "http://127.0.0.1:18120")
    WITNESSES = [u.rstrip("/") for u in os.environ.get(
        "SIGIL_CONFORMANCE_WITNESSES",
        "http://127.0.0.1:18106,http://127.0.0.1:18107,http://127.0.0.1:18108").split(",") if u.strip()]
    LAB = os.environ.get("SIGIL_LAB_DIR", "/tmp/sigil_lab")
    DATA = os.environ.get("SIGIL_CONFORMANCE_DATA", os.path.join(LAB, "data"))
    EFFECTS = os.environ.get("SIGIL_CONFORMANCE_EFFECTS", os.path.join(LAB, "effects"))
    KEYS = os.environ.get("SIGIL_CONFORMANCE_KEYS", os.path.join(LAB, "keys"))
    KMS_DIR = os.path.join(KEYS, "kms")
    PUB_DIR = os.path.join(KEYS, "public")
    P256_PRIV = os.path.join(KEYS, "p256", "private.pem")
    P256_PUB = os.path.join(PUB_DIR, "p256_cloud_public.pem")
    LEASE_PUB = os.path.join(PUB_DIR, "lease_public.pem")
    CONTROL_TOKEN = _read_token("SIGIL_CONTROL_TOKEN_FILE", os.path.join(KEYS, "control_token"))
    APPROVER_TOKEN = _read_token("SIGIL_APPROVER_TOKEN_FILE", os.path.join(KEYS, "approver_token"))
    CLIENT = httpx.Client(timeout=15, headers={"X-SIGIL-Token": CONTROL_TOKEN} if CONTROL_TOKEN else {})
    ACLIENT = httpx.Client(timeout=15, headers={"X-SIGIL-Token": APPROVER_TOKEN} if APPROVER_TOKEN else {})
    # Optional subsystems.  When unset the corresponding check is skipped
    # instead of failing, because the reference repo does not ship them:
    #   * SIGIL_CONFORMANCE_REMOTE_ANCHOR - a second anchor that stamps
    #     ``node: "remote"`` into its token (the development lab used an
    #     Oracle-hosted instance; deploy/docker-compose.yml has no such service).
    #   * SIGIL_CONFORMANCE_TSA=1 - anchor was started with SIGIL_TSA_ENABLE=1.
    #   * SIGIL_CONFORMANCE_PUBLIC_TSA=1 - anchor uses the public FreeTSA service
    #     (third-party network + CA files, not in the repo).
    REMOTE_EXPECTED = bool(os.environ.get("SIGIL_CONFORMANCE_REMOTE_ANCHOR", "").strip())
    TSA_EXPECTED = os.environ.get("SIGIL_CONFORMANCE_TSA", "0") == "1"
    PUBLIC_TSA_EXPECTED = os.environ.get("SIGIL_CONFORMANCE_PUBLIC_TSA", "0") == "1"


configure()

DRIVER = None
RESULTS = []
VERBOSE = True


# ---- driver protocol ------------------------------------------------------
class SkipCheck(Exception):
    """Raised by a driver for an operation the environment cannot perform."""


class Driver:
    name = "external"
    managed = False
    can_restart_gate = False
    can_standby = False
    can_witness = False
    can_isolation = False

    def start_gate(self, crash: bool = False) -> None:
        raise SkipCheck("gate lifecycle is not managed by this driver")

    def stop_gate(self) -> None:
        raise SkipCheck("gate lifecycle is not managed by this driver")

    def start_standby(self) -> None:
        raise SkipCheck("standby gate is not managed by this driver")

    def stop_standby(self) -> None:
        pass

    def witness(self, index: int, action: str) -> None:
        raise SkipCheck("lease witnesses are not managed by this driver")

    def keys_isolated(self) -> dict:
        raise SkipCheck("key isolation can only be observed inside containers")


def _docker_cmd() -> list[str]:
    return ["docker", "run", "-d", "--name", "sigil-gate", "--network", "host",
          "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--cap-drop", "ALL",
          "--security-opt", "no-new-privileges", "--user", "65534:65534",
          "-v", "/tmp/gama_proto_lab/sigil:/sigil:ro", "-v", "/tmp/gama_proto_lab/deps:/deps:ro",
          "-v", DATA + ":/data:rw",
          "-v", EFFECTS + ":/effects:rw",
          "-v", PUB_DIR + ":/pub:ro",
          "-v", os.path.join(KMS_DIR, "token") + ":/run/sigil-kms-token:ro",
          "-v", os.path.join(KEYS, "control_token") + ":/run/sigil-control-token:ro",
          "-v", os.path.join(KEYS, "approver_token") + ":/run/sigil-approver-token:ro",
          "-v", os.path.join(KEYS, "lease_token") + ":/run/sigil-lease-token:ro",
          "-e", "PYTHONPATH=/sigil:/deps", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "SIGIL_TEST=1",
          "-e", "SIGIL_CONTROL_TOKEN_FILE=/run/sigil-control-token",
          "-e", "SIGIL_APPROVER_TOKEN_FILE=/run/sigil-approver-token",
          "-e", "SIGIL_ALLOW_HMAC=0",
          "-e", "SIGIL_KEY_ID=gate-ed25519-1", "-e", "SIGIL_PUB_DIR=/pub",
          "-e", "SIGIL_KMS_URL=http://127.0.0.1:18103", "-e", "SIGIL_KMS_TOKEN_FILE=/run/sigil-kms-token",
          "-e", "SIGIL_LEASE_URLS=" + ",".join(WITNESSES),
          "-e", "SIGIL_LEASE_QUORUM=2", "-e", "SIGIL_LEASE_TOKEN_FILE=/run/sigil-lease-token",
          "-e", "SIGIL_LEASE_HOLDER=gate-primary", "-e", "SIGIL_LEASE_PUB=/pub/lease_public.pem",
          "python:3.12-slim", "python", "-m", "sigil.gate"]

WITNESS_CONTAINERS = {0: "sigil-w1", 1: "sigil-w2", 2: "sigil-w3"}


class DockerDriver(Driver):
    """Original development-lab layout (kept as the default)."""
    name = "docker"
    managed = True
    can_restart_gate = True
    can_standby = True
    can_witness = True
    can_isolation = True

    def start_gate(self, crash: bool = False) -> None:
        subprocess.run(["docker", "rm", "-f", "sigil-gate"], capture_output=True)
        cmd = _docker_cmd()
        if crash:
            idx = cmd.index("python:3.12-slim")
            cmd[idx:idx] = ["-e", "SIGIL_CRASH_AFTER_EFFECT=1"]
        subprocess.run(cmd, capture_output=True)
        assert wait_health(GATE), "gate did not start"

    def stop_gate(self) -> None:
        subprocess.run(["docker", "stop", "sigil-gate"], capture_output=True)

    def start_standby(self) -> None:
        subprocess.run(["docker", "rm", "-f", "sigil-gate-standby"], capture_output=True)
        sb = _docker_cmd()
        sb[sb.index("sigil-gate")] = "sigil-gate-standby"
        sb = [("sigil.standby" if x == "sigil.gate" else
               ("gate-standby" if x == "gate-primary" else x)) for x in sb]
        subprocess.run(sb, capture_output=True)
        time.sleep(1)

    def stop_standby(self) -> None:
        subprocess.run(["docker", "rm", "-f", "sigil-gate-standby"], capture_output=True)

    def witness(self, index: int, action: str) -> None:
        name = WITNESS_CONTAINERS.get(index)
        if name:
            subprocess.run(["docker", action, name], capture_output=True)

    def keys_isolated(self) -> dict:
        def dexists(container, path):
            return subprocess.run(["docker", "exec", container, "test", "-e", path],
                                  capture_output=True).returncode == 0
        return {
            "gate": dexists("sigil-gate", "/keys/ed25519_private.pem"),
            "anchor": dexists("sigil-anchor", "/keys/ed25519_private.pem"),
            "verify": dexists("sigil-verify", "/keys/ed25519_private.pem"),
            "kms_gate": dexists("sigil-kms", "/kms/gate-ed25519-1.pem"),
            "kms_anchor": dexists("sigil-kms", "/kms/anchor-ed25519-1.pem"),
        }


def start_gate(crash: bool = False) -> None:
    """Backwards-compatible wrapper: start the gate with the active driver."""
    (DRIVER or DockerDriver()).start_gate(crash=crash)


# ---- helpers --------------------------------------------------------------
def check(name, cond, detail=""):
    RESULTS.append({"test": name, "pass": bool(cond), "detail": detail})
    if VERBOSE:
        print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(detail)) if detail and not cond else ""))


def skip(name, reason):
    RESULTS.append({"test": name, "pass": None, "skipped": True, "reason": reason})
    if VERBOSE:
        print("SKIP " + name + " :: " + reason)


def reset():
    r = CLIENT.post(GATE + "/debug/reset")
    r.raise_for_status()
    if os.path.isdir(EFFECTS):
        for n in os.listdir(EFFECTS):
            p = os.path.join(EFFECTS, n)
            shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)


def grant(intent, caps=None, max_uses=10):
    r = CLIENT.post(GATE + "/grant", json={"intent": intent,
        "capabilities": caps or [{"id": intent["op"], "constraints": {}}],
        "max_uses": max_uses})
    r.raise_for_status(); return r.json()["grant"]


def approve(intent):
    r = ACLIENT.post(GATE + "/approve", json={"intent": intent})
    r.raise_for_status(); return r.json()["approval"]


def execute(intent, g, key, approval=None, **extra):
    body = {"intent": intent, "grant": g, "idem_key": key}
    if approval is not None: body["approval"] = approval
    body.update(extra)
    for _ in range(24):
        r = CLIENT.post(GATE + "/execute", json=body)
        if r.status_code != 503: return r
        time.sleep(0.5)
    return r


def chain():
    return CLIENT.get(GATE + "/receipts").json()


def anchor_root(root, seq=None):
    if seq is None:
        latest = CLIENT.get(ANCHOR + "/latest").json().get("anchor")
        seq = int(latest.get("seq", 0)) + 1 if latest else 1
    return CLIENT.post(ANCHOR + "/anchor", json={"root": root, "seq": seq})


def expect_error(resp, code):
    try: return resp.json().get("error", {}).get("code") == code
    except Exception: return False


def wait_health(url, tries=40):
    for _ in range(tries):
        try:
            if CLIENT.get(url + "/health").status_code == 200: return True
        except Exception: pass
        time.sleep(0.5)
    return False


def wait_lease(tries=60):
    for _ in range(tries):
        try:
            h = CLIENT.get(GATE + "/health").json()
            if h.get("lease") is True: return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def _mcp_session():
    init = CLIENT.post(PROXY + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "lab", "version": "0"}}},
        headers={"Accept": "application/json, text/event-stream"})
    sid = init.headers.get("mcp-session-id") or init.headers.get("MCP-Session-Id")
    CLIENT.post(PROXY + "/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers={"mcp-session-id": sid})
    return sid


def _mcp_call(body, sid):
    return CLIENT.post(PROXY + "/mcp", json=body, headers={"mcp-session-id": sid}).json()


# ---- stack mode -----------------------------------------------------------
def run(verbose: bool = True, driver: Driver | None = None) -> dict:
    global RESULTS, VERBOSE, DRIVER
    RESULTS = []
    VERBOSE = verbose
    DRIVER = driver or DockerDriver()
    d = DRIVER

    # 1 canonical
    obj = {"b": 1, "a": "č", "n": 1.0}
    r = CLIENT.post(VERIFY + "/canonical", json={"obj": obj}).json()
    check("1 canonical.jcs", r["canonical"] == rfc8785.dumps(obj).decode() and r["sha256"] == __import__("hashlib").sha256(rfc8785.dumps(obj)).hexdigest(), r)

    # 2 intent hash cross-transport envelopes
    intent = {"id": "i1", "op": "echo", "args": {"text": "zdravo"}, "contract": {"id": "echo/v1", "version": "1"}}
    envs = [
        {"transport": "mcp", "params": {"_meta": {"sigil": {"intent": intent}}}},
        {"transport": "a2a", "message": {"metadata": {"sigil": {"intent": intent}}}},
        {"transport": "http", "header": {"sigil": {"intent": intent}}},
    ]
    hs = [CLIENT.post(VERIFY + "/canonical", json={"obj": e["params"]["_meta"]["sigil"]["intent"] if "params" in e else e["message"]["metadata"]["sigil"]["intent"] if "message" in e else e["header"]["sigil"]["intent"]}).json()["sha256"] for e in envs]
    check("2 det.intent_hash.cross_transport", len(set(hs)) == 1, hs)

    # 3 route hash reproducible / sensitive
    r1 = CLIENT.post(GATE + "/route", json={"intent": intent}).json()
    r2 = CLIENT.post(GATE + "/route", json={"intent": intent}).json()
    bad = CLIENT.post(GATE + "/route", json={"intent": {"op": "rm_rf", "args": {}}}).json()
    check("3 det.route_hash.reproducible", r1["route_hash"] == r2["route_hash"] and r1["route_hash"] != bad["route_hash"], [r1["route_hash"], r2["route_hash"], bad["route_hash"]])

    # 4 strict rejects non-deterministic executor
    reset()
    si = {"id": "strict", "op": "echo", "args": {"text": "x"}, "executor": "llm", "determinism": {"mode": "strict"}}
    sg = grant(si)
    sr = execute(si, sg, "strict-1")
    check("4 det.strict_mode.rejects_nondet", sr.status_code == 422 and expect_error(sr, "E_CONTRACT_VIOLATION") and chain()["count"] == 0, sr.text)

    # 5 idempotency same key same effect
    reset()
    ii = {"id": "inc", "op": "increment_counter", "args": {"path": "counter.txt"}}
    ig = grant(ii)
    e1 = execute(ii, ig, "idem-1").json()
    e2 = execute(ii, ig, "idem-1").json()
    counter = open(os.path.join(EFFECTS, "counter.txt")).read() if os.path.exists(os.path.join(EFFECTS, "counter.txt")) else None
    check("5 idem.same_key_same_effect", counter == "1" and e2.get("replayed") is True and chain()["count"] == 1, {"counter": counter, "e2": e2})

    # 6 idempotency conflict
    i2 = {"id": "inc2", "op": "increment_counter", "args": {"path": "counter2.txt"}}
    g2 = grant(i2)
    c = execute(i2, g2, "idem-1")
    check("6 idem.conflict_on_payload_change", c.status_code == 409 and expect_error(c, "E_IDEMPOTENCY_CONFLICT") and not os.path.exists(os.path.join(EFFECTS, "counter2.txt")), c.text)

    # 7 crash recovery (kill gate after effect, restart, no double apply)
    if not d.can_restart_gate:
        skip("7 idem.crash_recovery_no_double_apply", "driver cannot restart the gate process")
    else:
        reset()
        ci = {"id": "crash", "op": "increment_counter", "args": {"path": "crash.txt"}}
        cg = grant(ci)
        d.start_gate(crash=True)
        try:
            CLIENT.post(GATE + "/execute", json={"intent": ci, "grant": cg, "idem_key": "crash-1"})
        except Exception:
            pass
        time.sleep(1)
        val_after_crash = open(os.path.join(EFFECTS, "crash.txt")).read() if os.path.exists(os.path.join(EFFECTS, "crash.txt")) else None
        d.start_gate(crash=False)
        rr = execute(ci, cg, "crash-1").json()
        val_after_recover = open(os.path.join(EFFECTS, "crash.txt")).read() if os.path.exists(os.path.join(EFFECTS, "crash.txt")) else None
        rec = rr.get("receipt", {})
        check("7 idem.crash_recovery_no_double_apply", val_after_crash == "1" and val_after_recover == "1" and rec.get("recovered") is True and chain()["count"] == 1, {"after_crash": val_after_crash, "after_recover": val_after_recover, "receipt": rec})

    # 8 replay record equivalence
    reset()
    ri = {"id": "replay", "op": "echo", "args": {"text": "zdravo"}}
    rg = grant(ri)
    rr = execute(ri, rg, "replay-1").json()
    ok1 = CLIENT.post(VERIFY + "/replay", json={"receipt": rr["receipt"], "recorded": {"result": rr["result"]}}).json()
    ok2 = CLIENT.post(VERIFY + "/replay", json={"receipt": rr["receipt"], "recorded": {"result": {"echo": "evil"}}}).json()
    check("8 replay.record_replay_equivalence", ok1["equal"] is True and ok2["equal"] is False, [ok1, ok2])

    # 9 tamper detection
    tampered = copy.deepcopy(rr["receipt"]); tampered["result"]["echo"] = "evil"
    v = CLIENT.post(VERIFY + "/verify", json={"receipt": tampered}).json()
    check("9 replay.tamper_detected", v["valid"] is False and "E_RESULT_DIGEST" in v["errors"], v)

    # 10 chain truncation
    reset()
    gi = {"id": "chain", "op": "echo", "args": {"text": "x"}}
    gg = grant(gi)
    for k in ("c1", "c2", "c3"):
        execute(gi, gg, k)
    rows = chain()["receipts"]
    recs = [json.loads(r["receipt_json"]) for r in rows]
    trunc = [recs[0], recs[2]] if len(recs) == 3 else recs
    vt = CLIENT.post(VERIFY + "/verify", json={"receipt": recs[-1], "chain": trunc}).json()
    check("10 replay.chain_truncation_detected", len(recs) == 3 and vt["valid"] is False, {"len": len(recs), "verify": vt})

    # 11 anchor binding
    reset()
    ai = {"id": "anchor", "op": "echo", "args": {"text": "x"}}
    ag = grant(ai)
    ar = execute(ai, ag, "anchor-1").json()
    tok = anchor_root(ar["receipt_hash"]).json()["anchor"]
    va = CLIENT.post(ANCHOR + "/verify", json={"anchor": tok}).json()
    bad = copy.deepcopy(tok); bad["root"] = "0" * 64
    vb = CLIENT.post(ANCHOR + "/verify", json={"anchor": bad}).json()
    vr = CLIENT.post(VERIFY + "/verify", json={"receipt": ar["receipt"], "anchor": tok}).json()
    check("11 replay.anchor_binding", va["valid"] and not vb["valid"] and vr["valid"], {"ok": va, "tampered": vb, "receipt": vr})

    # 12 policy deny fail-closed
    reset()
    di = {"id": "deny", "op": "rm_rf", "args": {"path": "/"}}
    dg = {"grant_id": "none"}
    dr = execute(di, dg, "deny-1")
    dj = dr.json()
    check("12 policy.deny_fail_closed", dr.status_code == 403 and dj["receipt"]["status"] == "denied" and dj["receipt"]["effects"] == [] and chain()["count"] == 1, dr.text)

    # 13 approval bound to intent
    reset()
    ia = {"id": "wa", "op": "write_file", "args": {"path": "ok/a.txt", "content": "A"}}
    ga = grant(ia, [{"id": "write_file", "constraints": {"path_prefix": "/ok"}}])
    aa = approve(ia)
    ra = execute(ia, ga, "wa-1", approval=aa)
    ib = {"id": "wb", "op": "write_file", "args": {"path": "ok/a.txt", "content": "B"}}
    gb = grant(ib, [{"id": "write_file", "constraints": {"path_prefix": "/ok"}}])
    rb = execute(ib, gb, "wb-1", approval=aa)
    content = open(os.path.join(EFFECTS, "ok/a.txt")).read() if os.path.exists(os.path.join(EFFECTS, "ok/a.txt")) else None
    check("13 policy.approval_bound_to_intent", ra.status_code == 200 and rb.status_code == 403 and expect_error(rb, "E_APPROVAL_INVALID") and content == "A", {"ra": ra.status_code, "rb": rb.text, "content": content})

    # 14 capability scope
    reset()
    ie = {"id": "evil", "op": "write_file", "args": {"path": "evil/x.txt", "content": "X"}}
    ge = grant(ie, [{"id": "write_file", "constraints": {"path_prefix": "/ok"}}])
    ae = approve(ie)
    re_ = execute(ie, ge, "evil-1", approval=ae)
    check("14 policy.capability_scope", re_.status_code == 403 and expect_error(re_, "E_CAPABILITY_SCOPE") and not os.path.exists(os.path.join(EFFECTS, "evil/x.txt")), re_.text)

    # 15 cross-transport observable equivalence
    reset()
    xi = {"id": "xt", "op": "echo", "args": {"text": "zdravo"}}
    xg = grant(xi)
    outs = [execute(xi, xg, "xt-" + t, transport=t).json() for t in ("mcp", "a2a", "http")]
    fields = [(o["receipt"]["intent_hash"], o["receipt"]["route_hash"], o["receipt"]["result_digest"]) for o in outs]
    ver = [CLIENT.post(VERIFY + "/verify", json={"receipt": o["receipt"], "intent": xi}).json()["valid"] for o in outs]
    check("15 xtransport.observable_equivalence", len(set(fields)) == 1 and all(ver) and chain()["count"] == 3, {"fields": fields, "verify": ver})

    # 16 Ed25519 signatures
    reset()
    ei = {"id": "ed", "op": "echo", "args": {"text": "ed25519"}}
    eg = grant(ei)
    er = execute(ei, eg, "ed-1").json()
    ev = CLIENT.post(VERIFY + "/verify", json={"receipt": er["receipt"]}).json()
    bad_sig = copy.deepcopy(er["receipt"]); v = bad_sig["sig"]["value"]; bad_sig["sig"]["value"] = ("B" if v[0] != "B" else "C") + v[1:]
    bv = CLIENT.post(VERIFY + "/verify", json={"receipt": bad_sig}).json()
    check("16 sig.ed25519", er["receipt"]["sig"]["alg"] == "ed25519" and ev["valid"] and not bv["valid"], {"alg": er["receipt"]["sig"]["alg"], "verify": ev, "tampered": bv})

    # 17 remote anchor (the development lab used an Oracle-hosted anchor)
    if not REMOTE_EXPECTED:
        skip("17 anchor.remote_anchor", "no remote anchor configured (set SIGIL_CONFORMANCE_REMOTE_ANCHOR=http://host:port)")
    else:
        reset()
        ri2 = {"id": "remote", "op": "echo", "args": {"text": "remote"}}
        rg2 = grant(ri2)
        rr2 = execute(ri2, rg2, "remote-1").json()
        ra = anchor_root(rr2["receipt_hash"]).json()["anchor"]
        rav = CLIENT.post(ANCHOR + "/verify", json={"anchor": ra}).json()
        bad_remote = copy.deepcopy(ra); bad_remote["remote"]["root"] = "0" * 64
        brv = CLIENT.post(ANCHOR + "/verify", json={"anchor": bad_remote}).json()
        check("17 anchor.remote_anchor", ra.get("remote", {}).get("node") == "remote" and rav.get("remote") is True and brv["valid"] is False and brv.get("remote") is False, {"remote": ra.get("remote", {}).get("node"), "verify": rav, "tampered": brv})

    # 18 MCP middleware (tools/call gets SIGIL receipt)
    reset()
    sid = _mcp_session()
    call = _mcp_call({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "echo", "arguments": {"text": "zdravo"}}}, sid)
    mrec = call.get("result", {}).get("_meta", {}).get("sigil", {}).get("receipt")
    mv = CLIENT.post(VERIFY + "/verify", json={"receipt": mrec}).json() if mrec else {"valid": False}
    check("18 mcp.middleware_receipt", bool(sid) and mrec and mrec["sig"]["alg"] == "ed25519" and mv["valid"], {"sid": sid, "has_receipt": bool(mrec), "verify": mv})

    # 19 A2A metadata extension
    reset()
    card = CLIENT.get(A2A + "/.well-known/agent-card.json").json()
    exts = [e.get("uri") for e in card.get("capabilities", {}).get("extensions", [])]
    msg = CLIENT.post(A2A + "/", json={"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
        "params": {"message": {"messageId": "a2a-c19", "role": "ROLE_USER", "parts": [{"text": "zdravo"}]}}},
        headers={"A2A-Version": "1.0"}).json()["result"]["message"]
    arec = msg.get("metadata", {}).get("sigil", {}).get("receipt")
    av = CLIENT.post(VERIFY + "/verify", json={"receipt": arec}).json() if arec else {"valid": False}
    check("19 a2a.metadata_extension", "https://sigil.dev/1" in exts and bool(arec) and arec["sig"]["alg"] == "ed25519" and av["valid"], {"ext": exts, "verify": av})

    # 20 RFC3161 timestamp token (local TSA)
    if not TSA_EXPECTED:
        skip("20 anchor.rfc3161", "anchor TSA not enabled (set SIGIL_CONFORMANCE_TSA=1)")
    else:
        reset()
        ti = {"id": "tsa", "op": "echo", "args": {"text": "tsa"}}
        tg = grant(ti)
        tr = execute(ti, tg, "tsa-1").json()
        ta = anchor_root(tr["receipt_hash"]).json()["anchor"]
        tv = CLIENT.post(ANCHOR + "/verify", json={"anchor": ta}).json()
        bad_tsa = copy.deepcopy(ta); bad_tsa["rfc3161"]["token_b64"] = "AAAA"
        btv = CLIENT.post(ANCHOR + "/verify", json={"anchor": bad_tsa}).json()
        check("20 anchor.rfc3161", "rfc3161" in ta and tv.get("rfc3161") is True and btv.get("rfc3161") is False, {"has": "rfc3161" in ta, "verify": tv, "tampered": btv})

    # 21 key isolation (needs container boundaries)
    if not d.can_isolation:
        skip("21 keys.isolation", "requires container isolation (docker exec); a CI process runner cannot prove it")
    else:
        iso = d.keys_isolated()
        # `tr`/`ta` come from check 20 when TSA is enabled; fall back to check 16's receipt.
        receipt_key = er["receipt"]["sig"]["key_id"]
        anchor_key = None
        try:
            anchor_key = CLIENT.get(ANCHOR + "/latest").json()["anchor"]["sig"]["key_id"]
        except Exception:
            pass
        check("21 keys.isolation", (not iso["gate"]) and (not iso["anchor"]) and (not iso["verify"])
              and iso["kms_gate"] and iso["kms_anchor"]
              and receipt_key == "gate-ed25519-1" and anchor_key == "anchor-ed25519-1",
              {**iso, "receipt_key": receipt_key, "anchor_key": anchor_key})

    # 22 MCP resources/read receipt
    reset()
    sid = _mcp_session()
    rr = _mcp_call({"jsonrpc": "2.0", "id": 2, "method": "resources/read",
                    "params": {"uri": "lab://info"}}, sid)
    rrec = rr.get("result", {}).get("_meta", {}).get("sigil", {}).get("receipt")
    rv = CLIENT.post(VERIFY + "/verify", json={"receipt": rrec}).json() if rrec else {"valid": False}
    check("22 mcp.resources_receipt", bool(rrec) and rrec["effects"][0]["kind"] == "mcp.resources.read" and rv["valid"], {"has": bool(rrec), "verify": rv})

    # 23 MCP prompts/get receipt
    pr = _mcp_call({"jsonrpc": "2.0", "id": 3, "method": "prompts/get",
                    "params": {"name": "lab_prompt", "arguments": {"topic": "sigil"}}}, sid)
    prec = pr.get("result", {}).get("_meta", {}).get("sigil", {}).get("receipt")
    pv = CLIENT.post(VERIFY + "/verify", json={"receipt": prec}).json() if prec else {"valid": False}
    check("23 mcp.prompts_receipt", bool(prec) and prec["effects"][0]["kind"] == "mcp.prompts.get" and pv["valid"], {"has": bool(prec), "verify": pv})

    # 24 public RFC3161 TSA (third party, not part of this repo)
    if not PUBLIC_TSA_EXPECTED:
        skip("24 anchor.public_rfc3161", "public FreeTSA not configured (third-party service; requires network + CA files)")
    else:
        reset()
        pi = {"id": "pubtsa", "op": "echo", "args": {"text": "pub"}}
        pg = grant(pi)
        pr = execute(pi, pg, "pubtsa-1").json()
        pa = anchor_root(pr["receipt_hash"]).json()["anchor"]
        pv = CLIENT.post(ANCHOR + "/verify", json={"anchor": pa}).json()
        check("24 anchor.public_rfc3161", pa.get("rfc3161", {}).get("mode") == "public" and pv.get("rfc3161") is True, {"tsa": pa.get("rfc3161", {}).get("mode"), "verify": pv})

    # 25 SQLite hot-standby replica + read failover
    if not d.can_restart_gate:
        skip("25 replica.hot_standby", "driver cannot stop/restart the gate process")
    else:
        reset()
        ri3 = {"id": "replica", "op": "echo", "args": {"text": "replica"}}
        rg3 = grant(ri3)
        for k in ("rep-1", "rep-2", "rep-3"):
            execute(ri3, rg3, k)
        CLIENT.post(REPLICA + "/debug/reset")
        gv = CLIENT.get(GATE + "/chain/verify").json()
        rep = CLIENT.post(REPLICA + "/sync").json()
        rst = CLIENT.get(REPLICA + "/status").json()
        rv = CLIENT.post(REPLICA + "/verify").json()
        d.stop_gate()
        time.sleep(2)
        down = CLIENT.get(REPLICA + "/receipts").json()
        dv = CLIENT.post(REPLICA + "/verify").json()
        d.start_gate(crash=False)
        gate_after = CLIENT.get(GATE + "/chain/verify").json()
        check("25 replica.hot_standby",
              rep["ok"] and rst["count"] == 3 and rst["root"] == gv["root"] and rv["valid"]
              and down["count"] == 3 and dv["valid"] and gate_after["count"] == 3,
              {"sync": rep, "status": rst, "down_count": down["count"], "gate_after": gate_after["count"]})

    # 26 replica auto-sync scheduler
    reset()
    CLIENT.post(REPLICA + "/debug/reset")
    ai3 = {"id": "autosync", "op": "echo", "args": {"text": "auto"}}
    ag3 = grant(ai3)
    for k in ("auto-1", "auto-2", "auto-3"):
        execute(ai3, ag3, k)
    gv2 = CLIENT.get(GATE + "/chain/verify").json()
    auto_ok = False; auto_st = {}
    for _ in range(40):
        auto_st = CLIENT.get(REPLICA + "/status").json()
        if auto_st.get("count") == 3 and auto_st.get("root") == gv2["root"] and auto_st.get("valid"):
            auto_ok = True; break
        time.sleep(0.5)
    check("26 replica.auto_sync", auto_ok, {"status": auto_st, "gate_root": gv2.get("root")})

    # 27 write failover with hot-standby gate (same SQLite, single active writer)
    if not (d.can_restart_gate and d.can_standby):
        skip("27 failover.write_standby", "driver cannot start a standby gate / stop the primary")
    else:
        wait_lease()
        reset()
        wi = {"id": "failover", "op": "echo", "args": {"text": "failover"}}
        wg = grant(wi)
        r1 = execute(wi, wg, "fo-1").json()
        before = CLIENT.get(GATE + "/chain/verify").json()["count"]
        d.start_standby()
        d.stop_gate()
        up = False
        for _ in range(40):
            try:
                if CLIENT.get(GATE + "/health").status_code == 200: up = True; break
            except Exception: pass
            time.sleep(0.5)
        wg2 = grant(wi) if up else None
        wr = execute(wi, wg2, "fo-2").json() if up else {}
        fence_ok = bool(r1.get("receipt", {}).get("lease")) and bool(wr.get("receipt", {}).get("lease")) and wr["receipt"]["lease"]["fencing_token"] > r1["receipt"]["lease"]["fencing_token"]
        during = CLIENT.get(GATE + "/chain/verify").json() if up else {}
        d.stop_standby()
        d.start_gate(crash=False)
        after = CLIENT.get(GATE + "/chain/verify").json()
        check("27 failover.write_standby", up and before == 1 and during.get("count") == 2
              and after.get("count") == 2 and after.get("ok") is True and fence_ok,
              {"up": up, "before": before, "during": during.get("count"), "after": after.get("count"), "fence": fence_ok})

    # 28 lease witness / fencing token
    if not d.can_witness:
        skip("28 lease.fencing_token", "lease witnesses are not managed by this driver")
    else:
        reset()
        li = {"id": "lease28", "op": "echo", "args": {"text": "lease"}}
        lg = grant(li)
        lr = execute(li, lg, "lease28-1").json()
        lst = CLIENT.get(WITNESSES[0] + "/status").json()
        lt = lr.get("receipt", {}).get("lease", {})
        check("28 lease.fencing_token",
              lt.get("holder") == "gate-primary" and lt.get("fencing_token", 0) >= lst.get("fencing", 0)
              and lt.get("quorum", {}).get("acquired", 0) >= 2,
              {"receipt_lease": lt, "witness": lst})

    # 29 quorum lease: survive one witness loss, fail with only one
    if not d.can_witness:
        skip("29 lease.quorum", "lease witnesses are not managed by this driver")
    else:
        reset()
        qi = {"id": "quorum", "op": "echo", "args": {"text": "quorum"}}
        qg = grant(qi)
        q1 = execute(qi, qg, "q-1")
        d.witness(1, "stop")
        time.sleep(3)
        q2 = execute(qi, qg, "q-2")
        d.witness(2, "stop")
        time.sleep(9)
        q3 = execute(qi, qg, "q-3")
        d.witness(1, "start"); d.witness(2, "start")
        time.sleep(2)
        q4 = execute(qi, qg, "q-4")
        check("29 lease.quorum",
              q1.status_code == 200 and q2.status_code == 200
              and q3.status_code == 503 and expect_error(q3, "E_LEASE_LOST")
              and q4.status_code == 200,
              {"q1": q1.status_code, "q2": q2.status_code, "q3": q3.status_code, "q4": q4.status_code})

    # 30 P-256 cloud-KMS-compatible signature backend
    from sigil.kms_backends import P256FileKMS
    kms = P256FileKMS(P256_PRIV)
    payload = {"op": "cloud-kms", "n": 1}
    sig = kms.sign(C.canon(payload))
    good = C.verify_sig(payload, sig, P256_PUB)
    badsig = dict(sig); badsig["value"] = ("A" if sig["value"][0] != "A" else "B") + sig["value"][1:]
    bad = C.verify_sig(payload, badsig, P256_PUB)
    check("30 kms.p256_cloud_compatible", sig["alg"] == "ecdsa-p256-sha256" and good and not bad,
          {"alg": sig["alg"], "good": good, "bad": bad})

    # 31 control-plane auth
    reset()
    anon = httpx.Client(timeout=10)
    ai = {"id": "auth", "op": "echo", "args": {"text": "x"}}
    ra = anon.post(GATE + "/grant", json={"intent": ai})
    rb = anon.post(GATE + "/approve", json={"intent": ai})
    rc = anon.post(GATE + "/route", json={"intent": ai})
    rd = anon.post(GATE + "/execute", json={"intent": ai, "grant": {}, "idem_key": "auth-1"})
    re_ = anon.post(GATE + "/record", json={"intent": ai, "grant": {}, "idem_key": "auth-2", "result": {}})
    rf = anon.post(GATE + "/debug/reset")
    ok = all(x.status_code == 401 and x.json().get("error", {}).get("code") == "E_UNAUTHENTICATED"
             for x in (ra, rb, rc, rd, re_, rf))
    ga = grant(ai)
    aa = approve(ai)
    check("31 auth.control_plane_required", ok and bool(ga) and bool(aa), {"codes": [x.status_code for x in (ra, rb, rc, rd, re_, rf)]})

    # 32 grant max_uses exhausted
    reset()
    mi = {"id": "maxuses", "op": "echo", "args": {"text": "x"}}
    mg = grant(mi, max_uses=1)
    m1 = execute(mi, mg, "max-1")
    m2 = execute(mi, mg, "max-2")
    check("32 grant.max_uses_exhausted",
          m1.status_code == 200 and m2.status_code == 403
          and expect_error(m2, "E_GRANT_EXHAUSTED") and chain()["count"] == 1,
          {"m1": m1.status_code, "m2": m2.text, "count": chain()["count"]})

    # 33 segment-safe path prefix
    reset()
    pi = {"id": "okevil", "op": "write_file", "args": {"path": "okevil/x.txt", "content": "X"}}
    pg = grant(pi, [{"id": "write_file", "constraints": {"path_prefix": "/ok"}}])
    pa = approve(pi)
    pr = execute(pi, pg, "okevil-1", approval=pa)
    check("33 policy.path_prefix_segment_safe",
          pr.status_code == 403 and expect_error(pr, "E_CAPABILITY_SCOPE")
          and not os.path.exists(os.path.join(EFFECTS, "okevil/x.txt")), pr.text)

    # 34 concurrent idempotency: one effect
    reset()
    ci = {"id": "conc", "op": "increment_counter", "args": {"path": "conc.txt"}}
    cg = grant(ci)
    import concurrent.futures as _cf
    def _run(k):
        return execute(ci, cg, "conc-1").status_code
    with _cf.ThreadPoolExecutor(max_workers=2) as ex:
        codes = sorted(ex.map(_run, (1, 2)))
    val = open(os.path.join(EFFECTS, "conc.txt")).read() if os.path.exists(os.path.join(EFFECTS, "conc.txt")) else None
    check("34 idem.concurrent_same_key",
          codes[0] == 200 and codes[1] in (200, 409) and val == "1" and chain()["count"] == 1,
          {"codes": codes, "value": val, "count": chain()["count"]})

    # 35 approval single-use under a second execute
    reset()
    ui = {"id": "approval-use", "op": "write_file", "args": {"path": "ok/u.txt", "content": "U"}}
    ug = grant(ui, [{"id": "write_file", "constraints": {"path_prefix": "/ok"}}], max_uses=5)
    ua = approve(ui)
    u1 = execute(ui, ug, "use-1", approval=ua)
    u2 = execute(ui, ug, "use-2", approval=ua)
    check("35 policy.approval_single_use",
          u1.status_code == 200 and u2.status_code == 403
          and expect_error(u2, "E_APPROVAL_INVALID"),
          {"u1": u1.status_code, "u2": u2.text})

    # 36 legacy HMAC downgrade rejected
    reset()
    hi = {"id": "hmac", "op": "echo", "args": {"text": "hmac"}}
    hg = grant(hi)
    hr = execute(hi, hg, "hmac-1").json()
    forged = copy.deepcopy(hr["receipt"])
    forged["sig"] = {"alg": "hmac-sha256", "key_id": "lab-hmac-1", "value": "00" * 32}
    hv = CLIENT.post(VERIFY + "/verify", json={"receipt": forged}).json()
    check("36 sig.hmac_downgrade_rejected", hv["valid"] is False, hv)

    # 37 authorize denies before any effect
    reset()
    di = {"id": "az-deny", "op": "rm_rf", "args": {"path": "/"}}
    da = CLIENT.post(GATE + "/authorize", json={"intent": di, "grant": {"grant_id": "none"},
                                                "idem_key": "az-deny-1"})
    dd = da.json()
    check("37 authorize.deny_before_effect",
          da.status_code == 403 and dd.get("receipt", {}).get("status") == "denied"
          and dd.get("receipt", {}).get("effects") == [] and chain()["count"] == 1, da.text)

    # 38 authorize claim then record
    reset()
    ai2 = {"id": "az-ok", "op": "echo", "args": {"text": "claim"}}
    ag2 = grant(ai2)
    az = CLIENT.post(GATE + "/authorize", json={"intent": ai2, "grant": ag2, "idem_key": "az-ok-1"})
    azd = az.json()
    rec = CLIENT.post(GATE + "/record", json={"claim_id": azd.get("claim_id"), "intent": ai2,
                                              "grant": ag2, "idem_key": "az-ok-1",
                                              "result": {"echo": "claim"}}).json()
    rec2 = CLIENT.post(GATE + "/record", json={"claim_id": azd.get("claim_id"), "intent": ai2,
                                               "grant": ag2, "idem_key": "az-ok-1",
                                               "result": {"echo": "claim"}}).json()
    check("38 authorize.claim_then_record",
          az.status_code == 200 and azd.get("authorized") is True
          and "receipt" in rec and rec2.get("replayed") is True and chain()["count"] == 1,
          {"az": az.text, "rec": rec, "rec2": rec2})

    # 39 MCP preflight denies destructive tool before upstream
    reset()
    sid = _mcp_session()
    bad = _mcp_call({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                     "params": {"name": "drop_table", "arguments": {}}}, sid)
    brec = bad.get("error", {}).get("data", {}).get("sigil", {}).get("receipt", {})
    check("39 mcp.preflight_deny_before_effect",
          bad.get("error", {}).get("code") == -32002 and brec.get("status") == "denied"
          and chain()["count"] == 1, bad)

    # 40 fencing token survives witness restart
    if not d.can_witness:
        skip("40 lease.fencing_persist", "lease witnesses are not managed by this driver")
    else:
        s1 = CLIENT.get(WITNESSES[1] + "/status").json()
        d.witness(1, "restart")
        s2 = {}
        for _ in range(20):
            try:
                s2 = CLIENT.get(WITNESSES[1] + "/status").json()
                break
            except Exception:
                time.sleep(0.5)
        check("40 lease.fencing_persist",
              s1.get("fencing", 0) > 0 and s2.get("fencing", 0) >= s1.get("fencing", 0),
              {"before": s1, "after": s2})

    # 41 anchor refuses a root that is not the gate chain root
    reset()
    ai3 = {"id": "anchor-bad", "op": "echo", "args": {"text": "anchor"}}
    ag3 = grant(ai3)
    ar3 = execute(ai3, ag3, "anchor-bad-1").json()
    bad_anchor = anchor_root("0" * 64)
    good_anchor = anchor_root(ar3["receipt_hash"])
    check("41 anchor.root_must_be_chain_root",
          bad_anchor.status_code == 409 and good_anchor.status_code == 200,
          {"bad": bad_anchor.text, "good": good_anchor.status_code})

    # 42 anchor rejects rollback / duplicate seq
    latest = CLIENT.get(ANCHOR + "/latest").json().get("anchor")
    roll = anchor_root(ar3["receipt_hash"], seq=int(latest.get("seq", 0))) if latest else None
    forward = anchor_root(ar3["receipt_hash"])
    check("42 anchor.reject_rollback",
          roll is not None and roll.status_code == 409
          and forward.status_code == 200, {"roll": roll.text if roll else None,
                                           "forward": forward.status_code})

    # 43 suffix inclusion proof for a linear hash chain
    reset()
    pi = {"id": "proof", "op": "echo", "args": {"text": "proof"}}
    pg = grant(pi)
    p1 = execute(pi, pg, "proof-1").json()
    execute(pi, pg, "proof-2")
    execute(pi, pg, "proof-3")
    proof = CLIENT.get(GATE + "/chain/proof/" + p1["receipt_hash"]).json()
    pv = CLIENT.post(VERIFY + "/proof", json={"proof": proof}).json()
    bad = copy.deepcopy(proof)
    bad["receipts"][0]["result"] = {"echo": "tampered"}
    bv = CLIENT.post(VERIFY + "/proof", json={"proof": bad}).json()
    check("43 chain.suffix_inclusion_proof",
          pv.get("valid") is True and bv.get("valid") is False
          and proof.get("root") == chain()["receipts"][-1]["receipt_hash"],
          {"proof": {k: proof.get(k) for k in ("receipt_hash", "root", "count")},
           "valid": pv, "tampered": bv})

    # 44 context/handoff GC
    import time as _time
    cr = CLIENT.post(CTX + "/ctx/ingest",
                     json={"entries": [{"k": "gc:1", "text": "prune-me"}]}).json()
    cid = cr["ctx_id"]
    man = CLIENT.post(CTX + "/handoff",
                      json={"from_session": "gc", "ctx_id": cid, "ttl_ms": 60000}).json()["handoff"]
    hid = man["handoff_id"]
    mpath = os.path.join(DATA, "ctx", "manifests", cid[5:] + ".json")
    b = cr["manifest"]["entries"][0]["b"]
    bpath = os.path.join(DATA, "ctx", "blobs", b[7:])
    hpath = os.path.join(DATA, "handoffs", hid[4:] + ".json")
    old = _time.time() - 3600
    for p in (mpath, bpath, hpath):
        if os.path.exists(p): os.utime(p, (old, old))
    pr = CLIENT.post(CTX + "/prune", json={"max_age_ms": 1000}).json()
    gone = CLIENT.get(CTX + "/ctx/" + cid).status_code == 404
    hgone = CLIENT.get(CTX + "/handoff/" + hid).status_code == 404
    check("44 ctx.gc_prune",
          pr.get("ctx", {}).get("manifests", 0) >= 1 and pr.get("handoff", {}).get("handoffs", 0) >= 1
          and gone and hgone, {"prune": pr, "ctx_gone": gone, "handoff_gone": hgone})

    # 45 MCP tool schema binding rejects wrong arguments before effect
    reset()
    sid = _mcp_session()
    bad_schema = _mcp_call({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                            "params": {"name": "echo", "arguments": {"wrong": 1}}}, sid)
    check("45 mcp.tool_schema_binding",
          bad_schema.get("error", {}).get("code") == -32602
          and bad_schema.get("error", {}).get("data", {}).get("sigil", {}).get("code") == "E_TOOL_SCHEMA"
          and chain()["count"] == 0, bad_schema)

    # 46 independent fixed vectors
    from sigil import vector_check
    vc = vector_check.run(verbose=False)
    check("46 vectors.independent", vc["passed"] == vc["total"] and vc["total"] >= 13,
          vc)

    # 47 key rotation: new key id signs, old receipts still verify
    from sigil.kms_rotate import rotate
    kid = "gate-ed25519-2"
    for p in (os.path.join(KMS_DIR, kid + ".pem"),
              os.path.join(PUB_DIR, kid.replace("-", "_") + "_public.pem")):
        if os.path.exists(p): os.remove(p)
    rot = rotate("gate", kid, KMS_DIR, PUB_DIR)
    try:
        os.chown(rot["private"], 65534, 65534)
    except PermissionError:
        pass
    token = open(os.path.join(KMS_DIR, "token")).read().strip()
    payload = {"rotation": 1}
    ns = httpx.post(KMS + "/sign",
                    json={"key_id": kid, "payload_b64": base64.b64encode(C.canon(payload)).decode()},
                    headers={"X-SIGIL-Token": token}, timeout=10).json()
    old = httpx.post(KMS + "/sign",
                     json={"key_id": "gate-ed25519-1", "payload_b64": base64.b64encode(C.canon(payload)).decode()},
                     headers={"X-SIGIL-Token": token}, timeout=10).json()
    check("47 kms.key_rotation",
          ns.get("key_id") == kid and C.verify_sig(payload, ns, rot["public"])
          and old.get("key_id") == "gate-ed25519-1"
          and C.verify_sig(payload, old, os.path.join(PUB_DIR, "gate_ed25519_public.pem")),
          {"new": ns.get("key_id"), "old": old.get("key_id")})

    # 48 quorum certificate: receipt carries each witness's signed lease token
    wait_lease()
    qci = {"id": "qcert48", "op": "echo", "args": {"text": "qcert"}}
    qcg = grant(qci)
    qcr = execute(qci, qcg, "qcert48-1").json()
    ql = qcr.get("receipt", {}).get("lease", {})
    proofs = ql.get("quorum", {}).get("proofs", [])
    def _pv(p):
        core = {k: v for k, v in p.items() if k != "sig"}
        return C.verify_sig(core, p.get("sig", {}), LEASE_PUB)
    tampered = copy.deepcopy(proofs[0]) if proofs else {}
    if tampered:
        tv = tampered["sig"]["value"]
        tampered["sig"]["value"] = ("A" if tv[0] != "A" else "B") + tv[1:]
    ok = (len(proofs) >= 2 and all(_pv(p) for p in proofs)
          and all(p.get("holder") == "gate-primary" for p in proofs)
          and max(p.get("fencing_token", 0) for p in proofs) == ql.get("fencing_token"))
    check("48 lease.quorum_certificate",
          ok and bool(tampered) and not _pv(tampered),
          {"proofs": len(proofs), "fencing": ql.get("fencing_token")})

    # 49 operational metrics
    m = CLIENT.get(GATE + "/metrics").text
    check("49 ops.metrics",
          "sigil_chain_receipts " in m and "sigil_requests_total " in m
          and "sigil_errors_total " in m and "sigil_lease_valid 1" in m,
          {"sample": m.splitlines()[:6]})

    return summarize(RESULTS)


# ---- offline mode ---------------------------------------------------------
@contextmanager
def _library_env(priv_path: str, pub_dir: str, effects_dir: str):
    """Point sigil.common at throw-away keys/dirs for the duration of a check."""
    saved = (C.PRIV_PATH, C.PUB_DIR, C.KMS_URL, C.ALLOW_HMAC, C.EFFECTS)
    C.PRIV_PATH, C.PUB_DIR, C.KMS_URL, C.ALLOW_HMAC, C.EFFECTS = priv_path, pub_dir, "", False, effects_dir
    try:
        yield
    finally:
        C.PRIV_PATH, C.PUB_DIR, C.KMS_URL, C.ALLOW_HMAC, C.EFFECTS = saved


def _write_ed25519(priv_path: str, pub_path: str):
    import os as _os
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    open(priv_path, "wb").write(priv); _os.chmod(priv_path, 0o600)
    open(pub_path, "wb").write(pub); _os.chmod(pub_path, 0o644)


def _signed_receipt(i: int, prev: str) -> tuple[dict, str]:
    policy = {"decision": "allow", "rule_ids": ["allow_read_echo_counter"]}
    policy["policy_hash"] = C.sha({"decision": policy["decision"], "rule_ids": policy["rule_ids"]})
    rec = {"v": "1", "receipt_id": f"r{i}", "intent_id": f"i{i}",
           "intent_hash": C.sha({"id": i}), "route_hash": C.sha({"stage": i}),
           "grant_id": "g1", "policy": policy,
           "executor": {"kind": "local", "id": "echo", "version": "1.0", "sandbox": "offline"},
           "effects": [], "result": {"n": i}, "result_digest": C.sha({"n": i}),
           "status": "ok", "nondet_used": [], "chain_id": "offline", "prev_hash": prev}
    rec["sig"] = C.sign(rec)
    return rec, C.receipt_hash(rec)


def run_offline(verbose: bool = True) -> dict:
    """Checks that need only the library and a temp directory (no ports)."""
    global RESULTS, VERBOSE
    RESULTS = []
    VERBOSE = verbose
    import tempfile

    td = tempfile.mkdtemp(prefix="sigil-offline-")
    # These modules build their store paths from SIGIL_DATA at import time, which
    # defaults to /data — a path an unprivileged runner cannot create. Point them
    # at the temp directory before importing.
    os.environ.setdefault("SIGIL_DATA", td)
    os.environ.setdefault("SIGIL_CTX_DIR", os.path.join(td, "ctx"))
    os.environ.setdefault("SIGIL_HANDOFF_DIR", os.path.join(td, "handoffs"))
    from sigil import ctx as ctx_mod, handoff as handoff_mod, vector_check
    try:
        pubdir = os.path.join(td, "pub"); os.makedirs(pubdir)
        effects = os.path.join(td, "effects"); os.makedirs(effects)
        priv = os.path.join(td, "kms", "gate.pem"); os.makedirs(os.path.dirname(priv))
        _write_ed25519(priv, os.path.join(pubdir, "gate_ed25519_public.pem"))

        # O1 canonical JCS + digest
        obj = {"b": 1, "a": "č", "n": 1.0}
        enc = rfc8785.dumps(obj)
        check("O1 canonical.jcs", C.canon(obj) == enc and C.sha(obj) == __import__("hashlib").sha256(enc).hexdigest())

        # O2 intent hash is transport-independent
        intent = {"id": "i1", "op": "echo", "args": {"text": "zdravo"},
                  "contract": {"id": "echo/v1", "version": "1"}}
        envelopes = [{"params": {"_meta": {"sigil": {"intent": intent}}}},
                     {"message": {"metadata": {"sigil": {"intent": intent}}}},
                     {"header": {"sigil": {"intent": intent}}}]
        picked = [e["params"]["_meta"]["sigil"]["intent"] if "params" in e else
                  e["message"]["metadata"]["sigil"]["intent"] if "message" in e else
                  e["header"]["sigil"]["intent"] for e in envelopes]
        check("O2 det.intent_hash.cross_transport", len({C.sha(x) for x in picked}) == 1)

        # O3 policy hash deterministic and sensitive
        p1 = {"decision": "allow", "rule_ids": ["allow_read_echo_counter"]}
        p2 = {"decision": "deny", "rule_ids": ["destructive_deny"]}
        ph = lambda p: C.sha({"decision": p["decision"], "rule_ids": p["rule_ids"]})
        check("O3 det.policy_hash", ph(p1) == ph(dict(p1)) and ph(p1) != ph(p2))

        with _library_env(priv, pubdir, effects):
            # O4 sign -> verify round trip (Ed25519)
            rec1, h1 = _signed_receipt(1, "GENESIS")
            core1 = {k: v for k, v in rec1.items() if k not in ("sig", "anchor")}
            check("O4 sig.ed25519_roundtrip",
                  rec1["sig"]["alg"] == "ed25519" and C.verify_sig(core1, rec1["sig"])
                  and h1 == C.sha(core1))

            # O5 tamper rejection: result and signature
            tampered = copy.deepcopy(rec1); tampered["result"] = {"n": 999}
            core_t = {k: v for k, v in tampered.items() if k not in ("sig", "anchor")}
            bad_sig = copy.deepcopy(rec1); bv = bad_sig["sig"]["value"]
            bad_sig["sig"]["value"] = ("B" if bv[0] != "B" else "C") + bv[1:]
            check("O5 replay.tamper_detected",
                  tampered["result_digest"] != C.sha(tampered["result"])
                  and not C.verify_sig(core_t, tampered["sig"])
                  and not C.verify_sig(core1, bad_sig["sig"]))

            # O6 chain continuity + truncation detection
            rec2, h2 = _signed_receipt(2, h1)
            rec3, h3 = _signed_receipt(3, h2)
            ok_chain, errs = C.verify_chain([rec1, rec2, rec3])
            ok_trunc, _ = C.verify_chain([rec1, rec3])
            check("O6 replay.chain_truncation_detected", ok_chain and not errs and not ok_trunc,
                  {"chain": errs, "truncated_ok": ok_trunc})

            # O7 suffix inclusion proof
            ok_proof, perrs = C.verify_suffix([rec2, rec3], h2, h3)
            bad_rec3 = copy.deepcopy(rec3); bad_rec3["result"] = {"n": 999}
            bad_proof, _ = C.verify_suffix([rec2, bad_rec3], h2, h3)
            check("O7 chain.suffix_inclusion_proof", ok_proof and not perrs and not bad_proof,
                  {"errors": perrs, "tampered_ok": bad_proof})

            # O8 segment-safe path prefix
            check("O8 policy.path_prefix_segment_safe",
                  C.within_prefix("/ok", "ok/a.txt")
                  and not C.within_prefix("/ok", "okevil/x.txt")
                  and not C.within_prefix("/ok", "../etc/passwd")
                  and not C.within_prefix("/ok", "/ok/../x"))

            # O9 legacy HMAC downgrade rejected
            forged = {"alg": "hmac-sha256", "key_id": "lab-hmac-1", "value": "00" * 32}
            check("O9 sig.hmac_downgrade_rejected",
                  not C.verify_sig(core1, forged) and not C.ALLOW_HMAC)

        # O10 P-256 backend (cloud-KMS-compatible signature shape)
        from sigil.kms_backends import P256FileKMS
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        p256_priv = os.path.join(td, "p256.pem")
        key = ec.generate_private_key(ec.SECP256R1())
        open(p256_priv, "wb").write(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        p256_pub = os.path.join(td, "p256_pub.pem")
        open(p256_pub, "wb").write(key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        kms = P256FileKMS(p256_priv)
        payload = {"op": "cloud-kms", "n": 1}
        sig = kms.sign(C.canon(payload))
        badsig = dict(sig); badsig["value"] = ("A" if sig["value"][0] != "A" else "B") + sig["value"][1:]
        check("O10 kms.p256_cloud_compatible",
              sig["alg"] == "ecdsa-p256-sha256" and C.verify_sig(payload, sig, p256_pub)
              and not C.verify_sig(payload, badsig, p256_pub))

        # O11 context + handoff lifecycle in a temp store
        old_ctx, old_ho = ctx_mod.ROOT, handoff_mod.ROOT
        old_blobs, old_manifests = ctx_mod.BLOBS, ctx_mod.MANIFESTS
        ctx_mod.ROOT = os.path.join(td, "ctx"); handoff_mod.ROOT = os.path.join(td, "handoffs")
        # BLOBS/MANIFESTS are computed at import; rebind them too or put_blob
        # still writes to the import-time path.
        ctx_mod.BLOBS = os.path.join(ctx_mod.ROOT, "blobs")
        ctx_mod.MANIFESTS = os.path.join(ctx_mod.ROOT, "manifests")
        try:
            blob = ctx_mod.put_blob(b"prune-me", "text/plain")
            cid = ctx_mod.build_ctx([{"k": "a", "b": blob["blob"], "t": "text/plain"}])
            cid2 = ctx_mod.merge(cid, [{"k": "b", "t": "lab://info"}])
            d = ctx_mod.diff(cid, cid2)
            ho = handoff_mod.create("offline", "agent:lab", cid, ttl_ms=60000)
            plan = handoff_mod.replay_plan(ho["handoff_id"])
            old = time.time() - 3600
            for p in (os.path.join(ctx_mod.MANIFESTS, cid[5:] + ".json"),
                      os.path.join(handoff_mod.ROOT, ho["handoff_id"][4:] + ".json")):
                if os.path.exists(p): os.utime(p, (old, old))
            pr = ctx_mod.prune(1000)
            hp = handoff_mod.prune(1000)
            check("O11 ctx.handoff_lifecycle",
                  cid.startswith("ctx1:") and d["added"] == ["b"] and plan["replayable"]
                  and pr["manifests"] >= 1 and hp["handoffs"] >= 1
                  and not os.path.exists(os.path.join(ctx_mod.MANIFESTS, cid[5:] + ".json")),
                  {"diff": d, "prune": pr, "handoff_prune": hp})
        finally:
            ctx_mod.ROOT, handoff_mod.ROOT = old_ctx, old_ho
            ctx_mod.BLOBS, ctx_mod.MANIFESTS = old_blobs, old_manifests

        # O12 fixed vectors
        vc = vector_check.run(verbose=False)
        check("O12 vectors.independent", vc["passed"] == vc["total"] and vc["total"] >= 13, vc)
    finally:
        shutil.rmtree(td, ignore_errors=True)
    return summarize(RESULTS)


# ---- summary --------------------------------------------------------------
def summarize(results: list[dict]) -> dict:
    passed = sum(1 for r in results if r["pass"] is True)
    failed = sum(1 for r in results if r["pass"] is False)
    skipped = sum(1 for r in results if r.get("skipped"))
    return {"passed": passed, "failed": failed, "skipped": skipped,
            "total": len(results), "results": results}


def format_summary(out: dict) -> str:
    executed = out["passed"] + out["failed"]
    line = (f"SIGIL/1 conformance: {out['passed']}/{executed} passed, "
            f"{out['failed']} failed, {out['skipped']} skipped ({out['total']} checks)")
    reasons = sorted({r.get("reason", "") for r in out["results"] if r.get("skipped")})
    if reasons:
        line += "\n  skipped because: " + "; ".join(r for r in reasons if r)
    return line


def main() -> int:
    ap = argparse.ArgumentParser(description="SIGIL/1 conformance suite")
    ap.add_argument("--offline", action="store_true",
                    help="run only library checks (no services, no containers)")
    ap.add_argument("--json", dest="json_path", default=os.environ.get("SIGIL_CONFORMANCE_REPORT", ""),
                    help="write the JSON report here")
    ap.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args()
    out = run_offline(verbose=not a.quiet) if a.offline else run(verbose=not a.quiet)
    print("\n" + format_summary(out))
    if a.json_path:
        p = os.path.abspath(a.json_path)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print("report:", p)
    return 0 if out["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
