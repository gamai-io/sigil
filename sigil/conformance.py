from __future__ import annotations
import base64, copy, json, os, shutil, subprocess, time
import httpx, rfc8785
from sigil import common as C

GATE = "http://127.0.0.1:18100"
VERIFY = "http://127.0.0.1:18101"
ANCHOR = "http://127.0.0.1:18102"
EFFECTS = "/tmp/sigil_lab/effects"
DATA = "/tmp/sigil_lab/data"
def _read_token(env_name: str, default_path: str) -> str:
    """Read an optional lab token; never fail at import time."""
    try:
        return open(os.environ.get(env_name, default_path), encoding="utf-8").read().strip()
    except OSError:
        return ""

CONTROL_TOKEN = _read_token("SIGIL_CONTROL_TOKEN_FILE", "/tmp/sigil_lab/keys/control_token")
APPROVER_TOKEN = _read_token("SIGIL_APPROVER_TOKEN_FILE", "/tmp/sigil_lab/keys/approver_token")
CLIENT = httpx.Client(timeout=15, headers={"X-SIGIL-Token": CONTROL_TOKEN} if CONTROL_TOKEN else {})
ACLIENT = httpx.Client(timeout=15, headers={"X-SIGIL-Token": APPROVER_TOKEN} if APPROVER_TOKEN else {})
RESULTS = []

VERBOSE = True

def check(name, cond, detail=""):
    RESULTS.append({"test": name, "pass": bool(cond), "detail": detail})
    if VERBOSE:
        print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(detail)) if detail and not cond else ""))

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

DOCKER = ["docker","run","-d","--name","sigil-gate","--network","host",
  "--read-only","--tmpfs","/tmp:rw,noexec,nosuid,size=64m","--cap-drop","ALL",
  "--security-opt","no-new-privileges","--user","65534:65534",
  "-v","/tmp/gama_proto_lab/sigil:/sigil:ro","-v","/tmp/gama_proto_lab/deps:/deps:ro",
  "-v","/tmp/sigil_lab/data:/data:rw","-v","/tmp/sigil_lab/effects:/effects:rw",
  "-v","/tmp/sigil_lab/keys/public:/pub:ro","-v","/tmp/sigil_lab/keys/kms/token:/run/sigil-kms-token:ro",
  "-v","/tmp/sigil_lab/keys/control_token:/run/sigil-control-token:ro",
  "-v","/tmp/sigil_lab/keys/approver_token:/run/sigil-approver-token:ro",
  "-v","/tmp/sigil_lab/keys/lease_token:/run/sigil-lease-token:ro",
  "-e","PYTHONPATH=/sigil:/deps","-e","PYTHONDONTWRITEBYTECODE=1","-e","SIGIL_TEST=1",
  "-e","SIGIL_CONTROL_TOKEN_FILE=/run/sigil-control-token",
  "-e","SIGIL_APPROVER_TOKEN_FILE=/run/sigil-approver-token",
  "-e","SIGIL_ALLOW_HMAC=0",
  "-e","SIGIL_KEY_ID=gate-ed25519-1","-e","SIGIL_PUB_DIR=/pub",
  "-e","SIGIL_KMS_URL=http://127.0.0.1:18103","-e","SIGIL_KMS_TOKEN_FILE=/run/sigil-kms-token",
  "-e","SIGIL_LEASE_URLS=http://127.0.0.1:18106,http://127.0.0.1:18107,http://127.0.0.1:18108",
  "-e","SIGIL_LEASE_QUORUM=2","-e","SIGIL_LEASE_TOKEN_FILE=/run/sigil-lease-token",
  "-e","SIGIL_LEASE_HOLDER=gate-primary","-e","SIGIL_LEASE_PUB=/pub/lease_public.pem",
  "python:3.12-slim","python","-m","sigil.gate"]

def start_gate(crash=False):
    subprocess.run(["docker","rm","-f","sigil-gate"], capture_output=True)
    cmd = list(DOCKER)
    if crash:
        idx = cmd.index("python:3.12-slim")
        cmd[idx:idx] = ["-e","SIGIL_CRASH_AFTER_EFFECT=1"]
    subprocess.run(cmd, capture_output=True)
    assert wait_health(GATE), "gate did not start"

VERBOSE = True

def run(verbose: bool = True) -> dict:
    global RESULTS, VERBOSE
    RESULTS = []
    VERBOSE = verbose
    # 1 canonical
    obj = {"b": 1, "a": "č", "n": 1.0}
    r = CLIENT.post(VERIFY + "/canonical", json={"obj": obj}).json()
    check("1 canonical.jcs", r["canonical"] == rfc8785.dumps(obj).decode() and r["sha256"] == __import__("hashlib").sha256(rfc8785.dumps(obj)).hexdigest(), r)

    # 2 intent hash cross-transport envelopes
    intent = {"id":"i1","op":"echo","args":{"text":"zdravo"},"contract":{"id":"echo/v1","version":"1"}}
    envs = [
     {"transport":"mcp","params":{"_meta":{"sigil":{"intent":intent}}}},
     {"transport":"a2a","message":{"metadata":{"sigil":{"intent":intent}}}},
     {"transport":"http","header":{"sigil":{"intent":intent}}},
    ]
    hs = [CLIENT.post(VERIFY + "/canonical", json={"obj": e["params"]["_meta"]["sigil"]["intent"] if "params" in e else e["message"]["metadata"]["sigil"]["intent"] if "message" in e else e["header"]["sigil"]["intent"]}).json()["sha256"] for e in envs]
    check("2 det.intent_hash.cross_transport", len(set(hs)) == 1, hs)

    # 3 route hash reproducible / sensitive
    r1 = CLIENT.post(GATE + "/route", json={"intent": intent}).json()
    r2 = CLIENT.post(GATE + "/route", json={"intent": intent}).json()
    bad = CLIENT.post(GATE + "/route", json={"intent": {"op":"rm_rf","args":{}}}).json()
    check("3 det.route_hash.reproducible", r1["route_hash"] == r2["route_hash"] and r1["route_hash"] != bad["route_hash"], [r1["route_hash"], r2["route_hash"], bad["route_hash"]])

    # 4 strict rejects non-deterministic executor
    reset()
    si = {"id":"strict","op":"echo","args":{"text":"x"},"executor":"llm","determinism":{"mode":"strict"}}
    sg = grant(si)
    sr = execute(si, sg, "strict-1")
    check("4 det.strict_mode.rejects_nondet", sr.status_code == 422 and expect_error(sr, "E_CONTRACT_VIOLATION") and chain()["count"] == 0, sr.text)

    # 5 idempotency same key same effect
    reset()
    ii = {"id":"inc","op":"increment_counter","args":{"path":"counter.txt"}}
    ig = grant(ii)
    e1 = execute(ii, ig, "idem-1").json()
    e2 = execute(ii, ig, "idem-1").json()
    counter = open(os.path.join(EFFECTS, "counter.txt")).read() if os.path.exists(os.path.join(EFFECTS, "counter.txt")) else None
    check("5 idem.same_key_same_effect", counter == "1" and e2.get("replayed") is True and chain()["count"] == 1, {"counter":counter,"e2":e2})

    # 6 idempotency conflict
    i2 = {"id":"inc2","op":"increment_counter","args":{"path":"counter2.txt"}}
    g2 = grant(i2)
    c = execute(i2, g2, "idem-1")
    check("6 idem.conflict_on_payload_change", c.status_code == 409 and expect_error(c, "E_IDEMPOTENCY_CONFLICT") and not os.path.exists(os.path.join(EFFECTS,"counter2.txt")), c.text)

    # 7 crash recovery (kill gate after effect, restart, no double apply)
    reset()
    ci = {"id":"crash","op":"increment_counter","args":{"path":"crash.txt"}}
    cg = grant(ci)
    start_gate(crash=True)
    try:
        CLIENT.post(GATE + "/execute", json={"intent":ci,"grant":cg,"idem_key":"crash-1"})
    except Exception:
        pass
    time.sleep(1)
    val_after_crash = open(os.path.join(EFFECTS,"crash.txt")).read() if os.path.exists(os.path.join(EFFECTS,"crash.txt")) else None
    start_gate(crash=False)
    rr = execute(ci, cg, "crash-1").json()
    val_after_recover = open(os.path.join(EFFECTS,"crash.txt")).read() if os.path.exists(os.path.join(EFFECTS,"crash.txt")) else None
    rec = rr.get("receipt", {})
    check("7 idem.crash_recovery_no_double_apply", val_after_crash == "1" and val_after_recover == "1" and rec.get("recovered") is True and chain()["count"] == 1, {"after_crash":val_after_crash,"after_recover":val_after_recover,"receipt":rec})

    # 8 replay record equivalence
    reset()
    ri = {"id":"replay","op":"echo","args":{"text":"zdravo"}}
    rg = grant(ri)
    rr = execute(ri, rg, "replay-1").json()
    ok1 = CLIENT.post(VERIFY + "/replay", json={"receipt": rr["receipt"], "recorded": {"result": rr["result"]}}).json()
    ok2 = CLIENT.post(VERIFY + "/replay", json={"receipt": rr["receipt"], "recorded": {"result": {"echo":"evil"}}}).json()
    check("8 replay.record_replay_equivalence", ok1["equal"] is True and ok2["equal"] is False, [ok1, ok2])

    # 9 tamper detection
    tampered = copy.deepcopy(rr["receipt"]); tampered["result"]["echo"] = "evil"
    v = CLIENT.post(VERIFY + "/verify", json={"receipt": tampered}).json()
    check("9 replay.tamper_detected", v["valid"] is False and "E_RESULT_DIGEST" in v["errors"], v)

    # 10 chain truncation
    reset()
    gi = {"id":"chain","op":"echo","args":{"text":"x"}}
    gg = grant(gi)
    for k in ("c1","c2","c3"):
        execute(gi, gg, k)
    rows = chain()["receipts"]
    recs = [json.loads(r["receipt_json"]) for r in rows]
    trunc = [recs[0], recs[2]] if len(recs) == 3 else recs
    vt = CLIENT.post(VERIFY + "/verify", json={"receipt": recs[-1], "chain": trunc}).json()
    check("10 replay.chain_truncation_detected", len(recs) == 3 and vt["valid"] is False, {"len":len(recs),"verify":vt})

    # 11 anchor binding
    reset()
    ai = {"id":"anchor","op":"echo","args":{"text":"x"}}
    ag = grant(ai)
    ar = execute(ai, ag, "anchor-1").json()
    tok = anchor_root(ar["receipt_hash"]).json()["anchor"]
    va = CLIENT.post(ANCHOR + "/verify", json={"anchor": tok}).json()
    bad = copy.deepcopy(tok); bad["root"] = "0"*64
    vb = CLIENT.post(ANCHOR + "/verify", json={"anchor": bad}).json()
    vr = CLIENT.post(VERIFY + "/verify", json={"receipt": ar["receipt"], "anchor": tok}).json()
    check("11 replay.anchor_binding", va["valid"] and not vb["valid"] and vr["valid"], {"ok":va,"tampered":vb,"receipt":vr})

    # 12 policy deny fail-closed
    reset()
    di = {"id":"deny","op":"rm_rf","args":{"path":"/"}}
    dg = grant(di, [{"id":"rm_rf","constraints":{}}]) if False else {"grant_id":"none"}
    dr = execute(di, dg, "deny-1")
    dj = dr.json()
    check("12 policy.deny_fail_closed", dr.status_code == 403 and dj["receipt"]["status"] == "denied" and dj["receipt"]["effects"] == [] and chain()["count"] == 1, dr.text)

    # 13 approval bound to intent
    reset()
    ia = {"id":"wa","op":"write_file","args":{"path":"ok/a.txt","content":"A"}}
    ga = grant(ia, [{"id":"write_file","constraints":{"path_prefix":"/ok"}}])
    aa = approve(ia)
    ra = execute(ia, ga, "wa-1", approval=aa)
    ib = {"id":"wb","op":"write_file","args":{"path":"ok/a.txt","content":"B"}}
    gb = grant(ib, [{"id":"write_file","constraints":{"path_prefix":"/ok"}}])
    rb = execute(ib, gb, "wb-1", approval=aa)
    content = open(os.path.join(EFFECTS,"ok/a.txt")).read() if os.path.exists(os.path.join(EFFECTS,"ok/a.txt")) else None
    check("13 policy.approval_bound_to_intent", ra.status_code == 200 and rb.status_code == 403 and expect_error(rb,"E_APPROVAL_INVALID") and content == "A", {"ra":ra.status_code,"rb":rb.text,"content":content})

    # 14 capability scope
    reset()
    ie = {"id":"evil","op":"write_file","args":{"path":"evil/x.txt","content":"X"}}
    ge = grant(ie, [{"id":"write_file","constraints":{"path_prefix":"/ok"}}])
    ae = approve(ie)
    re_ = execute(ie, ge, "evil-1", approval=ae)
    check("14 policy.capability_scope", re_.status_code == 403 and expect_error(re_,"E_CAPABILITY_SCOPE") and not os.path.exists(os.path.join(EFFECTS,"evil/x.txt")), re_.text)

    # 15 cross-transport observable equivalence
    reset()
    xi = {"id":"xt","op":"echo","args":{"text":"zdravo"}}
    xg = grant(xi)
    outs = [execute(xi, xg, "xt-"+t, transport=t).json() for t in ("mcp","a2a","http")]
    fields = [(o["receipt"]["intent_hash"], o["receipt"]["route_hash"], o["receipt"]["result_digest"]) for o in outs]
    ver = [CLIENT.post(VERIFY + "/verify", json={"receipt": o["receipt"], "intent": xi}).json()["valid"] for o in outs]
    check("15 xtransport.observable_equivalence", len(set(fields)) == 1 and all(ver) and chain()["count"] == 3, {"fields":fields,"verify":ver})


    # 16 Ed25519 signatures
    reset()
    ei = {"id":"ed","op":"echo","args":{"text":"ed25519"}}
    eg = grant(ei)
    er = execute(ei, eg, "ed-1").json()
    ev = CLIENT.post(VERIFY + "/verify", json={"receipt": er["receipt"]}).json()
    bad_sig = copy.deepcopy(er["receipt"]); v = bad_sig["sig"]["value"]; bad_sig["sig"]["value"] = ("B" if v[0] != "B" else "C") + v[1:]
    bv = CLIENT.post(VERIFY + "/verify", json={"receipt": bad_sig}).json()
    check("16 sig.ed25519", er["receipt"]["sig"]["alg"] == "ed25519" and ev["valid"] and not bv["valid"], {"alg":er["receipt"]["sig"]["alg"],"verify":ev,"tampered":bv})

    # 17 remote anchor (Oracle)
    reset()
    ri2 = {"id":"remote","op":"echo","args":{"text":"remote"}}
    rg2 = grant(ri2)
    rr2 = execute(ri2, rg2, "remote-1").json()
    ra = anchor_root(rr2["receipt_hash"]).json()["anchor"]
    rav = CLIENT.post(ANCHOR + "/verify", json={"anchor": ra}).json()
    bad_remote = copy.deepcopy(ra); bad_remote["remote"]["root"] = "0"*64
    brv = CLIENT.post(ANCHOR + "/verify", json={"anchor": bad_remote}).json()
    check("17 anchor.remote_anchor", ra.get("remote",{}).get("node") == "remote" and rav.get("remote") is True and brv["valid"] is False and brv.get("remote") is False, {"remote":ra.get("remote",{}).get("node"),"verify":rav,"tampered":brv})

    # 18 MCP middleware (tools/call gets SIGIL receipt)
    reset()
    PROXY = "http://127.0.0.1:18110"
    init = CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"lab","version":"0"}}}, headers={"Accept":"application/json, text/event-stream"})
    sid = init.headers.get("mcp-session-id") or init.headers.get("MCP-Session-Id")
    CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","method":"notifications/initialized"}, headers={"mcp-session-id": sid})
    call = CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"zdravo"}}}, headers={"mcp-session-id": sid}).json()
    mrec = call.get("result",{}).get("_meta",{}).get("sigil",{}).get("receipt")
    mv = CLIENT.post(VERIFY + "/verify", json={"receipt": mrec}).json() if mrec else {"valid":False}
    check("18 mcp.middleware_receipt", bool(sid) and mrec and mrec["sig"]["alg"]=="ed25519" and mv["valid"], {"sid":sid,"has_receipt":bool(mrec),"verify":mv})

    # 19 A2A metadata extension
    reset()
    card = CLIENT.get("http://127.0.0.1:18082/.well-known/agent-card.json").json()
    exts = [e.get("uri") for e in card.get("capabilities",{}).get("extensions",[])]
    msg = CLIENT.post("http://127.0.0.1:18082/", json={"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"a2a-c19","role":"ROLE_USER","parts":[{"text":"zdravo"}]}}}, headers={"A2A-Version":"1.0"}).json()["result"]["message"]
    arec = msg.get("metadata",{}).get("sigil",{}).get("receipt")
    av = CLIENT.post(VERIFY + "/verify", json={"receipt": arec}).json() if arec else {"valid":False}
    check("19 a2a.metadata_extension", "https://sigil.dev/1" in exts and bool(arec) and arec["sig"]["alg"]=="ed25519" and av["valid"], {"ext":exts,"verify":av})


    # 20 RFC3161 timestamp token (local TSA)
    reset()
    ti = {"id":"tsa","op":"echo","args":{"text":"tsa"}}
    tg = grant(ti)
    tr = execute(ti, tg, "tsa-1").json()
    ta = anchor_root(tr["receipt_hash"]).json()["anchor"]
    tv = CLIENT.post(ANCHOR + "/verify", json={"anchor": ta}).json()
    bad_tsa = copy.deepcopy(ta); bad_tsa["rfc3161"]["token_b64"] = "AAAA"
    btv = CLIENT.post(ANCHOR + "/verify", json={"anchor": bad_tsa}).json()
    check("20 anchor.rfc3161", "rfc3161" in ta and tv.get("rfc3161") is True and btv.get("rfc3161") is False, {"has": "rfc3161" in ta, "verify":tv, "tampered":btv})

    # 21 key isolation
    def dexists(container, path):
        return subprocess.run(["docker","exec",container,"test","-e",path], capture_output=True).returncode == 0
    gate_priv = dexists("sigil-gate", "/keys/ed25519_private.pem")
    anchor_priv = dexists("sigil-anchor", "/keys/ed25519_private.pem")
    verify_priv = dexists("sigil-verify", "/keys/ed25519_private.pem")
    kms_gate = dexists("sigil-kms", "/kms/gate-ed25519-1.pem")
    kms_anchor = dexists("sigil-kms", "/kms/anchor-ed25519-1.pem")
    check("21 keys.isolation", (not gate_priv) and (not anchor_priv) and (not verify_priv) and kms_gate and kms_anchor
          and tr["receipt"]["sig"]["key_id"] == "gate-ed25519-1"
          and ta["sig"]["key_id"] == "anchor-ed25519-1",
          {"gate":gate_priv,"anchor":anchor_priv,"verify":verify_priv,
           "kms_gate":kms_gate,"kms_anchor":kms_anchor,
           "receipt_key":tr["receipt"]["sig"]["key_id"],"anchor_key":ta["sig"]["key_id"]})

    # 22 MCP resources/read receipt
    reset()
    PROXY = "http://127.0.0.1:18110"
    init = CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"lab","version":"0"}}}, headers={"Accept":"application/json, text/event-stream"})
    sid = init.headers.get("mcp-session-id") or init.headers.get("MCP-Session-Id")
    CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","method":"notifications/initialized"}, headers={"mcp-session-id": sid})
    rr = CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"lab://info"}}, headers={"mcp-session-id": sid}).json()
    rrec = rr.get("result",{}).get("_meta",{}).get("sigil",{}).get("receipt")
    rv = CLIENT.post(VERIFY + "/verify", json={"receipt": rrec}).json() if rrec else {"valid":False}
    check("22 mcp.resources_receipt", bool(rrec) and rrec["effects"][0]["kind"]=="mcp.resources.read" and rv["valid"], {"has":bool(rrec),"verify":rv})

    # 23 MCP prompts/get receipt
    pr = CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"lab_prompt","arguments":{"topic":"sigil"}}}, headers={"mcp-session-id": sid}).json()
    prec = pr.get("result",{}).get("_meta",{}).get("sigil",{}).get("receipt")
    pv = CLIENT.post(VERIFY + "/verify", json={"receipt": prec}).json() if prec else {"valid":False}
    check("23 mcp.prompts_receipt", bool(prec) and prec["effects"][0]["kind"]=="mcp.prompts.get" and pv["valid"], {"has":bool(prec),"verify":pv})


    # 24 public RFC3161 TSA
    reset()
    pi = {"id":"pubtsa","op":"echo","args":{"text":"pub"}}
    pg = grant(pi)
    pr = execute(pi, pg, "pubtsa-1").json()
    pa = anchor_root(pr["receipt_hash"]).json()["anchor"]
    pv = CLIENT.post(ANCHOR + "/verify", json={"anchor": pa}).json()
    check("24 anchor.public_rfc3161", pa.get("rfc3161",{}).get("mode") == "public" and pv.get("rfc3161") is True, {"tsa":pa.get("rfc3161",{}).get("mode"),"verify":pv})

    # 25 SQLite hot-standby replica + read failover
    reset()
    ri3 = {"id":"replica","op":"echo","args":{"text":"replica"}}
    rg3 = grant(ri3)
    for k in ("rep-1","rep-2","rep-3"):
        execute(ri3, rg3, k)
    root_before = chain()["root"] if chain().get("root") else None
    # chain() returns count+receipts; use /chain/verify
    CLIENT.post("http://127.0.0.1:18104/debug/reset")
    gv = CLIENT.get(GATE + "/chain/verify").json()
    rep = CLIENT.post("http://127.0.0.1:18104/sync").json()
    rst = CLIENT.get("http://127.0.0.1:18104/status").json()
    rv = CLIENT.post("http://127.0.0.1:18104/verify").json()
    subprocess.run(["docker","stop","sigil-gate"], capture_output=True)
    time.sleep(2)
    down = CLIENT.get("http://127.0.0.1:18104/receipts").json()
    dv = CLIENT.post("http://127.0.0.1:18104/verify").json()
    start_gate(crash=False)
    gate_after = CLIENT.get(GATE + "/chain/verify").json()
    check("25 replica.hot_standby",
          rep["ok"] and rst["count"] == 3 and rst["root"] == gv["root"] and rv["valid"]
          and down["count"] == 3 and dv["valid"] and gate_after["count"] == 3,
          {"sync":rep,"status":rst,"down_count":down["count"],"gate_after":gate_after["count"]})
    

    # 26 replica auto-sync scheduler
    reset()
    CLIENT.post("http://127.0.0.1:18104/debug/reset")
    ai3 = {"id":"autosync","op":"echo","args":{"text":"auto"}}
    ag3 = grant(ai3)
    for k in ("auto-1","auto-2","auto-3"):
        execute(ai3, ag3, k)
    gv2 = CLIENT.get(GATE + "/chain/verify").json()
    auto_ok = False; auto_st = {}
    for _ in range(40):
        auto_st = CLIENT.get("http://127.0.0.1:18104/status").json()
        if auto_st.get("count") == 3 and auto_st.get("root") == gv2["root"] and auto_st.get("valid"):
            auto_ok = True; break
        time.sleep(0.5)
    check("26 replica.auto_sync", auto_ok, {"status":auto_st,"gate_root":gv2.get("root")})

    # 27 write failover with hot-standby gate (same SQLite, single active writer)
    wait_lease()
    reset()
    wi = {"id":"failover","op":"echo","args":{"text":"failover"}}
    wg = grant(wi)
    r1 = execute(wi, wg, "fo-1").json()
    before = CLIENT.get(GATE + "/chain/verify").json()["count"]
    sb = list(DOCKER)
    sb[sb.index("sigil-gate")] = "sigil-gate-standby"
    sb[sb.index("python") + 0:sb.index("python") + 1] = sb[sb.index("python"):sb.index("python") + 1]
    # replace module command
    sb = [("sigil.standby" if x == "sigil.gate" else ("gate-standby" if x == "gate-primary" else x)) for x in sb]
    subprocess.run(["docker","rm","-f","sigil-gate-standby"], capture_output=True)
    subprocess.run(sb, capture_output=True)
    time.sleep(1)
    subprocess.run(["docker","stop","sigil-gate"], capture_output=True)
    up = False
    for _ in range(40):
        try:
            if CLIENT.get(GATE + "/health").status_code == 200: up = True; break
        except Exception: pass
        time.sleep(0.5)
    wg2 = grant(wi) if up else None
    wr = execute(wi, wg2, "fo-2").json() if up else {}
    fence_ok = bool(r1.get("receipt",{}).get("lease")) and bool(wr.get("receipt",{}).get("lease")) and wr["receipt"]["lease"]["fencing_token"] > r1["receipt"]["lease"]["fencing_token"]
    during = CLIENT.get(GATE + "/chain/verify").json() if up else {}
    subprocess.run(["docker","rm","-f","sigil-gate-standby"], capture_output=True)
    start_gate(crash=False)
    after = CLIENT.get(GATE + "/chain/verify").json()
    check("27 failover.write_standby", up and before == 1 and during.get("count") == 2
          and after.get("count") == 2 and after.get("ok") is True and fence_ok,
          {"up":up,"before":before,"during":during.get("count"),"after":after.get("count"),"fence":fence_ok})


    # 28 lease witness / fencing token
    reset()
    li = {"id":"lease28","op":"echo","args":{"text":"lease"}}
    lg = grant(li)
    lr = execute(li, lg, "lease28-1").json()
    lst = CLIENT.get("http://127.0.0.1:18106/status").json()
    lt = lr.get("receipt",{}).get("lease",{})
    check("28 lease.fencing_token",
          lt.get("holder") == "gate-primary" and lt.get("fencing_token",0) >= lst.get("fencing",0)
          and lt.get("quorum",{}).get("acquired",0) >= 2,
          {"receipt_lease":lt,"witness":lst})


    # 29 quorum lease: survive one witness loss, fail with only one
    reset()
    qi = {"id":"quorum","op":"echo","args":{"text":"quorum"}}
    qg = grant(qi)
    q1 = execute(qi, qg, "q-1")
    subprocess.run(["docker","stop","sigil-w2"], capture_output=True)
    time.sleep(3)
    q2 = execute(qi, qg, "q-2")
    subprocess.run(["docker","stop","sigil-w3"], capture_output=True)
    time.sleep(9)
    q3 = execute(qi, qg, "q-3")
    subprocess.run(["docker","start","sigil-w2","sigil-w3"], capture_output=True)
    time.sleep(2)
    q4 = execute(qi, qg, "q-4")
    check("29 lease.quorum",
          q1.status_code == 200 and q2.status_code == 200
          and q3.status_code == 503 and expect_error(q3, "E_LEASE_LOST")
          and q4.status_code == 200,
          {"q1":q1.status_code,"q2":q2.status_code,"q3":q3.status_code,"q4":q4.status_code})


    # 30 P-256 cloud-KMS-compatible signature backend
    from sigil import common as _C
    from sigil.kms_backends import P256FileKMS
    kms = P256FileKMS("/tmp/sigil_lab/keys/p256/private.pem")
    payload = {"op": "cloud-kms", "n": 1}
    sig = kms.sign(_C.canon(payload))
    pub = "/tmp/sigil_lab/keys/public/p256_cloud_public.pem"
    good = _C.verify_sig(payload, sig, pub)
    badsig = dict(sig); badsig["value"] = "A" + sig["value"][1:]
    bad = _C.verify_sig(payload, badsig, pub)
    check("30 kms.p256_cloud_compatible", sig["alg"] == "ecdsa-p256-sha256" and good and not bad,
          {"alg":sig["alg"],"good":good,"bad":bad})

    # 31 control-plane auth
    reset()
    anon = httpx.Client(timeout=10)
    ai = {"id":"auth","op":"echo","args":{"text":"x"}}
    ra = anon.post(GATE + "/grant", json={"intent": ai})
    rb = anon.post(GATE + "/approve", json={"intent": ai})
    rc = anon.post(GATE + "/route", json={"intent": ai})
    rd = anon.post(GATE + "/execute", json={"intent": ai, "grant": {}, "idem_key": "auth-1"})
    re_ = anon.post(GATE + "/record", json={"intent": ai, "grant": {}, "idem_key": "auth-2", "result": {}})
    rf = anon.post(GATE + "/debug/reset")
    ok = all(x.status_code == 401 and x.json().get("error",{}).get("code") == "E_UNAUTHENTICATED"
             for x in (ra, rb, rc, rd, re_, rf))
    ga = grant(ai)
    aa = approve(ai)
    check("31 auth.control_plane_required", ok and bool(ga) and bool(aa), {"codes":[x.status_code for x in (ra,rb,rc,rd,re_,rf)]})

    # 32 grant max_uses exhausted
    reset()
    mi = {"id":"maxuses","op":"echo","args":{"text":"x"}}
    mg = grant(mi, max_uses=1)
    m1 = execute(mi, mg, "max-1")
    m2 = execute(mi, mg, "max-2")
    check("32 grant.max_uses_exhausted",
          m1.status_code == 200 and m2.status_code == 403
          and expect_error(m2, "E_GRANT_EXHAUSTED") and chain()["count"] == 1,
          {"m1":m1.status_code,"m2":m2.text,"count":chain()["count"]})

    # 33 segment-safe path prefix
    reset()
    pi = {"id":"okevil","op":"write_file","args":{"path":"okevil/x.txt","content":"X"}}
    pg = grant(pi, [{"id":"write_file","constraints":{"path_prefix":"/ok"}}])
    pa = approve(pi)
    pr = execute(pi, pg, "okevil-1", approval=pa)
    check("33 policy.path_prefix_segment_safe",
          pr.status_code == 403 and expect_error(pr, "E_CAPABILITY_SCOPE")
          and not os.path.exists(os.path.join(EFFECTS, "okevil/x.txt")), pr.text)

    # 34 concurrent idempotency: one effect
    reset()
    ci = {"id":"conc","op":"increment_counter","args":{"path":"conc.txt"}}
    cg = grant(ci)
    import concurrent.futures as _cf
    def _run(k):
        return execute(ci, cg, "conc-1").status_code
    with _cf.ThreadPoolExecutor(max_workers=2) as ex:
        codes = sorted(ex.map(_run, (1, 2)))
    val = open(os.path.join(EFFECTS, "conc.txt")).read() if os.path.exists(os.path.join(EFFECTS,"conc.txt")) else None
    check("34 idem.concurrent_same_key",
          codes[0] == 200 and codes[1] in (200, 409) and val == "1" and chain()["count"] == 1,
          {"codes":codes,"value":val,"count":chain()["count"]})

    # 35 approval single-use under a second execute
    reset()
    ui = {"id":"approval-use","op":"write_file","args":{"path":"ok/u.txt","content":"U"}}
    ug = grant(ui, [{"id":"write_file","constraints":{"path_prefix":"/ok"}}], max_uses=5)
    ua = approve(ui)
    u1 = execute(ui, ug, "use-1", approval=ua)
    u2 = execute(ui, ug, "use-2", approval=ua)
    check("35 policy.approval_single_use",
          u1.status_code == 200 and u2.status_code == 403
          and expect_error(u2, "E_APPROVAL_INVALID"),
          {"u1":u1.status_code,"u2":u2.text})

    # 36 legacy HMAC downgrade rejected
    reset()
    hi = {"id":"hmac","op":"echo","args":{"text":"hmac"}}
    hg = grant(hi)
    hr = execute(hi, hg, "hmac-1").json()
    forged = copy.deepcopy(hr["receipt"])
    forged["sig"] = {"alg":"hmac-sha256", "key_id":"lab-hmac-1", "value":"00"*32}
    hv = CLIENT.post(VERIFY + "/verify", json={"receipt": forged}).json()
    check("36 sig.hmac_downgrade_rejected", hv["valid"] is False, hv)

    # 37 authorize denies before any effect
    reset()
    di = {"id":"az-deny","op":"rm_rf","args":{"path":"/"}}
    da = CLIENT.post(GATE + "/authorize", json={"intent": di, "grant": {"grant_id":"none"},
                                                "idem_key":"az-deny-1"})
    dd = da.json()
    check("37 authorize.deny_before_effect",
          da.status_code == 403 and dd.get("receipt",{}).get("status") == "denied"
          and dd.get("receipt",{}).get("effects") == [] and chain()["count"] == 1, da.text)

    # 38 authorize claim then record
    reset()
    ai2 = {"id":"az-ok","op":"echo","args":{"text":"claim"}}
    ag2 = grant(ai2)
    az = CLIENT.post(GATE + "/authorize", json={"intent": ai2, "grant": ag2, "idem_key":"az-ok-1"})
    azd = az.json()
    rec = CLIENT.post(GATE + "/record", json={"claim_id": azd.get("claim_id"), "intent": ai2,
                                              "grant": ag2, "idem_key":"az-ok-1",
                                              "result":{"echo":"claim"}}).json()
    rec2 = CLIENT.post(GATE + "/record", json={"claim_id": azd.get("claim_id"), "intent": ai2,
                                               "grant": ag2, "idem_key":"az-ok-1",
                                               "result":{"echo":"claim"}}).json()
    check("38 authorize.claim_then_record",
          az.status_code == 200 and azd.get("authorized") is True
          and "receipt" in rec and rec2.get("replayed") is True and chain()["count"] == 1,
          {"az":az.text,"rec":rec,"rec2":rec2})

    # 39 MCP preflight denies destructive tool before upstream
    reset()
    PROXY = "http://127.0.0.1:18110"
    init = CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"lab","version":"0"}}},
        headers={"Accept":"application/json, text/event-stream"})
    sid = init.headers.get("mcp-session-id") or init.headers.get("MCP-Session-id")
    CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","method":"notifications/initialized"},
                headers={"mcp-session-id": sid})
    bad = CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","id":2,"method":"tools/call",
        "params":{"name":"drop_table","arguments":{}}}, headers={"mcp-session-id": sid}).json()
    brec = bad.get("error",{}).get("data",{}).get("sigil",{}).get("receipt",{})
    check("39 mcp.preflight_deny_before_effect",
          bad.get("error",{}).get("code") == -32002 and brec.get("status") == "denied"
          and chain()["count"] == 1, bad)

    # 40 fencing token survives witness restart
    s1 = CLIENT.get("http://127.0.0.1:18107/status").json()
    subprocess.run(["docker", "restart", "sigil-w2"], capture_output=True)
    s2 = {}
    for _ in range(20):
        try:
            s2 = CLIENT.get("http://127.0.0.1:18107/status").json()
            break
        except Exception:
            time.sleep(0.5)
    check("40 lease.fencing_persist",
          s1.get("fencing", 0) > 0 and s2.get("fencing", 0) >= s1.get("fencing", 0),
          {"before": s1, "after": s2})

    # 41 anchor refuses a root that is not the gate chain root
    reset()
    ai3 = {"id":"anchor-bad","op":"echo","args":{"text":"anchor"}}
    ag3 = grant(ai3)
    ar3 = execute(ai3, ag3, "anchor-bad-1").json()
    bad_anchor = anchor_root("0"*64)
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
    pi = {"id":"proof","op":"echo","args":{"text":"proof"}}
    pg = grant(pi)
    p1 = execute(pi, pg, "proof-1").json()
    execute(pi, pg, "proof-2")
    execute(pi, pg, "proof-3")
    proof = CLIENT.get(GATE + "/chain/proof/" + p1["receipt_hash"]).json()
    pv = CLIENT.post(VERIFY + "/proof", json={"proof": proof}).json()
    bad = copy.deepcopy(proof)
    bad["receipts"][0]["result"] = {"echo":"tampered"}
    bv = CLIENT.post(VERIFY + "/proof", json={"proof": bad}).json()
    check("43 chain.suffix_inclusion_proof",
          pv.get("valid") is True and bv.get("valid") is False
          and proof.get("root") == chain()["receipts"][-1]["receipt_hash"],
          {"proof": {k: proof.get(k) for k in ("receipt_hash","root","count")},
           "valid": pv, "tampered": bv})

    # 44 context/handoff GC
    import time as _time
    cr = CLIENT.post("http://127.0.0.1:18120/ctx/ingest",
                     json={"entries": [{"k":"gc:1","text":"prune-me"}]}).json()
    cid = cr["ctx_id"]
    man = CLIENT.post("http://127.0.0.1:18120/handoff",
                      json={"from_session":"gc","ctx_id":cid,"ttl_ms":60000}).json()["handoff"]
    hid = man["handoff_id"]
    mpath = os.path.join(DATA, "ctx", "manifests", cid[5:] + ".json")
    b = cr["manifest"]["entries"][0]["b"]
    bpath = os.path.join(DATA, "ctx", "blobs", b[7:])
    hpath = os.path.join(DATA, "handoffs", hid[4:] + ".json")
    old = _time.time() - 3600
    for p in (mpath, bpath, hpath):
        if os.path.exists(p): os.utime(p, (old, old))
    pr = CLIENT.post("http://127.0.0.1:18120/prune", json={"max_age_ms":1000}).json()
    gone = CLIENT.get("http://127.0.0.1:18120/ctx/" + cid).status_code == 404
    hgone = CLIENT.get("http://127.0.0.1:18120/handoff/" + hid).status_code == 404
    check("44 ctx.gc_prune",
          pr.get("ctx",{}).get("manifests",0) >= 1 and pr.get("handoff",{}).get("handoffs",0) >= 1
          and gone and hgone, {"prune":pr,"ctx_gone":gone,"handoff_gone":hgone})

    # 45 MCP tool schema binding rejects wrong arguments before effect
    reset()
    PROXY = "http://127.0.0.1:18110"
    init = CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"lab","version":"0"}}},
        headers={"Accept":"application/json, text/event-stream"})
    sid = init.headers.get("mcp-session-id") or init.headers.get("MCP-Session-id")
    CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","method":"notifications/initialized"},
                headers={"mcp-session-id": sid})
    bad_schema = CLIENT.post(PROXY + "/mcp", json={"jsonrpc":"2.0","id":2,"method":"tools/call",
        "params":{"name":"echo","arguments":{"wrong":1}}}, headers={"mcp-session-id": sid}).json()
    check("45 mcp.tool_schema_binding",
          bad_schema.get("error",{}).get("code") == -32602
          and bad_schema.get("error",{}).get("data",{}).get("sigil",{}).get("code") == "E_TOOL_SCHEMA"
          and chain()["count"] == 0, bad_schema)

    # 46 independent fixed vectors
    from sigil import vector_check
    vc = vector_check.run(verbose=False)
    check("46 vectors.independent", vc["passed"] == vc["total"] and vc["total"] >= 13,
          vc)

    # 47 key rotation: new key id signs, old receipts still verify
    from sigil.kms_rotate import rotate
    kms_dir = "/tmp/sigil_lab/keys/kms"
    pub_dir = "/tmp/sigil_lab/keys/public"
    kid = "gate-ed25519-2"
    for p in (os.path.join(kms_dir, kid + ".pem"),
              os.path.join(pub_dir, kid.replace("-", "_") + "_public.pem")):
        if os.path.exists(p): os.remove(p)
    rot = rotate("gate", kid, kms_dir, pub_dir)
    try:
        os.chown(rot["private"], 65534, 65534)
    except PermissionError:
        pass
    token = open("/tmp/sigil_lab/keys/kms/token").read().strip()
    payload = {"rotation": 1}
    ns = httpx.post("http://127.0.0.1:18103/sign",
                    json={"key_id": kid, "payload_b64": base64.b64encode(C.canon(payload)).decode()},
                    headers={"X-SIGIL-Token": token}, timeout=10).json()
    old = httpx.post("http://127.0.0.1:18103/sign",
                     json={"key_id": "gate-ed25519-1", "payload_b64": base64.b64encode(C.canon(payload)).decode()},
                     headers={"X-SIGIL-Token": token}, timeout=10).json()
    check("47 kms.key_rotation",
          ns.get("key_id") == kid and C.verify_sig(payload, ns, rot["public"])
          and old.get("key_id") == "gate-ed25519-1"
          and C.verify_sig(payload, old, os.path.join(pub_dir, "gate_ed25519_public.pem")),
          {"new": ns.get("key_id"), "old": old.get("key_id")})

    # 48 quorum certificate: receipt carries each witness's signed lease token
    wait_lease()
    qci = {"id":"qcert48","op":"echo","args":{"text":"qcert"}}
    qcg = grant(qci)
    qcr = execute(qci, qcg, "qcert48-1").json()
    ql = qcr.get("receipt", {}).get("lease", {})
    proofs = ql.get("quorum", {}).get("proofs", [])
    pub = "/tmp/sigil_lab/keys/public/lease_public.pem"
    def _pv(p):
        core = {k:v for k,v in p.items() if k != "sig"}
        return C.verify_sig(core, p.get("sig", {}), pub)
    tampered = copy.deepcopy(proofs[0]) if proofs else {}
    if tampered:
        tampered["sig"]["value"] = "A" + tampered["sig"]["value"][1:]
    ok = (len(proofs) >= 2 and all(_pv(p) for p in proofs)
          and all(p.get("holder") == "gate-primary" for p in proofs)
          and max(p.get("fencing_token", 0) for p in proofs) == ql.get("fencing_token"))
    check("48 lease.quorum_certificate",
          ok and bool(tampered) and not C.verify_sig({k:v for k,v in tampered.items() if k != "sig"}, tampered.get("sig", {}), pub),
          {"proofs": len(proofs), "fencing": ql.get("fencing_token")})

    # 49 operational metrics
    m = CLIENT.get(GATE + "/metrics").text
    check("49 ops.metrics",
          "sigil_chain_receipts " in m and "sigil_requests_total " in m
          and "sigil_errors_total " in m and "sigil_lease_valid 1" in m,
          {"sample": m.splitlines()[:6]})

    passed = sum(1 for r in RESULTS if r["pass"])
    return {"passed": passed, "total": len(RESULTS), "results": RESULTS}

def main() -> int:
    out = run(verbose=True)
    print(f"\nSIGIL/1 conformance: {out['passed']}/{out['total']}")
    import json as _json
    _json.dump(out, open("/tmp/gama_proto_lab/evidence/sigil_conformance.json", "w"), ensure_ascii=False, indent=2)
    return 0 if out["passed"] == out["total"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
