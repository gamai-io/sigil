#!/usr/bin/env python3
"""SIGIL invoice -> ERP demo.

Shows the whole trust path on synthetic data:
invoice math -> capability grant -> idempotent claim -> ERP write -> signed
receipt -> anchor -> independent verify -> replay/tamper checks.

No network, no model, no customer data. Services are started in a temporary
runtime when --start is used; otherwise gate/verify/anchor must already run.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
from decimal import Decimal, ROUND_HALF_UP

ROOT = pathlib.Path(__file__).resolve().parents[1]
INVOICE = {
    "invoice_no": "MOCK-2026-001",
    "supplier": "MOCK DOBAVLJAC DOO",
    "supplier_id": "SUP-001",
    "currency": "BAM",
    "lines": [
        {"name": "Rukavice 600mm", "qty": 4, "unit_price": "12.50"},
        {"name": "Filter 3M", "qty": 2, "unit_price": "7.25"},
    ],
    "net": "64.50",
    "vat_rate": "0.17",
    "vat": "10.97",
    "total": "75.47",
}


def D(v) -> Decimal:
    return Decimal(str(v)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def check_invoice(inv: dict) -> list[str]:
    errors = []
    net = D(0)
    for i, line in enumerate(inv["lines"], 1):
        line_total = D(D(line["qty"]) * D(line["unit_price"]))
        net += line_total
        if "line_total" in line and D(line["line_total"]) != line_total:
            errors.append(f"line {i}: total mismatch")
    net = D(net)
    vat = D(net * D(inv["vat_rate"]))
    total = D(net + vat)
    if D(inv["net"]) != net:
        errors.append(f"net mismatch: invoice {inv['net']} != computed {net}")
    if D(inv["vat"]) != vat:
        errors.append(f"vat mismatch: invoice {inv['vat']} != computed {vat}")
    if D(inv["total"]) != total:
        errors.append(f"total mismatch: invoice {inv['total']} != computed {total}")
    return errors


def wait(url: str, seconds: float = 15.0) -> None:
    import httpx
    end = time.time() + seconds
    while time.time() < end:
        try:
            if httpx.get(url, timeout=0.5).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.15)
    raise RuntimeError(f"service did not start: {url}")


def start_services(tmp: pathlib.Path) -> tuple[list[subprocess.Popen], dict]:
    runtime = tmp / "runtime"
    env0 = dict(os.environ, SIGIL_RUNTIME=str(runtime), SIGIL_RESET="1")
    subprocess.run(["bash", str(ROOT / "deploy" / "init.sh")], env=env0,
                   check=True, capture_output=True)
    base = {
        "SIGIL_DATA": str(runtime / "data"),
        "SIGIL_EFFECTS": str(runtime / "effects"),
        "SIGIL_PUB_DIR": str(runtime / "keys" / "pub"),
        "SIGIL_CONTROL_TOKEN_FILE": str(runtime / "keys" / "control_token"),
        "SIGIL_APPROVER_TOKEN_FILE": str(runtime / "keys" / "approver_token"),
        "SIGIL_CHAIN_ID": "demo-invoice-chain",
        "PYTHONPATH": str(ROOT),
    }
    procs = []
    gate_env = dict(env0, **base)
    gate_env.update({
        "SIGIL_PORT": "18100",
        "SIGIL_PRIV_PATH": str(runtime / "keys" / "kms" / "gate-ed25519-1.pem"),
        "SIGIL_KEY_ID": "gate-ed25519-1",
        "SIGIL_ANCHOR_KEY_ID": "anchor-ed25519-1",
    })
    verify_env = dict(env0, **base)
    verify_env.update({"SIGIL_PORT": "18101"})
    anchor_env = dict(env0, **base)
    anchor_env.update({
        "SIGIL_PORT": "18102",
        "SIGIL_PRIV_PATH": str(runtime / "keys" / "kms" / "anchor-ed25519-1.pem"),
        "SIGIL_KEY_ID": "anchor-ed25519-1",
        "SIGIL_ANCHOR_ALLOW_LOCAL": "1",
        "SIGIL_GATE": "http://127.0.0.1:18100",
    })
    for mod, env, url in [
        ("sigil.gate", gate_env, "http://127.0.0.1:18100/health"),
        ("sigil.verify", verify_env, "http://127.0.0.1:18101/health"),
        ("sigil.anchor", anchor_env, "http://127.0.0.1:18102/health"),
    ]:
        p = subprocess.Popen([sys.executable, "-m", mod], env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p)
        wait(url)
    return procs, base


def run(base: dict | None = None) -> dict:
    from sigil import SigilClient
    from sigil import common as C
    token_file = (base or {}).get("SIGIL_CONTROL_TOKEN_FILE")
    c = SigilClient(control_token_file=token_file or "/run/sigil-control-token")
    errors = check_invoice(INVOICE)
    if errors:
        raise SystemExit("invoice rejected: " + "; ".join(errors))
    print(f"[1] invoice {INVOICE['invoice_no']}: net={INVOICE['net']} vat={INVOICE['vat']} total={INVOICE['total']} -> math ok")

    intent = {
        "id": "inv-" + INVOICE["invoice_no"],
        "op": "mcp.erp.write_invoice",
        "args": {"tool": "erp.write_invoice", "invoice": INVOICE},
        "contract": {"id": "erp.write_invoice/v1", "version": "1"},
        "determinism": {"mode": "best_effort"},
    }
    grant = c.grant(intent, [{"id": "mcp.erp.write_invoice", "constraints": {}}], max_uses=1)
    print(f"[2] grant {grant['grant_id'][:8]} bound to intent, max_uses=1")

    idem = "invoice-" + INVOICE["invoice_no"]
    claim = c._post(c.gate_url + "/authorize",
                    {"intent": intent, "grant": grant, "idem_key": idem})
    print(f"[3] idempotent claim reserved: {claim['claim_id']}")

    erp_dir = pathlib.Path(tempfile.mkdtemp(prefix="sigil-erp-"))
    target = erp_dir / f"{INVOICE['invoice_no']}.json"
    target.write_text(json.dumps(INVOICE, indent=2, ensure_ascii=False))
    print(f"[4] ERP write: {target}")

    effects = [{"kind": "erp.write", "target": str(target),
                "result_digest": C.sha(INVOICE)}]
    result = {"erp_id": INVOICE["invoice_no"], "path": str(target), "total": INVOICE["total"]}
    rec = c._post(c.gate_url + "/record",
                  {"intent": intent, "grant": grant, "idem_key": idem,
                   "claim_id": claim["claim_id"], "result": result, "effects": effects})
    print(f"[5] receipt {rec['receipt_hash'][:16]}… recorded")

    v = c.verify(rec["receipt"])
    print(f"[6] independent verify: valid={v['valid']} errors={v['errors']}")
    anchor = c.anchor_root(rec["receipt_hash"], 1)
    av = c.verify_anchor(anchor)
    print(f"[7] anchor {anchor['anchor_hash'][:16]}… verify={av}")

    replay = c._post(c.gate_url + "/record",
                     {"intent": intent, "grant": grant, "idem_key": idem,
                      "result": result, "effects": effects})
    print(f"[8] same idempotency key -> replayed={replay.get('replayed')} (no second effect)")

    bad = json.loads(json.dumps(rec["receipt"]))
    bad["result"]["total"] = "999.99"
    bv = c.verify(bad)
    print(f"[9] tampered receipt -> valid={bv['valid']} errors={bv['errors']}")
    return {"ok": v["valid"] and av.get("valid") and replay.get("replayed") and not bv["valid"],
            "receipt_hash": rec["receipt_hash"], "anchor": anchor,
            "verify": v, "tampered": bv}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", action="store_true", help="start local services in a temp runtime")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    procs = []
    tmp = None
    try:
        if args.start:
            tmp = pathlib.Path(tempfile.mkdtemp(prefix="sigil-demo-"))
            procs, base = start_services(tmp)
        else:
            base = None
        out = run(base)
        if args.json:
            print(json.dumps(out, indent=2, ensure_ascii=False))
        print("\nRESULT:", "PASS" if out["ok"] else "FAIL")
        return 0 if out["ok"] else 1
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=3)
            except Exception:
                p.kill()
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
