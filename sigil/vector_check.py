"""Independent fixed vectors for SIGIL/1 (no running services)."""
from __future__ import annotations
import json, os
from . import common as C, ctx

HERE = os.path.dirname(__file__)
VECTORS = os.environ.get("SIGIL_VECTORS", os.path.join(HERE, "vectors.json"))


def _check(case: dict) -> tuple[bool, str]:
    k, inp, exp = case.get("kind"), case.get("input") or {}, case.get("expected") or {}
    if k == "jcs_sha":
        obj = inp.get("obj")
        got = {"canonical": C.canon(obj).decode(), "sha256": C.sha(obj)}
        return got == exp, f"got={got}"
    if k == "policy_hash":
        got = {"sha256": C.sha(inp.get("policy"))}
        return got == exp, f"got={got}"
    if k == "path_prefix":
        got = {"ok": C.within_prefix(inp.get("prefix", ""), inp.get("path", ""))}
        return got == exp, f"got={got}"
    if k == "entry_norm":
        got = {"normalized": ctx.normalize_entry(inp.get("entry") or {})}
        return got == exp, f"got={got}"
    if k == "receipt_hash":
        got = {"sha256": C.receipt_hash(inp.get("receipt") or {})}
        return got == exp, f"got={got}"
    if k == "schema":
        try:
            import jsonschema
            jsonschema.validate(instance=inp.get("args"), schema=inp.get("schema"))
            got = {"ok": True}
        except Exception:
            got = {"ok": False}
        return got == exp, f"got={got}"
    return False, f"unknown kind {k}"


def run(verbose: bool = True) -> dict:
    with open(VECTORS, encoding="utf-8") as f:
        data = json.load(f)
    results = []
    for c in data.get("cases", []):
        try:
            ok, detail = _check(c)
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        results.append({"id": c.get("id"), "pass": ok, "detail": detail})
        if verbose:
            print(("PASS " if ok else "FAIL ") + str(c.get("id")) + ("" if ok else " :: " + detail))
    passed = sum(1 for r in results if r["pass"])
    return {"passed": passed, "total": len(results), "results": results}


def main() -> int:
    out = run(True)
    print(f"SIGIL/1 vectors: {out['passed']}/{out['total']}")
    return 0 if out["passed"] == out["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
