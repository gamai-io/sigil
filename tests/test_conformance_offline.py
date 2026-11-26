"""Library-only conformance checks: no ports, containers or key material.

These are the canonicalization/hashing/signing/verification/tamper checks from
the stack suite, re-expressed against the library so they run on every Python
version in CI.  They are numbered O1..O12 and are deliberately *not* counted
as the 49 stack checks (see README for the exact split).
"""
from __future__ import annotations

from sigil import conformance


def test_offline_conformance():
    out = conformance.run_offline(verbose=True)
    print("\n" + conformance.format_summary(out))
    assert out["failed"] == 0, conformance.format_summary(out)
    assert out["skipped"] == 0
    assert out["passed"] == out["total"] == 12
