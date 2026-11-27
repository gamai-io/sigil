"""Strict JSON for anything that gets hashed or signed.

`json.loads` is permissive in ways that make a signature ambiguous:

* `{"a": 1, "a": 2}` parses to `{"a": 2}` — the first value silently disappears, so a
  verifier that canonicalises differently can disagree with the signer about what was
  signed;
* `NaN`, `Infinity` and `-Infinity` are accepted and are not JSON;
* integers beyond 2^53-1 lose precision in every JavaScript verifier;
* a lone surrogate (`"\\ud800"`) survives parsing in Python and crashes or changes bytes
  elsewhere;
* deeply nested input is a cheap way to blow a verifier's stack.

This module refuses all of them before any hash is computed. Same rules as the verifier in
`gama-mandate`; the idea is from Tracekit's `format.canon.loads_strict` (MIT).
"""
from __future__ import annotations

import json
from typing import Any

MAX_DEPTH = 128
MAX_INT = 2 ** 53 - 1


class StrictJSONError(ValueError):
    """The document is not acceptable as signed material."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


def _no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise StrictJSONError("duplicate_key", key)
        obj[key] = value
    return obj


def _no_constants(token: str):
    raise StrictJSONError("non_finite", token)


def _int_guard(token: str):
    digits = token.lstrip("-")
    if len(digits) > 16 or abs(int(token)) > MAX_INT:
        raise StrictJSONError("int_range", token)
    return int(token)


def _walk(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise StrictJSONError("depth", str(depth))
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise StrictJSONError("lone_surrogate", value[:20].encode("unicode_escape").decode()) from None
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError:
                    raise StrictJSONError("lone_surrogate", key[:20].encode("unicode_escape").decode()) from None
            _walk(item, depth + 1)
        return
    if isinstance(value, list):
        for item in value:
            _walk(item, depth + 1)


def loads_strict(text: str | bytes) -> Any:
    """Parse JSON, refusing everything that makes a signature ambiguous."""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError:
            raise StrictJSONError("invalid_utf8") from None
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates,
                           parse_constant=_no_constants, parse_int=_int_guard)
    except StrictJSONError:
        raise
    except json.JSONDecodeError as exc:
        raise StrictJSONError("syntax", str(exc)[:80]) from None
    _walk(value)
    return value


def load_strict(path: str) -> Any:
    with open(path, "rb") as fh:
        return loads_strict(fh.read())
