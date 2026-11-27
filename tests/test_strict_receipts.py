"""A receipt that another JSON parser reads differently must be refused, not verified."""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from sigil import strictjson
from sigil import verify as verify_mod

CLIENT = TestClient(verify_mod.app)


class Rejections(unittest.TestCase):
    def post(self, raw: bytes):
        return CLIENT.post("/verify", content=raw,
                           headers={"Content-Type": "application/json"}).json()

    def test_duplicate_key_is_refused(self):
        body = self.post(b'{"receipt": {"a": 1, "a": 2}}')
        self.assertFalse(body["valid"])
        self.assertEqual(body["error"]["code"], "E_JSON_DUPLICATE_KEY")

    def test_nan_is_refused(self):
        body = self.post(b'{"receipt": {"a": NaN}}')
        self.assertFalse(body["valid"])
        self.assertEqual(body["error"]["code"], "E_JSON_NON_FINITE")

    def test_big_integer_is_refused(self):
        body = self.post(b'{"receipt": {"a": 12345678901234567890}}')
        self.assertFalse(body["valid"])
        self.assertEqual(body["error"]["code"], "E_JSON_INT_RANGE")

    def test_lone_surrogate_is_refused(self):
        body = self.post(b'{"receipt": {"a": "\\ud800"}}')
        self.assertFalse(body["valid"])
        self.assertEqual(body["error"]["code"], "E_JSON_LONE_SURROGATE")

    def test_ordinary_receipt_still_reaches_the_checks(self):
        body = self.post(b'{"receipt": {"result": 1}}')
        self.assertFalse(body["valid"])            # no signature, but not a JSON refusal
        self.assertNotIn("error", body)


class Module(unittest.TestCase):
    def test_accepts_normal_documents(self):
        self.assertEqual(strictjson.loads_strict('{"a": [1, 2]}'), {"a": [1, 2]})

    def test_depth_limit(self):
        with self.assertRaises(strictjson.StrictJSONError):
            strictjson.loads_strict("[" * 200 + "]" * 200)


if __name__ == "__main__":
    unittest.main()
