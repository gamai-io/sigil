"""The package version must be the pyproject version."""
from __future__ import annotations

import pathlib
import re
import unittest

from sigil import __version__

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Version(unittest.TestCase):
    def test_matches_pyproject(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        expected = re.search(r'^version = "([^"]+)"', text, re.M).group(1)
        self.assertEqual(__version__, expected)
