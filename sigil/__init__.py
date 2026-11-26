"""SIGIL/1 — proof-carrying execution profile (lab reference implementation)."""
from .client import SigilClient, SigilError

__version__ = "0.22.2"
__all__ = ["SigilClient", "SigilError", "__version__"]
