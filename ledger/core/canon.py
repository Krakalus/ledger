# ledger/core/canon.py
import json
from typing import Any

try:
    import jcs
except ImportError:
    raise ImportError("Please install jcs: pip install jcs")

def canonical_json(obj: Any) -> bytes:
    """
    Produce deterministic UTF-8 bytes according to RFC 8785 (JSON Canonicalization Scheme).
    Returns bytes ready for hashing or signing.
    """
    return jcs.canonicalize(obj)


def canonical_json_str(obj: Any) -> str:
    """Same as above, but returns string (mostly for debugging)."""
    return canonical_json(obj).decode("utf-8")