# ledger/core/types.py
from dataclasses import dataclass, field, asdict
from typing import Literal, Optional
from uuid import uuid4  # temporary fallback — we'll switch to v7 soon

@dataclass(frozen=True)
class Proof:
    """W3C Data Integrity style signature proof (minimal version)."""
    type: str = "Ed25519Signature2020"
    created: str = ""                       # ← add default (will be set during signing)
    verification_method: str = ""           # ← will point to key URI / did / JWK thumbprint
    proof_purpose: str = "assertionMethod"
    proof_value: str = ""                   # base64url encoded Ed25519 sig

@dataclass(frozen=True)
class Message:
    """Single signed entry in the tamper-evident conversation chain."""
    id: str                         # UUIDv7 or similar monotonic
    timestamp: str                  # ISO 8601 UTC with millis
    session_id: str
    sequence: int
    agent_id: str                   # e.g. "agent:claude:inst-xyz"
    agent_role: Literal["user", "assistant", "system", "tool"]
    content: str
    content_type: str = "text/plain"
    prev_hash: str = ""             # hex(sha256) or empty for first message
    proof: Optional[Proof] = None   # None until signed

    def to_dict(self) -> dict:
        """Helper for canonicalization / hashing."""
        d = asdict(self)
        if d["proof"] is None:
            d["proof"] = {}             # empty dict for unsigned messages during tests
        return d