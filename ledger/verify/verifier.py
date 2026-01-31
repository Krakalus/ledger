# ledger/verify/verifier.py
from typing import List, Optional, Dict
from dataclasses import dataclass

from ledger.core.types import Message, Proof
from ledger.core.canon import canonical_json
from ledger.core.encoding import b64url_decode
from ledger.crypto.keys import AgentKeyPair
from ledger.crypto.hashing import message_hash


@dataclass
class VerificationFailure:
    index: int
    message: str
    category: str = "general"  # e.g. "hash_chain", "signature", "sequence", "session"


@dataclass
class VerificationResult:
    is_valid: bool
    message: str = ""
    failures: List[VerificationFailure] = None

    def __post_init__(self):
        if self.failures is None:
            self.failures = []

    @property
    def first_failure(self) -> Optional[VerificationFailure]:
        return self.failures[0] if self.failures else None

    def __bool__(self):
        return self.is_valid

    def __str__(self):
        if self.is_valid:
            return "Chain is valid ✓"
        lines = [f"Verification FAILED ({len(self.failures)} issues):"]
        for f in self.failures:
            lines.append(f"  • [{f.index}] {f.category}: {f.message}")
        return "\n".join(lines)


class LogVerifier:
    """
    Offline verifier for a complete conversation log (chain of signed messages).
    
    Checks:
    - Sequence numbers are consecutive starting from 0
    - prev_hash links form a correct chain
    - All messages belong to the same session
    - Every signature is cryptographically valid over its payload
    """

    def __init__(self, trusted_keys: Dict[str, str]):
        """
        Args:
            trusted_keys: REQUIRED map agent_id → base64url public key (future CA/trust anchor)
                          Example: {"agent:alice": "yq8kP9qW...43chars", "agent:bob": "..."}
        """
        if not trusted_keys:
            raise ValueError("trusted_keys map is required for signature verification")
        self.trusted_keys = trusted_keys

    def verify(self, chain: List[Message]) -> VerificationResult:
        if not chain:
            return VerificationResult(True, "Empty chain is considered valid")

        result = VerificationResult(True)

        # ── 1. Basic structure & session consistency ──
        session_id = chain[0].session_id
        for i, msg in enumerate(chain):
            if msg.session_id != session_id:
                result.failures.append(VerificationFailure(
                    i, f"Session ID mismatch (expected {session_id}, got {msg.session_id})",
                    "session"
                ))
                result.is_valid = False

            if msg.sequence != i:
                result.failures.append(VerificationFailure(
                    i, f"Sequence number mismatch (expected {i}, got {msg.sequence})",
                    "sequence"
                ))
                result.is_valid = False

            if msg.proof is None:
                result.failures.append(VerificationFailure(
                    i, "Message missing proof/signature",
                    "signature"
                ))
                result.is_valid = False

        if not result.is_valid:
            return result

        # ── 2. Hash chain integrity ──
        for i in range(1, len(chain)):
            expected_prev = message_hash(chain[i-1])
            if chain[i].prev_hash != expected_prev:
                result.failures.append(VerificationFailure(
                    i, f"prev_hash does not match hash of previous message",
                    "hash_chain"
                ))
                result.is_valid = False

        # ── 3. Signature verification using trusted key map ──
        for i, msg in enumerate(chain):
            payload = {k: v for k, v in msg.to_dict().items() if k != "proof"}
            canon_bytes = canonical_json(payload)

            signature_bytes = b64url_decode(msg.proof.proof_value)

            # Get agent_id from the message itself (most reliable source)
            agent_id = msg.agent_id

            pub_b64 = self.trusted_keys.get(agent_id)
            if pub_b64 is None:
                result.failures.append(VerificationFailure(
                    i, f"No trusted public key found for agent '{agent_id}'",
                    "signature"
                ))
                result.is_valid = False
                continue

            try:
                verifier = AgentKeyPair.from_public_b64url(pub_b64)
                if not verifier.verify_bytes(signature_bytes, canon_bytes):
                    result.failures.append(VerificationFailure(
                        i, "Signature verification failed",
                        "signature"
                    ))
                    result.is_valid = False
            except Exception as e:
                result.failures.append(VerificationFailure(
                    i, f"Failed to load trusted public key for '{agent_id}': {str(e)}",
                    "signature"
                ))
                result.is_valid = False

        if result.is_valid:
            result.message = f"Chain of {len(chain)} messages verified successfully"
        else:
            result.message = f"Chain verification failed with {len(result.failures)} issues"

        return result