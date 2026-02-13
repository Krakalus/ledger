# ledger/verify/verifier.py
from typing import List, Optional, Dict
from dataclasses import dataclass

from ledger.core.types import Message, Proof
from ledger.core.canon import canonical_json
from ledger.core.encoding import b64url_decode
from ledger.crypto.keys import AgentKeyPair
from ledger.crypto.hashing import message_hash
from ledger.storage import StorageBackend


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
    Offline verifier for attested conversation logs.
    Can verify a raw chain or load directly from storage.
    """

    def __init__(self, trusted_keys: Dict[str, str]):
        """
        trusted_keys: agent_id → base64url public key (your trust anchor / CA map)
        """
        if not trusted_keys:
            raise ValueError("trusted_keys map is required")
        self.trusted_keys = trusted_keys

    def verify(self, chain: List[Message]) -> VerificationResult:
        """Core verification logic over a loaded chain."""
        if not chain:
            return VerificationResult(True, "Empty chain is valid")

        result = VerificationResult(True)

        # 1. Session & sequence consistency
        session_id = chain[0].session_id
        for i, msg in enumerate(chain):
            if msg.session_id != session_id:
                result.failures.append(VerificationFailure(i, f"Session mismatch: {msg.session_id}", "session"))
                result.is_valid = False
            if msg.sequence != i:
                result.failures.append(VerificationFailure(i, f"Sequence mismatch: expected {i}, got {msg.sequence}", "sequence"))
                result.is_valid = False
            if msg.proof is None:
                result.failures.append(VerificationFailure(i, "Missing proof/signature", "signature"))
                result.is_valid = False

        if not result.is_valid:
            return result

        # 2. Hash chain
        for i in range(1, len(chain)):
            expected_prev = message_hash(chain[i-1])
            if chain[i].prev_hash != expected_prev:
                result.failures.append(VerificationFailure(i, "prev_hash does not match previous message hash", "hash_chain"))
                result.is_valid = False

        # 3. Signature verification
        for i, msg in enumerate(chain):
            payload = {k: v for k, v in msg.to_dict().items() if k != "proof"}
            canon_bytes = canonical_json(payload)
            signature_bytes = b64url_decode(msg.proof.proof_value)

            agent_id = msg.agent_id
            pub_b64 = self.trusted_keys.get(agent_id)
            if pub_b64 is None:
                result.failures.append(VerificationFailure(i, f"No trusted key for agent '{agent_id}'", "signature"))
                result.is_valid = False
                continue

            try:
                verifier = AgentKeyPair.from_public_b64url(pub_b64)
                if not verifier.verify_bytes(signature_bytes, canon_bytes):
                    result.failures.append(VerificationFailure(i, "Invalid signature", "signature"))
                    result.is_valid = False
            except Exception as e:
                result.failures.append(VerificationFailure(i, f"Key loading failed: {str(e)}", "signature"))
                result.is_valid = False

        result.message = "Valid chain" if result.is_valid else f"Failed with {len(result.failures)} issues"
        return result

    def verify_from_storage(self, session_id: str, storage: StorageBackend) -> VerificationResult:
        """
        Load messages from persistent storage and verify the chain.
        Returns result with extra info if load fails.
        """
        try:
            chain = storage.load_messages(session_id)
        except Exception as e:
            return VerificationResult(
                False,
                f"Failed to load session '{session_id}' from storage: {str(e)}",
                [VerificationFailure(-1, str(e), "storage")]
            )

        result = self.verify(chain)
        return result