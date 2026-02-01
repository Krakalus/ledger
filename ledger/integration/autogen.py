# ledger/integration/autogen.py
# Reusable AutoGen integration — class definition + helpers only

from typing import Dict
from datetime import datetime, timezone

from ledger import ConversationSession, AgentKeyPair, LogVerifier


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"


class LedgerAuditor:
    """AutoGen integration for Ledger audit trails."""

    def __init__(self, session_id: str, key_registry: Dict[str, AgentKeyPair]):
        self.session = ConversationSession(session_id)
        self.key_registry = key_registry

    def log(self, content: str, role: str, agent_name: str):
        keypair = self.key_registry[agent_name]
        self.session.append(
            content=content,
            role=role,
            signer=keypair,
            agent_id=f"agent:{agent_name}",
            timestamp=utc_now()
        )

    def export_chain(self) -> list:
        return self.session.get_chain()

    def create_verifier(self) -> LogVerifier:
        trusted_keys = {
            f"agent:{name}": kp.public_key_b64url()
            for name, kp in self.key_registry.items()
        }
        return LogVerifier(trusted_keys=trusted_keys)