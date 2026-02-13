# ledger/integration/autogen.py
from typing import Dict
from datetime import datetime, timezone

from ledger.chain.session import ConversationSession
from ledger.crypto.keys import AgentKeyPair
from ledger.verify.verifier import LogVerifier


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"


class LedgerAuditor:
    """AutoGen integration: logs messages to persistent Ledger chain."""

    def __init__(
        self,
        session_id: str,
        key_registry: Dict[str, AgentKeyPair],
        storage_uri: str = "sqlite://blackbox-logs.db"
    ):
        self.session = ConversationSession(session_id, storage=storage_uri)
        self.key_registry = key_registry

    def log(self, content: str, role: str, agent_name: str, timestamp: str | None = None):
        if agent_name not in self.key_registry:
            raise ValueError(f"Unknown agent: {agent_name}")
        keypair = self.key_registry[agent_name]
        self.session.append(
            content=content,
            role=role,
            signer=keypair,
            agent_id=f"agent:{agent_name}",
            timestamp=timestamp or utc_now()
        )

    def close(self):
        self.session.close()

    def export_chain(self) -> list:
        return self.session.get_chain()

    def create_verifier(self) -> LogVerifier:
        trusted_keys = {
            f"agent:{name}": kp.public_key_b64url()
            for name, kp in self.key_registry.items()
        }
        return LogVerifier(trusted_keys=trusted_keys)