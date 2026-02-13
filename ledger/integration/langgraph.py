# ledger/integration/langgraph.py
from typing import Any, Dict, List
from langchain_core.callbacks import BaseCallbackHandler
from ledger.chain.session import ConversationSession
from ledger.crypto.keys import AgentKeyPair
from ledger.verify.verifier import LogVerifier
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"


ROLE_MAP = {
    "human": "user",
    "ai": "assistant",
    "tool": "tool",
    "system": "system",
}


class _LedgerCallbackHandler(BaseCallbackHandler):
    """LangGraph callback that logs messages to Ledger."""

    def __init__(self, auditor: "LedgerAuditorLangGraph"):
        self.auditor = auditor
        self._seen = set()

    def on_chat_model_start(self, serialized: Dict, messages: List[Any], **kwargs):
        for msg_list in messages:
            for msg in msg_list:
                self._log_message(msg)

    def on_chat_model_end(self, response: Any, **kwargs):
        if hasattr(response, "generations") and response.generations:
            for gen in response.generations:
                for g in gen:
                    if hasattr(g, "message"):
                        self._log_message(g.message)

    def on_tool_end(self, output: Any, **kwargs):
        self.auditor.log(str(output), "tool", "tool")

    def _log_message(self, msg: Any):
        key = (msg.type, msg.content)
        if key in self._seen:
            return
        self._seen.add(key)

        role = ROLE_MAP.get(msg.type, "user")
        agent_name = role  # fallback
        if role in self.auditor.key_registry:
            self.auditor.log(msg.content, role, role)


class LedgerAuditorLangGraph:
    """LangGraph integration with callback support."""

    def __init__(
        self,
        session_id: str,
        key_registry: Dict[str, AgentKeyPair],
        storage_uri: str = "sqlite://blackbox-logs.db"
    ):
        self.session = ConversationSession(session_id, storage=storage_uri)
        self.key_registry = key_registry
        self._callback = _LedgerCallbackHandler(self)

    @property
    def callback(self) -> BaseCallbackHandler:
        return self._callback

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