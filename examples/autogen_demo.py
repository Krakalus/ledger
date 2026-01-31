# examples/autogen_demo.py
# Run with: poetry run python examples/autogen_demo.py
#
# Requires: pip install pyautogen
# Set OPENAI_API_KEY environment variable for LLM calls

from ledger import ConversationSession, AgentKeyPair, LogVerifier
from datetime import datetime, timezone
from dataclasses import replace
from typing import Dict, List

from autogen import AssistantAgent, UserProxyAgent


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"


# =============================================================================
# LedgerAuditor: AutoGen integration
# =============================================================================

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

    def export_chain(self) -> List:
        return self.session.get_chain()

    def create_verifier(self) -> LogVerifier:
        trusted_keys = {
            f"agent:{name}": kp.public_key_b64url()
            for name, kp in self.key_registry.items()
        }
        return LogVerifier(trusted_keys=trusted_keys)


# =============================================================================
# DEMO
# =============================================================================

if __name__ == "__main__":
    # Setup keypairs and auditor
    user_kp = AgentKeyPair.generate()
    assistant_kp = AgentKeyPair.generate()

    auditor = LedgerAuditor(
        session_id="autogen-conv-001",
        key_registry={"user": user_kp, "assistant": assistant_kp}
    )

    # Create AutoGen agents
    llm_config = {"config_list": [{"model": "gpt-4o-mini"}], "temperature": 0}

    assistant = AssistantAgent(
        name="assistant",
        system_message="You are a helpful assistant. Be concise.",
        llm_config=llm_config,
    )

    user_proxy = UserProxyAgent(
        name="user",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=0,
        code_execution_config=False,
    )

    # Run conversation
    print("\n[Running conversation...]")
    user_message = "What are three benefits of code review? Be brief."
    auditor.log(user_message, "user", "user")

    user_proxy.initiate_chat(assistant, message=user_message, silent=True)

    if assistant.last_message():
        auditor.log(assistant.last_message()["content"], "assistant", "assistant")

    # Show chain
    print("\n[Audit chain]")
    chain = auditor.export_chain()
    for i, msg in enumerate(chain):
        hash_preview = msg.prev_hash[:12] + "..." if msg.prev_hash else "(genesis)"
        print(f"  [{i}] {msg.agent_role:9} | {hash_preview} | {msg.content[:50]}...")

    # Verify
    print("\n[Verification]")
    verifier = auditor.create_verifier()
    result = verifier.verify(chain)
    print(f"  Valid: {result.is_valid}")

    # Tamper detection
    print("\n[Tamper detection]")
    tampered = chain.copy()
    tampered[0] = replace(tampered[0], content="TAMPERED!")
    tampered_result = verifier.verify(tampered)
    print(f"  Tampering detected: {not tampered_result.is_valid}")

    print("\n" + "=" * 60)
