# examples/langgraph_mockup_demo.py
# Run with: poetry run python examples/langgraph_mockup_demo.py
#
# Requires: pip install langchain-core langgraph langchain-openai
# Set OPENAI_API_KEY environment variable for real LLM calls

from ledger import ConversationSession, AgentKeyPair, LogVerifier
from datetime import datetime, timezone
from dataclasses import replace
from typing import Dict, List

from langchain_core.messages import HumanMessage
from langchain_core.callbacks import BaseCallbackHandler


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"


# =============================================================================
# LedgerAuditor: The proposed integration
# =============================================================================

ROLE_MAP = {
    "human": "user",
    "ai": "assistant",
    "tool": "tool",
    "system": "system",
}


class _LedgerCallbackHandler(BaseCallbackHandler):
    """Callback handler that captures LangGraph messages to a Ledger chain."""

    def __init__(self, auditor: "LedgerAuditor"):
        self.auditor = auditor
        self._seen = set()

    def on_chat_model_start(self, serialized, messages, **kwargs):
        for msg_list in messages:
            for msg in msg_list:
                self._log_message(msg)

    def on_chat_model_end(self, response, **kwargs):
        for gen in response.generations:
            for g in gen:
                if hasattr(g, 'message'):
                    self._log_message(g.message)

    def on_tool_end(self, output, **kwargs):
        self.auditor.log(str(output), "tool", "tool")

    def _log_message(self, msg):
        key = (msg.type, msg.content)
        if key in self._seen:
            return
        self._seen.add(key)

        role = ROLE_MAP.get(msg.type, "user")
        if role in self.auditor.key_registry:
            self.auditor.log(msg.content, role, role)


class LedgerAuditor:
    """Seamless LangGraph integration for Ledger audit trails."""

    def __init__(self, session_id: str, key_registry: Dict[str, AgentKeyPair]):
        self.session = ConversationSession(session_id)
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

    def export_chain(self) -> List:
        return self.session.get_chain()

    def create_verifier(self) -> LogVerifier:
        trusted_keys = {
            f"agent:{name}": kp.public_key_b64url()
            for name, kp in self.key_registry.items()
        }
        return LogVerifier(trusted_keys=trusted_keys)


# =============================================================================
# DEMO: Using LedgerAuditor with a real LangGraph ReAct agent
# =============================================================================

if __name__ == "__main__":
    from langgraph.prebuilt import create_react_agent
    from langchain_openai import ChatOpenAI
    from langchain_core.tools import tool

    print("=" * 70)
    print("LEDGER + LANGGRAPH INTEGRATION DEMO")
    print("=" * 70)
    print()

    # Step 1: Generate keypairs for each role
    user_keypair = AgentKeyPair.generate()
    assistant_keypair = AgentKeyPair.generate()
    tool_keypair = AgentKeyPair.generate()

    print("1. Generated keypairs for user, assistant, and tool")
    print()

    # Step 2: Create the auditor
    auditor = LedgerAuditor(
        session_id="conv-001",
        key_registry={
            "user": user_keypair,
            "assistant": assistant_keypair,
            "tool": tool_keypair,
        }
    )

    print("2. Created LedgerAuditor")
    print()

    # Step 3: Define tools
    @tool
    def get_weather(location: str) -> str:
        """Get the weather for a location."""
        return f'{{"location": "{location}", "temp": 65, "condition": "sunny"}}'

    @tool
    def get_time(timezone: str) -> str:
        """Get the current time in a timezone."""
        return f'{{"timezone": "{timezone}", "time": "2:30 PM"}}'

    print("3. Defined tools: get_weather, get_time")
    print()

    # Step 4: Create the LangGraph agent
    llm = ChatOpenAI(model="gpt-4o-mini")
    agent = create_react_agent(llm, [get_weather, get_time])

    print("4. Created LangGraph ReAct agent with GPT-4o-mini")
    print()

    # Step 5: Run with auditing
    print("5. Running agent with LedgerAuditor callback...")
    print("-" * 50)

    result = agent.invoke(
        {"messages": [HumanMessage(content="What's the weather in San Francisco?")]},
        config={"callbacks": [auditor.callback]}
    )

    for msg in result["messages"]:
        role = ROLE_MAP.get(msg.type, msg.type)
        content = msg.content[:60] + "..." if len(msg.content) > 60 else msg.content
        print(f"   [{role:9}] {content}")

    print()

    # Step 6: Export the signed chain
    print("6. Exported signed audit chain:")
    print("-" * 50)

    chain = auditor.export_chain()
    for i, msg in enumerate(chain):
        hash_preview = msg.prev_hash[:16] + "..." if msg.prev_hash else "(genesis)"
        content_preview = msg.content[:30] + "..." if len(msg.content) > 30 else msg.content
        print(f"   [{i}] seq={msg.sequence} role={msg.agent_role:9} prev_hash={hash_preview}")

    print()

    # Step 7: Verify
    print("7. Verifying chain integrity and signatures...")
    print("-" * 50)

    verifier = auditor.create_verifier()
    result = verifier.verify(chain)

    print(f"   Result: {result}")
    print(f"   Valid: {result.is_valid}")
    print()

    # Step 8: Tamper detection
    print("8. Demonstrating tamper detection...")
    print("-" * 50)

    if len(chain) > 1:
        tampered_chain = chain.copy()
        original = tampered_chain[1].content
        tampered_chain[1] = replace(tampered_chain[1], content="TAMPERED!")

        tampered_result = verifier.verify(tampered_chain)

        print(f"   Original msg[1]: \"{original[:40]}...\"")
        print(f"   Tampered msg[1]: \"TAMPERED!\"")
        print(f"   Verification: {tampered_result}")
        print(f"   Tampering detected: {not tampered_result.is_valid}")

    print()
    print("=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
