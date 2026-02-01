# examples/autogen_demo.py
# Run with: poetry run python examples/autogen_demo.py
#
# Requires: pip install pyautogen
# Set OPENAI_API_KEY environment variable for LLM calls

from ledger.integration.autogen import LedgerAuditor, utc_now
from ledger.crypto.keys import AgentKeyPair
from dataclasses import replace
from autogen import AssistantAgent, UserProxyAgent


if __name__ == "__main__":
    # Setup keypairs and auditor (consumes integration class)
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