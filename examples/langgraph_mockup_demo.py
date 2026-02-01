# examples/langgraph_mockup_demo.py
# Run with: poetry run python examples/langgraph_mockup_demo.py
#
# Requires: pip install langchain-core langgraph langchain-openai
# Set OPENAI_API_KEY for real LLM calls (dummy mode works without it)

from ledger.integration.langgraph import LedgerAuditorLangGraph, ROLE_MAP
from ledger.crypto.keys import AgentKeyPair
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from dataclasses import replace


if __name__ == "__main__":
    print("=" * 70)
    print("LEDGER + LANGGRAPH INTEGRATION DEMO")
    print("=" * 70)
    print()

    # Step 1: Generate keypairs
    user_keypair = AgentKeyPair.generate()
    assistant_keypair = AgentKeyPair.generate()
    tool_keypair = AgentKeyPair.generate()

    print("1. Generated keypairs for user, assistant, and tool")
    print()

    # Step 2: Create auditor from integration
    auditor = LedgerAuditorLangGraph(
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

    # Step 4: Create LangGraph agent
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

    # Step 6: Export chain
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