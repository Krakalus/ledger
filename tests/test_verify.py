# tests/test_verify.py
import pytest
from dataclasses import replace
from ledger.verify.verifier import LogVerifier, VerificationResult
from ledger.chain.session import ConversationSession
from ledger.crypto.keys import AgentKeyPair


def create_test_chain(n_messages=4):
    session = ConversationSession(session_id="verify-test-001")
    agents = [AgentKeyPair.generate() for _ in range(2)]  # index 0 = alice/user, 1 = bob/assistant

    for i in range(n_messages):
        agent_idx = i % 2
        role = "user" if agent_idx == 0 else "assistant"
        agent_id = f"agent:{'alice' if role == 'user' else 'bob'}"
        session.append(
            content=f"Message #{i}",
            role=role,
            signer=agents[agent_idx],
            agent_id=agent_id,
            timestamp=f"2026-01-31T14:00:{i:02d}.000Z"
        )
    return session.get_chain(), agents


def test_valid_chain():
    chain, agents = create_test_chain(6)
    trusted = {
        "agent:alice": agents[0].public_key_b64url(),
        "agent:bob": agents[1].public_key_b64url()
    }
    verifier = LogVerifier(trusted_keys=trusted)
    result = verifier.verify(chain)
    assert result.is_valid is True
    assert len(result.failures) == 0


def test_tamper_content():
    chain, agents = create_test_chain(5)
    tampered = chain.copy()
    tampered[2] = replace(tampered[2], content="HACKED CONTENT")

    trusted = {
        "agent:alice": agents[0].public_key_b64url(),
        "agent:bob": agents[1].public_key_b64url()
    }
    verifier = LogVerifier(trusted_keys=trusted)
    result = verifier.verify(tampered)
    assert result.is_valid is False
    assert any("signature" in f.message.lower() for f in result.failures)


def test_broken_hash_link():
    chain, agents = create_test_chain(5)
    tampered = chain.copy()
    tampered[3] = replace(tampered[3], prev_hash="deadbeef"*8)

    trusted = {
        "agent:alice": agents[0].public_key_b64url(),
        "agent:bob": agents[1].public_key_b64url()
    }
    verifier = LogVerifier(trusted_keys=trusted)
    result = verifier.verify(tampered)
    assert result.is_valid is False
    assert any("hash_chain" in f.category for f in result.failures)


def test_wrong_sequence():
    chain, agents = create_test_chain(4)
    tampered = chain.copy()
    tampered[2] = replace(tampered[2], sequence=99)

    trusted = {
        "agent:alice": agents[0].public_key_b64url(),
        "agent:bob": agents[1].public_key_b64url()
    }
    verifier = LogVerifier(trusted_keys=trusted)
    result = verifier.verify(tampered)
    assert result.is_valid is False
    assert any("sequence" in f.category for f in result.failures)


def test_different_session():
    chain, agents = create_test_chain(4)
    tampered = chain.copy()
    tampered[2] = replace(tampered[2], session_id="evil-session")

    trusted = {
        "agent:alice": agents[0].public_key_b64url(),
        "agent:bob": agents[1].public_key_b64url()
    }
    verifier = LogVerifier(trusted_keys=trusted)
    result = verifier.verify(tampered)
    assert result.is_valid is False
    assert any("session" in f.category for f in result.failures)