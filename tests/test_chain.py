# tests/test_chain.py
import pytest
from datetime import datetime, timezone

from ledger.core.types import Message
from ledger.chain.session import ConversationSession
from ledger.crypto.keys import AgentKeyPair
from ledger.crypto.hashing import message_hash


def utc_iso_now_ms():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@pytest.fixture
def empty_session():
    return ConversationSession(session_id="test-sess-20260131")


def test_session_starts_empty(empty_session):
    assert empty_session.length == 0
    assert empty_session.get_last_hash() is None


def test_append_one_message(empty_session):
    signer = AgentKeyPair.generate()

    msg = empty_session.append(
        content="User starts the conversation",
        role="user",
        signer=signer,
        agent_id="human:alice",
        timestamp=utc_iso_now_ms()
    )

    chain = empty_session.get_chain()
    assert len(chain) == 1
    assert chain[0].sequence == 0
    assert chain[0].prev_hash == ""
    assert chain[0].proof is not None
    assert chain[0].proof.proof_value != ""


def test_chain_links_hashes(empty_session):
    signer_a = AgentKeyPair.generate()
    signer_b = AgentKeyPair.generate()

    msg1 = empty_session.append(
        content="Hello from user",
        role="user",
        signer=signer_a,
        agent_id="human:alice",
        timestamp=utc_iso_now_ms()
    )

    msg2 = empty_session.append(
        content="Hi, assistant here",
        role="assistant",
        signer=signer_b,
        agent_id="agent:claude",
        timestamp=utc_iso_now_ms()
    )

    chain = empty_session.get_chain()
    assert len(chain) == 2
    assert chain[1].prev_hash == message_hash(chain[0])
    assert chain[0].sequence == 0
    assert chain[1].sequence == 1
    assert chain[0].proof is not None
    assert chain[1].proof is not None
