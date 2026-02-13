# tests/test_storage.py
import os
import pytest
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory

from ledger.storage import SQLiteStorage, create_storage, StorageBackend
from ledger.chain.session import ConversationSession
from ledger.crypto.keys import AgentKeyPair
from ledger.crypto.hashing import message_hash
from ledger.core.types import Message
from ledger.core.encoding import b64url_decode  # for tamper test
from ledger.core.canon import canonical_json
from ledger.verify.verifier import LogVerifier, VerificationResult
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage

@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture
def storage(temp_db_path: Path) -> SQLiteStorage:
    return SQLiteStorage(db_path=temp_db_path)


@pytest.fixture
def keys() -> AgentKeyPair:
    return AgentKeyPair.generate()


def test_create_storage_dynamic_routing(temp_db_path: Path):
    storage = create_storage(f"sqlite://{temp_db_path}")
    assert isinstance(storage, SQLiteStorage)
    # Compare resolved string paths (ignores /workspaces vs /tmp prefix)
    assert str(storage.db_path.resolve()) == str(temp_db_path.resolve())


def test_sqlite_init_default_and_env():
    with TemporaryDirectory() as tmpdir:
        os.chdir(tmpdir)
        default_storage = SQLiteStorage()
        assert default_storage.db_path.name == "blackbox-logs.db"

    os.environ["LEDGER_DB_PATH"] = "/tmp/env-test.db"
    env_storage = SQLiteStorage()
    assert env_storage.db_path == Path("/tmp/env-test.db").resolve()
    os.environ.pop("LEDGER_DB_PATH", None)


def test_sqlite_schema_creation(storage: SQLiteStorage):
    cursor = storage.conn.cursor()
    cursor.execute("PRAGMA table_info(messages)")
    columns = {row[1] for row in cursor.fetchall()}
    expected = {
        "session_id", "sequence", "prev_hash", "message_hash", "timestamp",
        "agent_id", "agent_role", "canonical_json", "proof_json"
    }
    assert columns == expected


def test_append_and_load_basic(storage: SQLiteStorage, keys: AgentKeyPair):
    msg = Message(
        id="msg-test-0001",
        timestamp="2026-02-13T12:00:00Z",
        session_id="test-sess",
        sequence=0,
        agent_id="agent:test",
        agent_role="user",
        content="Test content",
        prev_hash="",
        proof=None
    )
    signed = keys.sign_message(msg)

    storage.append(signed)
    loaded = storage.load_messages("test-sess")

    assert len(loaded) == 1
    assert loaded[0].content == "Test content"


def test_append_unsigned_raises(storage: SQLiteStorage):
    unsigned = Message(
        id="unsigned",
        timestamp="now",
        session_id="test",
        sequence=0,
        agent_id="agent",
        agent_role="user",
        content="no sig",
        prev_hash=""
    )
    with pytest.raises(ValueError, match="unsigned"):
        storage.append(unsigned)


def test_load_empty_session(storage: SQLiteStorage):
    assert storage.load_messages("non-existent") == []


def test_session_integration_with_storage(temp_db_path: Path, keys: AgentKeyPair):
    sess = ConversationSession("integ-sess", storage=f"sqlite://{temp_db_path}")
    sess.append("First msg", "user", keys, "agent:1", "2026-02-13T10:55:00Z")
    sess.append("Second msg", "assistant", keys, "agent:2", "2026-02-13T10:56:00Z")
    sess.close()

    sess2 = ConversationSession("integ-sess", storage=f"sqlite://{temp_db_path}")
    assert len(sess2.messages) == 2
    assert sess2.messages[0].content == "First msg"


def test_tamper_detection(temp_db_path: Path, keys: AgentKeyPair):
    sess = ConversationSession("tamper-sess", storage=f"sqlite://{temp_db_path}")
    sess.append("Original content", "user", keys, "agent:1", "2026-02-13T10:55:00Z")
    sess.close()

    conn = sqlite3.connect(temp_db_path)
    conn.execute("""
        UPDATE messages
        SET canonical_json = REPLACE(canonical_json, 'Original content', 'Tampered content')
        WHERE sequence = 0
    """)
    conn.commit()
    conn.close()

    sess2 = ConversationSession("tamper-sess", storage=f"sqlite://{temp_db_path}")
    assert len(sess2.messages) == 1
    tampered_msg = sess2.messages[0]
    assert tampered_msg.content == "Tampered content"

    # Signature verification should fail
    payload_dict = {k: v for k, v in tampered_msg.to_dict().items() if k != "proof"}
    canon_bytes = canonical_json(payload_dict)
    signature = b64url_decode(tampered_msg.proof.proof_value)
    assert not keys.verify_bytes(signature, canon_bytes)


def test_close_releases_resources(temp_db_path: Path, keys: AgentKeyPair):
    storage = SQLiteStorage(temp_db_path)
    assert storage._conn is not None

    # Sign the dummy message
    dummy_unsigned = Message(
        id="close-test",
        timestamp="2026-02-13T12:00:00Z",
        session_id="close-sess",
        sequence=0,
        agent_id="agent:close",
        agent_role="system",
        content="Testing close",
        prev_hash=""
    )
    dummy = keys.sign_message(dummy_unsigned)
    storage.append(dummy)
    storage.close()

    with pytest.raises(RuntimeError, match="closed"):
        storage.append(dummy)


def test_context_manager(temp_db_path: Path):
    with SQLiteStorage(temp_db_path) as storage:
        assert storage._conn is not None
    with pytest.raises(RuntimeError, match="closed"):
        storage.load_messages("test")

def test_verifier_with_storage(temp_db_path: Path, keys: AgentKeyPair):
    """
    End-to-end: write signed messages to persistent storage,
    reload them, and verify chain + signatures are intact.
    """
    # Prepare trusted key map (only one agent for this test)
    trusted_keys = {
        "agent:test": keys.public_key_b64url()   # agent_id → public key b64
    }
    verifier = LogVerifier(trusted_keys=trusted_keys)

    # Create session with persistence
    sess = ConversationSession(
        session_id="verifier-test-001",
        storage=f"sqlite://{temp_db_path}"
    )

    # Append two signed messages
    sess.append(
        content="Hello from user",
        role="user",
        signer=keys,
        agent_id="agent:test",
        timestamp="2026-02-13T14:00:00Z"
    )
    sess.append(
        content="Reply from assistant",
        role="assistant",
        signer=keys,
        agent_id="agent:test",
        timestamp="2026-02-13T14:01:00Z"
    )
    sess.close()

    # Verify directly from storage
    result = verifier.verify_from_storage(
        session_id="verifier-test-001",
        storage=SQLiteStorage(temp_db_path)
    )

    assert result.is_valid, f"Verification failed: {result}"
    assert "valid" in str(result).lower()

    # Extra check: tamper one message in DB and verify it fails
    conn = sqlite3.connect(temp_db_path)
    conn.execute("""
        UPDATE messages
        SET canonical_json = REPLACE(canonical_json, 'Reply from assistant', 'Tampered reply')
        WHERE sequence = 1
    """)
    conn.commit()
    conn.close()

    # Reload and re-verify → should now fail signature
    result_tampered = verifier.verify_from_storage(
        session_id="verifier-test-001",
        storage=SQLiteStorage(temp_db_path)
    )

    assert not result_tampered.is_valid, "Tampered chain should fail verification"
    assert any("signature" in f.category.lower() for f in result_tampered.failures)

def test_autogen_integration(temp_db_path: Path, keys: AgentKeyPair):
    """Test AutoGen-style logging via LedgerAuditor."""
    from ledger.integration.autogen import LedgerAuditor

    auditor = LedgerAuditor(
        session_id="autogen-test-001",
        key_registry={"test-agent": keys},
        storage_uri=f"sqlite://{temp_db_path}"
    )

    # Simulate messages
    auditor.log("User asks question", "user", "test-agent")
    auditor.log("Agent replies", "assistant", "test-agent")

    auditor.close()

    # Verify chain persisted and verifiable
    verifier = auditor.create_verifier()
    result = verifier.verify_from_storage("autogen-test-001", SQLiteStorage(temp_db_path))
    assert result.is_valid


def test_langgraph_integration(temp_db_path: Path, keys: AgentKeyPair):
    """Test LangGraph callback logs messages correctly using real LangChain messages."""
    from ledger.integration.langgraph import LedgerAuditorLangGraph
    from langchain_core.messages import HumanMessage, AIMessage

    # Use same key for both agent and "tool" (realistic for test)
    auditor = LedgerAuditorLangGraph(
        session_id="langgraph-test-001",
        key_registry={
            "test-agent": keys,
            "tool": keys  # ← add dummy entry so "tool" is known → no ValueError
        },
        storage_uri=f"sqlite://{temp_db_path}"
    )

    callback = auditor.callback

    # Human input
    callback.on_chat_model_start(
        serialized={},
        messages=[
            [HumanMessage(content="Hello from human")]
        ]
    )

    # AI reply
    fake_response = type("FakeResponse", (), {
        "generations": [[
            type("FakeGen", (), {
                "message": AIMessage(content="AI reply")
            })()
        ]]
    })()
    callback.on_chat_model_end(response=fake_response)

    # Tool output — now allowed because "tool" is in key_registry
    callback.on_tool_end(output="Tool result: 42")

    auditor.close()

    # Verify full chain (human + ai + tool)
    verifier = auditor.create_verifier()
    result = verifier.verify_from_storage("langgraph-test-001", SQLiteStorage(temp_db_path))
    assert result.is_valid, f"LangGraph log verification failed:\n{result}"

    # Quick debug print (optional — remove later)
    chain = auditor.export_chain()
    print("Logged chain contents:", [m.content for m in chain])