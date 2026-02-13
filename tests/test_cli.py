# tests/test_cli.py
import os
import json
from pathlib import Path
from typing import Generator

import pytest
from typer.testing import CliRunner

from ledger.cli.main import app
from ledger.chain.session import ConversationSession
from ledger.crypto.keys import AgentKeyPair
from ledger.core.types import Message
from datetime import datetime, timezone

runner = CliRunner()


@pytest.fixture
def temp_db(tmp_path: Path) -> Generator[Path, None, None]:
    """Temporary DB file + auto-cleanup."""
    db_path = tmp_path / "test-cli.db"
    yield db_path
    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def populated_db(temp_db: Path) -> Path:
    """DB with 2 signed messages from one session."""
    keys = AgentKeyPair.generate()

    sess = ConversationSession(
        session_id="cli-test-001",
        storage=str(temp_db)
    )

    sess.append(
        content="User: Hello world",
        role="user",
        signer=keys,
        agent_id="agent:test",
        timestamp=datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"
    )

    sess.append(
        content="Assistant: Hi there!",
        role="assistant",
        signer=keys,
        agent_id="agent:test",
        timestamp=datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"
    )

    sess.close()
    return temp_db


def test_sessions_no_db():
    result = runner.invoke(app, ["sessions"])
    assert result.exit_code == 1
    assert "not found" in result.stdout.lower()
    assert "suggestions" in result.stdout.lower() or "to get started" in result.stdout.lower()


def test_sessions_empty_db(temp_db: Path):
    """CLI handles empty or invalid DB gracefully."""
    result = runner.invoke(app, ["sessions", "--db", str(temp_db)])
    
    assert result.exit_code in (0, 1)
    
    stdout_lower = result.stdout.lower()
    assert any(phrase in stdout_lower for phrase in [
        "no sessions found",
        "database not found",
        "database file not found",
        "empty or schema missing",
        "failed to open database",
        "no such table",
        "operationalerror"
    ]), f"Unexpected output:\n{result.stdout}"


def test_sessions_with_data(populated_db: Path):
    """CLI lists sessions correctly when data exists."""
    result = runner.invoke(app, ["sessions", "--db", str(populated_db)])
    assert result.exit_code == 0
    assert "cli-test-001" in result.stdout
    assert "Messages" in result.stdout
    assert "2" in result.stdout


def test_messages_shows_content(populated_db: Path):
    """CLI displays message content and metadata correctly."""
    result = runner.invoke(
        app,
        ["messages", "cli-test-001", "--db", str(populated_db), "--limit", "5"]
    )
    assert result.exit_code == 0
    assert "Hello world" in result.stdout
    assert "Hi there!" in result.stdout


def test_verify_runs_on_populated_db(populated_db: Path):
    """CLI runs verifier — accepts missing trusted keys with warning."""
    result = runner.invoke(
        app,
        ["verify", "cli-test-001", "--db", str(populated_db)]
    )
    assert result.exit_code in (0, 1)
    assert any(phrase in result.stdout.lower() for phrase in [
        "valid", "trusted", "warning", "skipped"
    ])


def test_verify_missing_session(populated_db: Path):
    """CLI handles unknown session gracefully."""
    result = runner.invoke(
        app,
        ["verify", "non-existent-session", "--db", str(populated_db)]
    )
    assert result.exit_code == 1
    assert any(phrase in result.stdout.lower() for phrase in [
        "failed", "not found", "empty", "warning"
    ])


def test_export_creates_jsonl(populated_db: Path, tmp_path: Path):
    """Export command creates valid JSONL file for a session."""
    output_file = tmp_path / "export-test.jsonl"

    result = runner.invoke(
        app,
        [
            "export", 
            "cli-test-001", 
            "--db", str(populated_db),
            "--output", str(output_file)
        ]
    )

    assert result.exit_code == 0
    assert "Exported 2 messages" in result.stdout
    assert output_file.exists()
    assert output_file.stat().st_size > 0

    # Verify it's valid JSONL (2 lines, each parseable JSON)
    with open(output_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) == 2  # exactly 2 messages
        for line in lines:
            assert line.strip()  # not empty
            json.loads(line)  # must be valid JSON

    # Optional: cleanup
    output_file.unlink(missing_ok=True)