# ledger/storage/sqlite.py
import os
import sqlite3
import json
from pathlib import Path
from typing import List, Optional

from ledger.core.types import Message, Proof
from ledger.core.canon import canonical_json
from ledger.crypto.hashing import message_hash
from . import StorageBackend


class SQLiteStorage(StorageBackend):
    """SQLite persistent storage for attested conversation logs."""

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            env_path = os.environ.get("LEDGER_DB_PATH")
            db_path = env_path if env_path else Path.cwd() / "blackbox-logs.db"

        self.db_path = Path(db_path)

        # Ensure the entire parent directory tree exists
        # This fixes the recursive mkdir crash when "tmp/..." parents are missing
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.db_path = self.db_path.resolve()

        self._conn: Optional[sqlite3.Connection] = None
        self._connect()

    def _connect(self):
        conn_str = str(self.db_path)
        self._conn = sqlite3.connect(conn_str, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_schema()

    def _create_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                session_id      TEXT    NOT NULL,
                sequence        INTEGER NOT NULL,
                prev_hash       TEXT    NOT NULL,
                message_hash    TEXT    NOT NULL,
                timestamp       TEXT    NOT NULL,
                agent_id        TEXT    NOT NULL,
                agent_role      TEXT    NOT NULL,
                canonical_json  TEXT    NOT NULL,
                proof_json      TEXT    NOT NULL,
                PRIMARY KEY (session_id, sequence)
            )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(session_id, timestamp)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_agent     ON messages(agent_id)")

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Storage connection is closed")
        return self._conn

    def append(self, msg: Message) -> None:
        if msg.proof is None:
            raise ValueError("Cannot persist unsigned message")

        payload_dict = {k: v for k, v in msg.to_dict().items() if k != "proof"}
        canon_bytes = canonical_json(payload_dict)
        canon_str = canon_bytes.decode("utf-8")

        proof_str = json.dumps(msg.proof.__dict__, sort_keys=True, separators=(",", ":"))

        msg_hash = message_hash(msg)

        self.conn.execute("""
            INSERT OR IGNORE INTO messages
            (session_id, sequence, prev_hash, message_hash, timestamp,
             agent_id, agent_role, canonical_json, proof_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            msg.session_id, msg.sequence, msg.prev_hash, msg_hash,
            msg.timestamp, msg.agent_id, msg.agent_role, canon_str, proof_str
        ))

    def load_messages(self, session_id: str) -> List[Message]:
        cursor = self.conn.execute("""
            SELECT sequence, prev_hash, timestamp, agent_id, agent_role,
                   canonical_json, proof_json
            FROM messages WHERE session_id = ? ORDER BY sequence ASC
        """, (session_id,))

        loaded = []
        for row in cursor:
            seq, prev, ts, aid, role, cjson, pjson = row
            payload = json.loads(cjson)
            proof = Proof(**json.loads(pjson))

            msg = Message(
                id=payload["id"],
                timestamp=ts,
                session_id=session_id,
                sequence=seq,
                agent_id=aid,
                agent_role=role,
                content=payload["content"],
                content_type=payload.get("content_type", "text/plain"),
                prev_hash=prev,
                proof=proof
            )
            loaded.append(msg)
        for msg in loaded:
            computed_hash = message_hash(msg)
            if msg.sequence > 0 and msg.prev_hash != message_hash(loaded[msg.sequence - 1]):
                raise ValueError(f"Chain broken at sequence {msg.sequence}")    
        return loaded

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ── NEW: make it a context manager (fixes test_context_manager)
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def list_sessions(self) -> list[str]:
        """
        List all unique session_ids, sorted by most recent activity (latest timestamp).
        """
        cursor = self.conn.execute("""
            SELECT session_id
            FROM messages
            GROUP BY session_id
            ORDER BY MAX(timestamp) DESC
        """)
        return [row[0] for row in cursor.fetchall()]    

    def get_message_count(self, session_id: str) -> int:
        cursor = self.conn.execute(
            "SELECT COUNT(*) FROM messages WHERE session_id = ?",
            (session_id,)
        )
        return cursor.fetchone()[0]   

    def get_latest_timestamp(self, session_id: str) -> Optional[str]:
        cursor = self.conn.execute(
            "SELECT MAX(timestamp) FROM messages WHERE session_id = ?",
            (session_id,)
        )
        row = cursor.fetchone()
        return row[0] if row and row[0] else None
        
    def query_messages(self, session_id: str, limit: int = 50) -> List[Message]:
        cursor = self.conn.execute("""
            SELECT sequence, prev_hash, timestamp, agent_id, agent_role,
                canonical_json, proof_json
            FROM messages
            WHERE session_id = ?
            ORDER BY sequence DESC
            LIMIT ?
        """, (session_id, limit))

        loaded = []
        for row in cursor:
            seq, prev, ts, aid, role, cjson, pjson = row
            payload = json.loads(cjson)
            proof = Proof(**json.loads(pjson))

            msg = Message(
                id=payload["id"],
                timestamp=ts,
                session_id=session_id,
                sequence=seq,
                agent_id=aid,
                agent_role=role,
                content=payload["content"],
                content_type=payload.get("content_type", "text/plain"),
                prev_hash=prev,
                proof=proof
            )
            loaded.append(msg)
        loaded.reverse()  # latest last
        return loaded         