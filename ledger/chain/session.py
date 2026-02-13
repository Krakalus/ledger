# ledger/chain/session.py
from typing import List, Optional, Union
from dataclasses import dataclass, field, replace

from ledger.core.types import Message
from ledger.crypto.keys import AgentKeyPair
from ledger.crypto.hashing import message_hash
from ledger.core.canon import canonical_json
from ledger.storage import StorageBackend, create_storage


@dataclass
class ConversationSession:
    """
    Manages a single conversation / session.
    Maintains ordered list of signed messages with hash chaining.
    Supports optional persistent storage (SQLite, JSONL, etc.).
    """
    session_id: str
    messages: List[Message] = field(default_factory=list)
    storage: Optional[Union[StorageBackend, str]] = None

    def __post_init__(self):
        # Handle storage argument flexibly
        if isinstance(self.storage, str):
            stripped = self.storage.strip()
            if stripped.startswith(("sqlite://", "jsonl:")):
                # Proper URI → pass directly to factory
                self.storage = create_storage(stripped)
            elif stripped:
                # Plain file path → auto-convert to SQLite URI
                # This makes storage="/path/to/db.db" or "db.sqlite" just work
                # Previously would raise "Unsupported storage URI"
                self.storage = create_storage(f"sqlite://{stripped}")
            # else: empty string → treat as None (in-memory only)

        # Auto-load if persistent storage provided and messages list is empty
        if self.storage and not self.messages:
            try:
                loaded = self.storage.load_messages(self.session_id)
                self.messages = loaded
                print(f"[ledger] Loaded {len(loaded)} messages from storage for session {self.session_id}")
            except Exception as e:
                print(f"[ledger] Warning: Could not load session {self.session_id}: {e}")

    @property
    def length(self) -> int:
        return len(self.messages)

    def append(
        self,
        content: str,
        role: str,
        signer: AgentKeyPair,
        agent_id: str,
        timestamp: str,
        content_type: str = "text/plain"
    ) -> Message:
        """
        Append a new message: compute prev_hash → create unsigned → sign → append → persist if storage active
        Returns the newly signed message.
        """
        prev_hash = ""
        if self.messages:
            prev_hash = message_hash(self.messages[-1])

        unsigned = Message(
            id=f"msg-{self.length:04d}-{agent_id[-6:]}",  # temporary readable id
            timestamp=timestamp,
            session_id=self.session_id,
            sequence=self.length,
            agent_id=agent_id,
            agent_role=role,
            content=content,
            content_type=content_type,
            prev_hash=prev_hash,
            proof=None
        )

        if unsigned.proof is not None:
            raise ValueError("Cannot append already-signed message")

        signed = signer.sign_message(unsigned)
        self.messages.append(signed)

        # Persist immediately if storage is active
        if self.storage:
            try:
                self.storage.append(signed)
            except Exception as e:
                print(f"[ledger] Warning: Failed to persist message {signed.sequence}: {e}")

        return signed

    def get_chain(self) -> List[Message]:
        """Returns copy of the full signed chain (immutable view)"""
        return self.messages.copy()

    def get_last_hash(self) -> Optional[str]:
        """Hash of the last message — useful for checkpoints / next prev_hash"""
        if not self.messages:
            return None
        return message_hash(self.messages[-1])

    def close(self) -> None:
        """
        Release any storage resources (e.g. database connection).
        Good practice to call this when the session is no longer needed.
        """
        if self.storage:
            try:
                self.storage.close()
                print(f"[ledger] Storage closed for session {self.session_id}")
            except Exception as e:
                print(f"[ledger] Warning: Error closing storage: {e}")
            self.storage = None