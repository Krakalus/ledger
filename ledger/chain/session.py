# ledger/chain/session.py
from typing import List, Optional
from dataclasses import dataclass, replace

from ledger.core.types import Message
from ledger.crypto.keys import AgentKeyPair
from ledger.crypto.hashing import message_hash
from ledger.core.canon import canonical_json  # only needed if we want to expose more


@dataclass
class ConversationSession:
    """
    Manages a single conversation / session.
    Maintains ordered list of signed messages with hash chaining.
    """
    session_id: str
    messages: List[Message] = None

    def __post_init__(self):
        if self.messages is None:
            self.messages = []

    @property
    def length(self) -> int:
        return len(self.messages)

    def append(self,
               content: str,
               role: str,
               signer: AgentKeyPair,
               agent_id: str,
               timestamp: str,
               content_type: str = "text/plain") -> Message:
        """
        Append a new message: compute prev_hash → create unsigned → sign → append
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
        return signed

    def get_chain(self) -> List[Message]:
        """Returns copy of the full signed chain (immutable view)"""
        return self.messages.copy()

    def get_last_hash(self) -> Optional[str]:
        """Hash of the last message — useful for checkpoints / next prev_hash"""
        if not self.messages:
            return None
        return message_hash(self.messages[-1])