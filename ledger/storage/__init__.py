# ledger/storage/__init__.py
"""
Storage backends for persistent attested logs.
"""

from abc import ABC, abstractmethod
from typing import List
from pathlib import Path
from ledger.core.types import Message


class StorageBackend(ABC):
    """Abstract base for all persistent storage implementations."""

    @abstractmethod
    def append(self, msg: Message) -> None:
        pass

    @abstractmethod
    def load_messages(self, session_id: str) -> List[Message]:
        pass

    @abstractmethod
    def close(self) -> None:
        pass


def create_storage(uri: str) -> StorageBackend:
    if uri.startswith("sqlite://"):
        from .sqlite import SQLiteStorage
        # Extract everything after sqlite://
        raw_path = uri[len("sqlite://"):].lstrip("/")
        if not raw_path.startswith('/'):
            raw_path = '/' + raw_path
        
        absolute_path = Path(raw_path).resolve()
        return SQLiteStorage(absolute_path)
    
    elif uri.startswith("jsonl:"):
        raise NotImplementedError("JSONL backend coming soon")
    else:
        raise ValueError(f"Unsupported storage URI: {uri}")


from .sqlite import SQLiteStorage

__all__ = ["StorageBackend", "create_storage", "SQLiteStorage"]