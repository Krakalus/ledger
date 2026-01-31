# ledger/core/encoding.py
import base64

def b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url (no padding, URL-safe)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Decode base64url string back to bytes."""
    # Restore padding
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    return base64.urlsafe_b64decode(s)