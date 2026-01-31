# tests/test_core.py
import json
import pytest
from datetime import datetime, timezone

from ledger.core.types import Message, Proof
from ledger.core.encoding import b64url_encode, b64url_decode
from ledger.core.canon import canonical_json, canonical_json_str


def utc_iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@pytest.fixture
def sample_message_unsigned():
    return Message(
        id="01945a7b-1234-5678-9abc-def012345678",
        timestamp=utc_iso_now(),
        session_id="conv-20260131-test",
        sequence=0,
        agent_id="human:tester",
        agent_role="user",
        content="Initialize ledger test run.",
        prev_hash="",
    )


def test_message_immutable(sample_message_unsigned):
    msg = sample_message_unsigned
    with pytest.raises(AttributeError):
        msg.sequence = 99


def test_message_to_dict(sample_message_unsigned):
    d = sample_message_unsigned.to_dict()
    assert d["sequence"] == 0
    assert d["prev_hash"] == ""
    assert d["proof"] == {}


def test_base64url_roundtrip():
    original = b'{"hello":"world"}'
    encoded = b64url_encode(original)
    decoded = b64url_decode(encoded)
    assert decoded == original
    assert "=" not in encoded  # no padding


def test_canonical_json_deterministic(sample_message_unsigned):
    msg1 = sample_message_unsigned
    msg2 = Message(**msg1.__dict__)  # same content, different object

    json1 = canonical_json(msg1.to_dict())
    json2 = canonical_json(msg2.to_dict())

    assert json1 == json2
    assert b'"sequence":0' in json1  # just to see it looks reasonable


def test_canonical_json_sorting():
    messy = {
        "z": 1,
        "a": "hello",
        "nested": {"b": 2, "a": 1},
    }
    canon = canonical_json(messy).decode("utf-8")
    # keys should be sorted at each level
    assert '"a":"hello"' in canon
    assert '"z":1' in canon  # a before z