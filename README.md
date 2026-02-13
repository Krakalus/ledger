
# Attested Logs – Tamper-Evident Black Box for AI Agent Conversations

**Think of it as an airplane black box + content credentials for multi-agent LLM interactions.**

Every message is cryptographically signed (Ed25519), hash-chained (SHA-256), and can be verified offline — even if history is tampered with.  

Built to provide **last-mile attestation** for AI governance, regulatory compliance (e.g., EU AI Act), incident forensics, and cross-organizational trust.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### Features

- Per-message Ed25519 signatures with domain separation
- Deterministic JSON canonicalization (RFC 8785 via `jcs`)
- Linear hash chaining (`prev_hash`)
- Persistent SQLite storage (WAL + autocommit for crash-safety)
- Fully offline verification using trusted public keys
- Framework integrations: AutoGen (manual logging), LangGraph (callback handler)
- Real LLM demos (GPT-4o-mini) with dummy fallback (no API key needed)
- CLI commands: `sessions`, `messages`, `verify`, `export` (JSONL dump)
- 40+ passing tests covering core, crypto, chain, storage, CLI, and integrations

### Installation

```bash
# Recommended: Poetry (clean dependencies + venv)
git clone https://github.com/Krakalus/ledger.git
cd ledger
poetry install --with dev

# Or classic pip (editable mode)
pip install -e .

# Full install (agents, demos, testing)
pip install -r requirements.txt
```


### Quickstart (Pure Ledger – No Framework)

```python
from ledger import ConversationSession, AgentKeyPair, LogVerifier
from datetime import datetime, timezone

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"

# Create agents
alice = AgentKeyPair.generate()
bob   = AgentKeyPair.generate()

# Start session
session = ConversationSession(session_id="conversation-001")

# Agents sign their messages
session.append("Hey Bob, let's build something secure.", "user", alice, "agent:alice", utc_now())
session.append("I'm in! Every reply signed.", "assistant", bob, "agent:bob", utc_now())

chain = session.get_chain()

# Verify with trusted keys
trusted = {
    "agent:alice": alice.public_key_b64url(),
    "agent:bob":   bob.public_key_b64url()
}
verifier = LogVerifier(trusted_keys=trusted)
result = verifier.verify(chain)

print(result)          # → Chain is valid ✓
print(result.is_valid) # → True
```

### Tamper Detection Example

```python
# ... same setup as above ...

# Tamper with message #1
tampered = chain.copy()
tampered[1] = tampered[1].replace(content="HACKED REPLY!")

result = verifier.verify(tampered)
print(result)          # → Verification FAILED ... Signature verification failed
print(result.is_valid) # → False
```
### CLI Usage

```bash
# List all sessions
attested-logs sessions --db logs.db

# Show messages in a session
attested-logs messages conversation-001 --db logs.db --limit 10

# Verify chain integrity
attested-logs verify conversation-001 --db logs.db

# Export session as JSONL (one signed message per line)
attested-logs export conversation-001 --db logs.db --output audit.jsonl

All commands respect --db flag or LEDGER_DB_PATH env var.
Default DB location: ~/.ledger/blackbox-logs.db
```
### Running Framework Demos (AutoGen & LangGraph)

Both demos support **real LLM mode** (GPT-4o-mini).

1. **Set your OpenAI key** (optional – for real LLM runs)

   Create `.env` in repo root:

   ```
   OPENAI_API_KEY=sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   ```
2. **Run the demos**:

   ```bash
   poetry run python examples/autogen_demo.py
   poetry run python examples/langgraph_mockup_demo.py
   ```

   **Output** (real mode):
   - Real LLM replies (e.g., tool calls in LangGraph)
   - Signed chain with actual content
   - Verification: True
   - Tamper detection: True (shows hash_chain + signature failures)


### Project Structure

```
ledger/
├── ledger/                   # main package
│   ├── __init__.py
│   ├── core/                 # types, canonicalization
│   ├── crypto/               # keys & signing
│   ├── chain/                # sessions & chaining
│   ├── verify/               # offline verifier
│   ├── storage/              # SQLite backend
│   ├── integration/          # AutoGen + LangGraph hooks
│   └── cli/                  # CLI commands (main.py)
├── examples/                 # runnable demos
│   ├── autogen_demo.py
│   ├── langgraph_mockup_demo.py
│   └── verify_tamper_demo.py
├── tests/                    # pytest suite (40+ tests)
├── pyproject.toml
├── requirements.txt          # pip fallback
└── README.md
```

### Development

```bash
poetry shell          # enter venv
pytest -v             # run all tests
pytest --cov=ledger   # coverage report
poetry run attested-logs --help  # test CLI
```

### Summary of changes

- Features → added CLI export
- Installation → added pip fallback + minimal/full note
- New Dependencies Overview section
- Quickstart → showed plain-path storage
- New CLI Usage section
- Project Structure → added `cli/`
- Development → added CLI test command

### License

MIT – free to use, modify, distribute.

### Next Steps

- Merkle tree checkpoints for large logs
- Blockchain timestamp anchoring
- NLIP/ECMA-430 full augmentation
- Publish to PyPI

Contributions welcome!