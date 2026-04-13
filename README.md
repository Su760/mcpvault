# AgentVault

[![CI](https://github.com/Su760/mcpvault/actions/workflows/ci.yml/badge.svg)](https://github.com/Su760/mcpvault/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-mcpvault-blue)](https://su760.github.io/mcpvault)

**Biscuit-based capability tokens for MCP tool authorization.**

OAuth-style delegation for AI agents: mint scoped tokens, attenuate them per-hop, and verify them at MCP servers — without a central auth server.

---

## Architecture

```
  OAuth AS
  (or your backend)
       │
       │  root token (all tools)
       ▼
  Agent A ──────────────────────────────┐
       │                                │
       │  attenuated token              │
       │  (tools: ["db_query"], ttl: 5m)│
       ▼                                │
  Agent B                               │
       │                                │
       │  present token                 │
       ▼                                ▼
  MCP Server ◄──── verify(token, pubkey, {requested_tool: "db_query"})
       │
       └── authorized_facts: {tools: ["db_query"], issuer: "...", subject: "..."}
```

Tokens are cryptographically signed [Biscuit tokens](https://www.biscuitsec.org/) with Datalog policies. Each attenuation step adds restrictions; no step can widen scope.

---

## Installation

### Python

```bash
pip install mcpvault
```

### Rust / CLI

```bash
cargo install mcpvault
```

---

## Python Quickstart

```python
from mcpvault import MCPVault

vault = MCPVault()

# 1. Generate an Ed25519 keypair (issuer side)
priv_key, pub_key = vault.generate_keypair()

# 2. Mint a root token granting access to db_query
token = vault.mint(priv_key, {
    "tools": ["db_query"],
    "ttl": 3600,
    "issuer": "auth-server",
    "subject": "agent-a",
})

# 3. Attenuate: delegate to Agent B with a tighter TTL
delegated = vault.attenuate(token, {
    "tools": ["db_query"],
    "ttl": 300,
})

# 4. MCP Server verifies before executing the tool
facts = vault.verify(delegated, pub_key, {"requested_tool": "db_query"})
print(facts)
# {'tools': ['db_query'], 'issuer': 'auth-server', 'subject': 'agent-a', ...}

# Wrong tool raises McpVaultError
# vault.verify(token, pub_key, {"requested_tool": "admin_delete"})  # raises
```

---

## CLI Quickstart

```bash
# Generate Ed25519 keypair (saved to ~/.mcpvault/keys/default.json)
mcpvault keygen

# Mint a capability token
TOKEN=$(mcpvault mint \
  --key ~/.mcpvault/keys/default.json \
  --tools db_query,file_read \
  --ttl 3600 \
  --issuer auth-server \
  --subject agent-a)

# Inspect token structure (no crypto verification)
mcpvault inspect --token "$TOKEN"

# Verify token and print authorized facts as JSON
mcpvault verify \
  --token "$TOKEN" \
  --pubkey "$(jq -r .public_key ~/.mcpvault/keys/default.json)" \
  --tool db_query

# Attenuate: narrow scope before delegating
DELEGATED=$(mcpvault attenuate \
  --token "$TOKEN" \
  --tools db_query \
  --ttl 300)

mcpvault verify \
  --token "$DELEGATED" \
  --pubkey "$(jq -r .public_key ~/.mcpvault/keys/default.json)" \
  --tool db_query
```

## Express.js Quickstart

```bash
npm install mcpvault-express
```

```javascript
import { createMcpVaultMiddleware } from "mcpvault-express";

const auth = createMcpVaultMiddleware({
  publicKeyHex: process.env.MCPVAULT_PUBLIC_KEY,
});

// Protect a MCP route — only tokens scoped to tool("db_query") can proceed
app.post("/mcp", auth("db_query"), (req, res) => {
  // req.mcpvaultFacts.verified === true on success
  res.json({ ok: true });
});

// Token extraction order (automatic):
//   1. X-MCPVault-Token header  (HTTP transport)
//   2. req.body.params._meta.token  (stdio-over-HTTP / JSON-RPC)
```

> **Node.js < 22:** Run with `NODE_OPTIONS=--experimental-wasm-modules node server.js`

---

## Crates

| Crate             | Description                                         |
| ----------------- | --------------------------------------------------- |
| `mcpvault-core`   | Core Rust library: mint, attenuate, verify, inspect |
| `mcpvault-cli`    | `mcpvault` CLI binary                               |
| `mcpvault-python` | PyO3 Python bindings                                |

---

## Datalog Schema

Token policies use Biscuit's embedded Datalog. See [SCHEMA.md](SCHEMA.md) for the full fact and check reference.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
