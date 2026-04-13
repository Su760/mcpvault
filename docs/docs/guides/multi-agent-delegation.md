# Multi-Agent Delegation

This guide shows how to use MCPVault in a multi-agent pipeline where an orchestrator delegates narrowing authority to workers, each of which presents its own scoped token to the MCP server.

---

## Sequence Diagram

```
Orchestrator          Worker A              Worker B          MCP Server
     │                    │                    │                   │
     │  mint(root)        │                    │                   │
     │──────────────────► │                    │                   │
     │◄── root_token ──── │                    │                   │
     │                    │                    │                   │
     │  attenuate(        │                    │                   │
     │    tools=[db_query]│                    │                   │
     │    ttl=1800)       │                    │                   │
     │──────────────────► │                    │                   │
     │◄── token_a ─────── │                    │                   │
     │                    │                    │                   │
     │                    │  attenuate(        │                   │
     │                    │    tools=[db_query]│                   │
     │                    │    ttl=900)        │                   │
     │                    │──────────────────► │                   │
     │                    │◄── token_b ─────── │                   │
     │                    │                    │                   │
     │                    │                    │  POST /mcp        │
     │                    │                    │  X-MCPVault-Token │
     │                    │                    │──────────────────►│
     │                    │                    │                   │ verify(
     │                    │                    │                   │   token_b,
     │                    │                    │                   │   tool="db_query"
     │                    │                    │                   │ )
     │                    │                    │◄── AuthorizedFacts│
```

---

## Full Python Example

```python
from mcpvault import MCPVault

vault = MCPVault()

# --- Setup (done once at server start) ---
priv_key, pub_key = vault.generate_keypair()

# --- Orchestrator: mint a root token ---
# Grants db_query and file_read for 1 hour
root_token = vault.mint(priv_key, {
    "tools": ["db_query", "file_read"],
    "ttl": 3600,
    "issuer": "orchestrator",
    "subject": "root",
    "max_delegation_depth": 5,
})

# --- Orchestrator → Worker A: attenuate to db_query only ---
# Worker A can only use db_query, and only for 30 minutes
token_a = vault.attenuate(root_token, pub_key, {
    "tools": ["db_query"],
    "ttl": 1800,
})

# --- Worker A → Worker B: further attenuate with tighter TTL ---
# Worker B can use db_query for 15 minutes
token_b = vault.attenuate(token_a, pub_key, {
    "tools": ["db_query"],
    "ttl": 900,
})

# --- MCP Server: verify Worker B's token ---
facts = vault.verify(token_b, pub_key, {
    "requested_tool": "db_query",
})

print(facts)
# {
#   "tools": ["db_query"],
#   "tool_wildcard": False,
#   "operations": [],
#   "resource_limits": [],
#   "delegation_depth": 2,   # root(0) → A(1) → B(2)
#   "issuer": "orchestrator",
#   "subject": "root",
# }
```

---

## FastAPI Integration

On the MCP server side, use `MCPVaultAuth` to verify the token automatically on each request:

```python
import os
from fastapi import FastAPI, Request
from mcpvault.middleware.fastapi import MCPVaultAuth

app = FastAPI()
auth = MCPVaultAuth(public_key_hex=os.environ["MCPVAULT_PUBLIC_KEY"])

@app.post("/mcp")
@auth.require_tool("db_query")
async def handle_db_query(request: Request):
    facts = request.state.mcpvault_facts
    depth = facts["delegation_depth"]
    subject = facts["subject"]
    # depth tells you how many hops the token has travelled
    return {"depth": depth, "subject": subject}
```

Worker B sends its request with the attenuated token:

```bash
curl -X POST http://mcp-server/mcp \
  -H "Content-Type: application/json" \
  -H "X-MCPVault-Token: <token_b>" \
  -d '{"method": "tools/call", "params": {"name": "db_query"}}'
```

---

## Adding Resource Limits

Use `resource_limit` facts to cap what workers can consume at each delegation level:

```python
# Orchestrator mints with a 1000-row cap
root_token = vault.mint(priv_key, {
    "tools": ["db_query"],
    "ttl": 3600,
    "issuer": "orchestrator",
    "subject": "root",
    "resource_limits": [("db_query", "max_rows", 1000)],
})

# Worker A attenuates down to 100 rows
token_a = vault.attenuate(root_token, pub_key, {
    "tools": ["db_query"],
    "ttl": 1800,
    "resource_limits": [("db_query", "max_rows", 100)],
})
```

The attenuation block adds a Datalog check:

```datalog
check if resource_limit("db_query", "max_rows", $max), $max <= 100;
```

This check is evaluated at the MCP server — a worker cannot claim a higher limit than what its token allows.

---

## Key Rules

- **Attenuation is monotone**: each delegation step can only restrict, never expand, the parent token's grants
- **`delegation_depth` auto-increments**: the SDK increments it on each `attenuate()` call; root starts at 0
- **TTL must be shorter**: you cannot set a longer TTL in an attenuation block than the parent token has remaining
- **Root public key is all you need**: the MCP server only needs the public key — no network calls to any authorization service during verification

---

## Next Steps

- [Migrate from API Keys](migrate-from-api-keys.md) — step-by-step transition guide
- [Datalog Policy Reference](../concepts/datalog-reference.md) — full fact and check syntax
- [How It Works](../concepts/how-it-works.md) — Biscuit token internals
