# Migrate from API Keys

This guide walks you through replacing a static API key with an MCPVault capability token. The migration is additive — you can run both in parallel during a rollout.

---

## Before and After

### Before: Static API key

```python
# Server — checks a hardcoded secret
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()
API_KEY = "sk-abc123-hardcoded-secret"

@app.post("/mcp")
async def handle(request: Request):
    key = request.headers.get("Authorization", "").removeprefix("Bearer ")
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid key")
    # No way to know what this caller is allowed to do
    return {"result": "ok"}
```

Problems:

- Any holder of `sk-abc123` can call any tool
- Key doesn't expire
- Cannot be safely delegated — passing it downstream gives full access
- Revocation requires rotating the secret for all callers

### After: MCPVault capability token

```python
# Server — verifies a scoped, expiring Biscuit token
from fastapi import FastAPI, Request
from mcpvault.middleware.fastapi import MCPVaultAuth

app = FastAPI()
auth = MCPVaultAuth(public_key_hex=PUBLIC_KEY_HEX)

@app.post("/mcp")
@auth.require_tool("db_query")
async def handle(request: Request):
    # Token already verified: scoped to db_query, not expired
    facts = request.state.mcpvault_facts
    return {"result": "ok", "issuer": facts["issuer"]}
```

Benefits:

- Token is scoped to `db_query` — cannot be used for other tools
- Expires automatically via TTL check
- Sub-agents receive attenuated tokens with even fewer rights
- Revocation via revocation ID list (no key rotation needed)

---

## 5-Step Migration Checklist

**Step 1 — Generate a keypair**

```bash
mcpvault keygen --output ~/.mcpvault/keys/prod.json
```

Note the public key hex — this goes into your MCP server configuration.

**Step 2 — Replace the auth middleware**

=== "Python / FastAPI"

    ```python
    # Remove:
    if key != API_KEY: raise HTTPException(...)

    # Add:
    from mcpvault.middleware.fastapi import MCPVaultAuth
    auth = MCPVaultAuth(public_key_hex=os.environ["MCPVAULT_PUBLIC_KEY"])

    @app.post("/mcp")
    @auth.require_tool("your_tool_name")
    async def handle(request: Request): ...
    ```

=== "Express.js"

    ```javascript
    // Remove:
    if (req.headers.authorization !== `Bearer ${API_KEY}`) { ... }

    // Add:
    import { createMcpVaultMiddleware } from "mcpvault-express";
    const auth = createMcpVaultMiddleware({ publicKeyHex: process.env.MCPVAULT_PUBLIC_KEY });
    app.post("/mcp", auth("your_tool_name"), handler);
    ```

**Step 3 — Mint tokens at agent startup**

Never hardcode tokens. Mint at runtime with a short TTL:

```python
from mcpvault import MCPVault

vault = MCPVault()
token = vault.mint(private_key_hex, {
    "tools": ["db_query"],
    "ttl": 3600,           # 1 hour — refresh before expiry
    "issuer": "my-server",
    "subject": f"agent-{agent_id}",
})
```

**Step 4 — Attenuate before delegating**

When passing work to a sub-agent, never pass the root token:

```python
# Root token grants db_query + file_read for 1 hour
# Worker only needs db_query for 30 minutes
worker_token = vault.attenuate(root_token, pub_key, {
    "tools": ["db_query"],
    "ttl": 1800,
})
# Pass worker_token to the sub-agent, not root_token
```

**Step 5 — Add revocation for compromised tokens**

Collect revocation IDs from `mcpvault inspect` and pass them to `verify()`:

```python
# Get revocation IDs from a token
import subprocess, json
result = subprocess.run(
    ["mcpvault", "inspect", "--token", suspicious_token],
    capture_output=True, text=True
)
ids = json.loads(result.stdout)["revocation_ids"]

# Block those IDs on the server
auth = MCPVaultAuth(
    public_key_hex=pub_key,
    revocation_list=ids,
)
```

---

## Common Pitfalls

| Pitfall                                                                                   | Fix                                                                                       |
| ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| **Clock skew** between token issuer and MCP server causes valid tokens to fail TTL checks | Sync clocks with NTP; add a small grace window if needed                                  |
| **Public key distribution** — MCP server has wrong or stale public key                    | Store public key in environment variable or secrets manager; never hardcode               |
| **Passing root token downstream**                                                         | Always call `attenuate()` before delegating; never share the root token                   |
| **TTL too long**                                                                          | Use the shortest TTL that works for your workflow; 1 hour is a reasonable default         |
| **Not checking `delegation_depth`**                                                       | The SDK tracks depth automatically; set `max_delegation_depth` at mint time to cap chains |

---

## Next Steps

- [Multi-Agent Delegation](multi-agent-delegation.md) — full orchestrator → worker → MCP example
- [Datalog Policy Reference](../concepts/datalog-reference.md) — fine-grained operation and resource scoping
