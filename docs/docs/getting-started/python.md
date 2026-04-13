# Python Quickstart

Install the package:

```bash
pip install mcpvault fastapi httpx
```

## Full Example

```python
from mcpvault import MCPVault
from mcpvault.middleware.fastapi import MCPVaultAuth
from fastapi import FastAPI, Request

vault = MCPVault()

# 1. Generate an Ed25519 keypair (do this once; store securely)
priv_key, pub_key = vault.generate_keypair()

# 2. Mint a root token for agent-alpha, granting access to db_query for 1 hour
token = vault.mint(priv_key, {
    "tools": ["db_query"],
    "ttl": 3600,
    "issuer": "my-server",
    "subject": "agent-alpha",
})

# 3. Attenuate: delegate to a worker with tighter TTL (30 min)
worker_token = vault.attenuate(token, pub_key, {
    "tools": ["db_query"],
    "ttl": 1800,
})

# 4. Protect a FastAPI route — only accepts tokens scoped to db_query
app = FastAPI()
auth = MCPVaultAuth(public_key_hex=pub_key)

@app.post("/mcp")
@auth.require_tool("db_query")
async def handle_mcp_request(request: Request):
    # Verified facts are available on request.state
    facts = request.state.mcpvault_facts
    return {"issuer": facts["issuer"], "subject": facts["subject"]}
```

## Token Transport

MCPVaultAuth accepts the token from either location (in priority order):

| Transport             | Location                                   |
| --------------------- | ------------------------------------------ |
| HTTP (SSE/Streamable) | `X-MCPVault-Token` header                  |
| stdio (JSON-RPC)      | `params._meta.token` field in request body |

## Error Responses

| Condition        | Status | Body                                                      |
| ---------------- | ------ | --------------------------------------------------------- |
| No token         | 401    | `{"detail": {"error": "missing_token"}}`                  |
| Expired token    | 401    | `{"detail": {"error": "invalid_token", "detail": "..."}}` |
| Wrong tool scope | 403    | `{"detail": {"error": "forbidden", "detail": "..."}}`     |
| Bad signature    | 401    | `{"detail": {"error": "invalid_token", "detail": "..."}}` |

## Verified Facts

After a successful check, `request.state.mcpvault_facts` contains:

```python
{
    "tools": ["db_query"],          # granted tool names
    "tool_wildcard": False,         # True if token grants all tools
    "operations": [],               # e.g. [("db_query", "read")]
    "resource_limits": [],          # e.g. [("db_query", "max_rows", 100)]
    "delegation_depth": 1,          # 0 = root, 1 = first attenuation, …
    "issuer": "my-server",
    "subject": "agent-alpha",
}
```

## Next Steps

- [CLI Quickstart](cli.md) — mint and inspect tokens from the terminal
- [Multi-Agent Delegation](../guides/multi-agent-delegation.md) — orchestrator → worker → MCP server
