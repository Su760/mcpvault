# Express.js Quickstart

Install the middleware:

```bash
npm install mcpvault-express
```

## Full Example

```javascript
import express from "express";
import { createMcpVaultMiddleware } from "mcpvault-express";

const app = express();
app.use(express.json());

// Create middleware factory with your root public key
const auth = createMcpVaultMiddleware({
  publicKeyHex: process.env.MCPVAULT_PUBLIC_KEY,
});

// Protect a route — only tokens scoped to "db_query" are accepted
app.post("/mcp", auth("db_query"), (req, res) => {
  // req.mcpvaultFacts.verified === true
  res.json({ ok: true, facts: req.mcpvaultFacts });
});

app.listen(3000, () => console.log("MCP server listening on :3000"));
```

Set the environment variable before starting:

```bash
export MCPVAULT_PUBLIC_KEY=a3f8c2d1e4b57690123456789abcdef0...
node server.js
```

---

## Calling the Route

**Using the HTTP header (SSE/Streamable transport):**

```bash
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "X-MCPVault-Token: En0KEwoEd29ya...==" \
  -d '{"method": "tools/call", "params": {"name": "db_query"}}'
```

**Using the JSON body (stdio/JSON-RPC transport):**

```bash
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "db_query",
      "_meta": { "token": "En0KEwoEd29ya...==" }
    }
  }'
```

---

## Token Transport Priority

| Priority     | Location                            |
| ------------ | ----------------------------------- |
| 1 (first)    | `x-mcpvault-token` request header   |
| 2 (fallback) | `req.body.params._meta.token` field |

---

## Error Responses

| Condition        | Status | Body                                                           |
| ---------------- | ------ | -------------------------------------------------------------- |
| No token         | 401    | `{"error": "missing_token"}`                                   |
| Expired token    | 401    | `{"error": "invalid_token", "detail": "token expired"}`        |
| Bad signature    | 401    | `{"error": "invalid_token", "detail": "..."}`                  |
| Wrong tool scope | 403    | `{"error": "forbidden", "detail": "insufficient token scope"}` |

---

## Node.js Version Note

The `@biscuit-auth/biscuit-wasm` package (used internally) requires the WebAssembly runtime. It works out of the box on **Node.js 22+**.

For **Node.js < 22**, add `--experimental-vm-modules` when running Jest tests:

```json
// package.json
{
  "scripts": {
    "test": "node --experimental-vm-modules node_modules/.bin/jest"
  }
}
```

---

## Next Steps

- [CLI Quickstart](cli.md) — mint tokens from the terminal
- [Python Quickstart](python.md) — FastAPI decorator-based protection
- [How It Works](../concepts/how-it-works.md) — Biscuit token chaining explained
