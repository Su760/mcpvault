# MCPVault

**Biscuit-based capability tokens for MCP tool authorization.**

---

## Why MCPVault?

### The Confused Deputy Problem in MCP

When an AI agent calls an MCP tool, the MCP server has no reliable way to know _what the agent was authorized to do_. A static API key proves identity — not capability. An orchestrator that holds an `ADMIN_API_KEY` can pass it, unmodified, to every sub-agent it spawns. Those sub-agents can call any tool, read any resource, write anywhere. The key doesn't shrink as it flows downstream.

This is the confused deputy problem: the server (deputy) acts on behalf of the agent (principal) but has no way to verify that the action falls within what the agent was originally authorized to do. A sub-agent that should only run read-only queries can accidentally — or maliciously — trigger a write operation, because its token grants the same rights as the root.

### Why Static API Keys Fail at Scale

Static API keys are symmetric secrets: whoever holds the key has full authority. They cannot be scoped to a subset of tools, cannot expire on a short TTL, and cannot be safely delegated — you can only share the full key or create a new one out-of-band. In a multi-agent pipeline with five levels of orchestration, managing per-level keys becomes operationally intractable and audits become guesswork.

### What MCPVault Solves

MCPVault introduces _capability tokens_ built on [Biscuit](https://www.biscuitsec.org/): cryptographically signed, self-describing tokens that carry their own authorization policy as Datalog facts. A token minted for `db_query` cannot be used for `file_write`, even if the holder tries. Sub-agents receive _attenuated_ tokens — tokens with strictly fewer rights than the parent — without a round-trip to any authorization server. The attenuation is offline and verifiable at the MCP server using only the root public key.

---

## How It Works

```
1. MINT       Root keyholder issues a token with explicit tool scopes and a TTL.
              vault.mint(priv_key, {tools: ["db_query"], ttl: 3600, ...})

2. DELEGATE   Orchestrator attenuates before handing to a sub-agent.
              vault.attenuate(token, pub_key, {tools: ["db_query"], ttl: 1800})

3. VERIFY     MCP server checks the token cryptographically — no network call needed.
              vault.verify(token, pub_key, {requested_tool: "db_query"})

4. REVOKE     Expired tokens fail automatically. Revocation IDs enable explicit invalidation.
```

---

## Install

```bash
pip install mcpvault
```

```bash
cargo install mcpvault  # CLI
```

```bash
npm install mcpvault-express  # Express.js middleware
```

---

## Quickstarts

- [Python + FastAPI](getting-started/python.md) — decorator-based route protection in 20 lines
- [CLI](getting-started/cli.md) — `keygen → mint → attenuate → verify → inspect`
- [Express.js](getting-started/express.md) — `createMcpVaultMiddleware` with full route example
