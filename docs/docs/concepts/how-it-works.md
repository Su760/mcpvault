# How It Works

MCPVault uses [Biscuit tokens](https://www.biscuitsec.org/) — a cryptographic capability token format built on Ed25519 signatures and Datalog authorization policies.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Root Keyholder / OAuth AS                 │
│              (holds Ed25519 private key)                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           │  mint(tools=["*"], ttl=3600)
                           │  → root token (~340 bytes)
                           ▼
                  ┌────────────────┐
                  │   Agent A      │
                  │  (Orchestrator)│
                  └───────┬────────┘
                           │
                           │  attenuate(tools=["db_query"], ttl=1800)
                           │  → adds a block to the token (offline)
                           ▼
                  ┌────────────────┐
                  │   Agent B      │
                  │   (Worker)     │
                  └───────┬────────┘
                           │
                           │  X-MCPVault-Token: <token>
                           ▼
                  ┌────────────────┐
                  │   MCP Server   │
                  │                │─── verify(tool="db_query") ───► AuthorizedFacts
                  │  (Deputy)      │    (checks signature + policy,
                  └────────────────┘     no network call required)
```

---

## Key Concepts

### 1. Biscuit Token Structure

A Biscuit token is a sequence of _blocks_, each containing Datalog facts and checks:

- **Authority block** (block 0): Created by the root keyholder. Contains the initial set of facts (`tool(...)`, `issuer(...)`, etc.) and checks (TTL, delegation cap). Signed with the private key.
- **Attenuation blocks** (blocks 1..N): Appended offline by any token holder. Each block can only _restrict_ — never expand — the authority block's grants. Sealed with an ephemeral key chained to the root signature.

The MCP server only needs the **root public key** to verify the entire chain.

### 2. Offline Attenuation

Attenuation requires no round-trip to an authorization server. Agent A can derive a scoped token for Agent B without network access:

```
root_token  →  attenuate(tools=["db_query"])  →  worker_token
```

The worker token is cryptographically bound to the root token. A forged or tampered block fails signature verification at the MCP server.

### 3. Datalog Authorization

Each call to `verify()` runs a Datalog authorizer that evaluates:

1. Facts from the token blocks (tools granted, issuer, subject, …)
2. Runtime facts injected by the server (current time, requested tool)
3. Standard allow/deny policies

```datalog
// Server injects at verification time:
time(2026-04-13T12:00:00Z);
requested_tool("db_query");

// Token's authority block:
tool("db_query");
check if time($t), $t < 2026-04-13T13:00:00Z;

// Standard allow policy:
allow if tool($name), requested_tool($name);
deny if true;
```

If all checks pass and an `allow` rule fires, verification succeeds. Any failing check short-circuits to denial.

### 4. Revocation

Each block carries a `revocation_id` — a unique hex identifier. The MCP server can maintain a revocation list and pass it to `verify()`:

```python
facts = vault.verify(token, pub_key, {
    "requested_tool": "db_query",
    "revocation_list": ["1a2b3c4d..."],  # revoked IDs
})
```

Expired tokens fail automatically via TTL checks — no revocation list needed for expiry.

---

## Performance

| Metric                         | Value      |
| ------------------------------ | ---------- |
| Token size (per block)         | ~340 bytes |
| Verification latency (depth 5) | 184 µs     |
| Key algorithm                  | Ed25519    |
| Max delegation depth (default) | 5 levels   |

Benchmarks from `benches/verify_depth5.rs` on an M-series Mac. Verification is CPU-bound and allocation-free in the hot path.

---

## Next Steps

- [Datalog Policy Reference](datalog-reference.md) — full fact and check syntax
- [Multi-Agent Delegation](../guides/multi-agent-delegation.md) — end-to-end orchestrator → worker → MCP example
