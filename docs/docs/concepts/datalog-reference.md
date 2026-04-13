# Datalog Policy Reference

MCPVault tokens encode authorization policy as [Datalog](https://www.biscuitsec.org/docs/reference/datalog/) facts and checks. This reference covers the full fact and check namespace used by the SDK.

---

## Facts (Authority Block)

Facts are asserted in block 0 (the authority block) at mint time. They define what the token grants.

| Fact               | Signature                                                    | Description                                                                     |
| ------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `tool`             | `tool($name: string)`                                        | Grants access to a specific MCP tool by name                                    |
| `tool_wildcard`    | `tool_wildcard("*")`                                         | Grants access to all tools (use with caution)                                   |
| `operation`        | `operation($tool: string, $op: string)`                      | Scopes an operation on a tool. `$op` is one of `"read"`, `"write"`, `"execute"` |
| `resource_limit`   | `resource_limit($tool: string, $key: string, $max: integer)` | Numeric constraint, e.g. `max_rows`, `max_bytes`                                |
| `delegation_depth` | `delegation_depth($current: integer)`                        | Current depth in the delegation chain (0 = root)                                |
| `issuer`           | `issuer($id: string)`                                        | Identity of the token issuer                                                    |
| `subject`          | `subject($id: string)`                                       | Identity of the token holder                                                    |

### Fact Builder Examples

```datalog
// Grant two specific tools
tool("db_query");
tool("file_read");

// Grant all tools (wildcard)
tool_wildcard("*");

// Scope operations
operation("db_query", "read");
operation("file_read", "read");

// Numeric resource limit
resource_limit("db_query", "max_rows", 100);

// Identity facts
issuer("server-01");
subject("agent-alpha");

// Delegation tracking (always starts at 0 in root token)
delegation_depth(0);
```

---

## Checks

Checks are constraints evaluated at authorization time. They appear in the authority block or in attenuation blocks. A token is denied if any check fails.

| Check              | Datalog                                                     | Description                                      |
| ------------------ | ----------------------------------------------------------- | ------------------------------------------------ |
| TTL                | `check if time($t), $t < {expiry}`                          | Token expires at `{expiry}` (RFC 3339 timestamp) |
| Delegation cap     | `check if delegation_depth($d), $d < {max}`                 | Reject if chain exceeds `{max}` levels           |
| Resource limit cap | `check if resource_limit($tool, $key, $max), $max <= {cap}` | Enforce upper bound on a resource limit          |
| Operation scope    | `check if operation($tool, "read")`                         | Restrict to a specific operation type            |

---

## Authorizer Policies (Server-Side)

The MCP server injects runtime facts and runs standard allow/deny policies.

### Required Runtime Facts

```datalog
// Current time (injected by the server at verification)
time(2026-04-13T12:00:00Z);

// The tool being requested
requested_tool("db_query");
```

### Standard Policy

```datalog
// Allow if the token grants the specific requested tool
allow if tool($name), requested_tool($name);

// Allow if the token grants wildcard access
allow if tool_wildcard("*");

// Default deny (must be last)
deny if true;
```

---

## Common Policy Patterns

| Pattern          | Datalog Check                                                   | Where to Add      |
| ---------------- | --------------------------------------------------------------- | ----------------- |
| Read-only access | `check if operation("db_query", "read")`                        | Attenuation block |
| Row cap          | `check if resource_limit("db_query", "max_rows", $m), $m <= 50` | Attenuation block |
| Short TTL        | `check if time($t), $t < 2026-04-13T12:30:00Z`                  | Attenuation block |
| Depth limit      | `check if delegation_depth($d), $d < 3`                         | Authority block   |
| Tool restriction | `check if tool("db_query")` (implicit via `allow` policy)       | Authority block   |

---

## Full Token Example

### 1. Root token — two tools, 1-hour TTL

```datalog
// Authority block
tool("db_query");
tool("file_read");
operation("db_query", "read");
operation("file_read", "read");
resource_limit("db_query", "max_rows", 100);
delegation_depth(0);
issuer("server-01");
subject("agent-alpha");
check if time($t), $t < 2026-04-13T13:00:00Z;
check if delegation_depth($d), $d < 5;
```

### 2. Attenuation block — restrict to db_query, tighter row limit

```datalog
// Appended by delegating agent (offline, no server call)
check if operation("db_query", "read");
check if resource_limit("db_query", "max_rows", $max), $max <= 50;
check if time($t), $t < 2026-04-13T12:30:00Z;
```

### 3. Wildcard token for a trusted orchestrator

```datalog
// Authority block
tool_wildcard("*");
delegation_depth(0);
issuer("root-server");
subject("orchestrator-1");
check if delegation_depth($d), $d < 3;
```

---

## Design Constraints

- **No third-party blocks**: tokens are sealed to the issuer's key hierarchy; external parties cannot append blocks
- **Monotonic restriction**: attenuation blocks can only _reduce_ grants — never expand them
- **Delegation depth**: `delegation_depth` is incremented automatically on each `attenuate()` call
- **Default depth cap**: 5 levels (configurable at mint time via `max_delegation_depth`)
- **Key algorithm**: Ed25519 (biscuit-auth default)

---

## Transport

| Transport             | Token Location                             |
| --------------------- | ------------------------------------------ |
| HTTP (SSE/Streamable) | `X-MCPVault-Token` request header          |
| stdio (JSON-RPC)      | `params._meta.token` field in request body |
