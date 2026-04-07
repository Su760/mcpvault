# MCPVault Datalog Schema

Biscuit tokens in MCPVault encode MCP tool-scope authorization using the following Datalog fact and check namespace.

## Facts (Authority Block)

| Fact               | Signature                                                    | Description                                                                     |
| ------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `tool`             | `tool($name: string)`                                        | Grants access to a specific MCP tool by name                                    |
| `tool_wildcard`    | `tool_wildcard("*")`                                         | Grants access to all tools                                                      |
| `operation`        | `operation($tool: string, $op: string)`                      | Scopes an operation on a tool. `$op` is one of `"read"`, `"write"`, `"execute"` |
| `resource_limit`   | `resource_limit($tool: string, $key: string, $max: integer)` | Numeric constraint (e.g. `max_rows`, `max_bytes`)                               |
| `delegation_depth` | `delegation_depth($current: integer)`                        | Current delegation depth (incremented on each attenuation)                      |
| `issuer`           | `issuer($id: string)`                                        | Identity of the token issuer (server or delegating agent)                       |
| `subject`          | `subject($id: string)`                                       | Identity of the token holder (agent or user)                                    |

## Checks

Checks are constraints that must be satisfied at authorization time. They can appear in the authority block or in attenuation blocks (to further restrict a delegated token).

| Check              | Datalog                                                     | Description                                            |
| ------------------ | ----------------------------------------------------------- | ------------------------------------------------------ |
| TTL                | `check if time($t), $t < {expiry}`                          | Token expires at `{expiry}` (u64, seconds since epoch) |
| Delegation cap     | `check if delegation_depth($d), $d < {max}`                 | Reject if delegation chain exceeds `{max}`             |
| Resource limit cap | `check if resource_limit($tool, $key, $max), $max <= {cap}` | Enforce an upper bound on a resource limit             |

## Authorizer Policies (Server-Side)

The MCP server loads these policies into the `Authorizer` along with runtime facts.

### Required Runtime Facts

The server must inject these facts before authorization:

```datalog
// Current time for TTL checks
time(2026-04-06T12:00:00Z);

// The tool being requested
requested_tool("db_query");
```

### Standard Policy

```datalog
// Allow if the token grants the specific requested tool
allow if tool($name), requested_tool($name);

// Allow if the token grants wildcard access
allow if tool_wildcard("*");

// Default deny
deny if true;
```

## Examples

### 1. Mint a token granting access to two tools with a 1-hour TTL

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
check if time($t), $t < 2026-04-06T13:00:00Z;
check if delegation_depth($d), $d < 5;
```

### 2. Attenuate: restrict to read-only on db_query with tighter row limit

```datalog
// Attenuation block (appended by delegating agent)
check if operation("db_query", "read");
check if resource_limit("db_query", "max_rows", $max), $max <= 50;
check if time($t), $t < 2026-04-06T12:30:00Z;
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

## Transport

| Transport             | Token Location             |
| --------------------- | -------------------------- |
| stdio (JSON-RPC)      | `params._meta.token` field |
| HTTP (SSE/Streamable) | `X-MCPVault-Token` header  |

## Design Constraints

- **No third-party blocks**: tokens are sealed to the issuer's key hierarchy
- **Delegation depth**: tracked via `delegation_depth` fact, incremented on each `append()`
- **Default cap**: 5 levels of delegation (configurable at mint time)
- **Key algorithm**: Ed25519 (biscuit-auth default)
