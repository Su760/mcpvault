# CLI Quickstart

Install the CLI:

```bash
cargo install mcpvault
```

The CLI exposes five subcommands that form a complete token pipeline:

```
keygen → mint → attenuate → verify → inspect
```

---

## 1. keygen — Generate an Ed25519 keypair

```bash
mcpvault keygen
```

Output:

```
Public key: a3f8c2d1e4b57690123456789abcdef0a3f8c2d1e4b57690123456789abcdef0
Keys saved to: /Users/you/.mcpvault/keys/default.json
```

Options:

| Flag              | Default                         | Description                    |
| ----------------- | ------------------------------- | ------------------------------ |
| `--output <PATH>` | `~/.mcpvault/keys/default.json` | Where to save the keypair JSON |

The key file format:

```json
{
  "private_key": "...",
  "public_key": "a3f8c2d1e4b57690123456789abcdef0a3f8c2d1e4b57690123456789abcdef0"
}
```

---

## 2. mint — Issue a root token

```bash
mcpvault mint \
  --key ~/.mcpvault/keys/default.json \
  --tools db_query,file_read \
  --ttl 3600 \
  --issuer my-server \
  --subject agent-alpha
```

Output (base64-encoded Biscuit token):

```
En0KEwoEd29ya...truncated...Aw==
```

Options:

| Flag                 | Required | Default  | Description                                               |
| -------------------- | -------- | -------- | --------------------------------------------------------- |
| `--key <PATH>`       | yes      | —        | Path to keypair JSON from `keygen`                        |
| `--tools <LIST>`     | no       | wildcard | Comma-separated tool names; omit for `tool_wildcard("*")` |
| `--ttl <SECONDS>`    | no       | 3600     | Token lifetime in seconds                                 |
| `--issuer <STRING>`  | no       | `""`     | Issuer identity string                                    |
| `--subject <STRING>` | no       | `""`     | Subject (holder) identity string                          |

---

## 3. attenuate — Delegate with tighter restrictions

```bash
mcpvault attenuate \
  --token "En0KEwoEd29ya...==" \
  --pubkey a3f8c2d1e4b57690123456789abcdef0a3f8c2d1e4b57690123456789abcdef0 \
  --tools db_query \
  --ttl 1800
```

Output (new base64 token with attenuation block appended):

```
En0KEwoEd29ya...Bw==
```

Options:

| Flag               | Required | Description                                |
| ------------------ | -------- | ------------------------------------------ |
| `--token <BASE64>` | yes      | Token from `mint` or a prior `attenuate`   |
| `--pubkey <HEX>`   | yes      | Root public key (hex)                      |
| `--tools <LIST>`   | no       | Restrict to this subset of tools           |
| `--ttl <SECONDS>`  | no       | Tighter TTL (must be shorter than current) |

---

## 4. verify — Cryptographically verify a token

```bash
mcpvault verify \
  --token "En0KEwoEd29ya...Bw==" \
  --pubkey a3f8c2d1e4b57690123456789abcdef0a3f8c2d1e4b57690123456789abcdef0 \
  --tool db_query
```

Output (JSON `AuthorizedFacts`):

```json
{
  "tools": ["db_query"],
  "tool_wildcard": false,
  "operations": [],
  "resource_limits": [],
  "delegation_depth": 1,
  "issuer": "my-server",
  "subject": "agent-alpha"
}
```

Exits with code `1` and an error message if the token is expired, has a bad signature, or does not grant the requested tool.

---

## 5. inspect — Decode a token without verifying

```bash
mcpvault inspect \
  --token "En0KEwoEd29ya...Bw=="
```

Output:

```json
{
  "block_count": 2,
  "facts": [
    [
      "tool(\"db_query\")",
      "tool(\"file_read\")",
      "delegation_depth(0)",
      "issuer(\"my-server\")",
      "subject(\"agent-alpha\")"
    ],
    ["check if time($t), $t < 2026-04-13T14:00:00Z"]
  ],
  "checks": [
    [
      "check if time($t), $t < 2026-04-13T13:00:00Z",
      "check if delegation_depth($d), $d < 5"
    ],
    ["check if time($t), $t < 2026-04-13T14:00:00Z"]
  ],
  "revocation_ids": ["1a2b3c4d...", "5e6f7a8b..."]
}
```

`inspect` does **not** verify the signature. Use it for debugging and human-readable token inspection.

---

## Next Steps

- [Python Quickstart](python.md) — protect FastAPI routes with `MCPVaultAuth`
- [Express.js Quickstart](express.md) — `createMcpVaultMiddleware` for Node.js
- [Datalog Policy Reference](../concepts/datalog-reference.md) — full fact and check syntax
