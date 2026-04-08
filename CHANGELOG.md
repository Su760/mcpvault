# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-07

### Added

#### mcpvault-core

- `BiscuitProvider` — core struct implementing mint, attenuate, verify, and inspect operations
- `mint` — creates Ed25519-signed Biscuit tokens with tool grants, TTL, issuer, subject, and delegation depth cap
- `attenuate` — adds restriction blocks to existing tokens (narrows tool scope and/or TTL; cannot widen)
- `verify` — validates token signature and Datalog policies against a requested tool; returns `AuthorizedFacts`
- `inspect` — examines token structure (block count, facts, revocation IDs) without cryptographic verification
- Datalog policy schema: `tool`, `tool_wildcard`, `operation`, `resource_limit`, `delegation_depth`, `issuer`, `subject` facts
- Expiry check: tokens with elapsed TTL are rejected at verify time
- 17 unit tests covering roundtrips, wrong-key rejection, TTL enforcement, wildcard grants, delegation depth cap, and resource limits
- Criterion benchmark: verify at delegation depth 5 runs in ~184µs

#### mcpvault-python

- PyO3 bindings exposing `MCPVault` class with `generate_keypair`, `mint`, `attenuate`, `verify`, `inspect`
- `McpVaultError` Python exception type for all token errors
- Maturin build config for `manylinux`/`macosx` wheel distribution
- 10 pytest tests covering all public methods

#### mcpvault-cli

- `mcpvault keygen` — generates Ed25519 keypair, saves `{private_key, public_key}` JSON to `~/.mcpvault/keys/default.json` (or `--output`)
- `mcpvault mint` — creates token from key file with `--tools`, `--ttl`, `--issuer`, `--subject`; prints base64
- `mcpvault attenuate` — adds restriction block to existing token; prints new base64 token
- `mcpvault verify` — validates token against public key and `--tool`; prints authorized facts as JSON
- `mcpvault inspect` — prints token structure (block count, facts) without cryptographic verification
- 5 integration tests covering the full keygen → mint → verify pipeline

#### Project

- `SCHEMA.md` — Datalog fact and check reference for token policy authors
- Apache 2.0 license
- GitHub Actions CI: Rust tests, Python tests, Clippy + rustfmt, matrix across Python 3.10–3.13

[0.1.0]: https://github.com/supashramesha/agentvault/releases/tag/v0.1.0
