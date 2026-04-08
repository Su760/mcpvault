//! Configuration types, result types, and errors for MCPVault token operations.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use thiserror::Error;

pub use crate::policy::Operation;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum McpVaultError {
    #[error("biscuit token error: {0}")]
    Token(#[from] biscuit_auth::error::Token),

    #[error("authorization failed")]
    AuthorizationFailed,

    #[error("token has been revoked")]
    TokenRevoked,

    #[error("invalid X-MCPVault-Token header: expected base64-encoded token")]
    InvalidHeader,

    #[error("invalid JSON-RPC payload")]
    InvalidJson,

    #[error("token missing from JSON-RPC params._meta.token")]
    MissingToken,
}

// ---------------------------------------------------------------------------
// Mint
// ---------------------------------------------------------------------------

/// Configuration for minting a new authority token.
///
/// Set `tools` to `None` to grant wildcard access to all tools.
/// Set `tools` to `Some(vec![...])` to restrict to specific named tools.
#[derive(Debug, Clone)]
pub struct MintConfig {
    /// Tools to grant. `None` → wildcard (`tool_wildcard("*")`).
    pub tools: Option<Vec<String>>,
    /// Per-tool operation scopes: `(tool_name, operation)`.
    pub operations: Vec<(String, Operation)>,
    /// Numeric resource limits: `(tool_name, key, max)`.
    pub resource_limits: Vec<(String, String, i64)>,
    /// Token TTL counted from mint time.
    pub ttl: Duration,
    /// Maximum delegation depth (checked at verify time).
    pub max_delegation_depth: u32,
    /// Token issuer identifier.
    pub issuer: String,
    /// Token subject (agent / principal).
    pub subject: String,
}

// ---------------------------------------------------------------------------
// Attenuate
// ---------------------------------------------------------------------------

/// Checks to add when attenuating a token.
///
/// `None` fields add no check for that dimension.
#[derive(Debug, Clone)]
pub struct AttenuateConfig {
    /// Restrict to these tools (adds `check if tool($n), $n == "x"` per tool).
    pub tools: Option<Vec<String>>,
    /// Restrict operations: `(tool_name, operation)`.
    pub operations: Option<Vec<(String, Operation)>>,
    /// Tighten resource limits: `(tool_name, key, cap)`.
    pub resource_limits: Option<Vec<(String, String, i64)>>,
    /// Tighter TTL (ignored if later than the current token expiry).
    pub ttl: Option<Duration>,
    /// Tighter delegation depth cap.
    pub max_delegation_depth: Option<u32>,
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// Options for verifying a token.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Set of revoked block revocation IDs (raw bytes). Any match → rejected.
    pub revocation_list: HashSet<Vec<u8>>,
    /// Override the "current time" used for TTL checks. `None` → `SystemTime::now()`.
    pub current_time: Option<SystemTime>,
    /// The tool the caller is requesting access to.
    pub requested_tool: String,
}

// ---------------------------------------------------------------------------
// Verify result
// ---------------------------------------------------------------------------

/// Facts extracted from a successfully authorized token.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizedFacts {
    /// Granted tool names (from `tool($name)` facts in the authority block).
    pub tools: Vec<String>,
    /// Whether wildcard tool access was granted.
    pub tool_wildcard: bool,
    /// Granted operations: `(tool_name, op_string)`.
    pub operations: Vec<(String, String)>,
    /// Resource limits: `(tool_name, key, max)`.
    pub resource_limits: Vec<(String, String, i64)>,
    /// Delegation depth from authority block.
    pub delegation_depth: Option<u32>,
    /// Issuer identity.
    pub issuer: Option<String>,
    /// Subject identity.
    pub subject: Option<String>,
}

// ---------------------------------------------------------------------------
// Inspect result
// ---------------------------------------------------------------------------

/// Human-readable inspection output from an (optionally unverified) token.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// Number of blocks (authority + attenuation blocks).
    pub block_count: usize,
    /// Human-readable facts per block (one entry per block).
    pub facts: Vec<String>,
    /// Human-readable checks per block (one entry per block).
    pub checks: Vec<String>,
    /// Per-block revocation IDs as hex strings.
    pub revocation_ids: Vec<String>,
}
