//! Datalog fact and check builders for MCP tool-scope authorization.
//!
//! All functions return a modified `BiscuitBuilder` or `BlockBuilder` using
//! biscuit-auth's consuming builder pattern. Facts are added via raw Datalog
//! strings using `.code()` / `.code_with_params()`.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use biscuit_auth::builder::{BiscuitBuilder, BlockBuilder, Term};
use biscuit_auth::error;

/// Convert SystemTime to TAI-compatible u64 seconds since Unix epoch.
pub(crate) fn system_time_to_tai_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .expect("time must be after Unix epoch")
        .as_secs()
}

// ---------------------------------------------------------------------------
// Operation enum
// ---------------------------------------------------------------------------

/// Operations that can be scoped on an MCP tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Read,
    Write,
    Execute,
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::Read => "read",
            Operation::Write => "write",
            Operation::Execute => "execute",
        }
    }
}

// ---------------------------------------------------------------------------
// Authority-block fact builders (BiscuitBuilder)
// ---------------------------------------------------------------------------

/// Adds `tool({name})` — grants access to a specific MCP tool.
pub fn fact_tool(builder: BiscuitBuilder, tool_name: &str) -> Result<BiscuitBuilder, error::Token> {
    let mut params = HashMap::new();
    params.insert("name".to_string(), Term::Str(tool_name.to_string()));
    builder.code_with_params(r#"tool({name})"#, params, HashMap::new())
}

/// Adds `tool_wildcard("*")` — grants access to all tools.
pub fn fact_tool_wildcard(builder: BiscuitBuilder) -> Result<BiscuitBuilder, error::Token> {
    builder.code(r#"tool_wildcard("*")"#)
}

/// Adds `operation({tool}, {op})` — scopes an operation on a tool.
pub fn fact_operation(
    builder: BiscuitBuilder,
    tool: &str,
    op: Operation,
) -> Result<BiscuitBuilder, error::Token> {
    let mut params = HashMap::new();
    params.insert("tool".to_string(), Term::Str(tool.to_string()));
    params.insert("op".to_string(), Term::Str(op.as_str().to_string()));
    builder.code_with_params(r#"operation({tool}, {op})"#, params, HashMap::new())
}

/// Adds `resource_limit({tool}, {key}, {max})` — numeric constraint.
pub fn fact_resource_limit(
    builder: BiscuitBuilder,
    tool: &str,
    key: &str,
    max: i64,
) -> Result<BiscuitBuilder, error::Token> {
    let mut params = HashMap::new();
    params.insert("tool".to_string(), Term::Str(tool.to_string()));
    params.insert("key".to_string(), Term::Str(key.to_string()));
    params.insert("max".to_string(), Term::Integer(max));
    builder.code_with_params(
        r#"resource_limit({tool}, {key}, {max})"#,
        params,
        HashMap::new(),
    )
}

/// Adds `delegation_depth({depth})` — tracks current delegation depth.
pub fn fact_delegation_depth(
    builder: BiscuitBuilder,
    depth: u32,
) -> Result<BiscuitBuilder, error::Token> {
    let mut params = HashMap::new();
    params.insert("depth".to_string(), Term::Integer(depth as i64));
    builder.code_with_params(r#"delegation_depth({depth})"#, params, HashMap::new())
}

/// Adds `issuer({id})` and `subject({sub})` identity facts.
pub fn fact_identity(
    builder: BiscuitBuilder,
    issuer: &str,
    subject: &str,
) -> Result<BiscuitBuilder, error::Token> {
    let mut params = HashMap::new();
    params.insert("id".to_string(), Term::Str(issuer.to_string()));
    params.insert("sub".to_string(), Term::Str(subject.to_string()));
    builder.code_with_params("issuer({id});\nsubject({sub})", params, HashMap::new())
}

// ---------------------------------------------------------------------------
// Authority-block check builders (BiscuitBuilder)
// ---------------------------------------------------------------------------

/// Adds TTL check: `check if time($t), $t < {expiry}`.
pub fn check_ttl(
    builder: BiscuitBuilder,
    expiry: SystemTime,
) -> Result<BiscuitBuilder, error::Token> {
    let mut params = HashMap::new();
    params.insert(
        "expiry".to_string(),
        Term::Date(system_time_to_tai_secs(expiry)),
    );
    builder.code_with_params(
        r#"check if time($t), $t < {expiry}"#,
        params,
        HashMap::new(),
    )
}

/// Convenience: TTL from a duration from now.
pub fn check_ttl_duration(
    builder: BiscuitBuilder,
    ttl: Duration,
) -> Result<BiscuitBuilder, error::Token> {
    let expiry = SystemTime::now() + ttl;
    check_ttl(builder, expiry)
}

/// Adds delegation depth cap: `check if delegation_depth($d), $d < {max}`.
pub fn check_delegation_cap(
    builder: BiscuitBuilder,
    max_depth: u32,
) -> Result<BiscuitBuilder, error::Token> {
    let mut params = HashMap::new();
    params.insert("max".to_string(), Term::Integer(max_depth as i64));
    builder.code_with_params(
        r#"check if delegation_depth($d), $d < {max}"#,
        params,
        HashMap::new(),
    )
}

// ---------------------------------------------------------------------------
// Attenuation-block check builders (BlockBuilder)
// ---------------------------------------------------------------------------

/// Adds TTL check to an attenuation block.
pub fn block_check_ttl(
    builder: BlockBuilder,
    expiry: SystemTime,
) -> Result<BlockBuilder, error::Token> {
    let mut params = HashMap::new();
    params.insert(
        "expiry".to_string(),
        Term::Date(system_time_to_tai_secs(expiry)),
    );
    builder.code_with_params(
        r#"check if time($t), $t < {expiry}"#,
        params,
        HashMap::new(),
    )
}

/// Adds delegation depth cap check to an attenuation block.
pub fn block_check_delegation_cap(
    builder: BlockBuilder,
    max_depth: u32,
) -> Result<BlockBuilder, error::Token> {
    let mut params = HashMap::new();
    params.insert("max".to_string(), Term::Integer(max_depth as i64));
    builder.code_with_params(
        r#"check if delegation_depth($d), $d < {max}"#,
        params,
        HashMap::new(),
    )
}

/// Adds resource limit check to an attenuation block.
pub fn block_check_resource_limit(
    builder: BlockBuilder,
    tool: &str,
    key: &str,
    max_cap: i64,
) -> Result<BlockBuilder, error::Token> {
    let mut params = HashMap::new();
    params.insert("tool".to_string(), Term::Str(tool.to_string()));
    params.insert("key".to_string(), Term::Str(key.to_string()));
    params.insert("cap".to_string(), Term::Integer(max_cap));
    builder.code_with_params(
        r#"check if resource_limit({tool}, {key}, $max), $max <= {cap}"#,
        params,
        HashMap::new(),
    )
}

// ---------------------------------------------------------------------------
// Authorizer policy Datalog (returned as strings for use with Authorizer)
// ---------------------------------------------------------------------------

/// Returns the standard MCP authorizer policy as a Datalog string.
///
/// This policy should be loaded into the `Authorizer` on the server side.
/// The server must also add `time(now)` and `tool(requested_tool)` facts.
pub fn authorizer_policy() -> &'static str {
    r#"
        // Allow if the token grants the specific tool
        allow if tool($name), requested_tool($name);

        // Allow if the token grants wildcard access
        allow if tool_wildcard("*");

        // Default deny
        deny if true;
    "#
}
