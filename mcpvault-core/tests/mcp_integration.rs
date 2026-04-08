//! MCP transport integration tests.
//!
//! Simulates MCP server token verification via:
//!   - HTTP `X-MCPVault-Token` header
//!   - JSON-RPC `params._meta.token` field
//!
//! No real MCP server process is started; tests exercise the full
//! token-extraction → verification pipeline with realistic message formats.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use biscuit_auth::KeyPair;
use mcpvault_core::provider::{BiscuitProvider, TokenProvider};
use mcpvault_core::transport::{
    build_header_value, embed_token_in_jsonrpc, extract_token_from_header,
    extract_token_from_jsonrpc,
};
use mcpvault_core::types::{AttenuateConfig, AuthorizedFacts, McpVaultError, MintConfig, VerifyOptions};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal JSON-RPC request skeleton for `tools/call`.
struct McpRequest {
    method: String,
    params_name: String,
    id: u64,
}

impl McpRequest {
    fn new(method: &str, tool_name: &str, id: u64) -> Self {
        Self {
            method: method.to_string(),
            params_name: tool_name.to_string(),
            id,
        }
    }

    /// Serialise to JSON string (without a token embedded yet).
    fn to_json(&self) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","method":"{method}","params":{{"name":"{name}"}},"id":{id}}}"#,
            method = self.method,
            name = self.params_name,
            id = self.id,
        )
    }
}

/// Verify token bytes against a public key for a given tool.
fn verify_mcp_request(
    token_bytes: &[u8],
    public_key: &biscuit_auth::PublicKey,
    tool_name: &str,
    opts_override: Option<VerifyOptions>,
) -> Result<AuthorizedFacts, McpVaultError> {
    let provider = BiscuitProvider;
    let opts = opts_override.unwrap_or(VerifyOptions {
        revocation_list: HashSet::new(),
        current_time: None,
        requested_tool: tool_name.to_string(),
    });
    provider.verify(token_bytes, public_key, opts)
}

fn mint_token(keypair: &KeyPair, tools: Option<Vec<String>>) -> Vec<u8> {
    let provider = BiscuitProvider;
    provider
        .mint(
            keypair,
            MintConfig {
                tools,
                operations: vec![],
                resource_limits: vec![],
                ttl: Duration::from_secs(3600),
                max_delegation_depth: 5,
                issuer: "test-issuer".to_string(),
                subject: "test-agent".to_string(),
            },
        )
        .expect("mint should succeed")
}

// ---------------------------------------------------------------------------
// TEST 1: mint → HTTP header → extract → verify (basic round-trip)
// ---------------------------------------------------------------------------
#[test]
fn test_mint_verify_via_http_header() {
    let keypair = KeyPair::new();
    let token_bytes = mint_token(&keypair, Some(vec!["db_query".to_string()]));

    // MCP server receives this header value
    let header_value = build_header_value(&token_bytes);

    // Server extracts token bytes from header
    let extracted = extract_token_from_header(&header_value)
        .expect("header extraction should succeed");

    // Server verifies
    let facts = verify_mcp_request(&extracted, &keypair.public(), "db_query", None)
        .expect("verify should succeed");

    assert!(facts.tools.contains(&"db_query".to_string()));
}

// ---------------------------------------------------------------------------
// TEST 2: mint → JSON-RPC envelope → extract → verify (basic round-trip)
// ---------------------------------------------------------------------------
#[test]
fn test_mint_verify_via_jsonrpc_envelope() {
    let keypair = KeyPair::new();
    let token_bytes = mint_token(&keypair, Some(vec!["db_query".to_string()]));

    // Client embeds token in JSON-RPC request
    let req = McpRequest::new("tools/call", "db_query", 1);
    let json_with_token = embed_token_in_jsonrpc(&req.to_json(), &token_bytes)
        .expect("embed should succeed");

    // MCP server extracts token from JSON-RPC
    let extracted = extract_token_from_jsonrpc(&json_with_token)
        .expect("jsonrpc extraction should succeed");

    // Server verifies
    let facts = verify_mcp_request(&extracted, &keypair.public(), "db_query", None)
        .expect("verify should succeed");

    assert!(facts.tools.contains(&"db_query".to_string()));
    assert_eq!(facts.issuer.as_deref(), Some("test-issuer"));
}

// ---------------------------------------------------------------------------
// TEST 3: attenuated token via header — allowed tool passes
// ---------------------------------------------------------------------------
#[test]
fn test_attenuated_token_via_header_allowed_tool_passes() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;

    // Mint wildcard token then attenuate to db_query only
    let wildcard_token = mint_token(&keypair, None);
    let attenuated = provider
        .attenuate(
            &wildcard_token,
            &keypair.public(),
            AttenuateConfig {
                tools: Some(vec!["db_query".to_string()]),
                operations: None,
                resource_limits: None,
                ttl: None,
                max_delegation_depth: None,
            },
        )
        .expect("attenuate should succeed");

    let header_value = build_header_value(&attenuated);
    let extracted = extract_token_from_header(&header_value).unwrap();

    // db_query is in the allowed set — should succeed
    verify_mcp_request(&extracted, &keypair.public(), "db_query", None)
        .expect("db_query should be allowed by attenuated token");
}

// ---------------------------------------------------------------------------
// TEST 4: attenuated token via header — disallowed tool fails
// ---------------------------------------------------------------------------
#[test]
fn test_attenuated_token_via_header_disallowed_tool_fails() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;

    let wildcard_token = mint_token(&keypair, None);
    let attenuated = provider
        .attenuate(
            &wildcard_token,
            &keypair.public(),
            AttenuateConfig {
                tools: Some(vec!["db_query".to_string()]),
                operations: None,
                resource_limits: None,
                ttl: None,
                max_delegation_depth: None,
            },
        )
        .unwrap();

    let header_value = build_header_value(&attenuated);
    let extracted = extract_token_from_header(&header_value).unwrap();

    // file_write is NOT in the allowed set — should fail
    let result = verify_mcp_request(&extracted, &keypair.public(), "file_write", None);
    assert!(
        result.is_err(),
        "disallowed tool should be rejected by attenuated token"
    );
}

// ---------------------------------------------------------------------------
// TEST 5: expired token in header is rejected
// ---------------------------------------------------------------------------
#[test]
fn test_expired_token_in_header_is_rejected() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;

    // Mint with 1-second TTL
    let token_bytes = provider
        .mint(
            &keypair,
            MintConfig {
                tools: Some(vec!["db_query".to_string()]),
                operations: vec![],
                resource_limits: vec![],
                ttl: Duration::from_secs(1),
                max_delegation_depth: 5,
                issuer: "issuer".to_string(),
                subject: "agent".to_string(),
            },
        )
        .unwrap();

    let header_value = build_header_value(&token_bytes);
    let extracted = extract_token_from_header(&header_value).unwrap();

    // Simulate verification 10 seconds in the future
    let future_time = SystemTime::now() + Duration::from_secs(10);
    let opts = VerifyOptions {
        revocation_list: HashSet::new(),
        current_time: Some(future_time),
        requested_tool: "db_query".to_string(),
    };

    let result = verify_mcp_request(&extracted, &keypair.public(), "db_query", Some(opts));
    assert!(result.is_err(), "expired token should be rejected");
}

// ---------------------------------------------------------------------------
// TEST 6: revoked token in header is rejected
// ---------------------------------------------------------------------------
#[test]
fn test_revoked_token_in_header_is_rejected() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;

    let token_bytes = mint_token(&keypair, Some(vec!["db_query".to_string()]));

    // Collect revocation ID via inspect
    let info = provider.inspect(&token_bytes).unwrap();
    let rev_id = hex::decode(&info.revocation_ids[0]).unwrap();

    let header_value = build_header_value(&token_bytes);
    let extracted = extract_token_from_header(&header_value).unwrap();

    let opts = VerifyOptions {
        revocation_list: std::iter::once(rev_id).collect(),
        current_time: None,
        requested_tool: "db_query".to_string(),
    };

    let result = verify_mcp_request(&extracted, &keypair.public(), "db_query", Some(opts));
    assert!(
        matches!(result, Err(McpVaultError::TokenRevoked)),
        "revoked token should be rejected with TokenRevoked error"
    );
}

// ---------------------------------------------------------------------------
// TEST 7: token with wrong public key is rejected
// ---------------------------------------------------------------------------
#[test]
fn test_wrong_public_key_in_header_is_rejected() {
    let keypair = KeyPair::new();
    let wrong_keypair = KeyPair::new();

    let token_bytes = mint_token(&keypair, Some(vec!["db_query".to_string()]));

    let header_value = build_header_value(&token_bytes);
    let extracted = extract_token_from_header(&header_value).unwrap();

    // MCP server uses wrong public key — simulates wrong server or key mismatch
    let result = verify_mcp_request(&extracted, &wrong_keypair.public(), "db_query", None);
    assert!(
        result.is_err(),
        "token signed with different key should be rejected"
    );
}

// ---------------------------------------------------------------------------
// TEST 8: full JSON-RPC round-trip with attenuated token
// ---------------------------------------------------------------------------
#[test]
fn test_jsonrpc_round_trip_attenuated_allowed_and_denied() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;

    let wildcard_token = mint_token(&keypair, None);
    let attenuated = provider
        .attenuate(
            &wildcard_token,
            &keypair.public(),
            AttenuateConfig {
                tools: Some(vec!["metrics_read".to_string()]),
                operations: None,
                resource_limits: None,
                ttl: None,
                max_delegation_depth: None,
            },
        )
        .unwrap();

    // Embed into JSON-RPC
    let req = McpRequest::new("tools/call", "metrics_read", 42);
    let json_with_token = embed_token_in_jsonrpc(&req.to_json(), &attenuated).unwrap();

    // Allowed tool
    let extracted_allowed = extract_token_from_jsonrpc(&json_with_token).unwrap();
    verify_mcp_request(&extracted_allowed, &keypair.public(), "metrics_read", None)
        .expect("metrics_read should pass");

    // Denied tool — same token, different tool request
    let extracted_denied = extract_token_from_jsonrpc(&json_with_token).unwrap();
    let result = verify_mcp_request(&extracted_denied, &keypair.public(), "admin_exec", None);
    assert!(result.is_err(), "admin_exec should be denied");
}

// ---------------------------------------------------------------------------
// TEST 9: malformed base64 header is rejected gracefully
// ---------------------------------------------------------------------------
#[test]
fn test_malformed_header_returns_error() {
    let result = extract_token_from_header("not-valid-base64!!!");
    assert!(
        matches!(result, Err(McpVaultError::InvalidHeader)),
        "malformed base64 header should return InvalidHeader"
    );
}

// ---------------------------------------------------------------------------
// TEST 10: JSON-RPC missing _meta.token field returns MissingToken error
// ---------------------------------------------------------------------------
#[test]
fn test_jsonrpc_missing_token_field_returns_error() {
    let json = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"db_query"},"id":1}"#;
    let result = extract_token_from_jsonrpc(json);
    assert!(
        matches!(result, Err(McpVaultError::MissingToken)),
        "missing token field should return MissingToken"
    );
}
