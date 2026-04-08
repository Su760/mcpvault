//! MCP token transport helpers for HTTP header and JSON-RPC envelope formats.
//!
//! # HTTP header format
//! ```text
//! X-MCPVault-Token: <base64-encoded-token>
//! ```
//!
//! # JSON-RPC envelope format
//! ```json
//! {"jsonrpc":"2.0","method":"tools/call","params":{"name":"db_query","_meta":{"token":"<base64>"}}}
//! ```

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;

use crate::types::McpVaultError;

/// Build the value for the `X-MCPVault-Token` HTTP header from raw token bytes.
///
/// The returned string is standard base64, ready to be used as the header value.
pub fn build_header_value(token_bytes: &[u8]) -> String {
    STANDARD.encode(token_bytes)
}

/// Extract raw token bytes from an `X-MCPVault-Token` HTTP header value.
///
/// The header value must be a base64-encoded biscuit token.
pub fn extract_token_from_header(header: &str) -> Result<Vec<u8>, McpVaultError> {
    STANDARD
        .decode(header.trim())
        .map_err(|_| McpVaultError::InvalidHeader)
}

/// Embed a token into a JSON-RPC request's `params._meta.token` field.
///
/// The `json` argument must be a valid JSON object. The token is base64-encoded
/// and written to `params._meta.token`, creating intermediate objects as needed.
pub fn embed_token_in_jsonrpc(json: &str, token_bytes: &[u8]) -> Result<String, McpVaultError> {
    let mut value: Value =
        serde_json::from_str(json).map_err(|_| McpVaultError::InvalidJson)?;

    let token_b64 = STANDARD.encode(token_bytes);

    // Navigate/create params → _meta → token
    let params = value
        .get_mut("params")
        .and_then(|v| v.as_object_mut())
        .ok_or(McpVaultError::InvalidJson)?;

    let meta = params
        .entry("_meta")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));

    if let Some(meta_obj) = meta.as_object_mut() {
        meta_obj.insert("token".to_string(), Value::String(token_b64));
    } else {
        return Err(McpVaultError::InvalidJson);
    }

    serde_json::to_string(&value).map_err(|_| McpVaultError::InvalidJson)
}

/// Extract raw token bytes from a JSON-RPC request's `params._meta.token` field.
///
/// Returns `McpVaultError::MissingToken` if the field is absent, and
/// `McpVaultError::InvalidJson` if the JSON is malformed or the base64 is invalid.
pub fn extract_token_from_jsonrpc(json: &str) -> Result<Vec<u8>, McpVaultError> {
    let value: Value =
        serde_json::from_str(json).map_err(|_| McpVaultError::InvalidJson)?;

    let token_b64 = value
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get("token"))
        .and_then(|t| t.as_str())
        .ok_or(McpVaultError::MissingToken)?;

    STANDARD
        .decode(token_b64)
        .map_err(|_| McpVaultError::InvalidJson)
}
