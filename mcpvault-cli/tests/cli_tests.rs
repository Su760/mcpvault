use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn mcpvault() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mcpvault"))
}

/// keygen --output path creates a file with valid JSON containing 64-char hex keys
#[test]
fn keygen_creates_file_with_valid_json_hex_keys() {
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("test.json");

    let status = mcpvault()
        .args(["keygen", "--output", key_path.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen should exit 0");

    let content = fs::read_to_string(&key_path).unwrap();
    let key: serde_json::Value = serde_json::from_str(&content)
        .expect("output file should be valid JSON");

    let priv_hex = key["private_key"].as_str().expect("private_key field missing");
    let pub_hex = key["public_key"].as_str().expect("public_key field missing");
    assert_eq!(priv_hex.len(), 64, "private_key should be 64 hex chars (32 bytes)");
    assert_eq!(pub_hex.len(), 64, "public_key should be 64 hex chars (32 bytes)");
}

/// mint with keygen output produces non-empty base64 token
#[test]
fn mint_produces_nonempty_base64() {
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("key.json");

    mcpvault()
        .args(["keygen", "--output", key_path.to_str().unwrap()])
        .status().unwrap();

    let output = mcpvault()
        .args([
            "mint",
            "--key", key_path.to_str().unwrap(),
            "--tools", "db_query,file_read",
            "--ttl", "3600",
            "--issuer", "me",
            "--subject", "agent",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "mint should exit 0");
    let token_b64 = String::from_utf8(output.stdout).unwrap().trim().to_string();
    assert!(!token_b64.is_empty(), "minted token should be non-empty");
    // Validate it's base64 (no invalid chars)
    assert!(
        token_b64.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='),
        "token should be valid base64"
    );
}

/// mint | verify round-trip: verify returns success and facts JSON
#[test]
fn mint_verify_roundtrip_succeeds() {
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("key.json");

    // keygen
    mcpvault()
        .args(["keygen", "--output", key_path.to_str().unwrap()])
        .status().unwrap();

    let key_data: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&key_path).unwrap()
    ).unwrap();
    let pub_hex = key_data["public_key"].as_str().unwrap();

    // mint
    let mint_out = mcpvault()
        .args([
            "mint",
            "--key", key_path.to_str().unwrap(),
            "--tools", "db_query",
            "--ttl", "3600",
            "--issuer", "me",
            "--subject", "agent",
        ])
        .output().unwrap();
    assert!(mint_out.status.success());
    let token_b64 = String::from_utf8(mint_out.stdout).unwrap().trim().to_string();

    // verify
    let verify_out = mcpvault()
        .args([
            "verify",
            "--token", &token_b64,
            "--pubkey", pub_hex,
            "--tool", "db_query",
        ])
        .output().unwrap();

    assert!(verify_out.status.success(), "verify should succeed for valid token");
    let facts: serde_json::Value = serde_json::from_str(
        &String::from_utf8(verify_out.stdout).unwrap()
    ).expect("verify output should be valid JSON");
    assert!(facts.is_object(), "verify should return a JSON object");
}

/// mint | attenuate | verify round-trip: attenuated token still verifies for allowed tool
#[test]
fn mint_attenuate_verify_roundtrip_succeeds() {
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("key.json");

    mcpvault()
        .args(["keygen", "--output", key_path.to_str().unwrap()])
        .status().unwrap();

    let key_data: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&key_path).unwrap()
    ).unwrap();
    let pub_hex = key_data["public_key"].as_str().unwrap();

    // mint with two tools
    let mint_out = mcpvault()
        .args([
            "mint",
            "--key", key_path.to_str().unwrap(),
            "--tools", "db_query,file_read",
            "--ttl", "3600",
            "--issuer", "me",
            "--subject", "agent",
        ])
        .output().unwrap();
    assert!(mint_out.status.success());
    let token_b64 = String::from_utf8(mint_out.stdout).unwrap().trim().to_string();

    // attenuate — restrict to db_query only
    let att_out = mcpvault()
        .args([
            "attenuate",
            "--token", &token_b64,
            "--pubkey", pub_hex,
            "--tools", "db_query",
            "--ttl", "1800",
        ])
        .output().unwrap();
    assert!(att_out.status.success(), "attenuate should succeed");
    let att_token = String::from_utf8(att_out.stdout).unwrap().trim().to_string();
    assert!(!att_token.is_empty(), "attenuated token should be non-empty");

    // verify attenuated token for db_query — should succeed
    let verify_out = mcpvault()
        .args([
            "verify",
            "--token", &att_token,
            "--pubkey", pub_hex,
            "--tool", "db_query",
        ])
        .output().unwrap();
    assert!(verify_out.status.success(), "verify of attenuated token for allowed tool should succeed");
}

/// inspect on a fresh minted token shows block_count = 1
#[test]
fn inspect_shows_block_count_1_for_fresh_token() {
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("key.json");

    mcpvault()
        .args(["keygen", "--output", key_path.to_str().unwrap()])
        .status().unwrap();

    let mint_out = mcpvault()
        .args([
            "mint",
            "--key", key_path.to_str().unwrap(),
            "--tools", "db_query",
            "--ttl", "3600",
            "--issuer", "me",
            "--subject", "agent",
        ])
        .output().unwrap();
    assert!(mint_out.status.success());
    let token_b64 = String::from_utf8(mint_out.stdout).unwrap().trim().to_string();

    let inspect_out = mcpvault()
        .args(["inspect", "--token", &token_b64])
        .output().unwrap();

    assert!(inspect_out.status.success(), "inspect should succeed");
    let info: serde_json::Value = serde_json::from_str(
        &String::from_utf8(inspect_out.stdout).unwrap()
    ).expect("inspect output should be valid JSON");
    assert_eq!(info["block_count"], 1, "fresh token should have block_count = 1");
}
