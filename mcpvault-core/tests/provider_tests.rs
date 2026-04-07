use biscuit_auth::KeyPair;
use mcpvault_core::provider::{BiscuitProvider, TokenProvider};
use mcpvault_core::types::{AttenuateConfig, MintConfig, VerifyOptions};
use std::collections::HashSet;
use std::time::Duration;

fn default_mint_config() -> MintConfig {
    MintConfig {
        tools: Some(vec!["db_query".to_string()]),
        operations: vec![],
        resource_limits: vec![],
        ttl: Duration::from_secs(3600),
        max_delegation_depth: 5,
        issuer: "test-issuer".to_string(),
        subject: "test-agent".to_string(),
    }
}

fn default_verify_options(tool: &str) -> VerifyOptions {
    VerifyOptions {
        revocation_list: HashSet::new(),
        current_time: None,
        requested_tool: tool.to_string(),
    }
}

// TEST 1
#[test]
fn test_mint_returns_nonempty_bytes() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;
    let bytes = provider
        .mint(&keypair, default_mint_config())
        .expect("mint should succeed");
    assert!(!bytes.is_empty());
}

// TEST 2 — mint → verify round trip
#[test]
fn test_mint_verify_roundtrip() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;
    let bytes = provider.mint(&keypair, default_mint_config()).unwrap();
    let facts = provider
        .verify(&bytes, &keypair.public(), default_verify_options("db_query"))
        .expect("verify should succeed");
    assert!(facts.tools.contains(&"db_query".to_string()));
}

// TEST 3 — verify with wrong tool fails
#[test]
fn test_verify_wrong_tool_fails() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;
    let bytes = provider.mint(&keypair, default_mint_config()).unwrap();
    let result = provider.verify(&bytes, &keypair.public(), default_verify_options("other_tool"));
    assert!(result.is_err(), "wrong tool should fail authorization");
}

// TEST 4 — wildcard token allows any tool
#[test]
fn test_wildcard_tool_grants_any_tool() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;
    let config = MintConfig {
        tools: None, // wildcard
        ..default_mint_config()
    };
    let bytes = provider.mint(&keypair, config).unwrap();
    let facts = provider
        .verify(
            &bytes,
            &keypair.public(),
            default_verify_options("any_arbitrary_tool"),
        )
        .expect("wildcard should allow any tool");
    assert!(facts.tool_wildcard);
}

// TEST 5 — attenuate restricts to subset of tools
#[test]
fn test_attenuate_restricts_tool_scope() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;
    // Mint with wildcard
    let config = MintConfig {
        tools: None,
        ..default_mint_config()
    };
    let token = provider.mint(&keypair, config).unwrap();

    // Attenuate to db_query only
    let att = AttenuateConfig {
        tools: Some(vec!["db_query".to_string()]),
        operations: None,
        resource_limits: None,
        ttl: None,
        max_delegation_depth: None,
    };
    let attenuated = provider
        .attenuate(&token, &keypair.public(), att)
        .unwrap();

    // db_query should still work
    provider
        .verify(
            &attenuated,
            &keypair.public(),
            default_verify_options("db_query"),
        )
        .expect("db_query should be allowed after attenuation");

    // other_tool should be rejected
    let result = provider.verify(
        &attenuated,
        &keypair.public(),
        default_verify_options("other_tool"),
    );
    assert!(
        result.is_err(),
        "other_tool should be blocked after attenuation"
    );
}

// TEST 6 — TTL enforcement: expired token is rejected
#[test]
fn test_expired_token_is_rejected() {
    use std::time::SystemTime;
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;

    // Mint with 1-second TTL
    let config = MintConfig {
        ttl: Duration::from_secs(1),
        ..default_mint_config()
    };
    let bytes = provider.mint(&keypair, config).unwrap();

    // Verify as if 10 seconds have passed
    let future = SystemTime::now() + Duration::from_secs(10);
    let opts = VerifyOptions {
        current_time: Some(future),
        ..default_verify_options("db_query")
    };
    let result = provider.verify(&bytes, &keypair.public(), opts);
    assert!(result.is_err(), "expired token should be rejected");
}

// TEST 7 — TTL valid when within window
#[test]
fn test_token_valid_within_ttl() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;
    let bytes = provider.mint(&keypair, default_mint_config()).unwrap();
    provider
        .verify(&bytes, &keypair.public(), default_verify_options("db_query"))
        .expect("token should be valid within TTL");
}

// TEST 8 — attenuate adds tighter TTL and token expires sooner
#[test]
fn test_attenuate_tighter_ttl() {
    use std::time::SystemTime;
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;

    // Mint with 1-hour TTL
    let token = provider.mint(&keypair, default_mint_config()).unwrap();

    // Attenuate with 30-second TTL
    let att = AttenuateConfig {
        tools: None,
        operations: None,
        resource_limits: None,
        ttl: Some(Duration::from_secs(30)),
        max_delegation_depth: None,
    };
    let attenuated = provider
        .attenuate(&token, &keypair.public(), att)
        .unwrap();

    // 60 seconds later — should fail (past 30s TTL)
    let slightly_future = SystemTime::now() + Duration::from_secs(60);
    let opts = VerifyOptions {
        current_time: Some(slightly_future),
        ..default_verify_options("db_query")
    };
    let result = provider.verify(&attenuated, &keypair.public(), opts);
    assert!(result.is_err(), "attenuated TTL should expire sooner");
}

// TEST 9 — delegation depth cap: over-deep token fails
#[test]
fn test_delegation_depth_cap_enforced() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;

    // Mint with depth cap of 2
    let config = MintConfig {
        max_delegation_depth: 2,
        ..default_mint_config()
    };
    let token = provider.mint(&keypair, config).unwrap();

    // First attenuate: tighten cap to 1
    let att1 = AttenuateConfig {
        max_delegation_depth: Some(1),
        tools: None,
        operations: None,
        resource_limits: None,
        ttl: None,
    };
    let token1 = provider.attenuate(&token, &keypair.public(), att1).unwrap();

    // Second attenuate: tighten cap to 0
    let att2 = AttenuateConfig {
        max_delegation_depth: Some(0),
        tools: None,
        operations: None,
        resource_limits: None,
        ttl: None,
    };
    let token2 = provider.attenuate(&token1, &keypair.public(), att2).unwrap();

    // delegation_depth(0) < 0 is false → check fails
    let result =
        provider.verify(&token2, &keypair.public(), default_verify_options("db_query"));
    assert!(
        result.is_err(),
        "token with exceeded delegation cap should fail"
    );
}

// TEST 10 — verify with wrong public key fails
#[test]
fn test_verify_wrong_public_key_fails() {
    let keypair = KeyPair::new();
    let wrong_keypair = KeyPair::new();
    let provider = BiscuitProvider;
    let bytes = provider.mint(&keypair, default_mint_config()).unwrap();
    let result = provider.verify(
        &bytes,
        &wrong_keypair.public(),
        default_verify_options("db_query"),
    );
    assert!(result.is_err(), "wrong public key should fail verification");
}

// TEST 11 — malformed bytes rejected
#[test]
fn test_malformed_token_rejected() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;
    let garbage: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22];
    let result = provider.verify(&garbage, &keypair.public(), default_verify_options("db_query"));
    assert!(result.is_err(), "malformed bytes should fail");
}

// TEST 12 — revoked token rejected
#[test]
fn test_revoked_token_rejected() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;
    let bytes = provider.mint(&keypair, default_mint_config()).unwrap();

    // Get revocation IDs via inspect
    let info = provider.inspect(&bytes).unwrap();
    let rev_id = hex::decode(&info.revocation_ids[0]).unwrap();

    let opts = VerifyOptions {
        revocation_list: std::iter::once(rev_id).collect(),
        ..default_verify_options("db_query")
    };
    let result = provider.verify(&bytes, &keypair.public(), opts);
    assert!(
        matches!(result, Err(mcpvault_core::types::McpVaultError::TokenRevoked)),
        "token in revocation list should be rejected"
    );
}

// TEST 13 — inspect shows correct block count
#[test]
fn test_inspect_block_count() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;
    let token = provider.mint(&keypair, default_mint_config()).unwrap();

    let info = provider.inspect(&token).unwrap();
    assert_eq!(
        info.block_count, 1,
        "freshly minted token has 1 block (authority)"
    );

    let att = AttenuateConfig {
        tools: None,
        operations: None,
        resource_limits: None,
        ttl: Some(Duration::from_secs(1800)),
        max_delegation_depth: None,
    };
    let attenuated = provider
        .attenuate(&token, &keypair.public(), att)
        .unwrap();
    let info2 = provider.inspect(&attenuated).unwrap();
    assert_eq!(info2.block_count, 2, "one attenuation adds one block");
}

// TEST 14 — inspect shows expected facts in output
#[test]
fn test_inspect_facts_contain_tool() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;
    let token = provider.mint(&keypair, default_mint_config()).unwrap();
    let info = provider.inspect(&token).unwrap();
    assert!(
        info.facts.iter().any(|f| f.contains("db_query")),
        "facts should contain the granted tool name"
    );
}

// TEST 15 — inspect has revocation IDs (hex strings, non-empty)
#[test]
fn test_inspect_revocation_ids_nonempty() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;
    let token = provider.mint(&keypair, default_mint_config()).unwrap();
    let info = provider.inspect(&token).unwrap();
    assert!(!info.revocation_ids.is_empty(), "must have at least one revocation ID");
    assert!(
        info.revocation_ids[0].chars().all(|c| c.is_ascii_hexdigit()),
        "revocation ID should be hex-encoded"
    );
}

// TEST 16 — resource limits are enforced via check
#[test]
fn test_resource_limit_check_enforced() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;

    // Mint with resource limit: db_query/rows <= 100
    let config = MintConfig {
        tools: Some(vec!["db_query".to_string()]),
        resource_limits: vec![("db_query".to_string(), "rows".to_string(), 100)],
        ..default_mint_config()
    };
    let token = provider.mint(&keypair, config).unwrap();

    // Attenuate with tighter cap: rows <= 10
    // The check is: resource_limit("db_query","rows",$max), $max <= 10
    // Authority has resource_limit("db_query","rows",100) → 100 <= 10 is false → check fails
    let att = AttenuateConfig {
        resource_limits: Some(vec![("db_query".to_string(), "rows".to_string(), 10)]),
        tools: None,
        operations: None,
        ttl: None,
        max_delegation_depth: None,
    };
    let attenuated = provider.attenuate(&token, &keypair.public(), att).unwrap();

    let result =
        provider.verify(&attenuated, &keypair.public(), default_verify_options("db_query"));
    assert!(
        result.is_err(),
        "tighter resource cap should reject tokens with higher limits"
    );
}

// TEST 17 — authorized facts include issuer and subject
#[test]
fn test_authorized_facts_include_identity() {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;
    let bytes = provider.mint(&keypair, default_mint_config()).unwrap();
    let facts = provider
        .verify(&bytes, &keypair.public(), default_verify_options("db_query"))
        .unwrap();
    assert_eq!(facts.issuer.as_deref(), Some("test-issuer"));
    assert_eq!(facts.subject.as_deref(), Some("test-agent"));
}
