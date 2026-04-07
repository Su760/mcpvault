//! `TokenProvider` trait and `BiscuitProvider` concrete implementation.

use std::collections::HashMap;
use std::time::SystemTime;

use biscuit_auth::builder::{BlockBuilder, Term};
use biscuit_auth::{AuthorizerBuilder, Biscuit, KeyPair, PublicKey, UnverifiedBiscuit};

use crate::policy::{
    authorizer_policy, block_check_delegation_cap, block_check_resource_limit, block_check_ttl,
    check_delegation_cap, check_ttl_duration, fact_delegation_depth, fact_identity,
    fact_operation, fact_resource_limit, fact_tool, fact_tool_wildcard, system_time_to_tai_secs,
};
use crate::types::{
    AttenuateConfig, AuthorizedFacts, McpVaultError, MintConfig, TokenInfo, VerifyOptions,
};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

pub trait TokenProvider {
    /// Mint a new authority token signed with `keypair`.
    fn mint(&self, keypair: &KeyPair, config: MintConfig) -> Result<Vec<u8>, McpVaultError>;

    /// Append a restriction block to an existing token (offline delegation).
    fn attenuate(
        &self,
        token: &[u8],
        root_public_key: &PublicKey,
        config: AttenuateConfig,
    ) -> Result<Vec<u8>, McpVaultError>;

    /// Verify a token and return the authorized facts.
    fn verify(
        &self,
        token: &[u8],
        public_key: &PublicKey,
        options: VerifyOptions,
    ) -> Result<AuthorizedFacts, McpVaultError>;

    /// Inspect a token without signature verification.
    fn inspect(&self, token: &[u8]) -> Result<TokenInfo, McpVaultError>;
}

// ---------------------------------------------------------------------------
// BiscuitProvider
// ---------------------------------------------------------------------------

/// Stateless Biscuit token provider. Keys are passed per-call.
pub struct BiscuitProvider;

impl TokenProvider for BiscuitProvider {
    fn mint(&self, keypair: &KeyPair, config: MintConfig) -> Result<Vec<u8>, McpVaultError> {
        let mut builder = Biscuit::builder();

        match &config.tools {
            None => {
                builder = fact_tool_wildcard(builder)?;
            }
            Some(tools) => {
                for name in tools {
                    builder = fact_tool(builder, name)?;
                }
            }
        }

        for (tool, op) in &config.operations {
            builder = fact_operation(builder, tool, *op)?;
        }

        for (tool, key, max) in &config.resource_limits {
            builder = fact_resource_limit(builder, tool, key, *max)?;
        }

        builder = fact_delegation_depth(builder, 0)?;
        builder = fact_identity(builder, &config.issuer, &config.subject)?;
        builder = check_ttl_duration(builder, config.ttl)?;
        builder = check_delegation_cap(builder, config.max_delegation_depth)?;

        let token = builder.build(keypair)?;
        Ok(token.to_vec()?)
    }

    fn attenuate(
        &self,
        token: &[u8],
        root_public_key: &PublicKey,
        config: AttenuateConfig,
    ) -> Result<Vec<u8>, McpVaultError> {
        let biscuit = Biscuit::from(token, root_public_key)?;
        let mut block = BlockBuilder::new();

        // Restrict to specific tools via requested_tool check
        if let Some(tools) = &config.tools {
            for tool_name in tools {
                block = block_check_requested_tool(block, tool_name)?;
            }
        }

        // Restrict operations
        if let Some(ops) = &config.operations {
            for (tool, op) in ops {
                block = block_check_operation(block, tool, *op)?;
            }
        }

        // Tighter TTL
        if let Some(ttl) = config.ttl {
            let expiry = SystemTime::now() + ttl;
            block = block_check_ttl(block, expiry)?;
        }

        // Tighter resource limits
        if let Some(limits) = &config.resource_limits {
            for (tool, key, cap) in limits {
                block = block_check_resource_limit(block, tool, key, *cap)?;
            }
        }

        // Tighter delegation depth cap
        if let Some(max_depth) = config.max_delegation_depth {
            block = block_check_delegation_cap(block, max_depth)?;
        }

        let new_token = biscuit.append(block)?;
        Ok(new_token.to_vec()?)
    }

    fn verify(
        &self,
        token: &[u8],
        public_key: &PublicKey,
        options: VerifyOptions,
    ) -> Result<AuthorizedFacts, McpVaultError> {
        let biscuit = Biscuit::from(token, public_key)?;

        // Revocation check
        for rev_id in biscuit.revocation_identifiers() {
            if options.revocation_list.contains(&rev_id) {
                return Err(McpVaultError::TokenRevoked);
            }
        }

        let current_time = options.current_time.unwrap_or_else(SystemTime::now);
        let now_secs = system_time_to_tai_secs(current_time);

        // Build authorizer with context facts and policies
        let mut time_params = HashMap::new();
        time_params.insert("t".to_string(), Term::Date(now_secs));

        let mut tool_params = HashMap::new();
        tool_params.insert("tool".to_string(), Term::Str(options.requested_tool.clone()));

        let mut ab = AuthorizerBuilder::new();
        ab = ab.code_with_params("time({t});", time_params, HashMap::new())?;
        ab = ab.code_with_params("requested_tool({tool});", tool_params, HashMap::new())?;
        ab = ab.code(authorizer_policy())?;

        let mut authorizer = ab.build(&biscuit)?;

        authorizer
            .authorize()
            .map_err(|_| McpVaultError::AuthorizationFailed)?;

        // Extract facts from the world via query rules
        let tools: Vec<(String,)> = authorizer
            .query("q($n) <- tool($n)")
            .unwrap_or_default();
        let wildcard: Vec<(String,)> = authorizer
            .query("q($w) <- tool_wildcard($w)")
            .unwrap_or_default();
        let ops: Vec<(String, String)> = authorizer
            .query("q($t, $o) <- operation($t, $o)")
            .unwrap_or_default();
        let limits: Vec<(String, String, i64)> = authorizer
            .query("q($t, $k, $m) <- resource_limit($t, $k, $m)")
            .unwrap_or_default();
        let depths: Vec<(i64,)> = authorizer
            .query("q($d) <- delegation_depth($d)")
            .unwrap_or_default();
        let issuers: Vec<(String,)> = authorizer
            .query("q($i) <- issuer($i)")
            .unwrap_or_default();
        let subjects: Vec<(String,)> = authorizer
            .query("q($s) <- subject($s)")
            .unwrap_or_default();

        Ok(AuthorizedFacts {
            tools: tools.into_iter().map(|(n,)| n).collect(),
            tool_wildcard: !wildcard.is_empty(),
            operations: ops,
            resource_limits: limits,
            delegation_depth: depths.into_iter().next().map(|(d,)| d as u32),
            issuer: issuers.into_iter().next().map(|(i,)| i),
            subject: subjects.into_iter().next().map(|(s,)| s),
        })
    }

    fn inspect(&self, token: &[u8]) -> Result<TokenInfo, McpVaultError> {
        let biscuit = UnverifiedBiscuit::from(token)?;

        let block_count = biscuit.block_count();
        let revocation_ids: Vec<String> = biscuit
            .revocation_identifiers()
            .into_iter()
            .map(|id| hex::encode(&id))
            .collect();

        let mut facts = Vec::new();
        let mut checks = Vec::new();

        for i in 0..block_count {
            if let Ok(src) = biscuit.print_block_source(i) {
                facts.push(src.clone());
                checks.push(src);
            }
        }

        Ok(TokenInfo {
            block_count,
            facts,
            checks,
            revocation_ids,
        })
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Adds `check if requested_tool($n), $n == {name}` to an attenuation block.
/// This restricts the token to a specific tool at verify time.
fn block_check_requested_tool(
    builder: BlockBuilder,
    tool_name: &str,
) -> Result<BlockBuilder, biscuit_auth::error::Token> {
    let mut params = HashMap::new();
    params.insert("name".to_string(), Term::Str(tool_name.to_string()));
    builder.code_with_params(
        r#"check if requested_tool($n), $n == {name}"#,
        params,
        HashMap::new(),
    )
}

/// Adds `check if operation($t, $o), $t == {tool}, $o == {op}` to an attenuation block.
fn block_check_operation(
    builder: BlockBuilder,
    tool: &str,
    op: crate::policy::Operation,
) -> Result<BlockBuilder, biscuit_auth::error::Token> {
    let mut params = HashMap::new();
    params.insert("tool".to_string(), Term::Str(tool.to_string()));
    params.insert("op".to_string(), Term::Str(op.as_str().to_string()));
    builder.code_with_params(
        r#"check if operation($t, $o), $t == {tool}, $o == {op}"#,
        params,
        HashMap::new(),
    )
}
