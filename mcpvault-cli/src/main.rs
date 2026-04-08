use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use biscuit_auth::{Algorithm, KeyPair, PrivateKey, PublicKey};
use clap::{Parser, Subcommand};
use mcpvault_core::{
    provider::{BiscuitProvider, TokenProvider},
    types::{AttenuateConfig, MintConfig, VerifyOptions},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, path::PathBuf, time::Duration};

// ---------------------------------------------------------------------------
// Key file schema
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct KeyFile {
    private_key: String,
    public_key: String,
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "mcpvault", about = "MCP capability token management")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate an Ed25519 keypair and save to a key file
    Keygen {
        /// Output path (default: ~/.mcpvault/keys/default.json)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Mint a new capability token signed with a private key
    Mint {
        /// Path to key file (JSON with private_key + public_key hex fields)
        #[arg(long)]
        key: PathBuf,
        /// Comma-separated tools to grant; omit to grant wildcard access
        #[arg(long)]
        tools: Option<String>,
        /// Token TTL in seconds
        #[arg(long, default_value = "3600")]
        ttl: u64,
        /// Token issuer identifier
        #[arg(long, default_value = "")]
        issuer: String,
        /// Token subject (agent / principal)
        #[arg(long, default_value = "")]
        subject: String,
    },

    /// Append a restriction block to an existing token
    Attenuate {
        /// Base64-encoded token
        #[arg(long)]
        token: String,
        /// Root public key as hex
        #[arg(long)]
        pubkey: String,
        /// Restrict to these tools (comma-separated)
        #[arg(long)]
        tools: Option<String>,
        /// Tighter TTL in seconds (ignored if looser than existing expiry)
        #[arg(long)]
        ttl: Option<u64>,
    },

    /// Verify a token and print authorized facts as JSON
    Verify {
        /// Base64-encoded token
        #[arg(long)]
        token: String,
        /// Root public key as hex
        #[arg(long)]
        pubkey: String,
        /// Tool name to request access for
        #[arg(long)]
        tool: String,
    },

    /// Inspect a token without signature verification, print block info as JSON
    Inspect {
        /// Base64-encoded token
        #[arg(long)]
        token: String,
    },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_key_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".mcpvault")
        .join("keys")
        .join("default.json")
}

fn load_public_key(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str).context("invalid public key hex")?;
    PublicKey::from_bytes(&bytes, Algorithm::Ed25519).context("invalid public key bytes")
}

fn parse_tools(tools: Option<String>) -> Option<Vec<String>> {
    tools.map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    let provider = BiscuitProvider;

    match cli.command {
        Commands::Keygen { output } => {
            let path = output.unwrap_or_else(default_key_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).context("failed to create key directory")?;
            }

            let kp = KeyPair::new();
            let key_file = KeyFile {
                private_key: hex::encode(kp.private().to_bytes()),
                public_key: hex::encode(kp.public().to_bytes()),
            };

            fs::write(&path, serde_json::to_string_pretty(&key_file)?)
                .context("failed to write key file")?;
            println!("{}", key_file.public_key);
        }

        Commands::Mint {
            key,
            tools,
            ttl,
            issuer,
            subject,
        } => {
            let key_data: KeyFile =
                serde_json::from_str(&fs::read_to_string(&key).context("failed to read key file")?)
                    .context("invalid key file JSON")?;

            let priv_bytes =
                hex::decode(&key_data.private_key).context("invalid private key hex")?;
            let priv_key = PrivateKey::from_bytes(&priv_bytes, Algorithm::Ed25519)
                .context("invalid private key bytes")?;
            let kp = KeyPair::from(&priv_key);

            let config = MintConfig {
                tools: parse_tools(tools),
                operations: vec![],
                resource_limits: vec![],
                ttl: Duration::from_secs(ttl),
                max_delegation_depth: 3,
                issuer,
                subject,
            };

            let token_bytes = provider.mint(&kp, config)?;
            println!("{}", B64.encode(&token_bytes));
        }

        Commands::Attenuate {
            token,
            pubkey,
            tools,
            ttl,
        } => {
            let token_bytes = B64.decode(&token).context("invalid base64 token")?;
            let pub_key = load_public_key(&pubkey)?;

            let config = AttenuateConfig {
                tools: parse_tools(tools),
                operations: None,
                resource_limits: None,
                ttl: ttl.map(Duration::from_secs),
                max_delegation_depth: None,
            };

            let new_bytes = provider.attenuate(&token_bytes, &pub_key, config)?;
            println!("{}", B64.encode(&new_bytes));
        }

        Commands::Verify {
            token,
            pubkey,
            tool,
        } => {
            let token_bytes = B64.decode(&token).context("invalid base64 token")?;
            let pub_key = load_public_key(&pubkey)?;

            let opts = VerifyOptions {
                revocation_list: HashSet::new(),
                current_time: None,
                requested_tool: tool,
            };

            let facts = provider.verify(&token_bytes, &pub_key, opts)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "tools": facts.tools,
                    "tool_wildcard": facts.tool_wildcard,
                    "operations": facts.operations,
                    "resource_limits": facts.resource_limits,
                    "delegation_depth": facts.delegation_depth,
                    "issuer": facts.issuer,
                    "subject": facts.subject,
                }))?
            );
        }

        Commands::Inspect { token } => {
            let token_bytes = B64.decode(&token).context("invalid base64 token")?;
            let info = provider.inspect(&token_bytes)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "block_count": info.block_count,
                    "facts": info.facts,
                    "checks": info.checks,
                    "revocation_ids": info.revocation_ids,
                }))?
            );
        }
    }

    Ok(())
}
