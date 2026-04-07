use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use biscuit_auth::{Algorithm, KeyPair, PrivateKey, PublicKey};
use mcpvault_core::{
    provider::{BiscuitProvider, TokenProvider},
    types::{AttenuateConfig, MintConfig, Operation, VerifyOptions},
};
use pyo3::{exceptions::PyException, prelude::*, types::PyDict};
use std::{collections::HashSet, time::Duration};

pyo3::create_exception!(mcpvault, McpVaultError, PyException);

fn map_err(e: impl std::fmt::Display) -> PyErr {
    McpVaultError::new_err(e.to_string())
}

fn b64_decode(s: &str) -> PyResult<Vec<u8>> {
    B64.decode(s).map_err(map_err)
}

fn hex_decode_pubkey(hex_str: &str) -> PyResult<PublicKey> {
    let bytes = hex::decode(hex_str).map_err(map_err)?;
    PublicKey::from_bytes(&bytes, Algorithm::Ed25519).map_err(map_err)
}

fn parse_op(s: &str) -> PyResult<Operation> {
    match s.to_lowercase().as_str() {
        "read" => Ok(Operation::Read),
        "write" => Ok(Operation::Write),
        "execute" => Ok(Operation::Execute),
        _ => Err(McpVaultError::new_err(format!("unknown operation: {s}"))),
    }
}

fn parse_mint_config(d: &Bound<'_, PyDict>) -> PyResult<MintConfig> {
    let tools: Option<Vec<String>> = d
        .get_item("tools")?
        .and_then(|v| v.extract::<Option<Vec<String>>>().ok().flatten());
    let ttl_secs: u64 = d
        .get_item("ttl")?
        .ok_or_else(|| McpVaultError::new_err("MintConfig missing 'ttl'"))?
        .extract()?;
    let issuer: String = d
        .get_item("issuer")?
        .ok_or_else(|| McpVaultError::new_err("MintConfig missing 'issuer'"))?
        .extract()?;
    let subject: String = d
        .get_item("subject")?
        .ok_or_else(|| McpVaultError::new_err("MintConfig missing 'subject'"))?
        .extract()?;
    let max_delegation_depth: u32 = d
        .get_item("max_delegation_depth")?
        .and_then(|v| v.extract().ok())
        .unwrap_or(5);
    let operations: Vec<(String, Operation)> = match d.get_item("operations")? {
        Some(v) => {
            let list: Vec<(String, String)> = v.extract()?;
            list.into_iter()
                .map(|(t, op)| Ok((t, parse_op(&op)?)))
                .collect::<PyResult<_>>()?
        }
        None => vec![],
    };
    let resource_limits: Vec<(String, String, i64)> = d
        .get_item("resource_limits")?
        .and_then(|v| v.extract().ok())
        .unwrap_or_default();
    Ok(MintConfig {
        tools,
        operations,
        resource_limits,
        ttl: Duration::from_secs(ttl_secs),
        max_delegation_depth,
        issuer,
        subject,
    })
}

fn parse_attenuate_config(d: &Bound<'_, PyDict>) -> PyResult<AttenuateConfig> {
    let tools: Option<Vec<String>> = d
        .get_item("tools")?
        .and_then(|v| v.extract::<Option<Vec<String>>>().ok().flatten());
    let ttl = d
        .get_item("ttl")?
        .and_then(|v| v.extract::<u64>().ok())
        .map(Duration::from_secs);
    let max_delegation_depth = d
        .get_item("max_delegation_depth")?
        .and_then(|v| v.extract().ok());
    let operations: Option<Vec<(String, Operation)>> = match d.get_item("operations")? {
        Some(v) => {
            let list: Vec<(String, String)> = v.extract()?;
            Some(
                list.into_iter()
                    .map(|(t, op)| Ok((t, parse_op(&op)?)))
                    .collect::<PyResult<_>>()?,
            )
        }
        None => None,
    };
    let resource_limits: Option<Vec<(String, String, i64)>> =
        d.get_item("resource_limits")?.and_then(|v| v.extract().ok());
    Ok(AttenuateConfig {
        tools,
        operations,
        resource_limits,
        ttl,
        max_delegation_depth,
    })
}

fn parse_verify_options(d: &Bound<'_, PyDict>) -> PyResult<VerifyOptions> {
    let requested_tool: String = d
        .get_item("requested_tool")?
        .ok_or_else(|| McpVaultError::new_err("VerifyOptions missing 'requested_tool'"))?
        .extract()?;
    let revocation_list: HashSet<Vec<u8>> = match d.get_item("revocation_list")? {
        Some(v) => {
            let list: Vec<String> = v.extract()?;
            list.into_iter()
                .map(|s| hex::decode(&s).map_err(map_err))
                .collect::<PyResult<_>>()?
        }
        None => HashSet::new(),
    };
    Ok(VerifyOptions {
        revocation_list,
        current_time: None,
        requested_tool,
    })
}

#[pyclass]
pub struct MCPVault;

#[pymethods]
impl MCPVault {
    #[new]
    fn new() -> Self {
        MCPVault
    }

    fn generate_keypair(&self) -> PyResult<(String, String)> {
        let kp = KeyPair::new();
        let priv_hex = hex::encode(kp.private().to_bytes());
        let pub_hex = hex::encode(kp.public().to_bytes());
        Ok((priv_hex, pub_hex))
    }

    fn mint(&self, private_key_hex: &str, config: &Bound<'_, PyDict>) -> PyResult<String> {
        let priv_bytes = hex::decode(private_key_hex).map_err(map_err)?;
        let priv_key = PrivateKey::from_bytes(&priv_bytes, Algorithm::Ed25519).map_err(map_err)?;
        let kp = KeyPair::from(&priv_key);
        let mc = parse_mint_config(config)?;
        let bytes = BiscuitProvider.mint(&kp, mc).map_err(map_err)?;
        Ok(B64.encode(bytes))
    }

    fn attenuate(
        &self,
        token_b64: &str,
        public_key_hex: &str,
        config: &Bound<'_, PyDict>,
    ) -> PyResult<String> {
        let token_bytes = b64_decode(token_b64)?;
        let pub_key = hex_decode_pubkey(public_key_hex)?;
        let ac = parse_attenuate_config(config)?;
        let bytes = BiscuitProvider
            .attenuate(&token_bytes, &pub_key, ac)
            .map_err(map_err)?;
        Ok(B64.encode(bytes))
    }

    fn verify<'py>(
        &self,
        py: Python<'py>,
        token_b64: &str,
        public_key_hex: &str,
        options: &Bound<'_, PyDict>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let token_bytes = b64_decode(token_b64)?;
        let pub_key = hex_decode_pubkey(public_key_hex)?;
        let opts = parse_verify_options(options)?;
        let facts = BiscuitProvider
            .verify(&token_bytes, &pub_key, opts)
            .map_err(map_err)?;
        let d = PyDict::new_bound(py);
        d.set_item("tools", facts.tools)?;
        d.set_item("tool_wildcard", facts.tool_wildcard)?;
        d.set_item("operations", facts.operations)?;
        d.set_item("resource_limits", facts.resource_limits)?;
        d.set_item("delegation_depth", facts.delegation_depth)?;
        d.set_item("issuer", facts.issuer)?;
        d.set_item("subject", facts.subject)?;
        Ok(d)
    }

    fn inspect<'py>(&self, py: Python<'py>, token_b64: &str) -> PyResult<Bound<'py, PyDict>> {
        let token_bytes = b64_decode(token_b64)?;
        let info = BiscuitProvider.inspect(&token_bytes).map_err(map_err)?;
        let d = PyDict::new_bound(py);
        d.set_item("block_count", info.block_count)?;
        d.set_item("facts", info.facts)?;
        d.set_item("checks", info.checks)?;
        d.set_item("revocation_ids", info.revocation_ids)?;
        Ok(d)
    }
}

#[pymodule]
fn mcpvault(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.0")?;
    m.add_class::<MCPVault>()?;
    m.add("McpVaultError", m.py().get_type_bound::<McpVaultError>())?;
    Ok(())
}
