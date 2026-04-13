import time
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from mcpvault import MCPVault

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
vault = MCPVault()
priv_key, pub_key = vault.generate_keypair()
_, wrong_pub_key = vault.generate_keypair()  # different keypair for negative test


def mint(tools=None, ttl=3600):
    """Mint a token with given tools list and ttl."""
    return vault.mint(
        priv_key,
        {
            "tools": tools,
            "ttl": ttl,
            "issuer": "test-issuer",
            "subject": "test-agent",
        },
    )


def build_app(auth):
    """Build a minimal FastAPI app using the given auth guard."""
    app = FastAPI()

    @app.post("/mcp")
    @auth.require_tool("db_query")
    async def handle_mcp(request: Request):
        facts = request.state.mcpvault_facts
        return {"result": "ok", "subject": facts.get("subject")}

    return TestClient(app)


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

def test_valid_token_in_header_returns_200():
    """Happy path: valid token in X-MCPVault-Token header."""
    from mcpvault.middleware.fastapi import MCPVaultAuth

    auth = MCPVaultAuth(public_key_hex=pub_key)
    client = build_app(auth)
    token = mint(tools=["db_query"])
    resp = client.post("/mcp", headers={"X-MCPVault-Token": token})
    assert resp.status_code == 200
    assert resp.json()["result"] == "ok"


def test_valid_token_in_jsonrpc_body_returns_200():
    """Happy path: token in params._meta.token JSON body fallback."""
    from mcpvault.middleware.fastapi import MCPVaultAuth

    auth = MCPVaultAuth(public_key_hex=pub_key)
    client = build_app(auth)
    token = mint(tools=["db_query"])
    payload = {"jsonrpc": "2.0", "method": "tools/call", "params": {"_meta": {"token": token}}}
    resp = client.post("/mcp", json=payload)
    assert resp.status_code == 200


def test_missing_token_returns_401():
    """No token in header or body → 401 missing_token."""
    from mcpvault.middleware.fastapi import MCPVaultAuth

    auth = MCPVaultAuth(public_key_hex=pub_key)
    client = build_app(auth)
    resp = client.post("/mcp", json={})
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "missing_token"


def test_expired_token_returns_401():
    """Token with ttl=1 second, wait 2s → 401 invalid_token."""
    from mcpvault.middleware.fastapi import MCPVaultAuth

    auth = MCPVaultAuth(public_key_hex=pub_key)
    client = build_app(auth)
    token = mint(tools=["db_query"], ttl=1)
    time.sleep(2)
    resp = client.post("/mcp", headers={"X-MCPVault-Token": token})
    assert resp.status_code == 401
    body = resp.json()["detail"]
    assert body["error"] == "invalid_token"


def test_wrong_tool_returns_403():
    """Token grants 'read_data' only; requesting 'db_query' → 403 forbidden."""
    from mcpvault.middleware.fastapi import MCPVaultAuth

    auth = MCPVaultAuth(public_key_hex=pub_key)
    client = build_app(auth)
    token = mint(tools=["read_data"])  # does NOT include db_query
    resp = client.post("/mcp", headers={"X-MCPVault-Token": token})
    assert resp.status_code == 403
    body = resp.json()["detail"]
    assert body["error"] == "forbidden"


def test_wrong_public_key_returns_401():
    """Token signed by priv_key but verified with wrong_pub_key → 401."""
    from mcpvault.middleware.fastapi import MCPVaultAuth

    auth = MCPVaultAuth(public_key_hex=wrong_pub_key)
    client = build_app(auth)
    token = mint(tools=["db_query"])
    resp = client.post("/mcp", headers={"X-MCPVault-Token": token})
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "invalid_token"


def test_attenuated_token_allows_correct_tool():
    """Wildcard token attenuated to db_query → db_query request is 200."""
    from mcpvault.middleware.fastapi import MCPVaultAuth

    auth = MCPVaultAuth(public_key_hex=pub_key)
    client = build_app(auth)
    base_token = mint(tools=None)
    attenuated = vault.attenuate(base_token, pub_key, {"tools": ["db_query"]})
    resp = client.post("/mcp", headers={"X-MCPVault-Token": attenuated})
    assert resp.status_code == 200


def test_attenuated_token_blocks_wrong_tool():
    """Wildcard token attenuated to read_data only → db_query request is 403."""
    from mcpvault.middleware.fastapi import MCPVaultAuth

    auth = MCPVaultAuth(public_key_hex=pub_key)
    client = build_app(auth)
    base_token = mint(tools=None)
    attenuated = vault.attenuate(base_token, pub_key, {"tools": ["read_data"]})
    resp = client.post("/mcp", headers={"X-MCPVault-Token": attenuated})
    assert resp.status_code == 403


def test_facts_injected_into_request_state():
    """Verified facts (subject) are available on request.state.mcpvault_facts."""
    from mcpvault.middleware.fastapi import MCPVaultAuth

    auth = MCPVaultAuth(public_key_hex=pub_key)
    client = build_app(auth)
    token = mint(tools=["db_query"])
    resp = client.post("/mcp", headers={"X-MCPVault-Token": token})
    assert resp.status_code == 200
    assert resp.json()["subject"] == "test-agent"
