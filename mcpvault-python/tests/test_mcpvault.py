import pytest
from mcpvault import MCPVault, McpVaultError

vault = MCPVault()


def test_generate_keypair_returns_hex_strings():
    priv_key, pub_key = vault.generate_keypair()
    assert isinstance(priv_key, str)
    assert isinstance(pub_key, str)
    # Ed25519 keys are 32 bytes = 64 hex chars
    assert len(priv_key) == 64
    assert len(pub_key) == 64
    assert all(c in "0123456789abcdef" for c in priv_key)
    assert all(c in "0123456789abcdef" for c in pub_key)


def test_mint_returns_nonempty_base64():
    priv_key, pub_key = vault.generate_keypair()
    token = vault.mint(
        priv_key,
        {"tools": ["db_query"], "ttl": 3600, "issuer": "me", "subject": "agent"},
    )
    assert isinstance(token, str)
    assert len(token) > 0
    import base64
    decoded = base64.b64decode(token)
    assert len(decoded) > 0


def test_mint_verify_roundtrip():
    priv_key, pub_key = vault.generate_keypair()
    token = vault.mint(
        priv_key,
        {"tools": ["db_query"], "ttl": 3600, "issuer": "me", "subject": "agent"},
    )
    facts = vault.verify(token, pub_key, {"requested_tool": "db_query"})
    assert "db_query" in facts["tools"]


def test_verify_wrong_tool_raises_mcpvaulterror():
    priv_key, pub_key = vault.generate_keypair()
    token = vault.mint(
        priv_key,
        {"tools": ["db_query"], "ttl": 3600, "issuer": "me", "subject": "agent"},
    )
    with pytest.raises(McpVaultError):
        vault.verify(token, pub_key, {"requested_tool": "other_tool"})


def test_wildcard_tool_grants_any():
    priv_key, pub_key = vault.generate_keypair()
    token = vault.mint(
        priv_key,
        {"tools": None, "ttl": 3600, "issuer": "me", "subject": "agent"},
    )
    facts = vault.verify(token, pub_key, {"requested_tool": "any_arbitrary_tool"})
    assert facts["tool_wildcard"] is True


def test_attenuate_restricts_tool_scope():
    priv_key, pub_key = vault.generate_keypair()
    # Mint with wildcard (tools=None allows any tool)
    token = vault.mint(
        priv_key,
        {"tools": None, "ttl": 3600, "issuer": "me", "subject": "agent"},
    )
    # Attenuate to db_query only
    attenuated = vault.attenuate(token, pub_key, {"tools": ["db_query"]})
    # db_query is allowed — just verify it doesn't raise
    vault.verify(attenuated, pub_key, {"requested_tool": "db_query"})
    # other_tool is blocked
    with pytest.raises(McpVaultError):
        vault.verify(attenuated, pub_key, {"requested_tool": "other_tool"})


def test_authorized_facts_include_identity():
    priv_key, pub_key = vault.generate_keypair()
    token = vault.mint(
        priv_key,
        {
            "tools": ["db_query"],
            "ttl": 3600,
            "issuer": "test-issuer",
            "subject": "test-agent",
        },
    )
    facts = vault.verify(token, pub_key, {"requested_tool": "db_query"})
    assert facts["issuer"] == "test-issuer"
    assert facts["subject"] == "test-agent"


def test_inspect_block_count_after_attenuation():
    priv_key, pub_key = vault.generate_keypair()
    token = vault.mint(
        priv_key,
        {"tools": ["db_query"], "ttl": 3600, "issuer": "me", "subject": "agent"},
    )
    info = vault.inspect(token)
    assert info["block_count"] == 1, "fresh token has 1 block (authority only)"
    attenuated = vault.attenuate(token, pub_key, {"ttl": 1800})
    info2 = vault.inspect(attenuated)
    assert info2["block_count"] == 2, "one attenuation adds one block"


def test_inspect_facts_contain_tool():
    priv_key, pub_key = vault.generate_keypair()
    token = vault.mint(
        priv_key,
        {"tools": ["db_query"], "ttl": 3600, "issuer": "me", "subject": "agent"},
    )
    info = vault.inspect(token)
    assert any("db_query" in f for f in info["facts"])


def test_malformed_token_raises_error():
    priv_key, pub_key = vault.generate_keypair()
    import base64
    garbage = base64.b64encode(b"\xde\xad\xbe\xef\x00\x11\x22").decode()
    with pytest.raises(McpVaultError):
        vault.verify(garbage, pub_key, {"requested_tool": "db_query"})
