"""
FastAPI middleware for MCPVault Biscuit token verification.

Usage:
    from fastapi import FastAPI, Request
    from mcpvault.middleware.fastapi import MCPVaultAuth

    app = FastAPI()
    auth = MCPVaultAuth(public_key_hex="<hex>")

    @app.post("/mcp")
    @auth.require_tool("db_query")
    async def handle_mcp_request(request: Request):
        # request.state.mcpvault_facts contains the verified AuthorizedFacts dict
        return {"result": "ok"}
"""
from __future__ import annotations

import functools
import json as _json
import re
from datetime import datetime, timezone
from typing import Callable, List, Optional

from fastapi import Request
from fastapi.responses import JSONResponse

from mcpvault import MCPVault, McpVaultError


class MCPVaultAuth:
    """Auth guard that verifies MCPVault Biscuit tokens on FastAPI endpoints.

    Args:
        public_key_hex: Hex-encoded Ed25519 public key of the token issuer.
        revocation_list: Optional list of hex-encoded revoked token IDs.
    """

    def __init__(
        self,
        public_key_hex: str,
        revocation_list: Optional[List[str]] = None,
    ) -> None:
        self._vault = MCPVault()
        self._public_key_hex = public_key_hex
        self._revocation_list: List[str] = revocation_list or []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def require_tool(self, tool_name: str) -> Callable:
        """Return a decorator that enforces capability-token auth for ``tool_name``.

        Token extraction order:
          1. ``X-MCPVault-Token`` request header (HTTP transport)
          2. ``params._meta.token`` field in JSON request body (stdio-over-HTTP)

        On success, verified facts are stored on ``request.state.mcpvault_facts``.
        """

        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            async def wrapper(request: Request, *args, **kwargs):
                token_b64 = await self._extract_token(request)

                if token_b64 is None:
                    return JSONResponse(
                        status_code=401,
                        content={"detail": {"error": "missing_token"}},
                    )

                verify_options: dict = {"requested_tool": tool_name}
                if self._revocation_list:
                    verify_options["revocation_list"] = self._revocation_list

                try:
                    facts = self._vault.verify(
                        token_b64,
                        self._public_key_hex,
                        verify_options,
                    )
                except McpVaultError as exc:
                    return self._error_response(exc, token_b64)

                request.state.mcpvault_facts = facts
                return await func(request, *args, **kwargs)

            return wrapper

        return decorator

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _extract_token(self, request: Request) -> Optional[str]:
        """Try header first, then JSON body _meta.token."""
        token = request.headers.get("X-MCPVault-Token")
        if token:
            return token

        try:
            body_bytes = await request.body()
            if body_bytes:
                body = _json.loads(body_bytes)
                token = (
                    body.get("params", {})
                    .get("_meta", {})
                    .get("token")
                )
        except Exception:
            pass

        return token or None

    def _error_response(self, exc: McpVaultError, token_b64: str) -> JSONResponse:
        """Map McpVaultError to the appropriate HTTP error response.

        When the error is 'authorization failed', inspect the token to distinguish
        an expired TTL (→ 401 invalid_token) from a wrong-tool failure (→ 403 forbidden).
        """
        detail_str = str(exc)
        if "authorization failed" in detail_str.lower():
            if self._is_expired(token_b64):
                return JSONResponse(
                    status_code=401,
                    content={"detail": {"error": "invalid_token", "detail": detail_str}},
                )
            return JSONResponse(
                status_code=403,
                content={"detail": {"error": "forbidden", "detail": detail_str}},
            )
        return JSONResponse(
            status_code=401,
            content={"detail": {"error": "invalid_token", "detail": detail_str}},
        )

    def _is_expired(self, token_b64: str) -> bool:
        """Return True if the token's TTL has passed.

        Calls inspect() (no signature check) and parses the expiry datetime
        from the Biscuit check fact: ``check if time($t), $t < <ISO_DATETIME>;``
        """
        try:
            info = self._vault.inspect(token_b64)
            # info is a dict with a 'facts' key containing a list of fact strings
            facts_list = info.get("facts", []) if isinstance(info, dict) else [str(info)]
            combined = "\n".join(facts_list)
            match = re.search(
                r"check if time\(\$t\),\s*\$t\s*<\s*(\S+Z)", combined
            )
            if match:
                expiry = datetime.fromisoformat(match.group(1).rstrip(";"))
                return datetime.now(timezone.utc) >= expiry
        except Exception:
            pass
        return False
