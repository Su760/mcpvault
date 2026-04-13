import {
  Biscuit,
  PublicKey,
  authorizer,
  fact,
  policy,
} from "@biscuit-auth/biscuit-wasm";

/**
 * Create an Express middleware factory for MCPVault Biscuit token verification.
 *
 * @param {object} options
 * @param {string} options.publicKeyHex - Raw hex-encoded Ed25519 public key (without "ed25519/" prefix)
 * @returns {function} auth(toolName) → Express middleware
 */
export function createMcpVaultMiddleware({ publicKeyHex }) {
  const pubkey = PublicKey.fromString(publicKeyHex);

  return function auth(toolName) {
    return async function (req, res, next) {
      const tokenB64 = extractToken(req);
      if (!tokenB64) {
        return res.status(401).json({ error: "missing_token" });
      }

      // 1. Verify signature — throws if key mismatch or malformed token
      let biscuitToken;
      try {
        biscuitToken = Biscuit.fromBase64(tokenB64, pubkey);
      } catch (err) {
        return res
          .status(401)
          .json({ error: "invalid_token", detail: String(err) });
      }

      // 2. Full authorization with current time
      const runAuth = (timeDate) => {
        const ab = authorizer``;
        ab.addFact(fact`time(${timeDate})`);
        ab.addFact(fact`requested_tool(${toolName})`);
        ab.addPolicy(policy`allow if tool($t), requested_tool($t)`);
        ab.addPolicy(policy`allow if tool_wildcard("*")`);
        ab.addPolicy(policy`deny if true`);
        ab.buildAuthenticated(biscuitToken).authorize();
      };

      try {
        runAuth(new Date());
      } catch (_err) {
        // Classify: retry with epoch — if epoch passes, the failure was due to expiry
        try {
          runAuth(new Date(0));
          return res
            .status(401)
            .json({ error: "invalid_token", detail: "token expired" });
        } catch (_epochErr) {
          return res
            .status(403)
            .json({ error: "forbidden", detail: "insufficient token scope" });
        }
      }

      req.mcpvaultFacts = { verified: true };
      next();
    };
  };
}

function extractToken(req) {
  const header = req.headers?.["x-mcpvault-token"];
  if (header) return header;
  return req.body?.params?._meta?.token ?? null;
}
