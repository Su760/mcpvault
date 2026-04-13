import request from "supertest";
import express from "express";
import { KeyPair, biscuit, block } from "@biscuit-auth/biscuit-wasm";
import { createMcpVaultMiddleware } from "../src/index.js";

// ─── Shared test state ────────────────────────────────────────────────────────
let kp, pubHex, auth;

beforeAll(() => {
  kp = new KeyPair();
  // toString() returns "ed25519/<hex>" — strip the prefix for our middleware
  pubHex = kp.getPublicKey().toString().split("/")[1];
  auth = createMcpVaultMiddleware({ publicKeyHex: pubHex });
});

// Helper: mint a signed token with given tool and TTL
function mintToken({ tool = "db_query", ttlMs = 3_600_000 } = {}) {
  return biscuit`
    tool(${tool});
    issuer("test-issuer");
    subject("test-agent");
    check if time($t), $t < ${new Date(Date.now() + ttlMs)};
  `
    .build(kp.getPrivateKey())
    .toBase64();
}

// Helper: mint a wildcard root then attenuate to restrict requested_tool
function mintAttenuated({ allowedTool = "db_query", ttlMs = 3_600_000 } = {}) {
  const root = biscuit`
    tool_wildcard("*");
    issuer("test-issuer");
    subject("test-agent");
    check if time($t), $t < ${new Date(Date.now() + ttlMs)};
  `.build(kp.getPrivateKey());
  const attenuated = root.appendBlock(block`
    check if requested_tool(${allowedTool});
  `);
  return attenuated.toBase64();
}

// Helper: build an Express app where POST /mcp is protected by auth(toolName)
function buildApp(toolName) {
  const app = express();
  app.use(express.json());
  app.post("/mcp", auth(toolName), (req, res) => {
    res.json(req.mcpvaultFacts ?? {});
  });
  return app;
}

// ─── Test 3: Missing token ────────────────────────────────────────────────────
test("missing token → 401 missing_token", async () => {
  const app = buildApp("db_query");
  const res = await request(app).post("/mcp").send({});
  expect(res.status).toBe(401);
  expect(res.body.error).toBe("missing_token");
});

// ─── Test 5: Wrong public key ─────────────────────────────────────────────────
test("wrong public key → 401 invalid_token", async () => {
  const otherKp = new KeyPair();
  const wrongPubHex = otherKp.getPublicKey().toString().split("/")[1];
  const wrongAuth = createMcpVaultMiddleware({ publicKeyHex: wrongPubHex });

  const app = express();
  app.use(express.json());
  app.post("/mcp", wrongAuth("db_query"), (req, res) =>
    res.json(req.mcpvaultFacts ?? {}),
  );

  const res = await request(app)
    .post("/mcp")
    .set("X-MCPVault-Token", mintToken())
    .send({});
  expect(res.status).toBe(401);
  expect(res.body.error).toBe("invalid_token");
});

// ─── Test 8: Expired token ────────────────────────────────────────────────────
test("expired token → 401 invalid_token", async () => {
  const expired = mintToken({ ttlMs: -1 });
  const app = buildApp("db_query");
  const res = await request(app)
    .post("/mcp")
    .set("X-MCPVault-Token", expired)
    .send({});
  expect(res.status).toBe(401);
  expect(res.body.error).toBe("invalid_token");
});

// ─── Test 4: Wrong tool ───────────────────────────────────────────────────────
test("wrong tool → 403 forbidden", async () => {
  const tokenForOtherTool = mintToken({ tool: "read_data" });
  const app = buildApp("db_query");
  const res = await request(app)
    .post("/mcp")
    .set("X-MCPVault-Token", tokenForOtherTool)
    .send({});
  expect(res.status).toBe(403);
  expect(res.body.error).toBe("forbidden");
});

// ─── Test 7: Attenuated token blocks wrong tool ────────────────────────────────
test("attenuated token blocks wrong tool → 403", async () => {
  const tokenB64 = mintAttenuated({ allowedTool: "read_data" });
  const app = buildApp("db_query");
  const res = await request(app)
    .post("/mcp")
    .set("X-MCPVault-Token", tokenB64)
    .send({});
  expect(res.status).toBe(403);
  expect(res.body.error).toBe("forbidden");
});

// ─── Test 1: Valid token in header ────────────────────────────────────────────
test("valid token in header → 200, req.mcpvaultFacts set", async () => {
  const app = buildApp("db_query");
  const res = await request(app)
    .post("/mcp")
    .set("X-MCPVault-Token", mintToken())
    .send({});
  expect(res.status).toBe(200);
  expect(res.body.verified).toBe(true);
});

// ─── Test 2: Valid token in body _meta.token ──────────────────────────────────
test("valid token in body _meta.token → 200", async () => {
  const app = buildApp("db_query");
  const res = await request(app)
    .post("/mcp")
    .send({ params: { _meta: { token: mintToken() } } });
  expect(res.status).toBe(200);
  expect(res.body.verified).toBe(true);
});

// ─── Test 6: Attenuated token allows correct tool ─────────────────────────────
test("attenuated token allows correct tool → 200", async () => {
  const tokenB64 = mintAttenuated({ allowedTool: "db_query" });
  const app = buildApp("db_query");
  const res = await request(app)
    .post("/mcp")
    .set("X-MCPVault-Token", tokenB64)
    .send({});
  expect(res.status).toBe(200);
  expect(res.body.verified).toBe(true);
});
