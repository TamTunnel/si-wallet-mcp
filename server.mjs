#!/usr/bin/env node
// server.mjs — sovereign-identity wallet as an MCP server.
//
// Transports:
//   stdio (default):  node server.mjs
//     For local MCP clients (Claude Code, Hermes, OpenClaw, ...). The process
//     runs as you, keys never leave the machine.
//
//   streamable HTTP:  node server.mjs --http --port 8787
//     Serves POST /mcp (JSON-RPC). REQUIRED env: SI_MCP_TOKEN — every request
//     must carry `Authorization: Bearer <token>`. Bind address defaults to
//     127.0.0.1; set SI_MCP_HOST=0.0.0.0 to expose it, but only behind TLS.
//
// A wallet signs with the owner's and agent's private keys, so think about
// where this process runs: whoever can reach it can ask it to sign. The
// non-custodial model is one server per user, on hardware the user controls.

import http from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import {
  WalletError,
  onboard,
  getDid,
  issueGrant,
  mintMandate,
  verifyMandate,
  verifyChain,
  pairwiseDid,
} from "./lib/wallet.mjs";

const VERSION = "0.1.0";

function makeServer() {
  const server = new McpServer(
    { name: "si-wallet", version: VERSION },
    { capabilities: {} }
  );

  const ok = (data) => ({
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
  });
  const wrap = (fn) => async (args) => {
    try {
      return ok(await fn(args));
    } catch (e) {
      const code = e instanceof WalletError ? e.code : "internal_error";
      return {
        content: [{ type: "text", text: JSON.stringify({ ok: false, code, error: e.message }) }],
        isError: code !== "over_limit" && code !== "bad_grant" && code !== "scope_exceeded" && code !== "amount_exceeded",
      };
    }
  };

  server.tool(
    "wallet_did",
    "Get the DID for the owner or agent identity in this wallet.",
    { role: z.enum(["owner", "agent"]).default("agent").describe("Which identity") },
    wrap(async ({ role }) => getDid(role))
  );

  server.tool(
    "wallet_onboard",
    "Create the owner or agent identity (returns the existing one if present). Requires SI_WALLET_PASSPHRASE.",
    { role: z.enum(["owner", "agent"]).describe("Which identity to create") },
    wrap(async ({ role }) => onboard(role))
  );

  server.tool(
    "issue_grant",
    "Owner issues an agency grant delegating authority to an agent DID (scopes + USD amount limit + TTL).",
    {
      agentDid: z.string().describe("Agent's did:key"),
      scope: z.array(z.string()).describe("Granted scopes, e.g. ['book_flight','read']"),
      amountLimit: z.number().describe("Max USD the agent may commit"),
      ttlDays: z.number().default(365).describe("Grant lifetime in days"),
      note: z.string().default("").describe("Human-readable note"),
    },
    wrap(async (a) => issueGrant(a))
  );

  server.tool(
    "mint_mandate",
    "Agent mints a task mandate for a website audience, bound to an agency grant. Returns the mandate JWS and the Authorization header value. Amounts over $100 need confirmOverLimit=true (only after the owner explicitly approved). Pass subjectDid to delegate to a downstream agent (e.g. Muse delegating to Hermes) with narrowed scope/amount.",
    {
      audience: z.string().describe("Website audience, e.g. 'example.com'"),
      scope: z.array(z.string()).describe("Task scopes (must be a subset of the grant)"),
      amount: z.number().default(0).describe("USD amount for this task"),
      ttlSec: z.number().default(3600).describe("Mandate lifetime in seconds"),
      task: z.string().default("").describe("Human-readable task description"),
      grantJws: z.string().describe("Agency-grant JWS from issue_grant (or a parent mandate JWS when delegating)"),
      confirmOverLimit: z.boolean().default(false).describe("Owner confirmed amounts over $100"),
      subjectDid: z.string().optional().describe("Downstream agent DID for delegation; defaults to this wallet's agent DID"),
    },
    wrap(async (a) => mintMandate(a))
  );

  server.tool(
    "verify_mandate",
    "Website-side verification of a task mandate chain: signatures, expiry, audience, replay, grant binding, scope/amount confinement. Records the JTI in the local replay ledger on success.",
    {
      mandateJws: z.string().describe("Task mandate JWS"),
      expectedAudience: z.string().optional().describe("Audience this verifier expects"),
    },
    wrap(async (a) => verifyMandate(a))
  );

  server.tool(
    "verify_chain",
    "Website-side verification of a multi-hop delegation chain (Owner → … → leaf agent): walks every link, enforcing parent signatures, parent-issued-to-signer binding, scope subset and amount confinement at each hop, expiry, leaf audience, and replay protection. Returns the full attenuated chain.",
    {
      mandateJws: z.string().describe("Leaf task mandate JWS"),
      expectedAudience: z.string().optional().describe("Audience this verifier expects"),
    },
    wrap(async (a) => verifyChain(a))
  );

  server.tool(
    "pairwise_did",
    "Generate a fresh pairwise DID for one audience (prevents cross-site correlation).",
    { audience: z.string().describe("Site or service this DID is for") },
    wrap(async ({ audience }) => pairwiseDid(audience))
  );

  return server;
}

async function runStdio() {
  const server = makeServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("si-wallet MCP server listening on stdio");
}

async function runHttp() {
  const token = process.env.SI_MCP_TOKEN;
  if (!token) {
    console.error("REFUSED: HTTP mode requires SI_MCP_TOKEN (bearer auth).");
    process.exit(1);
  }
  const host = process.env.SI_MCP_HOST || "127.0.0.1";
  const port = parseInt(process.argv[process.argv.indexOf("--port") + 1] || "8787", 10);

  const srv = http.createServer(async (req, res) => {
    if (req.url !== "/mcp" || req.method !== "POST") {
      res.writeHead(404).end("not found");
      return;
    }
    const auth = req.headers.authorization || "";
    if (auth !== `Bearer ${token}`) {
      res.writeHead(401, { "WWW-Authenticate": "Bearer" }).end("unauthorized");
      return;
    }
    let body = "";
    for await (const chunk of req) body += chunk;
    let msg;
    try {
      msg = JSON.parse(body);
    } catch {
      res.writeHead(400).end("invalid JSON-RPC");
      return;
    }
    const server = makeServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => transport.close().catch(() => {}));
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, msg);
    } catch (e) {
      console.error("request error:", e.message);
      if (!res.headersSent) res.writeHead(500).end("internal error");
    }
  });

  srv.listen(port, host, () =>
    console.error(`si-wallet MCP server listening on http://${host}:${port}/mcp`)
  );
}

const mode = process.argv.includes("--http") ? "http" : "stdio";
if (process.env.SI_MCP_TOKEN === "" ) {
  console.error("REFUSED: SI_MCP_TOKEN must not be empty in HTTP mode.");
  process.exit(1);
}
(mode === "http" ? runHttp() : runStdio()).catch((e) => {
  console.error("fatal: " + e.message);
  process.exit(1);
});
