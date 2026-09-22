#!/usr/bin/env node
// examples/dogfood/run.mjs — the honest dogfood.
//
// Runs the FULL agent loop the way Meta Muse would against a deployed
// wallet: discovers the merchant's AWAS manifest over HTTP, talks to the
// wallet ONLY through its bearer-authenticated MCP endpoint (no library
// imports, no shared filesystem), mints real mandates, and books a flight.
//
// The wallet and merchant run as separate processes — separate machines in
// production. Start them first:
//
//   # terminal 1 — the wallet (your signing service)
//   SI_MCP_TOKEN="$(openssl rand -hex 32)" SI_WALLET_PASSPHRASE="correct horse" \
//     SI_WALLET_DIR=/tmp/dogfood-wallet node server.mjs --http --port 8789
//
//   # terminal 2 — the merchant (someone else's website; from the AWAS repo)
//   cd <AWAS>/examples/merchant-demo && npm start          # :8788
//
//   # terminal 3 — the agent (this script; stands in for Muse)
//   SI_MCP_TOKEN="<same token>" node examples/dogfood/run.mjs
//
// All identities created here are throwaway test identities. The real
// owner onboarding is yours to run.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const WALLET_URL = process.env.WALLET_URL || "http://127.0.0.1:8789/mcp";
const MERCHANT_URL = process.env.MERCHANT_URL || "http://127.0.0.1:8788";
const TOKEN = process.env.SI_MCP_TOKEN;
if (!TOKEN) {
  console.error("SI_MCP_TOKEN is required (same token the wallet was started with)");
  process.exit(1);
}
// In production this is the site's domain. The demo merchant is hardcoded to it.
const AUDIENCE = "acme.travel";

const step = (n, t) => console.log(`\n── ${n}: ${t}`);
const say = (m) => console.log(`   ${m}`);
const short = (did) => did.slice(0, 24) + "…";

// 0. the wallet enforces bearer auth ------------------------------------------------
step(0, "prove the wallet rejects unauthenticated callers");
{
  const r = await fetch(WALLET_URL, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  if (r.status !== 401) throw new Error(`expected 401, got ${r.status}`);
  say("✅ 401 without a bearer token — strangers can't ask it to sign");
}

// 1. connect as an MCP client, exactly like Muse would --------------------------------
step(1, "connect to the wallet over MCP (streamable HTTP + bearer)");
const client = new Client({ name: "dogfood-agent", version: "1.0.0" });
await client.connect(
  new StreamableHTTPClientTransport(new URL(WALLET_URL), {
    requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
  })
);
const tools = (await client.listTools()).tools.map((t) => t.name);
for (const t of ["wallet_onboard", "issue_grant", "mint_mandate"]) {
  if (!tools.includes(t)) throw new Error(`wallet missing tool ${t}`);
}
say(`✅ connected; wallet exposes: ${tools.join(", ")}`);

const call = async (name, args) => {
  const r = await client.callTool({ name, arguments: args });
  const data = JSON.parse(r.content[0].text);
  if (data.ok === false) throw new Error(`${name} failed: ${data.error || JSON.stringify(data)}`);
  return data;
};

// 2. discover the merchant's AWAS manifest --------------------------------------------
step(2, "discover what the website offers (AWAS manifest)");
const manifest = await (await fetch(`${MERCHANT_URL}/.well-known/ai-actions.json`)).json();
const authCfg = manifest.authentication.mandate;
say(`✅ ${manifest.name} — auth: ${manifest.authentication.methods.join(", ")}`);
say(`   requires scope [${authCfg.required_scope}], max $${authCfg.max_amount_usd}`);

// 3. identities -----------------------------------------------------------------------
step(3, "onboard test identities (throwaway — not a real owner)");
const owner = await call("wallet_onboard", { role: "owner" });
const agent = await call("wallet_onboard", { role: "agent" });
say(`✅ owner ${short(owner.did)}`);
say(`✅ agent ${short(agent.did)}`);

// 4. owner grants the agent authority --------------------------------------------------
step(4, "owner issues an agency grant to the agent");
const grant = await call("issue_grant", {
  agentDid: agent.did,
  scope: ["travel.book", "travel.cancel"],
  amountLimit: 2000,
  ttlDays: 30,
  note: "dogfood: may book/cancel travel",
});
say(`✅ grant ${grant.grant.slice(-8)}: [${grant.scope}] up to $${grant.amount_limit}`);

// 5. search flights (no auth needed) -----------------------------------------------------
step(5, "search flights (read-only, no mandate)");
const search = await (await fetch(`${MERCHANT_URL}/flights/search?from=SFO&to=NRT`)).json();
const flight = search.flights.find((f) => f.id === "AC101");
say(`✅ ${flight.id} ${flight.from}→${flight.to} $${flight.price_usd}`);

// 6. preview with a mandate ----------------------------------------------------------------
step(6, "mint a mandate and preview the booking (dry-run)");
const M1 = await call("mint_mandate", {
  audience: AUDIENCE, scope: ["travel.book"], amount: flight.price_usd,
  ttlSec: 600, task: "Preview SFO→NRT booking", grantJws: grant.grant,
  confirmOverLimit: true,
});
let r = await fetch(`${MERCHANT_URL}/book/preview`, {
  method: "POST",
  headers: { Authorization: `Mandate ${M1.mandate}`, "Content-Type": "application/json" },
  body: JSON.stringify({ flight_id: flight.id, amount: flight.price_usd }),
});
if (r.status !== 200) throw new Error(`preview failed: ${r.status} ${await r.text()}`);
say(`✅ preview OK: $${(await r.json()).total_usd}, nothing charged`);

// 7. book with a fresh mandate ----------------------------------------------------------------
step(7, "mint a fresh mandate and book");
const M2 = await call("mint_mandate", {
  audience: AUDIENCE, scope: ["travel.book"], amount: flight.price_usd,
  ttlSec: 600, task: "Book SFO→NRT flight", grantJws: grant.grant,
  confirmOverLimit: true,
});
r = await fetch(`${MERCHANT_URL}/book`, {
  method: "POST",
  headers: {
    Authorization: `Mandate ${M2.mandate}`,
    "Content-Type": "application/json",
    "Idempotency-Key": "dogfood-" + Date.now(),
  },
  body: JSON.stringify({ flight_id: flight.id, amount: flight.price_usd }),
});
if (r.status !== 200) throw new Error(`book failed: ${r.status} ${await r.text()}`);
const receipt = await r.json();
say(`✅ booked: ${receipt.booking_ref} — $${receipt.amount_usd}`);
say(`   charged to ${receipt.charged_to_owner} via agent ${receipt.booked_by_agent}`);

await client.close();
console.log("\nDogfood complete: manifest → MCP wallet → mandate → booking → receipt.");
console.log("No passwords, no sessions, no OTP codes touched this flow.");
