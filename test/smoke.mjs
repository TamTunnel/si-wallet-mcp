// test/smoke.mjs — repeatable smoke test for the si-wallet MCP server.
// Runs the server over stdio and exercises every tool end to end.
// Usage: SI_WALLET_DIR=/tmp/si-smoke SI_WALLET_PASSPHRASE=test-pw node test/smoke.mjs

import { spawn } from "node:child_process";

const server = spawn("node", ["server.mjs"], {
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env },
});

let rid = 0;
let buf = "";
const pending = new Map();
server.stdout.on("data", (d) => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id !== undefined && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  }
});

function call(method, params) {
  return new Promise((resolve) => {
    const id = ++rid;
    pending.set(id, resolve);
    const m = { jsonrpc: "2.0", id, method };
    if (params !== undefined) m.params = params;
    server.stdin.write(JSON.stringify(m) + "\n");
  });
}

const results = [];
function check(name, cond, detail = "") {
  results.push([cond ? "PASS" : "FAIL", name, detail]);
  if (!cond) process.exitCode = 1;
}

async function tcall(tool, args) {
  const r = await call("tools/call", { name: tool, arguments: args });
  return JSON.parse(r.result.content[0].text);
}

const init = await call("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "smoke", version: "0" },
});
check("initialize", init.result?.serverInfo?.name === "si-wallet");
server.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

const tools = (await call("tools/list")).result.tools.map((t) => t.name);
check("tools/list", ["wallet_did","wallet_onboard","issue_grant","mint_mandate","verify_mandate","pairwise_did"].every((t) => tools.includes(t)), tools.join(","));

const owner = await tcall("wallet_onboard", { role: "owner" });
check("wallet_onboard owner", owner.did.startsWith("did:key:z6Mk"));
const agent = await tcall("wallet_onboard", { role: "agent" });
check("wallet_onboard agent", agent.did.startsWith("did:key:z6Mk"));
const did = await tcall("wallet_did", { role: "agent" });
check("wallet_did", did.did === agent.did);

const grant = await tcall("issue_grant", { agentDid: agent.did, scope: ["book_flight", "read"], amountLimit: 500 });
check("issue_grant", grant.grant.split(".").length === 3);

const mandate = await tcall("mint_mandate", {
  audience: "example.com", scope: ["book_flight"], amount: 50,
  task: "smoke test", grantJws: grant.grant,
});
check("mint_mandate", mandate.authorizationHeader.startsWith("Mandate eyJ"));

const v = await tcall("verify_mandate", { mandateJws: mandate.mandate, expectedAudience: "example.com" });
check("verify_mandate ok", v.ok === true && v.owner === owner.did && v.scope.includes("book_flight"));

const v2 = await tcall("verify_mandate", { mandateJws: mandate.mandate, expectedAudience: "example.com" });
check("replay rejected", v2.ok === false && /replay/.test(v2.reason));

const big = await tcall("mint_mandate", { audience: "example.com", scope: ["read"], amount: 5000, grantJws: grant.grant });
check("over-limit refused", big.ok === false && big.code === "over_limit");

const tampered = mandate.mandate.slice(0, -1) + "X";
const v3 = await tcall("verify_mandate", { mandateJws: tampered });
check("non-canonical base64url rejected", v3.ok === false);

const pw = await tcall("pairwise_did", { audience: "example.com" });
check("pairwise_did", pw.did.startsWith("did:key:z6Mk") && pw.did !== agent.did);

for (const [s, n, d] of results) console.log(`${s}  ${n}${d ? "  " + d : ""}`);
server.kill();
