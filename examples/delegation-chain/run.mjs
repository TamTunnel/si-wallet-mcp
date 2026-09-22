#!/usr/bin/env node
// examples/delegation-chain/run.mjs
//
// Owner → Muse → Hermes delegation demo.
//
// Three independent wallets (separate keystores, as if on separate machines):
//   owner  — the human; holds the root agency-grant signing key
//   muse   — the orchestrating agent; receives a broad grant, delegates narrowly
//   hermes — the downstream agent; receives only what it needs for one task
//
// The website verifies the full chain with verifyChain: every link's
// signature, parent-issued-to-signer binding, scope subset and amount
// confinement at each hop, expiry, leaf audience, and replay protection.
//
// Run:  SI_WALLET_PASSPHRASE=demo-only node examples/delegation-chain/run.mjs
// (Passphrase defaults to a demo value; real deployments use separate secrets.)

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  onboard,
  issueGrant,
  mintMandate,
  verifyChain,
  WalletError,
} from "../../lib/wallet.mjs";

if (!process.env.SI_WALLET_PASSPHRASE) {
  process.env.SI_WALLET_PASSPHRASE = "delegation-demo-only";
}

const base = mkdtempSync(join(tmpdir(), "delegation-demo-"));
const dir = (name) => join(base, name);

async function asWallet(name, fn) {
  const prev = process.env.SI_WALLET_DIR;
  process.env.SI_WALLET_DIR = dir(name);
  try {
    return await fn();
  } finally {
    if (prev === undefined) delete process.env.SI_WALLET_DIR;
    else process.env.SI_WALLET_DIR = prev;
  }
}

const short = (did) => did.slice(0, 24) + "…";
const step = (n, title) => console.log(`\n── step ${n}: ${title}`);
const ok = (msg) => console.log(`   ✅ ${msg}`);
const refused = (msg) => console.log(`   🛡️  refused as expected: ${msg}`);

let n = 0;

// 1. Identities ------------------------------------------------------------
step(++n, "each party onboards its own DID (separate keystores)");
const ownerDid = await asWallet("owner", () => onboard("owner").did);
const museDid = await asWallet("muse", () => onboard("agent").did);
const hermesDid = await asWallet("hermes", () => onboard("agent").did);
console.log(`   owner:  ${short(ownerDid)}\n   muse:   ${short(museDid)}\n   hermes: ${short(hermesDid)}`);

// 2. Owner → Muse grant -----------------------------------------------------
step(++n, "owner grants Muse broad travel authority (up to $2000)");
const G1 = await asWallet("owner", () =>
  issueGrant({
    agentDid: museDid,
    scope: ["travel.book", "travel.cancel"],
    amountLimit: 2000,
    ttlDays: 30,
    note: "Muse may book/cancel travel on my behalf",
  })
);
ok(`grant ${G1.grant.slice(-8)}: scope=[${G1.scope}] limit=$${G1.amount_limit}`);

// 3. Muse → Hermes delegation -----------------------------------------------
step(++n, "Muse delegates to Hermes, attenuated: book-only, up to $500");
const M1 = await asWallet("muse", () =>
  mintMandate({
    audience: "acme.travel",
    scope: ["travel.book"],
    amount: 500,
    confirmOverLimit: true, // owner approved the $500 envelope out-of-band
    task: "Book SFO→NRT for owner",
    grantJws: G1.grant,
    subjectDid: hermesDid,
  })
);
ok(`mandate for ${short(M1.subject)}: scope=[${M1.scope}] limit=$${M1.amount_limit}`);

// 4. Hermes mints the leaf mandate -------------------------------------------
step(++n, "Hermes mints the leaf mandate it will present to acme.travel ($320)");
const M2 = await asWallet("hermes", () =>
  mintMandate({
    audience: "acme.travel",
    scope: ["travel.book"],
    amount: 320,
    confirmOverLimit: true,
    task: "Book SFO→NRT flight",
    grantJws: M1.mandate,
  })
);
ok(`leaf mandate ${M2.mandate.slice(-8)}`);

// 5. Website verifies the whole chain -----------------------------------------
step(++n, "acme.travel verifies the full chain (Owner → Muse → Hermes)");
const v = await asWallet("website", () =>
  verifyChain({ mandateJws: M2.mandate, expectedAudience: "acme.travel" })
);
if (!v.ok) throw new Error("chain verification failed: " + v.reason);
ok(`chain valid, ${v.hops} delegation hops`);
for (const [i, link] of v.chain.entries()) {
  const tag = link.agency_grant ? "agency grant (root)" : `link ${i}`;
  console.log(
    `   ${tag}: iss=${short(link.issuer)} scope=[${link.scope}] limit=$${link.amount_limit}`
  );
}
console.log(`   owner=${short(v.owner)} → agent=${short(v.agent)}  task="${v.task}"`);

// 6. Negative: Hermes tries to exceed its delegated scope ----------------------
step(++n, "attack 1: Hermes tries scope=travel.cancel (outside its delegation)");
try {
  await asWallet("hermes", () =>
    mintMandate({
      audience: "acme.travel",
      scope: ["travel.cancel"],
      amount: 50,
      task: "Cancel someone else's trip",
      grantJws: M1.mandate,
    })
  );
  throw new Error("ATTACK SUCCEEDED — this must not happen");
} catch (e) {
  if (!(e instanceof WalletError)) throw e;
  refused(e.message);
}

// 7. Negative: Hermes tries to exceed its delegated amount ----------------------
step(++n, "attack 2: Hermes tries $600 (over its $500 envelope)");
try {
  await asWallet("hermes", () =>
    mintMandate({
      audience: "acme.travel",
      scope: ["travel.book"],
      amount: 600,
      confirmOverLimit: true,
      task: "Book first-class instead",
      grantJws: M1.mandate,
    })
  );
  throw new Error("ATTACK SUCCEEDED — this must not happen");
} catch (e) {
  if (!(e instanceof WalletError)) throw e;
  refused(e.message);
}

// 8. Negative: tampered leaf ----------------------------------------------------
step(++n, "attack 3: tampered mandate presented to the website");
const tampered = M2.mandate.slice(0, 60) + (M2.mandate[60] === "A" ? "B" : "A") + M2.mandate.slice(61);
const vt = await asWallet("website", () =>
  verifyChain({ mandateJws: tampered, expectedAudience: "acme.travel" })
);
if (vt.ok) throw new Error("ATTACK SUCCEEDED — this must not happen");
refused(vt.reason);

// 9. Negative: replay ------------------------------------------------------------
step(++n, "attack 4: replay the valid mandate");
const vr = await asWallet("website", () =>
  verifyChain({ mandateJws: M2.mandate, expectedAudience: "acme.travel" })
);
if (vr.ok) throw new Error("ATTACK SUCCEEDED — this must not happen");
refused(vr.reason);

console.log("\nAll delegation checks passed. Keystores were at:", base);
rmSync(base, { recursive: true, force: true });
