// lib/wallet.mjs — sovereign-identity wallet core as a function API.
//
// Same cryptography as the sid CLI: Ed25519 did:key identities, compact
// EdDSA JWS mandates, scrypt + AES-256-GCM encrypted keystore. Passphrase
// comes from SI_WALLET_PASSPHRASE (or SOV_ID_PASSPHRASE); state lives in
// SI_WALLET_DIR (or ~/.sov-id).
//
// Keystore files are written mode 600. Mandates above $100 require explicit
// owner confirmation (confirmOverLimit). Verification enforces strict
// canonical base64url: non-canonical encodings are rejected outright.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Resolved per call (not at import time) so one process can drive several
// independent wallets — e.g. the Owner → Muse → Hermes delegation demo,
// where each party's keystore lives in its own directory.
const stateDir = () => process.env.SI_WALLET_DIR || path.join(os.homedir(), ".sov-id");
const pairwiseDir = () => path.join(stateDir(), "pairwise");
const grantsDir = () => path.join(stateDir(), "grants");
const replayPath = () => path.join(stateDir(), "replay.json");
const AGENCY_AUD = "sovereign-identity/agency";
const OVER_LIMIT_USD = 100;
const CLOCK_SKEW_S = 60;

export class WalletError extends Error {
  constructor(message, code = "wallet_error") {
    super(message);
    this.code = code;
  }
}

// ------------------------------------------------------------------ base58

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function b58encode(buf) {
  let n = 0n;
  for (const b of buf) n = (n << 8n) + BigInt(b);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of buf) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s || "1";
}

function b58decode(str) {
  let n = 0n;
  for (const c of str) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error("invalid base58 character");
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let zeros = 0;
  for (const c of str) {
    if (c !== "1") break;
    zeros++;
  }
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(bytes)]);
}

// ------------------------------------------------------------------ DID

function didFromRawPub(raw32) {
  return "did:key:z" + b58encode(Buffer.concat([Buffer.from([0xed, 0x01]), raw32]));
}

function rawPubFromDid(did) {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did || "");
  if (!m) throw new WalletError(`malformed did:key: ${did}`, "bad_did");
  const raw = b58decode(m[1]);
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) {
    throw new WalletError("did:key is not an Ed25519 key", "bad_did");
  }
  return raw.subarray(2);
}

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function publicKeyObjFromDid(did) {
  const raw = rawPubFromDid(did);
  return crypto.createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

export function fingerprint(did) {
  return crypto.createHash("sha256").update(did).digest("hex").slice(0, 16);
}

// ------------------------------------------------- strict base64url + JWS

const b64u = (v) => Buffer.from(v).toString("base64url");

// JWS compact serialization forbids padding and requires canonical encoding
// (unused trailing bits zero). Node's decoder is lenient, so decode,
// re-encode canonically, and require the original string back exactly.
export function unb64uStrict(s) {
  if (typeof s !== "string" || s.length === 0 || /[^A-Za-z0-9_-]/.test(s)) {
    throw new WalletError("not canonical base64url", "bad_encoding");
  }
  const buf = Buffer.from(s, "base64url");
  if (buf.toString("base64url") !== s) {
    throw new WalletError("not canonical base64url", "bad_encoding");
  }
  return buf;
}

function signJws(payload, privateKeyObj, kid) {
  const h = b64u(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid }));
  const p = b64u(JSON.stringify(payload));
  const sig = crypto.sign(null, Buffer.from(h + "." + p), privateKeyObj);
  return `${h}.${p}.${b64u(sig)}`;
}

function verifyJwsInner(jws, expectedDid) {
  const parts = (jws || "").split(".");
  if (parts.length !== 3)
    return { ok: false, reason: "malformed JWS (want 3 parts)" };
  const [h, p, s] = parts;
  let header, payload;
  try {
    header = JSON.parse(unb64uStrict(h).toString("utf8"));
    payload = JSON.parse(unb64uStrict(p).toString("utf8"));
  } catch (e) {
    return { ok: false, reason: "JWS header/payload is not valid base64url JSON" };
  }
  if (header.alg !== "EdDSA")
    return { ok: false, reason: `unsupported alg ${header.alg}` };
  const kidDid = String(header.kid || "").split("#")[0];
  if (expectedDid && kidDid !== expectedDid)
    return { ok: false, reason: "kid does not match expected issuer DID" };
  let pub;
  try {
    pub = publicKeyObjFromDid(kidDid);
  } catch (e) {
    return { ok: false, reason: "cannot resolve issuer did:key: " + e.message };
  }
  const sigOk = crypto.verify(
    null,
    Buffer.from(h + "." + p),
    pub,
    unb64uStrict(s)
  );
  if (!sigOk) return { ok: false, reason: "signature invalid" };
  return { ok: true, header, payload, issuerDid: kidDid };
}

function verifyJws(jws, expectedDid) {
  try {
    return verifyJwsInner(jws, expectedDid);
  } catch (e) {
    return { ok: false, reason: "verification error: " + e.message };
  }
}

// ------------------------------------------------------- encrypted keystore

function ensureDirs() {
  for (const d of [stateDir(), pairwiseDir(), grantsDir()]) {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  }
}

const SCRYPT = { N: 16384, r: 8, p: 1 };

function encryptPem(pem, password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32, SCRYPT);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(pem, "utf8"), cipher.final()]);
  return {
    kdf: "scrypt",
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    salt: salt.toString("hex"),
    iv: iv.toString("hex"),
    authTag: cipher.getAuthTag().toString("hex"),
    content: data.toString("hex"),
  };
}

function decryptPem(env, password) {
  const key = crypto.scryptSync(password, Buffer.from(env.salt, "hex"), 32, {
    N: env.N,
    r: env.r,
    p: env.p,
  });
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(env.iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(env.authTag, "hex"));
  return Buffer.concat([
    decipher.update(Buffer.from(env.content, "hex")),
    decipher.final(),
  ]).toString("utf8");
}

function getPassphrase() {
  const pw = process.env.SI_WALLET_PASSPHRASE || process.env.SOV_ID_PASSPHRASE;
  if (!pw)
    throw new WalletError(
      "no wallet passphrase: set SI_WALLET_PASSPHRASE",
      "no_passphrase"
    );
  return pw;
}

function identityPath(role) {
  return path.join(stateDir(), `${role}.json`);
}

function loadIdentity(role) {
  const p = identityPath(role);
  if (!fs.existsSync(p)) return null;
  const file = JSON.parse(fs.readFileSync(p, "utf8"));
  const pem = decryptPem(file.key, getPassphrase());
  const privateKey = crypto.createPrivateKey({ key: pem, format: "pem" });
  return { did: file.did, created: file.created, privateKey };
}

function saveIdentity(role, did, pem) {
  const file = {
    did,
    created: new Date().toISOString(),
    key: encryptPem(pem, getPassphrase()),
  };
  fs.writeFileSync(identityPath(role), JSON.stringify(file, null, 2), {
    mode: 0o600,
  });
}

function loadReplay() {
  try {
    return JSON.parse(fs.readFileSync(replayPath(), "utf8"));
  } catch {
    return {};
  }
}

function saveReplay(r) {
  fs.writeFileSync(replayPath(), JSON.stringify(r), { mode: 0o600 });
}

const nowSec = () => Math.floor(Date.now() / 1000);

// ------------------------------------------------------------------- API

/** Create (or return the existing) owner/agent identity. */
export function onboard(role) {
  ensureDirs();
  if (!["owner", "agent"].includes(role))
    throw new WalletError('role must be "owner" or "agent"', "bad_role");
  const p = identityPath(role);
  if (fs.existsSync(p)) {
    const file = JSON.parse(fs.readFileSync(p, "utf8"));
    return { did: file.did, fingerprint: fingerprint(file.did), existing: true };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const did = didFromRawPub(raw);
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  saveIdentity(role, did, pem);
  return { did, fingerprint: fingerprint(did), existing: false };
}

/** Return the DID for a role. Throws if the identity does not exist. */
export function getDid(role = "agent") {
  const p = identityPath(role);
  if (!fs.existsSync(p))
    throw new WalletError(
      `no ${role} identity; call wallet_onboard first`,
      "no_identity"
    );
  const file = JSON.parse(fs.readFileSync(p, "utf8"));
  return { did: file.did, fingerprint: fingerprint(file.did) };
}

/**
 * Owner issues an agency grant to an agent DID.
 * { agentDid, scope: string[], amountLimit, ttlDays = 365, note = "" }
 */
export function issueGrant({ agentDid, scope, amountLimit, ttlDays = 365, note = "" }) {
  ensureDirs();
  if (!agentDid) throw new WalletError("agentDid is required", "bad_args");
  rawPubFromDid(agentDid); // validates
  const scopes = (Array.isArray(scope) ? scope : String(scope || "").split(","))
    .map((s) => s.trim())
    .filter(Boolean);
  if (!scopes.length) throw new WalletError("at least one scope is required", "bad_args");
  const amount = Number(amountLimit);
  if (!Number.isFinite(amount) || amount < 0)
    throw new WalletError("amountLimit must be a non-negative number", "bad_args");
  const owner = loadIdentity("owner");
  if (!owner)
    throw new WalletError("no owner identity; call wallet_onboard first", "no_identity");

  const iat = nowSec();
  const grant = {
    iss: owner.did,
    sub: agentDid,
    aud: AGENCY_AUD,
    iat,
    exp: iat + Math.floor(Number(ttlDays) * 86400),
    jti: crypto.randomUUID(),
    claims: { scope: scopes, amount_limit: amount, currency: "USD", note },
  };
  const jws = signJws(grant, owner.privateKey, owner.did + "#key-1");
  const outPath = path.join(grantsDir(), `${grant.jti}.jwt`);
  fs.writeFileSync(outPath, jws, { mode: 0o600 });
  return {
    grant: jws,
    owner: owner.did,
    agent: agentDid,
    scope: scopes,
    amount_limit: amount,
    expires: new Date(grant.exp * 1000).toISOString(),
  };
}

/**
 * Agent mints a task mandate for a website audience, bound to an agency grant.
 * { audience, scope: string[], amount = 0, ttlSec = 3600, task = "",
 *   grantJws, confirmOverLimit = false, subjectDid = null }
 *
 * subjectDid enables delegation: an intermediate agent (e.g. Muse) mints a
 * mandate whose subject is a downstream agent (e.g. Hermes), narrowing scope
 * and amount relative to its own grant. Defaults to the minter's own DID.
 */
export function mintMandate({
  audience,
  scope,
  amount = 0,
  ttlSec = 3600,
  task = "",
  grantJws,
  confirmOverLimit = false,
  subjectDid = null,
}) {
  ensureDirs();
  if (!audience) throw new WalletError("audience is required", "bad_args");
  const scopes = (Array.isArray(scope) ? scope : String(scope || "").split(","))
    .map((s) => s.trim())
    .filter(Boolean);
  if (!scopes.length) throw new WalletError("at least one scope is required", "bad_args");
  const amt = Number(amount) || 0;
  if (amt > OVER_LIMIT_USD && !confirmOverLimit) {
    throw new WalletError(
      `REFUSED: amount $${amt} exceeds $${OVER_LIMIT_USD} consent limit. ` +
        `Re-call with confirmOverLimit=true only after the owner explicitly approved.`,
      "over_limit"
    );
  }
  if (!grantJws) throw new WalletError("grantJws is required", "bad_args");
  const agent = loadIdentity("agent");
  if (!agent)
    throw new WalletError("no agent identity; call wallet_onboard first", "no_identity");
  const subject = subjectDid || agent.did;
  if (subjectDid) rawPubFromDid(subjectDid); // validates

  const g = verifyJws(String(grantJws).trim());
  if (!g.ok) throw new WalletError("agency grant failed verification: " + g.reason, "bad_grant");
  if (g.payload.sub !== agent.did)
    throw new WalletError("agency grant is not issued to this agent DID", "bad_grant");
  const overScope = scopes.filter((s) => !(g.payload.claims.scope || []).includes(s));
  if (overScope.length)
    throw new WalletError(`scope [${overScope}] exceeds agency grant scope`, "scope_exceeded");
  if (amt > (g.payload.claims.amount_limit || 0))
    throw new WalletError(
      `amount $${amt} exceeds grant limit $${g.payload.claims.amount_limit}`,
      "amount_exceeded"
    );

  const iat = nowSec();
  const mandate = {
    iss: agent.did,
    sub: subject,
    aud: audience,
    iat,
    exp: iat + Math.floor(Number(ttlSec) || 3600),
    jti: crypto.randomUUID(),
    claims: { task, scope: scopes, amount_limit: amt, currency: "USD" },
    grant: String(grantJws).trim(),
  };
  const jws = signJws(mandate, agent.privateKey, agent.did + "#key-1");
  return {
    mandate: jws,
    authorizationHeader: `Mandate ${jws}`,
    agent: agent.did,
    subject,
    audience,
    scope: scopes,
    amount_limit: amt,
    expires: new Date(mandate.exp * 1000).toISOString(),
  };
}

/**
 * Verify a task mandate chain (the website-side checks). Records the JTI in
 * the local replay ledger on success.
 * { mandateJws, expectedAudience = null }
 */
export function verifyMandate({ mandateJws, expectedAudience = null }) {
  ensureDirs();
  const fail = (reason) => ({ ok: false, reason });
  const token = String(mandateJws || "").trim();

  const m = verifyJws(token);
  if (!m.ok) return fail("task mandate: " + m.reason);
  const p = m.payload;
  const now = nowSec();

  if (typeof p.exp !== "number" || p.exp <= now) return fail("task mandate expired");
  if (typeof p.iat === "number" && p.iat > now + CLOCK_SKEW_S)
    return fail("task mandate issued in the future");
  if (expectedAudience && p.aud !== expectedAudience)
    return fail(`audience mismatch: mandate for "${p.aud}", expected "${expectedAudience}"`);

  const replay = loadReplay();
  if (replay[p.jti]) return fail("replay detected: jti already seen");

  if (!p.grant) return fail("task mandate carries no agency grant");
  const g = verifyJws(p.grant);
  if (!g.ok) return fail("agency grant: " + g.reason);
  const gp = g.payload;
  if (gp.aud !== AGENCY_AUD) return fail("agency grant has wrong audience");
  if (typeof gp.exp !== "number" || gp.exp <= now) return fail("agency grant expired");
  if (gp.sub !== p.iss) return fail("agency grant was not issued to the mandate signer");

  const claims = p.claims || {};
  const gclaims = gp.claims || {};
  const overScope = (claims.scope || []).filter(
    (s) => !(gclaims.scope || []).includes(s)
  );
  if (overScope.length) return fail(`scope exceeds grant: [${overScope}]`);
  if ((claims.amount_limit || 0) > (gclaims.amount_limit || 0))
    return fail("amount exceeds grant limit");

  replay[p.jti] = p.exp;
  saveReplay(replay);

  return {
    ok: true,
    agent: p.iss,
    agent_fingerprint: fingerprint(p.iss),
    owner: gp.iss,
    owner_fingerprint: fingerprint(gp.iss),
    aud: p.aud,
    scope: claims.scope || [],
    amount_limit: claims.amount_limit || 0,
    task: claims.task || "",
    expires: new Date(p.exp * 1000).toISOString(),
  };
}

/**
 * Verify a multi-hop delegation chain: Owner → … → leaf agent → website.
 *
 * Each link is a mandate whose `grant` field embeds its parent; the root
 * parent is the owner's agency grant (aud "sovereign-identity/agency").
 * At every hop the verifier enforces: parent signature, parent issued to
 * this link's signer, scope subset, amount ≤ parent limit, expiry. The
 * expected audience is enforced on the leaf only; intermediates may target
 * the same audience (task-scoped delegation) or omit the check.
 * Replay protection applies to the presented (leaf) token only: parent
 * mandates and the root agency grant are reusable authority while valid,
 * so one long-lived grant can back many distinct task mandates.
 * { mandateJws, expectedAudience = null }
 */
export function verifyChain({ mandateJws, expectedAudience = null }) {
  ensureDirs();
  const fail = (reason) => ({ ok: false, reason });
  const now = nowSec();
  const replay = loadReplay();
  const chain = [];

  let token = String(mandateJws || "").trim();
  let expectAud = expectedAudience;
  for (let depth = 0; depth <= 8; depth++) {
    const m = verifyJws(token);
    if (!m.ok) return fail(`link ${depth}: ${m.reason}`);
    const p = m.payload;
    if (typeof p.exp !== "number" || p.exp <= now)
      return fail(`link ${depth}: expired`);
    if (typeof p.iat === "number" && p.iat > now + CLOCK_SKEW_S)
      return fail(`link ${depth}: issued in the future`);
    if (expectAud && p.aud !== expectAud)
      return fail(
        `link ${depth}: audience mismatch (for "${p.aud}", expected "${expectAud}")`
      );
    if (depth === 0 && replay[p.jti]) return fail("replay detected: leaf jti already seen");
    if (!p.grant) return fail(`link ${depth}: carries no parent grant/mandate`);

    const g = verifyJws(p.grant);
    if (!g.ok) return fail(`link ${depth}: parent: ${g.reason}`);
    const gp = g.payload;
    if (typeof gp.exp !== "number" || gp.exp <= now)
      return fail(`link ${depth}: parent expired`);
    if (gp.sub !== p.iss)
      return fail(`link ${depth}: parent was not issued to this link's signer`);
    const claims = p.claims || {};
    const gclaims = gp.claims || {};
    const overScope = (claims.scope || []).filter(
      (s) => !(gclaims.scope || []).includes(s)
    );
    if (overScope.length)
      return fail(`link ${depth}: scope exceeds parent: [${overScope}]`);
    if ((claims.amount_limit || 0) > (gclaims.amount_limit || 0))
      return fail(`link ${depth}: amount exceeds parent limit`);

    chain.push({
      issuer: p.iss,
      issuer_fingerprint: fingerprint(p.iss),
      subject: p.sub,
      aud: p.aud,
      scope: claims.scope || [],
      amount_limit: claims.amount_limit || 0,
      task: claims.task || "",
      expires: new Date(p.exp * 1000).toISOString(),
    });
    if (depth === 0) replay[p.jti] = p.exp;

    if (gp.aud === AGENCY_AUD) {
      // Root: the owner's agency grant. Reusable authority — not consumed.
      chain.push({
        issuer: gp.iss,
        issuer_fingerprint: fingerprint(gp.iss),
        subject: gp.sub,
        aud: gp.aud,
        scope: gclaims.scope || [],
        amount_limit: gclaims.amount_limit || 0,
        agency_grant: true,
        expires: new Date(gp.exp * 1000).toISOString(),
      });
      saveReplay(replay);
      const leaf = chain[0];
      const root = chain[chain.length - 1];
      return {
        ok: true,
        hops: chain.length - 1,
        agent: leaf.issuer,
        owner: root.issuer,
        owner_fingerprint: root.issuer_fingerprint,
        aud: leaf.aud,
        scope: leaf.scope,
        amount_limit: leaf.amount_limit,
        task: leaf.task,
        expires: leaf.expires,
        chain,
      };
    }
    // Parent is itself a mandate: descend one hop.
    token = p.grant;
    expectAud = null;
  }
  return fail("delegation chain too deep (max 8 links)");
}

/** Create a pairwise DID for one audience (never reuse across sites). */
export function pairwiseDid(audience) {
  ensureDirs();
  if (!audience) throw new WalletError("audience is required", "bad_args");
  getPassphrase(); // fail fast if no passphrase configured
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const did = didFromRawPub(raw);
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const file = {
    did,
    aud: audience,
    created: new Date().toISOString(),
    key: encryptPem(pem, getPassphrase()),
  };
  const outPath = path.join(
    pairwiseDir(),
    String(audience).replace(/[^a-z0-9.-]/gi, "_") + ".json"
  );
  fs.writeFileSync(outPath, JSON.stringify(file, null, 2), { mode: 0o600 });
  return { did, fingerprint: fingerprint(did), audience };
}
