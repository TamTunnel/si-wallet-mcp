# Delegation chain demo: Owner → Muse → Hermes

A runnable proof that sovereign-identity mandates compose across agents and
frameworks — no pair-specific connectors, just one shared protocol plus thin
adapters.

## The topology

```
Owner ──grant──▶ Muse ──mandate──▶ Hermes ──mandate──▶ acme.travel
$2000            $500 (book-only)   $320
[book,cancel]    [book]             [book]
```

Each hop **attenuates**: narrower scopes, lower amount limits. The website
verifies the whole chain with `verifyChain`, which enforces at every link:

- parent signature valid (Ed25519 did:key, strict canonical base64url)
- parent was issued to this link's signer (`sub` binding — no token theft)
- scope ⊆ parent scope, amount ≤ parent limit
- expiry, leaf audience match, replay protection (every link's JTI recorded)

## Run it

```bash
node examples/delegation-chain/run.mjs
```

Three throwaway wallets are created in a temp dir (as if on three machines),
the chain is built and verified, then four attacks are attempted — scope
escalation, amount escalation, a tampered token, and a replay — and all four
are refused.

## How Hermes / OpenClaw plug in

There is no Hermes adapter or OpenClaw adapter to write at the protocol
level. Each framework:

1. Runs its own `si-wallet` MCP server (or imports `lib/wallet.mjs`),
2. Calls `mint_mandate` with `subjectDid` set to the downstream agent when
   delegating, and `verify_chain` when receiving,
3. Maps its own internal task auth to these two calls — that mapping is the
   only framework-specific code, and it's a few dozen lines.

The demo uses the library directly; over MCP the same calls are
`issue_grant`, `mint_mandate` (with `subjectDid`), and `verify_chain`.

## Trust model

Bilateral, not reputational. The website trusts the chain because it trusts
the owner's key (established out-of-band, e.g. first booking + email
confirmation), and every hop is cryptographically confined by its parent.
No global registry, no scores — v1 stays boring on purpose.
