# si-wallet-mcp

Sovereign-identity wallet as an [MCP](https://modelcontextprotocol.io/) server.
Gives any MCP-capable agent a DID, owner→agent grants, and task mandates —
the identity layer underneath AWAS website authentication.

**Protocol:** [TamTunnel/sovereign-identity](https://github.com/TamTunnel/sovereign-identity) —
DIDs, agency grants, task mandates, and the AWAS website binding this wallet implements.

**Version:** 0.1.0 · **License:** Apache-2.0

## Tools

| Tool | What it does |
|---|---|
| `wallet_onboard` | Create the owner/agent identity (returns existing if present) |
| `wallet_did` | Get the DID for a role |
| `issue_grant` | Owner delegates scopes + USD limit to an agent DID |
| `mint_mandate` | Agent mints a task mandate for a website audience (returns `Authorization: Mandate …` value). Pass `subjectDid` to delegate to a downstream agent with narrowed scope/amount |
| `verify_mandate` | Website-side verification: signatures, expiry, audience, replay, grant binding, scope/amount confinement |
| `verify_chain` | Website-side verification of a multi-hop delegation chain (Owner → … → agent): per-hop signatures, binding, attenuation, replay |
| `pairwise_did` | Fresh pairwise DID per audience (no cross-site correlation) |

Guardrails are enforced server-side: mandates over **$100** need
`confirmOverLimit=true` (only after the owner explicitly approved), and the
verifier rejects non-canonical base64url outright.

## Quick start

```bash
npm install -g @tamtunnel/si-wallet-mcp   # after publish; or clone and npm install
export SI_WALLET_PASSPHRASE="your passphrase"   # required for signing
si-wallet-mcp                                # stdio mode (default)
```

State lives in `~/.sov-id` (override with `SI_WALLET_DIR`). Keys are
scrypt + AES-256-GCM encrypted at rest, files mode 600.

### Local MCP clients (Claude Code, Hermes, OpenClaw, …)

Add to the client's MCP config:

```json
{
  "mcpServers": {
    "si-wallet": {
      "command": "node",
      "args": ["/path/to/si-wallet-mcp/server.mjs"],
      "env": { "SI_WALLET_PASSPHRASE": "your passphrase" }
    }
  }
}
```

### Muse (custom connector)

Muse custom connectors reach **remote** MCP servers over streamable HTTP —
a server on your laptop is not reachable from Meta's cloud. Run:

```bash
export SI_WALLET_PASSPHRASE="your passphrase"
export SI_MCP_TOKEN="$(openssl rand -hex 32)"   # required in HTTP mode
si-wallet-mcp --http --port 8787
```

Expose it on a public HTTPS URL (your VPS, fly.io, Tailscale, …), then add
that URL as a custom connector in Muse with `Authorization: Bearer <token>`.
The server binds `127.0.0.1` by default; only set `SI_MCP_HOST=0.0.0.0`
behind TLS. Full walkthrough: [DEPLOY.md](DEPLOY.md).

### Docker

```bash
docker build -t si-wallet-mcp .
docker run -d --name si-wallet \
  -e SI_MCP_TOKEN="$(openssl rand -hex 32)" \
  -e SI_WALLET_PASSPHRASE="your passphrase" \
  -v si-wallet-data:/data \
  -p 127.0.0.1:8787:8787 \
  si-wallet-mcp
```

See [DEPLOY.md](DEPLOY.md) for fly.io, Tailscale, TLS, onboarding, backups,
and connecting Meta Muse.

## Delegation demo: Owner → Muse → Hermes

`examples/delegation-chain/` is a runnable proof that mandates compose
across agents and frameworks with no pair-specific connectors: the owner
grants Muse broad authority, Muse delegates a narrowed envelope to Hermes,
Hermes presents the leaf mandate to a website, and the website verifies the
whole attenuated chain. Four attacks (scope escalation, amount escalation,
tampering, replay) are attempted and refused.

```bash
node examples/delegation-chain/run.mjs
```

## Who hosts this?

**Each user hosts their own.** That is the point. A wallet holds private
keys, so there is no shared hosted instance — that would be custodial and
would contradict the "sovereign" in sovereign identity.

- **You, for your own use:** run it on hardware you control (your Mac, a VPS
  you own). One command, keys never leave your machine.
- **Other users:** same — they run their own instance and point their agent
  at it. This mirrors how Hermes/OpenClaw already work (self-hosted).
- **Stateless verification** (`verify_mandate` without the replay ledger)
  is the only piece that could ever be shared, and even that is safer local.

Whoever can reach the server can ask it to sign. Treat the bearer token
like a password and never expose the HTTP port without TLS.

## Security notes

- HTTP mode refuses to start without `SI_MCP_TOKEN`; every request needs
  `Authorization: Bearer <token>` (401 otherwise).
- The server never logs the passphrase, keys, or tokens.
- Demo identities created with a test passphrase must be replaced before
  real use — the real owner onboarding is yours to run.
- This tooling has not had an independent cryptographic audit.
