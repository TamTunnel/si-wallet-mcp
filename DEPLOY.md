# Deploying si-wallet-mcp

One server **per user**, on hardware the user controls. This is a signing
service: whoever can reach it can ask it to sign. There is no shared
custodial instance — that is the point.

## 1. Secrets

Generate both before anything else:

```bash
export SI_MCP_TOKEN=$(openssl rand -hex 32)        # bearer token for the MCP endpoint
export SI_WALLET_PASSPHRASE=$(openssl rand -hex 32) # encrypts keys at rest
```

Save them in a password manager. The bearer token is what you will hand to
Muse later through its secure credential flow — never paste it into chat.

## 2. Option A — Docker on any host

```bash
docker build -t si-wallet-mcp .
docker run -d --name si-wallet \
  -e SI_MCP_TOKEN="$SI_MCP_TOKEN" \
  -e SI_WALLET_PASSPHRASE="$SI_WALLET_PASSPHRASE" \
  -v si-wallet-data:/data \
  -p 127.0.0.1:8787:8787 \
  si-wallet-mcp
```

Notes:

- The wallet state lives in the `si-wallet-data` volume (`/data/wallet`).
  **Back it up.** Losing it means re-onboarding and re-issuing every grant.
- The container binds `0.0.0.0` inside, but the example above only publishes
  to the host's loopback. Do not expose 8787 to the internet without TLS in
  front (Caddy, nginx, or your cloud provider's HTTPS ingress). Bearer auth
  alone over plain HTTP is not enough.

## 3. Option B — fly.io (public HTTPS, ~5 minutes)

```bash
fly launch --no-deploy --name my-si-wallet --region iad
fly volumes create si_wallet_data --size 1
fly secrets set SI_MCP_TOKEN="$SI_MCP_TOKEN" SI_WALLET_PASSPHRASE="$SI_WALLET_PASSPHRASE"
fly deploy
```

`fly.toml` needs (add to the repo or generate):

```toml
app = "my-si-wallet"
primary_region = "iad"

[build]
  dockerfile = "Dockerfile"

[[mounts]]
  source = "si_wallet_data"
  destination = "/data"

[http_service]
  internal_port = 8787
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true

[[http_service.checks]]
  grace_period = "10s"
  interval = "30s"
  method = "POST"
  path = "/mcp"
  # unauthenticated -> 401 counts as healthy (auth enforced)
```

Your endpoint: `https://my-si-wallet.fly.dev/mcp` (streamable HTTP).

## 4. Option C — Tailscale (private, no public domain)

If the wallet should never touch the public internet:

```bash
# on the host running the container
tailscale funnel 8787   # or: tailscale serve https / http://127.0.0.1:8787
```

You get an `https://<tailnet-name>.ts.net/mcp` URL reachable only from your
tailnet. Muse's cloud cannot reach a tailnet address — this option is for
local MCP clients (Claude Code, Hermes, OpenClaw) and for testing.

## 5. First run: onboard your owner identity

Once the server is up, call `wallet_onboard` with `role: "owner"` through
any connected MCP client (or `docker exec`). This creates your root DID and
encrypted key. **This is the real identity — the demo passphrases and
throwaway DIDs from development must never be used here.** Back up the
volume afterwards.

Then: `issue_grant` to your agent's DID with least-privilege scopes.

## 6. Connect Meta Muse

Muse has no settings-menu MCP directory. You connect by asking it in chat —
it builds an MCP client on its own VM over streamable HTTP and saves the
integration as a skill:

> Connect the si-wallet MCP server at `https://my-si-wallet.fly.dev/mcp`.
> It needs a bearer token, which I'll provide through the secure prompt.

When it asks for the token, enter `SI_MCP_TOKEN` through Muse's secure
credential flow (stored outside the agent runtime), not in chat. Requirements:

- The URL must be **publicly reachable HTTPS** from Meta's cloud. A laptop
  `localhost` or a Tailscale-only address will not work.
- The server speaks **streamable HTTP** at `/mcp` — exactly what this
  image serves.

## 7. Local clients (Claude Code, Hermes, OpenClaw)

No deployment needed — run over stdio as your own user, keys never leave
the machine:

```json
{
  "mcpServers": {
    "si-wallet": {
      "command": "npx",
      "args": ["-y", "@tamtunnel/si-wallet-mcp"],
      "env": {
        "SI_WALLET_DIR": "/home/you/.sov-id",
        "SI_WALLET_PASSPHRASE": "..."
      }
    }
  }
}
```

## 8. Operations

- **Backups:** snapshot the `/data` volume (or `si-wallet-data`) regularly,
  especially after onboarding and after issuing long-lived grants.
- **Token rotation:** change `SI_MCP_TOKEN`, restart, re-enter it in Muse's
  credential flow. Old bearer tokens die with the restart.
- **Updates:** `docker pull` / rebuild from the repo, restart. The volume
  carries state across image updates.
- **What the server never does:** it never exfiltrates keys, never phones
  home, and never signs without a tool call. Audit with the smoke tests:
  `npm run test:smoke-ci`.
