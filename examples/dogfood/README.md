# Dogfood: the full agent loop over real transports

`run.mjs` stands in for Meta Muse and drives the entire booking flow the
way a deployed agent would — no library imports, no shared filesystem:

1. Proves the wallet's HTTP endpoint 401s without a bearer token.
2. Connects to the wallet **only** through MCP over streamable HTTP.
3. Fetches the merchant's AWAS manifest and reads its mandate auth config.
4. Onboards throwaway test identities, issues an agency grant, searches
   flights, previews with one mandate, books with a fresh one.

```bash
# terminal 1 — the wallet (your signing service)
SI_MCP_TOKEN="$(openssl rand -hex 32)" SI_WALLET_PASSPHRASE="..." \
  SI_WALLET_DIR=/tmp/dogfood-wallet node server.mjs --http --port 8789

# terminal 2 — the merchant (someone else's website)
cd <AWAS>/examples/merchant-demo && npm start   # :8788

# terminal 3 — the agent (this script)
SI_MCP_TOKEN="<same token>" node examples/dogfood/run.mjs
```

All identities are throwaway test identities. The real owner onboarding is
yours to run. Last verified green 2026-09-22 against
`@tamtunnel/si-wallet-mcp@0.1.1` and the AWAS demo merchant.
