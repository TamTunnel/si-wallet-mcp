# node:22-alpine keeps the image small; the wallet is pure JS + node:crypto.
FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY server.mjs ./
COPY lib ./lib

# Never run a signing service as root. Key material lives in /data.
RUN adduser -D -H wallet && mkdir -p /data/wallet && chown -R wallet:wallet /app /data
USER wallet

ENV SI_MCP_HOST=0.0.0.0 \
    PORT=8787 \
    SI_WALLET_DIR=/data/wallet

EXPOSE 8787
VOLUME ["/data"]

# No auth header -> 401 proves the server is up and enforcing bearer auth.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/mcp',{method:'POST',headers:{'content-type':'application/json'}}).then(r=>{if(r.status!==401&&r.status!==400)process.exit(1)}).catch(()=>process.exit(1))"

# Refuses to start without SI_MCP_TOKEN (fail-fast, enforced by server.mjs).
CMD ["sh","-c","node server.mjs --http --port ${PORT:-8787}"]
