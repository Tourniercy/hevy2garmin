# The Next.js dashboard as a self-hosted container. Build from this directory:
#
#   docker build -t hevy2garmin-web web/
#
# The root Dockerfile is a different image: it builds the Python CLI.
#
# Dependencies come from web/package-lock.json exactly as CI installs them, so
# the `hevy2garmin` engine is the published npm release the lockfile pins, not
# the typescript/ folder of this checkout.

FROM node:22.23.4-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund


FROM node:22.23.4-bookworm-slim AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# H2G_BASE_PATH serves the dashboard under a path prefix (README: Under a
# sub-path). Next.js bakes it into the build, so it is a build argument.
ARG H2G_BASE_PATH=""
# Routes are force-dynamic, so the build never connects to a database; it only
# needs a URL to be set, the same as the CI build. Scoped to this one command
# so it does not end up in the image.
RUN H2G_BASE_PATH="$H2G_BASE_PATH" DATABASE_URL=postgres://build:build@localhost:5432/build npm run build


FROM node:22.23.4-bookworm-slim

# Kept at runtime for the health check, which has to call the prefixed path.
ARG H2G_BASE_PATH=""
ENV H2G_BASE_PATH=$H2G_BASE_PATH
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=8096 \
    HOSTNAME=0.0.0.0

WORKDIR /app

# `output: "standalone"` (next.config.ts, off Vercel) traces the node_modules the
# server needs into .next/standalone. The static assets are not part of that and
# are copied next to it. There is no public/ folder to copy.
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

# The code stays root-owned and read-only for the app. Only Next's cache
# directory is writable, by the `node` user (uid 1000) that ships in the base image.
RUN mkdir -p .next/cache && chown node:node .next/cache

USER node
EXPOSE 8096

# /api/version needs no session and no database, so it says whether the server
# is up without turning a database outage into a restart loop.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.PORT || 8096) + (process.env.H2G_BASE_PATH || '') + '/api/version').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]

CMD ["node", "server.js"]
