# rusty-gateway

Single-user MCP aggregator in Go. One long-lived child process per configured
stdio MCP server, exposed over namespaced streamable HTTP endpoints, protected
by OAuth bearer tokens validated against an external IdP.

```
Claude / Claude Code / Inspector  --bearer-->  /mcp/{namespace}  -->  supervised stdio children
```

## Run

```sh
go build ./cmd/gateway
GATEWAY_STATIC_TOKEN=... ./gateway -config gateway.toml
```

See `gateway.example.toml`. A bare `command` like `uvx` is resolved through
`PATH` once at load and pinned to its absolute path; a missing or
non-executable binary fails startup. `${VAR}` in `env` values is
expanded from the host environment at load and missing variables are an error.

Endpoints:

- `POST|GET|DELETE /mcp/{namespace}` streamable HTTP MCP; tools are named `{server}__{tool}`
- `GET /.well-known/oauth-protected-resource[/mcp/{namespace}]` RFC 9728 metadata, per namespace
- `GET /healthz` upstream states, pids and tool counts; 503 if any upstream is failed
- `GET /audit?namespace=&server=&tool=&status=&since=24h&limit=100` recent tool calls (bearer required)

## Audit log

Every tool call is written to SQLite at `audit.path`, off the request path
through a bounded buffer (rows are dropped and counted if it fills). Args and
results are redacted before the row exists: keys matching
`(?i)(token|key|secret|password|passwd|auth|credential)` are dropped, values
that look like API keys, JWTs, bearer tokens or long hex/base64 runs are
replaced, and JSON carried inside text content is scrubbed recursively.
Payloads are capped at `audit.max_payload_kb`; the true result size is kept.
Rows older than `audit.retention_days` are pruned daily.

```sh
./gateway audit tail -config gateway.toml -n 50 -f
```

## Logging

The gateway logs JSON to stderr. Each upstream's stderr is captured line by
line and emitted as `upstream stderr` records tagged with the upstream ID, at
debug level by default so it is silent unless you run with `-debug`. Set
`stderr_level` per server to `info`/`warn`/`error` to surface a noisy or
important server, or `discard` to drop it. Filter with:

```sh
docker logs gateway 2>&1 | jq -c 'select(.msg=="upstream stderr" and .upstream=="personal/tradingview") | .line'
```

## Limits and resilience

`[limits]` bounds in-flight tool calls globally, per namespace, and per
server (override with `max_concurrent` on a namespace or server). Queue time
counts against `call_timeout`. `[breaker]` opens an upstream after N
consecutive transport errors or timeouts, rejects calls immediately while
open, and lets one trial call through after the cooldown. Breaker states are
in `/healthz`. Tool-level errors (`isError: true`) never trip the breaker.

Upstreams are either stdio (`command`) or remote streamable HTTP (`url` plus
optional `headers`). Remote upstreams get the same health checks, restarts,
limits and audit as local ones.

## OAuth-protected upstreams

A `url` server with `oauth = true` (Notion, for example) makes the gateway an
OAuth client toward that server. Until you log in, the upstream sits in
`needs_login` and its tools are absent. On startup the gateway begins the
login itself and logs the URL to open:

```
"msg":"upstream needs login: open this url in a browser","upstream":"personal/notion","url":"https://mcp.notion.com/authorize?..."
```

The URL is valid for an hour; a fresh one is logged when it lapses, or on
demand with your gateway bearer:

```sh
curl -H "Authorization: Bearer $GATEWAY_STATIC_TOKEN" \
  https://gw.example/oauth/upstream/personal/notion/login
```

The server redirects back to `/oauth/callback`, the gateway stores the
credentials in `data_dir/state.db`, connects, and refreshes tokens silently
from then on, across restarts. If the server revokes the grant the upstream
returns to `needs_login`. Client registration uses the gateway's own client
metadata document at `/oauth/client.json`, with dynamic registration as
fallback; `oauth_client_id` and `oauth_client_secret_env` cover servers that
require a pre-registered client.

## Auth

The gateway is a resource server only. It validates JWT access tokens (`iss`,
`aud`, `exp`, signature via JWKS, `scope`) and never issues or stores tokens.
Each namespace is its own protected resource: clients send
`resource=https://gw.example/mcp/{namespace}` and the IdP must allow that
value as an audience for the client.
A static bearer token from `auth.static_token_env` is accepted alongside for
scripts. Client registration is static in the IdP; see
[docs/auth-and-dcr.md](docs/auth-and-dcr.md) for why and for Authelia config.

## Process model

One child per `(namespace, server)`, started at boot in its own process group,
shared by every client session. Health is checked with `ping` every 30s;
crashes restart with exponential backoff (1s to 60s) and an upstream is marked
failed after 5 consecutive failures. Stopping signals the whole process group,
so `uvx`/`npx` wrappers do not leave grandchildren behind. The test suite
asserts that the number of live children equals the number of configured,
non-failed upstreams regardless of client sessions.

## Status

| Milestone | State |
|---|---|
| M0 proxy tools/list and tools/call over stdio | done |
| M1 supervisor: process groups, restart, health, clean shutdown | done |
| M2 namespaces, TOML config, streamable HTTP, tool prefixing | done |
| M3 audit log: schema, redaction, buffered writer, read API, retention | done |
| M4 auth: protected resource metadata, JWKS, static token | done |
| M5 ops: Dockerfile, RSS metrics, memory limit | done |

Config reload on SIGHUP is not implemented; restart the process.

## Deploy

Each release publishes tarballs for linux/darwin on amd64/arm64 and a
multi-arch image at `ghcr.io/jegork/rusty-gateway:<tag>` (also `latest`).
The image is private like the repo, so pulling from Dokploy needs a GitHub
token with `read:packages`.

The image runs as uid 1000 and ships node 22 with npm, plus uv/uvx, with
writable caches at `/var/cache/uv` and `/var/cache/npm`. Reference those in
`gateway.toml` env blocks. Prefer pre-installing servers over `npx -y` or
`uvx` at start by layering on the image:

```dockerfile
FROM ghcr.io/jegork/rusty-gateway:latest
USER root
RUN npm install -g hevy-mcp && uv tool install tradingview-mcp-server
USER gateway
```

`docker-compose.yml` works for both `docker compose up` and
`docker stack deploy`; the `deploy` block carries the memory limit and
restart policy so Dokploy can run it in either mode. The compose file
expects `gateway.toml` next to it and secrets from the environment. The
container HEALTHCHECK uses `gateway healthcheck <url>`, so no curl is needed.

`/healthz` reports `rss_bytes` per upstream, summed over the child and its
descendants, so the memory a wrapper launcher spawns is visible.
