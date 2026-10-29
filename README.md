# rusty-gateway

Single-user MCP aggregator in Go. A personal project: single-user by design,
no multi-tenancy, no support promised. Issues and PRs are welcome but may sit.

One long-lived child process per configured stdio MCP server, exposed over
namespaced streamable HTTP endpoints, protected by OAuth bearer tokens
validated against an external IdP.

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

## Dashboard

`/ui/` is a small operator dashboard: upstream states, RSS and breakers
updated live, pending OAuth logins as clickable links, a tool browser with
search per namespace, and the audit log with filters. By default, sign in
with the static gateway token; the session lives in a cookie for a week.
It's server-rendered Go templates kept live with [Datastar](https://data-star.dev)
over SSE, embedded in the binary with no build step. Disable with
`[ui] enabled = false`.

To use Cloudflare Access instead, add both settings to your gateway config:

```toml
[ui.cloudflare]
team_domain = "https://your-team.cloudflareaccess.com"
audience = "your-access-application-aud-tag"
```

Create a self-hosted Access application for the gateway hostname scoped to
`/ui` and its subpaths, with an Allow policy for the operator's email or group.
Keep `/mcp/*`, OAuth discovery, and OAuth callbacks outside the browser-login
policy. Access does not create DNS records or origin routing; the hostname
must already reach the gateway through Cloudflare.

In this mode every dashboard request, including assets and SSE connections,
requires a `Cf-Access-Jwt-Assertion` header. The gateway checks its RS256
signature, team issuer, application audience, and expiry using Cloudflare's
cached, automatically refreshed signing keys. Missing or invalid assertions
return 401, including direct-to-origin requests without an assertion.
Plain identity headers, Access cookies alone, static bearer tokens, and old
dashboard session cookies cannot bypass verification. There is no local
token login or local session; logout redirects to `/cdn-cgi/access/logout`.
MCP bearer authentication is unchanged, and the dashboard no longer requires
a static MCP token when Cloudflare Access is configured.

Both Cloudflare settings are required together, and `team_domain` must be an
HTTPS origin without a path, query, or credentials. Omitting both retains
the static-token login. Restrict direct origin access with Cloudflare Tunnel
or firewall rules as well. Verification happens when each HTTP request starts;
an already-open SSE connection is not terminated when its token expires.

See [Cloudflare's JWT validation documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
for the team domain, application AUD, and signing-key endpoint.

## Tool discovery modes

Each namespace picks how clients see its tools with `discovery`:

- `full` (default): every tool as `server__tool`. Simple, but a namespace
  with 100 tools costs the client 100 schemas of context on every session.
- `connector`: two meta-tools per server, `{server}__list_tools` and
  `{server}__call`. The client loads a server's real tools only when it
  needs that server.
- `search`: two meta-tools for the whole namespace, `search_tools(query)`
  and `call_tool(name, arguments)`. Search matches keywords against tool
  names, titles, descriptions and parameter names and returns schemas.

Meta-tool calls go through the same dispatcher, so limits, timeouts, the
breaker and the audit log apply, and audit rows record the resolved server
and tool rather than the meta-tool.

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
from then on, across restarts. Running the login again on an upstream that
already has credentials re-authorizes it, for example after granting new
permissions on the provider's side; the dashboard has a re-authorize link
per OAuth upstream. If the server revokes the grant the upstream
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

The resource metadata advertises `required_scope` plus `offline_access`
(override with `auth.scopes`). Clients such as Codex request exactly what is
advertised, and without `offline_access` the IdP never issues a refresh
token, so every session would die when the access token expires.

The full login flow against a real Authelia runs as an integration test
(needs Docker):

```sh
go test -tags integration -run TestAuthelia ./internal/auth/
```

### Cloudflare Managed OAuth for MCP clients

As an alternative to OIDC/static bearer authentication, let Cloudflare Access
handle interactive MCP client login:

```toml
[auth.cloudflare]
team_domain = "https://your-team.cloudflareaccess.com"
audience = "your-mcp-access-application-aud-tag"
```

Remove `issuer`, `audience`, `required_scope`, `scopes`, and `static_token_env`
from `[auth]` when enabling this mode; combining them is a startup error.
The `[ui.cloudflare]` configuration is independent: use separate Access
applications and audiences for the dashboard and MCP API.

In Cloudflare Zero Trust, create a self-hosted Access application covering
`/mcp/*` on the gateway hostname. Add destinations for `/audit` and
`/oauth/upstream/*` too if using those authenticated management endpoints.
Apply an Allow policy for the permitted users, then enable **Managed OAuth**
in the application's advanced settings. Configure allowed client redirect
URIs; enable localhost/loopback redirects for local CLI clients as needed.
Keep `/oauth/callback` and `/oauth/client.json` outside Access protection.

Clients must support OAuth resource indicators (RFC 8707). Cloudflare owns
the OAuth challenge, discovery, registration, token exchange, and refresh.
It resolves the client's opaque bearer token and forwards a signed
`Cf-Access-Jwt-Assertion` to the gateway. The gateway checks the assertion's
signature, issuer, MCP application audience, expiry, and non-empty subject;
the subject is used for MCP session identity and audit records.
Cloudflare's Access policy replaces the legacy `required_scope` check.

The origin does not accept the client's opaque token, a raw JWT bearer,
static token, email header, or dashboard cookie as an alternative.
Its own protected-resource metadata is disabled in this mode to avoid
advertising a competing OAuth flow. Cloudflare must provide discovery and
challenges at the public hostname; do not enable this mode behind ordinary
Access browser redirects without Managed OAuth. Restrict direct origin
access with a Tunnel or firewall rules as well.

See [Cloudflare Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/)
for client prerequisites, redirect allowlists, and refresh-token settings.

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
multi-arch image at `ghcr.io/jegork/rusty-gateway:<tag>` (also `latest`),
pullable without authentication.

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

## License

MIT, see [LICENSE](LICENSE).
