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

See `gateway.example.toml`. Every `command` must be an absolute path to an
executable; the gateway refuses to start otherwise. `${VAR}` in `env` values is
expanded from the host environment at load and missing variables are an error.

Endpoints:

- `POST|GET|DELETE /mcp/{namespace}` streamable HTTP MCP; tools are named `{server}__{tool}`
- `GET /.well-known/oauth-protected-resource` RFC 9728 metadata
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

## Auth

The gateway is a resource server only. It validates JWT access tokens (`iss`,
`aud`, `exp`, signature via JWKS, `scope`) and never issues or stores tokens.
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
| M5 ops: Dockerfile, RSS metrics, memory limit | not started |

Config reload on SIGHUP is not implemented; restart the process.
