# MCP Gateway — Design Doc

A single-user MCP aggregator in Go. Replaces MetaMCP for a one-person deployment: namespaced endpoints over stdio upstreams, OAuth-protected, with a real audit log.

**Status:** M0–M5 implemented · **Language:** Go · **Storage:** SQLite · **Date:** 2026-09-07

---

## 1. Why build this

Four failure modes observed on MetaMCP 2.4.22 (rev `32b6e981`), all in one evening:

| Symptom | Root cause | Fixed by this design? |
|---|---|---|
| 14 child processes for 3 configured servers, 2.4 GB RSS | Child processes allocated **per session**; sessions accumulate across reconnects | **Yes, by construction** — processes keyed by config, not connection |
| `uvx` failing with `Permission denied` on `~/.cache/uv` | Children spawned with a minimal env; container-level vars never reach them | **Yes** — explicit, inspectable env composition |
| `No server found for command: /usr/local/bin/uvx …` | Upstream matched by raw command **string** comparison | **Yes** — upstreams keyed by stable ID |
| Constant OAuth re-authorization | Weak/absent refresh path (cf. upstream issue #142) | **Yes** — delegate to a real IdP, hold no tokens |
| No record of which tool was called with what | Not implemented upstream | **Yes** — audit log is a first-class component |

The decisive simplification is **dropping multi-tenancy**. MetaMCP allocates per-session child processes because sessions may belong to different tenants. One user means one shared process pool, and the memory problem stops being a bug to fix and becomes a state that cannot be represented.

---

## 2. Goals and non-goals

**Goals**

- Aggregate N stdio MCP servers behind namespaced HTTP endpoints
- One long-lived child process per `(namespace, server)`, supervised and restarted on crash
- OAuth 2.1 bearer-token protection, delegating all authorization to an external IdP
- Durable, queryable, redacted audit log of every tool call
- Single static binary + one SQLite file + one TOML config

**Non-goals**

- Multi-tenancy, organizations, RBAC
- Being an OAuth **authorization server** (issuing tokens, consent screens, DCR)
- An admin web UI — config is a file in git
- A custom inspector — the official `@modelcontextprotocol/inspector` already points at any endpoint
- Tool discovery modes beyond the full merged list (tracked in issue #2)

---

## 3. Architecture

```
                    ┌──────────────────────────────────────────────┐
   Claude, Code,    │  Gateway (single Go binary)                   │
   Inspector  ─────►│                                              │
   Bearer token     │  ┌────────────┐                              │
                    │  │ Auth MW    │ JWKS validate, scope check   │
                    │  └─────┬──────┘                              │
                    │        ▼                                     │
                    │  ┌────────────┐                              │
                    │  │ Namespace  │ /mcp/{ns} → MCP server       │
                    │  │ Router     │ merged tool list             │
                    │  └─────┬──────┘                              │
                    │        ▼                                     │
                    │  ┌────────────┐      ┌──────────────┐        │
                    │  │ Dispatcher │─────►│ Audit sink   │─►SQLite│
                    │  └─────┬──────┘      └──────────────┘        │
                    │        ▼                                     │
                    │  ┌────────────────────────────────┐          │
                    │  │ Supervisor: one child per      │          │
                    │  │ (namespace, server)            │          │
                    │  └───┬──────────┬─────────┬───────┘          │
                    └──────┼──────────┼─────────┼──────────────────┘
                           ▼          ▼         ▼
                      tradingview   hevy     dokploy      (stdio subprocesses,
                       (uvx/py)    (node)    (node)        own process groups)
```

**Components**

1. **Config loader** (`internal/config`) — parse TOML, validate, expand env references.
2. **Supervisor** (`internal/supervisor`) — owns the child process table. Start, health-check, restart with backoff, shut down cleanly.
3. **Namespace router + dispatcher** (`internal/gateway`) — one MCP server endpoint per namespace, exposing the merged tool list of that namespace's upstreams; resolves a prefixed tool name to an upstream and forwards the call.
4. **Auth middleware** (`internal/auth`) — validate bearer tokens against the IdP's JWKS; serve protected-resource metadata.
5. **Audit sink** (`internal/audit`, `internal/redact`) — buffered writes to SQLite, off the request path, fed through `Gateway.Observe`.

---

## 4. Libraries

| Purpose | Module | Why |
|---|---|---|
| MCP protocol | `github.com/modelcontextprotocol/go-sdk` v1.7.0 (pinned) | Official. `CommandTransport` for spawning stdio upstreams, `NewStreamableHTTPHandler` for the frontend, `auth.RequireBearerToken` and `auth.ProtectedResourceMetadataHandler` for the resource-server side. |
| HTTP server | `net/http` (stdlib) | Go 1.22+ pattern routing covers `/mcp/{ns}`. |
| Token validation | `github.com/coreos/go-oidc/v3/oidc` | `NewProvider` handles OIDC discovery and JWKS fetch/cache/rotation. |
| SQLite driver | `modernc.org/sqlite` | Pure Go, no cgo — preserves the single static binary and cross-compilation. |
| Queries and schema | `database/sql` with an embedded `schema.sql` | Three queries and one table did not justify sqlc and goose; revisit when a second migration is needed. |
| Config | `github.com/pelletier/go-toml/v2` | Fast, strict, good error messages. |
| Logging | `log/slog` (stdlib) | JSON handler, structured, zero dependencies. |
| Process groups | `os/exec` + `syscall` (stdlib) | `SysProcAttr{Setpgid: true}` and killing the negative PID. |

**Version caveat on the SDK.** v1.7.0 largely rewrote the wire protocol for MCP spec `2026-07-28`, with `MCPGODEBUG` escape-hatch flags for the old behavior — and those flags are scheduled for removal in v1.9.0. Pin an exact version, and treat SDK upgrades as real work rather than routine dependency bumps.

---

## 5. Process supervision

One `Upstream` per `(namespace, server)`, started once at boot and shared by every client session.

**Starting.** Build the environment explicitly — base allowlist (`PATH HOME LANG LC_ALL TMPDIR USER LOGNAME TZ`) plus per-server config, expanded from the host env, logged at debug level with secret-looking keys masked.

**Stopping.** Signal the whole group, not just the direct child — this is what stops `uvx` and `npx` wrappers from orphaning their grandchildren: SIGTERM the group, close stdin and let the SDK wait/escalate, then SIGKILL the group.

**Health.** `Ping()` every 30s. On failure or unexpected exit, restart with exponential backoff (1s → 60s cap), and mark the upstream `Failed` after 5 consecutive failures. The failure counter resets once a child has stayed up for 60s. Failed upstreams are reported in `/healthz` and their tools disappear from the namespace rather than erroring at call time.

**Invariant asserted in tests:** the number of live children equals the number of configured, non-failed upstreams, regardless of how many clients connect, disconnect, or reconnect.

---

## 6. Namespaces and routing

A namespace is a name, a list of servers, and an endpoint path.

- Endpoint: `POST /mcp/{namespace}` (streamable HTTP)
- Tool naming: `{server}__{tool}`
- Collisions: prefixing makes them impossible within a namespace; two namespaces are independent
- `tools/list` returns the union across that namespace's ready upstreams; `tools/list_changed` from an upstream re-syncs it

---

## 7. Auth: resource server, not authorization server

**The gateway never issues, refreshes, or stores a token.** It validates them.

**Flow**

1. Unauthenticated request → `401` with `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"`
2. Gateway serves that metadata, naming the IdP as `authorization_servers`
3. Client runs the OAuth dance **against the IdP**
4. Client returns with a bearer token; gateway validates signature (JWKS), `iss`, `aud`, `exp`, and required scope
5. Refresh, consent, and revocation are entirely the IdP's problem

**IdP decision.** Authelia, with static client registration. See [auth-and-dcr.md](auth-and-dcr.md) for the verification and the cost of the alternative.

**Escape hatch.** A static bearer token from config (constant-time compare) for scripts and for bootstrapping. The auth method used is logged per request at debug level.

---

## 8. Audit log

```sql
CREATE TABLE tool_calls (
  id           INTEGER PRIMARY KEY,
  ts           INTEGER NOT NULL,      -- unix millis
  namespace    TEXT    NOT NULL,
  server       TEXT    NOT NULL,
  tool         TEXT    NOT NULL,
  client_id    TEXT,                  -- from token claims
  session_id   TEXT,
  args_json    TEXT,                  -- redacted, truncated
  result_size  INTEGER,               -- bytes, before truncation
  result_json  TEXT,                  -- redacted, truncated
  duration_ms  INTEGER NOT NULL,
  status       TEXT    NOT NULL,      -- ok | error | timeout
  error        TEXT
);
CREATE INDEX idx_calls_ts   ON tool_calls(ts DESC);
CREATE INDEX idx_calls_tool ON tool_calls(namespace, server, tool, ts DESC);
```

**Redaction is mandatory.** Redact before the row is constructed:

- Drop any arg whose key matches `(?i)(token|key|secret|password|auth|credential)`
- Replace values matching known secret shapes (`sk_`, `sk-`, long base64/hex runs) with `«redacted»`
- Cap `args_json` and `result_json` at ~8 KB each; keep the true size in `result_size`

**Writes are buffered** — a bounded channel with a single writer goroutine. Drop with a counted warning if the buffer fills rather than applying backpressure.

**Retention:** nightly `DELETE FROM tool_calls WHERE ts < ?` plus periodic `VACUUM`. 90 days default.

**Read path:** `GET /audit?namespace=&tool=&since=&limit=` returning JSON, plus a `gateway audit tail` CLI subcommand.

---

## 9. Config

See `gateway.example.toml`. `${VAR}` interpolates from the host environment at load and unset variables are an error. Every `command` must be an absolute path to an executable, checked at load.

---

## 10. Milestones

| # | Scope | State |
|---|---|---|
| M0 | Spawn one upstream, proxy `tools/list` + `tools/call` over stdio | done |
| M1 | Supervisor: process groups, restart/backoff, health, clean shutdown, process-count invariant test | done |
| M2 | Namespaces, config file, streamable HTTP endpoint, tool prefixing | done |
| M3 | Audit log: schema, redaction, buffered writer, read API, retention | done |
| M4 | Auth: protected-resource metadata, JWKS validation, static-token fallback | done |
| M5 | Ops: per-child RSS metrics, Dockerfile, memory limit | done |

---

## 11. Open questions

1. ~~Does Authelia support DCR?~~ No. Resolved in [auth-and-dcr.md](auth-and-dcr.md).
2. ~~Remote (HTTP) upstreams~~ — implemented as `url` servers sharing the same supervisor loop.
3. **Tool-level authorization** — is `mcp:use` enough, or eventually per-namespace scopes (`mcp:personal`, `mcp:ops`)?
4. **Cold-start cost** — upstreams start at boot. Acceptable, or start lazily on first use per namespace?
5. **Migration path** — run alongside MetaMCP on a different port and cut over one namespace at a time, or replace outright?
6. **SIGHUP reload** — not implemented; a restart is the reload.
