# Auth decision: Authelia, static client registration, no DCR

Date: 2026-09-07. Answers open question 1 of the design doc.

## What was verified

| Question | Answer | Source |
|---|---|---|
| Does Authelia ship RFC 7591 Dynamic Client Registration? | **No.** Latest release is v4.39.22 (2026-09-03). DCR is on the roadmap under "Beta 8, in progress v4.40.0", requiring a new in-database client table. | [Authelia OIDC roadmap](https://www.authelia.com/roadmap/active/openid-connect-1.0-provider/), [discussion #7304](https://github.com/authelia/authelia/discussions/7304) |
| Does Authelia support Client ID Metadata Documents (CIMD)? | **No.** Not mentioned on the roadmap; no issues or PRs in the repo. | repo search |
| RFC 8414 authorization server metadata | Yes, since v4.34.0 | roadmap |
| RFC 8707 resource indicators (MCP clients send `resource=`) | Yes, since v4.39.21. v4.39.22 has a bug where the token exchange rejects the `resource` value ([#12970](https://github.com/authelia/authelia/issues/12970), fix merged, not yet released). | issue tracker |
| RFC 9068 JWT access tokens | Yes, per client via `access_token_signed_response_alg`. Default is opaque tokens, which the gateway cannot validate with JWKS. | Authelia docs |
| What does the MCP spec want now? | The 2026-07-28 spec **deprecated DCR in favor of CIMD**. DCR stays supported for at least twelve months. Claude Code, claude.ai and the SDKs ship CIMD. | [MCP 2026-07-28 blog](https://blog.modelcontextprotocol.io/posts/2026-07-28/), [WorkOS on DCR in MCP](https://workos.com/blog/dynamic-client-registration-dcr-mcp-oauth) |
| Can the clients work without DCR? | Yes. Claude Code takes `claude mcp add --transport http --client-id ... --client-secret ...`, claude.ai custom connectors accept a client id and secret in advanced settings, and Inspector accepts a preconfigured client id. Claude Code's pre-registered path has had bugs ([#68853](https://github.com/anthropics/claude-code/issues/68853), [#67258](https://github.com/anthropics/claude-code/issues/67258)); check the version you run. | issue tracker, [claude.ai connector auth docs](https://claude.com/docs/connectors/building/authentication) |

## Decision

**Keep Authelia. Register each MCP client statically in Authelia's config. Build no DCR.**

Reasons:

- DCR is already deprecated by the protocol. Building it now means building the legacy path.
- CIMD is an authorization server feature, so there is nothing for the gateway to build either way. When Authelia ships it, nothing here changes.
- The clients that matter accept a pre-registered client id. For one user with three or four clients, a static list in a git-tracked config is the better model anyway.
- The static bearer token in the gateway covers scripts and bootstrapping.

Cost: one Authelia client block per MCP client, and one `--client-id` flag per Claude Code install.

## Authelia client configuration

Every client must use the JWT access token profile so the gateway can validate with JWKS.

**Audience is per namespace.** MCP clients send `resource=<the endpoint URL they connect to>` (RFC 8707), so Claude Code asking for `/mcp/personal` sends `resource=https://gw.example/mcp/personal`. Authelia only issues a token for a resource listed in the client's `audience`, so list every namespace URL there. The gateway accepts a token whose `aud` is any of its namespace URLs or its `public_url`, and serves per-namespace metadata at `/.well-known/oauth-protected-resource/mcp/{ns}` so clients discover the right resource value.

The provider itself needs a signing key the first time OIDC is enabled. Generate one with `authelia crypto pair rsa generate --bits 4096` and a random `hmac_secret`; both can also come from files via `AUTHELIA_IDENTITY_PROVIDERS_OIDC_HMAC_SECRET_FILE` and `AUTHELIA_IDENTITY_PROVIDERS_OIDC_JWKS_0_KEY_FILE`.

```yaml
identity_providers:
  oidc:
    hmac_secret: '<64 random bytes, hex>'
    jwks:
      - key_id: main
        algorithm: RS256
        use: sig
        key: |
          -----BEGIN PRIVATE KEY-----
          ...
          -----END PRIVATE KEY-----
    clients:
      - client_id: claude-code
        client_name: Claude Code
        public: true
        authorization_policy: two_factor
        redirect_uris:
          - http://localhost:3000/callback   # match --callback-port
        scopes: [openid, offline_access, mcp:use]
        audience: [https://gw.example/mcp/personal, https://gw.example/mcp/ops]
        grant_types: [authorization_code, refresh_token]
        response_types: [code]
        token_endpoint_auth_method: none
        require_pkce: true
        pkce_challenge_method: S256
        access_token_signed_response_alg: RS256
      - client_id: claude-ai
        client_name: Claude.ai
        client_secret: '$pbkdf2-sha512$...'
        authorization_policy: two_factor
        redirect_uris:
          - https://claude.ai/api/mcp/auth_callback
          - https://claude.com/api/mcp/auth_callback
        scopes: [openid, offline_access, mcp:use]
        audience: [https://gw.example/mcp/personal, https://gw.example/mcp/ops]
        grant_types: [authorization_code, refresh_token]
        response_types: [code]
        token_endpoint_auth_method: client_secret_post
        require_pkce: true
        pkce_challenge_method: S256
        access_token_signed_response_alg: RS256
      - client_id: chatgpt
        client_name: ChatGPT
        client_secret: '$pbkdf2-sha512$...'
        authorization_policy: two_factor
        redirect_uris:
          - https://chatgpt.com/connector_platform_oauth_redirect
        scopes: [openid, offline_access, mcp:use]
        audience: [https://gw.example/mcp/personal, https://gw.example/mcp/ops]
        grant_types: [authorization_code, refresh_token]
        response_types: [code]
        token_endpoint_auth_method: client_secret_post
        require_pkce: true
        pkce_challenge_method: S256
        access_token_signed_response_alg: RS256
      - client_id: codex
        client_name: Codex CLI
        public: true
        authorization_policy: two_factor
        redirect_uris:
          - http://localhost:8432/oauth/callback   # match oauth.callback_url below
        scopes: [openid, offline_access, mcp:use]
        audience: [https://gw.example/mcp/personal, https://gw.example/mcp/ops]
        grant_types: [authorization_code, refresh_token]
        response_types: [code]
        token_endpoint_auth_method: none
        require_pkce: true
        pkce_challenge_method: S256
        access_token_signed_response_alg: RS256
    scopes:
      mcp:use:
        description: Use the MCP gateway
```

Gateway side. `audience` is optional and only adds one more accepted `aud` value on top of the namespace URLs:

```toml
[auth]
issuer         = "https://auth.example"
required_scope = "mcp:use"
```

Claude Code:

```sh
claude mcp add --transport http --client-id claude-code --callback-port 3000 personal https://gw.example/mcp/personal
```

Codex (`~/.codex/config.toml`). Codex binds a random callback port by default, so the fixed port and URL are what keep the Authelia redirect URI stable:

```toml
[mcp_servers.personal]
url = "https://gw.example/mcp/personal"
oauth_resource = "https://gw.example/mcp/personal"

[mcp_servers.personal.oauth]
client_id = "codex"
callback_port = 8432
callback_url = "http://localhost:8432/oauth/callback"
```

Then `codex mcp login personal`. Codex prefers CIMD and only falls back to DCR when the server does not advertise it, so once Authelia ships CIMD the pre-registered client block becomes optional.

ChatGPT: Settings, Connectors, Create, MCP URL `https://gw.example/mcp/personal`, OAuth, Advanced settings, user-defined client, client id `chatgpt` plus the plaintext secret. Developer mode must be on for connectors that expose arbitrary tools; without it ChatGPT only uses the `search`/`fetch` deep-research contract. ChatGPT validates the connector on save, so wire Authelia and test with a CLI client first.

## If Authelia turns out to be unusable: what building DCR would take

Authelia's clients live in a static config file with no admin API, so the gateway cannot register a client into Authelia at runtime. A DCR shim therefore cannot be a thin `/register` endpoint. It has to become an OAuth authorization server that fronts Authelia:

| Piece | Notes |
|---|---|
| `POST /register` (RFC 7591) | Validate metadata, store client in SQLite, return `client_id` |
| `/.well-known/oauth-authorization-server` (RFC 8414) | Point clients at the shim's endpoints |
| `GET /authorize` | Validate client and redirect URI, store PKCE challenge, redirect to Authelia as one confidential client |
| `GET /callback` | Exchange Authelia's code, bind the Authelia session to the pending MCP authorization, issue our own code |
| `POST /token` | Authorization code and refresh token grants, PKCE verification, mint JWTs with our own signing key |
| JWKS endpoint plus key generation and rotation | The gateway's own validator would then trust the shim's keys |
| Storage | Clients, pending authorizations, refresh tokens, revocation |

Estimate: **4 to 6 days** for a careful implementation, roughly 1,200 to 1,500 lines of Go plus tests, and it replaces the smallest part of the design (a JWKS check) with the most security-sensitive one (an authorization server holding refresh tokens). It directly contradicts the "hold no tokens" goal in the design doc.

If static registration ever stops being enough, the cheaper path is to swap the IdP rather than build the shim. Keycloak ships DCR. Check the current CIMD status of any candidate before choosing, since that is the path the protocol is converging on. The gateway only needs an issuer URL, a JWKS endpoint, and JWT access tokens with an `aud` claim, so an IdP swap touches only the `[auth]` block.
