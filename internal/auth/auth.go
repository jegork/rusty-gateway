// Package auth validates bearer tokens. The gateway is a resource server
// only: it never issues, refreshes, or stores tokens.
package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

const MetadataPath = "/.well-known/oauth-protected-resource"

type Config struct {
	PublicURL string
	Issuer    string
	// Audience is an extra accepted aud value; the public URL and every
	// resource URL are always accepted.
	Audience      string
	RequiredScope string
	StaticToken   string
	// Resources are the protected endpoints, e.g. "/mcp/personal". Each gets
	// its own RFC 9728 metadata document and is an accepted aud value, so
	// clients can send resource=<endpoint url> as the MCP spec requires.
	Resources []string
	Logger    *slog.Logger
}

type Authenticator struct {
	cfg      Config
	verifier *oidc.IDTokenVerifier
	audience []string
}

func New(ctx context.Context, cfg Config) (*Authenticator, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	a := &Authenticator{cfg: cfg, audience: []string{cfg.PublicURL}}
	if cfg.Audience != "" {
		a.audience = append(a.audience, cfg.Audience)
	}
	for _, r := range cfg.Resources {
		a.audience = append(a.audience, cfg.PublicURL+r)
	}
	if cfg.Issuer != "" {
		provider, err := oidc.NewProvider(ctx, cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery for %s: %w", cfg.Issuer, err)
		}
		a.verifier = provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
	}
	if a.verifier == nil && cfg.StaticToken == "" {
		return nil, errors.New("no auth method configured")
	}
	return a, nil
}

// Middleware wraps h with bearer-token enforcement for the given resource
// path, so the 401 challenge points at that resource's metadata.
func (a *Authenticator) Middleware(resource string) func(http.Handler) http.Handler {
	opts := &sdkauth.RequireBearerTokenOptions{
		ResourceMetadataURL: a.cfg.PublicURL + MetadataPath + resource,
	}
	if a.cfg.RequiredScope != "" {
		opts.Scopes = []string{a.cfg.RequiredScope}
	}
	return sdkauth.RequireBearerToken(a.verify, opts)
}

// MetadataHandler serves RFC 9728 metadata at MetadataPath (for the
// gateway as a whole) and MetadataPath+resource for each resource.
func (a *Authenticator) MetadataHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(MetadataPath, a.metadata(""))
	for _, r := range a.cfg.Resources {
		mux.Handle(MetadataPath+r, a.metadata(r))
	}
	return mux
}

func (a *Authenticator) metadata(resource string) http.Handler {
	md := &oauthex.ProtectedResourceMetadata{
		Resource:               a.cfg.PublicURL + resource,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "rusty-gateway" + resource,
	}
	if a.cfg.Issuer != "" {
		md.AuthorizationServers = []string{a.cfg.Issuer}
	}
	if a.cfg.RequiredScope != "" {
		md.ScopesSupported = []string{a.cfg.RequiredScope}
	}
	return sdkauth.ProtectedResourceMetadataHandler(md)
}

func (a *Authenticator) verify(ctx context.Context, token string, r *http.Request) (*sdkauth.TokenInfo, error) {
	if a.cfg.StaticToken != "" &&
		subtle.ConstantTimeCompare([]byte(token), []byte(a.cfg.StaticToken)) == 1 {
		a.cfg.Logger.DebugContext(ctx, "authenticated", "method", "static")
		return &sdkauth.TokenInfo{
			Scopes:     strings.Fields(a.cfg.RequiredScope),
			Expiration: time.Now().Add(time.Hour),
			UserID:     "static",
			Extra:      map[string]any{"auth_method": "static", "client_id": "static"},
		}, nil
	}
	if a.verifier == nil {
		a.cfg.Logger.WarnContext(ctx, "token rejected", "method", "static", "err", "no match and no issuer configured", "remote", r.RemoteAddr)
		return nil, sdkauth.ErrInvalidToken
	}
	idt, err := a.verifier.Verify(ctx, token)
	if err != nil {
		a.cfg.Logger.WarnContext(ctx, "token rejected", "method", "oidc", "err", err, "remote", r.RemoteAddr)
		return nil, fmt.Errorf("%w: %v", sdkauth.ErrInvalidToken, err)
	}
	if !slices.ContainsFunc(idt.Audience, func(aud string) bool { return slices.Contains(a.audience, aud) }) {
		a.cfg.Logger.WarnContext(ctx, "token rejected", "method", "oidc", "err", "audience mismatch", "aud", idt.Audience, "accepted", a.audience, "remote", r.RemoteAddr)
		return nil, fmt.Errorf("%w: audience %v not accepted", sdkauth.ErrInvalidToken, idt.Audience)
	}
	var claims struct {
		Scope    string `json:"scope"`
		ClientID string `json:"client_id"`
		Azp      string `json:"azp"`
	}
	if err := idt.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", sdkauth.ErrInvalidToken, err)
	}
	clientID := claims.ClientID
	if clientID == "" {
		clientID = claims.Azp
	}
	a.cfg.Logger.DebugContext(ctx, "authenticated", "method", "oidc", "sub", idt.Subject, "client_id", clientID)
	return &sdkauth.TokenInfo{
		Scopes:     strings.Fields(claims.Scope),
		Expiration: idt.Expiry,
		UserID:     idt.Subject,
		Extra:      map[string]any{"auth_method": "oidc", "client_id": clientID},
	}, nil
}

// ClientID extracts the caller identity recorded by verify, for audit rows.
func ClientID(ctx context.Context) string {
	ti := sdkauth.TokenInfoFromContext(ctx)
	if ti == nil {
		return ""
	}
	if v, ok := ti.Extra["client_id"].(string); ok {
		return v
	}
	return ti.UserID
}
