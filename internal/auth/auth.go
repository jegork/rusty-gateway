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
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

const MetadataPath = "/.well-known/oauth-protected-resource"

type Config struct {
	PublicURL     string
	Issuer        string
	Audience      string
	RequiredScope string
	StaticToken   string
	Logger        *slog.Logger
}

type Authenticator struct {
	cfg      Config
	verifier *oidc.IDTokenVerifier
}

func New(ctx context.Context, cfg Config) (*Authenticator, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	a := &Authenticator{cfg: cfg}
	if cfg.Issuer != "" {
		provider, err := oidc.NewProvider(ctx, cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery for %s: %w", cfg.Issuer, err)
		}
		a.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.Audience})
	}
	if a.verifier == nil && cfg.StaticToken == "" {
		return nil, errors.New("no auth method configured")
	}
	return a, nil
}

// Middleware wraps h with bearer-token enforcement.
func (a *Authenticator) Middleware() func(http.Handler) http.Handler {
	opts := &sdkauth.RequireBearerTokenOptions{
		ResourceMetadataURL: a.cfg.PublicURL + MetadataPath,
	}
	if a.cfg.RequiredScope != "" {
		opts.Scopes = []string{a.cfg.RequiredScope}
	}
	return sdkauth.RequireBearerToken(a.verify, opts)
}

// MetadataHandler serves RFC 9728 protected resource metadata.
func (a *Authenticator) MetadataHandler() http.Handler {
	md := &oauthex.ProtectedResourceMetadata{
		Resource:               a.cfg.PublicURL,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "rusty-gateway",
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
		return nil, sdkauth.ErrInvalidToken
	}
	idt, err := a.verifier.Verify(ctx, token)
	if err != nil {
		a.cfg.Logger.DebugContext(ctx, "token rejected", "method", "oidc", "err", err)
		return nil, fmt.Errorf("%w: %v", sdkauth.ErrInvalidToken, err)
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
