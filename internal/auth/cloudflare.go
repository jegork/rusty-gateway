package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jegork/rusty-gateway/internal/config"
	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

func NewCloudflareVerifier(ctx context.Context, cfg config.CloudflareAccess) (*oidc.IDTokenVerifier, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.TeamDomain == "" {
		return nil, nil
	}
	issuer := strings.TrimSuffix(cfg.TeamDomain, "/")
	client := *oauth2.NewClient(ctx, nil)
	client.Timeout = 10 * time.Second
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(ctx, &client), issuer+"/cdn-cgi/access/certs")
	return oidc.NewVerifier(issuer, keys, &oidc.Config{
		ClientID: cfg.Audience, SupportedSigningAlgs: []string{oidc.RS256},
	}), nil
}

func (a *Authenticator) cloudflareMiddleware(next http.Handler) http.Handler {
	// adapt the verified assertion to the sdk middleware so mcp sessions remain
	// bound to the authenticated user, not the opaque client bearer token
	authenticated := sdkauth.RequireBearerToken(func(ctx context.Context, assertion string, r *http.Request) (*sdkauth.TokenInfo, error) {
		token, err := a.accessVerifier.Verify(ctx, assertion)
		if err != nil {
			return nil, sdkauth.ErrInvalidToken
		}
		if token.Subject == "" {
			return nil, sdkauth.ErrInvalidToken
		}
		return &sdkauth.TokenInfo{
			UserID: token.Subject, Expiration: token.Expiry,
			Extra: map[string]any{"auth_method": "cloudflare", "client_id": token.Subject},
		}, nil
	}, nil)(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertion := r.Header.Get("Cf-Access-Jwt-Assertion")
		if assertion == "" {
			http.Error(w, "Cloudflare Access authentication required", http.StatusUnauthorized)
			return
		}
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+assertion)
		authenticated.ServeHTTP(w, r)
	})
}
