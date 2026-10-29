package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jegork/rusty-gateway/internal/config"
	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
)

func TestCloudflareMCPAuthentication(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cdn-cgi/access/certs" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "access", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	defer certs.Close()
	ctx := oidc.ClientContext(context.Background(), certs.Client())
	cfg := Config{PublicURL: "https://gw.example", Resources: []string{"/mcp/personal"},
		Cloudflare: config.CloudflareAccess{TeamDomain: certs.URL, Audience: "mcp-audience"}}
	a, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(claims jwt.MapClaims) string {
		t.Helper()
		base := jwt.MapClaims{"iss": certs.URL, "aud": "mcp-audience", "sub": "operator-123", "exp": time.Now().Add(time.Hour).Unix()}
		for k, v := range claims {
			base[k] = v
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, base)
		token.Header["kid"] = "access"
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp/personal", a.Middleware("/mcp/personal")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := sdkauth.TokenInfoFromContext(r.Context())
		if info == nil || info.UserID != "operator-123" || !info.Expiration.After(time.Now()) {
			t.Error("MCP session is not bound to the verified user and expiry")
			http.Error(w, "missing authenticated principal", 500)
			return
		}
		if ClientID(r.Context()) != "operator-123" {
			t.Error("audit identity does not match the verified subject")
		}
		w.Write([]byte("private tool catalog"))
	})))
	mux.Handle(MetadataPath+"/", a.MetadataHandler())
	srv := httptest.NewServer(mux)
	defer srv.Close()
	valid := sign(nil)
	for _, tc := range []struct {
		name, assertion, bearer, email string
		status                         int
	}{
		{"missing assertion", "", "", "", 401},
		{"opaque bearer alone", "", "oauth:opaque-client-token", "", 401},
		{"static bearer alone", "", "old-static-token", "", 401},
		{"raw JWT bearer alone", "", valid, "", 401},
		{"spoofed email", "", "", "operator@example.com", 401},
		{"malformed assertion", "garbage", "oauth:opaque-client-token", "", 401},
		{"dashboard audience", sign(jwt.MapClaims{"aud": "dashboard-audience"}), "", "", 401},
		{"wrong issuer", sign(jwt.MapClaims{"iss": "https://other.cloudflareaccess.com"}), "", "", 401},
		{"expired assertion", sign(jwt.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()}), "", "", 401},
		{"missing subject", sign(jwt.MapClaims{"sub": ""}), "", "", 401},
		{"valid edge assertion", valid, "oauth:opaque-client-token", "", 200},
		{"valid assertion without bearer", valid, "", "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", srv.URL+"/mcp/personal", nil)
			req.Header.Set("Cf-Access-Jwt-Assertion", tc.assertion)
			req.Header.Set("Cf-Access-Authenticated-User-Email", tc.email)
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != tc.status {
				t.Fatalf("want %d, got %d", tc.status, res.StatusCode)
			}
			if tc.status == 200 && res.Header.Get("WWW-Authenticate") != "" {
				t.Fatal("gateway challenged an already authenticated Cloudflare client")
			}
		})
	}
	res, err := http.Get(srv.URL + MetadataPath + "/mcp/personal")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("Cloudflare must own OAuth discovery, got %d", res.StatusCode)
	}
	cfg.StaticToken = "old-static-token"
	if _, err := New(ctx, cfg); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("must reject ambiguous auth modes: %v", err)
	}
}
