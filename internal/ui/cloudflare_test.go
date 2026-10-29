package ui

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
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jegork/rusty-gateway/internal/config"
	"github.com/jegork/rusty-gateway/internal/gateway"
	"github.com/jegork/rusty-gateway/internal/supervisor"
)

func TestCloudflareDashboard(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.RWMutex
	published, kid, unavailable := key, "initial", false
	certs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cdn-cgi/access/certs" {
			http.NotFound(w, r)
			return
		}
		mu.RLock()
		defer mu.RUnlock()
		if unavailable {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(published.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(published.E)).Bytes()),
		}}})
	}))
	defer certs.Close()
	ctx := oidc.ClientContext(context.Background(), certs.Client())
	sup := supervisor.New(nil, supervisor.Options{})
	gw := gateway.New(sup, []gateway.Namespace{{Name: "p"}}, gateway.Options{})
	deps := Deps{Supervisor: sup, Gateway: gw, Token: "old-token", Cloudflare: config.CloudflareAccess{
		TeamDomain: certs.URL, Audience: "dashboard-audience",
	}}
	u, err := New(ctx, deps)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(u.Handler())
	defer srv.Close()
	c := client(t)
	sign := func(key *rsa.PrivateKey, kid string, overrides jwt.MapClaims) string {
		t.Helper()
		claims := jwt.MapClaims{"iss": certs.URL, "aud": []string{"dashboard-audience"},
			"sub": "operator", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
		for k, v := range overrides {
			claims[k] = v
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	valid := sign(key, "initial", nil)
	request := func(method, path, token string, cookie *http.Cookie) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader("token=old-token"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if token != "" {
			req.Header.Set("Cf-Access-Jwt-Assertion", token)
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	t.Run("reject invalid assertions", func(t *testing.T) {
		cases := []struct{ name, token string }{
			{"missing", ""},
			{"malformed", "garbage"},
			{"wrong signature", sign(other, "initial", nil)},
			{"wrong issuer", sign(key, "initial", jwt.MapClaims{"iss": "https://other.cloudflareaccess.com"})},
			{"wrong audience", sign(key, "initial", jwt.MapClaims{"aud": "another-application"})},
			{"missing audience", sign(key, "initial", jwt.MapClaims{"aud": nil})},
			{"expired", sign(key, "initial", jwt.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()})},
			{"missing expiry", sign(key, "initial", jwt.MapClaims{"exp": nil})},
			{"not yet valid", sign(key, "initial", jwt.MapClaims{"nbf": time.Now().Add(time.Hour).Unix()})},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				res := request("GET", "/ui/", tc.token, nil)
				defer res.Body.Close()
				if res.StatusCode != http.StatusUnauthorized || res.Header.Get("Location") != "" {
					t.Fatalf("want 401 without redirect, got %d %s", res.StatusCode, res.Header.Get("Location"))
				}
			})
		}
	})

	t.Run("no local session or email header bypass", func(t *testing.T) {
		local, err := New(context.Background(), Deps{Token: "old-token"})
		if err != nil {
			t.Fatal(err)
		}
		for _, cookie := range []*http.Cookie{
			{Name: cookieName, Value: local.newSession()},
			{Name: "CF_Authorization", Value: valid},
		} {
			res := request("GET", "/ui/", "", cookie)
			res.Body.Close()
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("cookie %s bypassed JWT header: %d", cookie.Name, res.StatusCode)
			}
		}
		req, _ := http.NewRequest("GET", srv.URL+"/ui/", nil)
		req.Header.Set("Cf-Access-Authenticated-User-Email", "operator@example.com")
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("email header bypassed JWT: %d", res.StatusCode)
		}
	})

	t.Run("all dashboard routes protected", func(t *testing.T) {
		for _, route := range []struct{ method, path string }{
			{"GET", "/ui/"}, {"GET", "/ui/tools"}, {"GET", "/ui/audit"},
			{"GET", "/ui/events/overview"}, {"GET", "/ui/tools/list"}, {"GET", "/ui/audit/rows"},
			{"GET", "/ui/oauth/p/server/login"}, {"GET", "/ui/static/style.css"},
			{"GET", "/ui/login"}, {"POST", "/ui/login"}, {"POST", "/ui/logout"},
		} {
			res := request(route.method, route.path, "", nil)
			res.Body.Close()
			if res.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s without JWT: %d", route.method, route.path, res.StatusCode)
			}
		}
	})

	t.Run("valid assertion renders dashboard without local session", func(t *testing.T) {
		for _, path := range []string{"/ui/", "/ui/tools", "/ui/audit", "/ui/static/style.css"} {
			res := request("GET", path, valid, nil)
			body := readAll(res)
			if res.StatusCode != http.StatusOK {
				t.Fatalf("%s: %d %s", path, res.StatusCode, body)
			}
			if path == "/ui/" && !strings.Contains(body, "Overview") {
				t.Fatalf("did not render overview: %s", body)
			}
			if len(res.Cookies()) != 0 {
				t.Fatalf("created a local session: %v", res.Cookies())
			}
		}
		for _, path := range []string{"/ui/events/overview", "/ui/tools/list", "/ui/audit/rows"} {
			res := request("GET", path, valid, nil)
			res.Body.Close()
			if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
				t.Fatalf("%s: %d %s", path, res.StatusCode, res.Header.Get("Content-Type"))
			}
		}
	})

	t.Run("login and logout use Cloudflare session", func(t *testing.T) {
		for _, route := range []struct {
			method, path, location string
			status                 int
		}{
			{"GET", "/ui/login", "/ui/", http.StatusSeeOther},
			{"POST", "/ui/logout", "/cdn-cgi/access/logout", http.StatusSeeOther},
		} {
			res := request(route.method, route.path, valid, nil)
			res.Body.Close()
			if res.StatusCode != route.status || res.Header.Get("Location") != route.location {
				t.Errorf("%s %s: %d %s", route.method, route.path, res.StatusCode, res.Header.Get("Location"))
			}
		}
	})

	t.Run("refresh keys after rotation and fail closed on fetch error", func(t *testing.T) {
		mu.Lock()
		published, kid = other, "rotated"
		mu.Unlock()
		res := request("GET", "/ui/", sign(other, "rotated", nil), nil)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("rotated key rejected: %d", res.StatusCode)
		}
		mu.Lock()
		unavailable = true
		mu.Unlock()
		res = request("GET", "/ui/", sign(key, "unpublished", nil), nil)
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unavailable signing keys must fail closed: %d", res.StatusCode)
		}
	})

	t.Run("does not need MCP static token", func(t *testing.T) {
		deps.Token = ""
		if _, err := New(ctx, deps); err != nil {
			t.Fatal(err)
		}
	})
}
