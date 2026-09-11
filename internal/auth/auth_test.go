package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu       sync.Mutex
	refresh  map[string]grant // refresh token -> what it was granted for
	nextID   int
	tokenTTL time.Duration
}

type grant struct{ scope, aud string }

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, refresh: map[string]grant{}, tokenTTL: time.Hour}
	mux := http.NewServeMux()
	// token endpoint that behaves like authelia: any code is accepted, a
	// refresh token is only issued when offline_access was requested
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		f.mu.Lock()
		defer f.mu.Unlock()
		var g grant
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			g = grant{scope: r.Form.Get("scope"), aud: r.Form.Get("resource")}
		case "refresh_token":
			old, ok := f.refresh[r.Form.Get("refresh_token")]
			if !ok {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			delete(f.refresh, r.Form.Get("refresh_token"))
			g = old
		default:
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
			return
		}
		f.nextID++
		resp := map[string]any{
			"access_token": f.token(t, key, jwt.MapClaims{"aud": g.aud, "scope": g.scope, "client_id": r.Form.Get("client_id"),
				"jti": fmt.Sprint(f.nextID), "exp": time.Now().Add(f.tokenTTL).Unix()}),
			"token_type": "bearer",
			"expires_in": int(f.tokenTTL.Seconds()),
		}
		if strings.Contains(" "+g.scope+" ", " offline_access ") {
			rt := fmt.Sprintf("rt-%d", f.nextID)
			f.refresh[rt] = g
			resp["refresh_token"] = rt
		}
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"jwks_uri":                              f.srv.URL + "/jwks",
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{
			{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256", "n": n, "e": e},
		}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) token(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = f.srv.URL
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func protected(t *testing.T, cfg Config) *httptest.Server {
	return protectedCtx(t, context.Background(), cfg)
}

func protectedCtx(t *testing.T, ctx context.Context, cfg Config) *httptest.Server {
	t.Helper()
	a, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp/x", a.Middleware("/mcp/x")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ClientID(r.Context())))
	})))
	mux.Handle(MetadataPath+"/", a.MetadataHandler())
	mux.Handle(MetadataPath, a.MetadataHandler())
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func get(t *testing.T, url, bearer string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := res.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return res.StatusCode, sb.String(), res.Header
}

func TestStaticToken(t *testing.T) {
	s := protected(t, Config{PublicURL: "https://gw.example", StaticToken: "s3cret", RequiredScope: "mcp:use", Resources: []string{"/mcp/x"}})

	code, _, hdr := get(t, s.URL+"/mcp/x", "")
	if code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if want := `resource_metadata="https://gw.example` + MetadataPath + `/mcp/x"`; !strings.Contains(hdr.Get("WWW-Authenticate"), want) {
		t.Errorf("WWW-Authenticate = %q", hdr.Get("WWW-Authenticate"))
	}
	for _, bad := range []string{"s3cre", "S3CRET", "s3cretx"} {
		if code, _, _ := get(t, s.URL+"/mcp/x", bad); code != 401 {
			t.Errorf("token %q accepted", bad)
		}
	}
	code, body, _ := get(t, s.URL+"/mcp/x", "s3cret")
	if code != 200 || body != "static" {
		t.Errorf("good token: %d %q", code, body)
	}

	code, body, _ = get(t, s.URL+MetadataPath, "")
	if code != 200 || !strings.Contains(body, `"resource":"https://gw.example"`) || strings.Contains(body, "authorization_servers") {
		t.Errorf("metadata: %d %s", code, body)
	}
	code, body, _ = get(t, s.URL+MetadataPath+"/mcp/x", "")
	if code != 200 || !strings.Contains(body, `"resource":"https://gw.example/mcp/x"`) {
		t.Errorf("per-resource metadata: %d %s", code, body)
	}
	if code, _, _ := get(t, s.URL+MetadataPath+"/mcp/nope", ""); code != 404 {
		t.Errorf("unknown resource metadata: %d", code)
	}
}

func TestOIDCToken(t *testing.T) {
	idp := newFakeIdP(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := protected(t, Config{
		PublicURL: "https://gw.example", Issuer: idp.srv.URL, Audience: "mcp-gateway",
		RequiredScope: "mcp:use", StaticToken: "s3cret", Resources: []string{"/mcp/x"},
	})

	good := jwt.MapClaims{"aud": "mcp-gateway", "scope": "openid mcp:use", "sub": "jegor", "client_id": "claude-code"}
	cases := []struct {
		name   string
		claims jwt.MapClaims
		key    *rsa.PrivateKey
		want   int
	}{
		{"valid", good, idp.key, 200},
		{"aud list", jwt.MapClaims{"aud": []string{"x", "mcp-gateway"}, "scope": "mcp:use"}, idp.key, 200},
		{"aud public url", jwt.MapClaims{"aud": "https://gw.example", "scope": "mcp:use"}, idp.key, 200},
		{"aud resource url", jwt.MapClaims{"aud": "https://gw.example/mcp/x", "scope": "mcp:use"}, idp.key, 200},
		{"aud other resource", jwt.MapClaims{"aud": "https://gw.example/mcp/other", "scope": "mcp:use"}, idp.key, 401},
		{"no aud", jwt.MapClaims{"scope": "mcp:use"}, idp.key, 401},
		{"wrong signer", good, other, 401},
		{"wrong aud", jwt.MapClaims{"aud": "other", "scope": "mcp:use"}, idp.key, 401},
		{"wrong iss", jwt.MapClaims{"iss": "https://evil", "aud": "mcp-gateway", "scope": "mcp:use"}, idp.key, 401},
		{"expired", jwt.MapClaims{"aud": "mcp-gateway", "scope": "mcp:use", "exp": time.Now().Add(-time.Minute).Unix()}, idp.key, 401},
		{"scp array (fosite/authelia)", jwt.MapClaims{"aud": "mcp-gateway", "scp": []string{"openid", "mcp:use"}}, idp.key, 200},
		{"scp array missing scope", jwt.MapClaims{"aud": "mcp-gateway", "scp": []string{"openid"}}, idp.key, 403},
		{"missing scope", jwt.MapClaims{"aud": "mcp-gateway", "scope": "openid"}, idp.key, 403},
		{"no scope claim", jwt.MapClaims{"aud": "mcp-gateway"}, idp.key, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := get(t, s.URL+"/mcp/x", idp.token(t, tc.key, tc.claims))
			if code != tc.want {
				t.Fatalf("want %d got %d: %s", tc.want, code, body)
			}
			if tc.name == "valid" && body != "claude-code" {
				t.Errorf("client id = %q", body)
			}
		})
	}

	if code, _, _ := get(t, s.URL+"/mcp/x", "s3cret"); code != 200 {
		t.Errorf("static fallback alongside oidc: %d", code)
	}
	code, body, _ := get(t, s.URL+MetadataPath, "")
	if code != 200 || !strings.Contains(body, `"authorization_servers":["`+idp.srv.URL+`"]`) {
		t.Errorf("metadata: %d %s", code, body)
	}
}

// walks the flow a spec-following MCP client uses: 401 -> resource metadata
// -> scopes_supported -> token exchange -> call -> refresh -> call
func TestClientFlowGetsRefreshableToken(t *testing.T) {
	idp := newFakeIdP(t)
	s := protected(t, Config{
		PublicURL: "https://gw.example", Issuer: idp.srv.URL, RequiredScope: "mcp:use",
		Scopes: []string{"mcp:use", "offline_access"}, Resources: []string{"/mcp/x"},
	})

	code, _, hdr := get(t, s.URL+"/mcp/x", "")
	if code != 401 {
		t.Fatalf("unauthenticated: %d", code)
	}
	m := regexp.MustCompile(`resource_metadata="([^"]+)"`).FindStringSubmatch(hdr.Get("WWW-Authenticate"))
	if m == nil {
		t.Fatalf("no resource_metadata in %q", hdr.Get("WWW-Authenticate"))
	}
	// the metadata url is built from the public url; rewrite to the test server
	code, body, _ := get(t, strings.Replace(m[1], "https://gw.example", s.URL, 1), "")
	if code != 200 {
		t.Fatalf("metadata: %d %s", code, body)
	}
	var md struct {
		Resource string   `json:"resource"`
		Scopes   []string `json:"scopes_supported"`
	}
	if err := json.Unmarshal([]byte(body), &md); err != nil {
		t.Fatal(err)
	}

	conf := &oauth2.Config{
		ClientID: "codex",
		Endpoint: oauth2.Endpoint{AuthURL: idp.srv.URL + "/authorize", TokenURL: idp.srv.URL + "/token", AuthStyle: oauth2.AuthStyleInParams},
		Scopes:   md.Scopes,
	}
	ctx := context.Background()
	tok, err := conf.Exchange(ctx, "any-code", oauth2.SetAuthURLParam("resource", md.Resource),
		oauth2.SetAuthURLParam("scope", strings.Join(md.Scopes, " ")))
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken == "" {
		t.Fatalf("no refresh token issued for scopes %v", md.Scopes)
	}
	if code, body, _ := get(t, s.URL+"/mcp/x", tok.AccessToken); code != 200 || body != "codex" {
		t.Fatalf("first token: %d %s", code, body)
	}

	tok.Expiry = time.Now().Add(-time.Minute)
	fresh, err := conf.TokenSource(ctx, tok).Token()
	if err != nil {
		t.Fatal(err)
	}
	if fresh.AccessToken == tok.AccessToken {
		t.Fatal("token source did not refresh")
	}
	if code, body, _ := get(t, s.URL+"/mcp/x", fresh.AccessToken); code != 200 || body != "codex" {
		t.Fatalf("refreshed token: %d %s", code, body)
	}
	// a rotated refresh token is single use
	if _, err := conf.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token(); err == nil {
		t.Fatal("old refresh token still accepted")
	}

	t.Run("required scope alone yields no refresh token", func(t *testing.T) {
		conf := *conf
		conf.Scopes = []string{"mcp:use"}
		tok, err := conf.Exchange(ctx, "any-code", oauth2.SetAuthURLParam("resource", md.Resource),
			oauth2.SetAuthURLParam("scope", "mcp:use"))
		if err != nil {
			t.Fatal(err)
		}
		if tok.RefreshToken != "" {
			t.Fatal("fake idp handed out a refresh token without offline_access")
		}
		if code, _, _ := get(t, s.URL+"/mcp/x", tok.AccessToken); code != 200 {
			t.Fatalf("access token still valid: %d", code)
		}
	})
}
