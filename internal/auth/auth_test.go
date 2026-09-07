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

	"github.com/golang-jwt/jwt/v5"
)

type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key}
	mux := http.NewServeMux()
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
	t.Helper()
	a, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp/", a.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ClientID(r.Context())))
	})))
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
	s := protected(t, Config{PublicURL: "https://gw.example", StaticToken: "s3cret", RequiredScope: "mcp:use"})

	code, _, hdr := get(t, s.URL+"/mcp/x", "")
	if code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if want := `resource_metadata="https://gw.example` + MetadataPath + `"`; !strings.Contains(hdr.Get("WWW-Authenticate"), want) {
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
}

func TestOIDCToken(t *testing.T) {
	idp := newFakeIdP(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := protected(t, Config{
		PublicURL: "https://gw.example", Issuer: idp.srv.URL, Audience: "mcp-gateway",
		RequiredScope: "mcp:use", StaticToken: "s3cret",
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
		{"wrong signer", good, other, 401},
		{"wrong aud", jwt.MapClaims{"aud": "other", "scope": "mcp:use"}, idp.key, 401},
		{"wrong iss", jwt.MapClaims{"iss": "https://evil", "aud": "mcp-gateway", "scope": "mcp:use"}, idp.key, 401},
		{"expired", jwt.MapClaims{"aud": "mcp-gateway", "scope": "mcp:use", "exp": time.Now().Add(-time.Minute).Unix()}, idp.key, 401},
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
