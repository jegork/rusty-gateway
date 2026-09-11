//go:build integration

package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/argon2"
	"golang.org/x/oauth2"
)

// the same shape as the production client in docs/auth-and-dcr.md, minus 2FA
// and with implicit consent so the flow needs no browser
const autheliaConfig = `
server:
  address: 'tcp://0.0.0.0:9091'
  tls:
    certificate: '/config/tls/cert.pem'
    key: '/config/tls/key.pem'
log:
  level: 'debug'
identity_validation:
  reset_password:
    jwt_secret: 'integration-test-jwt-secret-that-is-long-enough-0000'
authentication_backend:
  file:
    path: '/config/users.yml'
access_control:
  default_policy: 'one_factor'
session:
  secret: 'integration-test-session-secret-that-is-long-enough-00'
  cookies:
    - domain: '127.0.0.1'
      authelia_url: '{{ISSUER}}'
storage:
  encryption_key: 'integration-test-encryption-key-that-is-long-enough'
  local:
    path: '/config/db.sqlite3'
notifier:
  filesystem:
    filename: '/config/notification.txt'
identity_providers:
  oidc:
    hmac_secret: 'integration-test-hmac-secret-that-is-long-enough-0000'
    jwks:
      - key_id: 'main'
        algorithm: 'RS256'
        use: 'sig'
        key: |
{{KEY}}
    lifespans:
      access_token: '1h'
      refresh_token: '2h'
    clients:
      - client_id: 'codex'
        client_name: 'Codex CLI'
        public: true
        authorization_policy: 'one_factor'
        consent_mode: 'implicit'
        redirect_uris:
          - 'http://localhost:8432/oauth/callback'
        scopes: ['openid', 'offline_access', 'mcp:use']
        audience:
          - '{{RESOURCE}}'
        grant_types: ['authorization_code', 'refresh_token']
        response_types: ['code']
        token_endpoint_auth_method: 'none'
        require_pkce: true
        pkce_challenge_method: 'S256'
        access_token_signed_response_alg: 'RS256'
`

const (
	gatewayURL  = "http://gateway.test"
	resource    = gatewayURL + "/mcp/x"
	callbackURL = "http://localhost:8432/oauth/callback"
	username    = "tester"
	password    = "correct horse battery staple"
)

func TestAutheliaAuthorizationCodeAndRefresh(t *testing.T) {
	ctx := context.Background()
	issuer, client := startAuthelia(t, ctx)
	// the gateway's discovery and jwks fetches and the client's token calls
	// all need to trust the self-signed cert
	ctx = oidc.ClientContext(context.WithValue(ctx, oauth2.HTTPClient, client), client)

	s := protectedCtx(t, ctx, Config{
		PublicURL: gatewayURL, Issuer: issuer, RequiredScope: "mcp:use",
		Scopes: []string{"mcp:use", "offline_access"}, Resources: []string{"/mcp/x"},
	})
	code, body, _ := get(t, s.URL+MetadataPath+"/mcp/x", "")
	if code != 200 {
		t.Fatalf("metadata: %d %s", code, body)
	}
	var md struct {
		Scopes []string `json:"scopes_supported"`
	}
	if err := json.Unmarshal([]byte(body), &md); err != nil {
		t.Fatal(err)
	}

	conf := &oauth2.Config{
		ClientID:    "codex",
		RedirectURL: callbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL: issuer + "/api/oidc/authorization", TokenURL: issuer + "/api/oidc/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		Scopes: md.Scopes,
	}
	browser := newBrowser(t, client)
	tok := browser.login(t, ctx, conf)
	if tok.RefreshToken == "" {
		t.Fatalf("no refresh token for advertised scopes %v", md.Scopes)
	}
	if code, body, _ := get(t, s.URL+"/mcp/x", tok.AccessToken); code != 200 || body != "codex" {
		t.Fatalf("access token rejected: %d %s", code, body)
	}

	tok.Expiry = time.Now().Add(-time.Minute)
	fresh, err := conf.TokenSource(ctx, tok).Token()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if fresh.AccessToken == tok.AccessToken {
		t.Fatal("token source did not refresh")
	}
	if code, body, _ := get(t, s.URL+"/mcp/x", fresh.AccessToken); code != 200 || body != "codex" {
		t.Fatalf("refreshed token rejected: %d %s", code, body)
	}
	if _, err := conf.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token(); err == nil {
		t.Error("rotated refresh token was accepted again")
	}

	t.Run("required scope alone yields no refresh token", func(t *testing.T) {
		conf := *conf
		conf.Scopes = []string{"mcp:use"}
		tok := browser.login(t, ctx, &conf)
		if tok.RefreshToken != "" {
			t.Fatal("authelia issued a refresh token without offline_access")
		}
		if code, _, _ := get(t, s.URL+"/mcp/x", tok.AccessToken); code != 200 {
			t.Fatalf("access token rejected: %d", code)
		}
	})
}

func startAuthelia(t *testing.T, ctx context.Context) (string, *http.Client) {
	t.Helper()
	image := os.Getenv("AUTHELIA_IMAGE")
	if image == "" {
		image = "authelia/authelia:master"
	}
	port := freePort(t)
	// authelia insists on an https issuer and a cookie domain with a dot or an ip
	issuer := "https://127.0.0.1:" + strconv.Itoa(port)
	certPEM, certKeyPEM := selfSigned(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	indented := "          " + strings.ReplaceAll(strings.TrimSpace(pemKey), "\n", "\n          ")

	cfg := strings.NewReplacer("{{ISSUER}}", issuer, "{{KEY}}", indented, "{{RESOURCE}}", resource).Replace(autheliaConfig)
	users := fmt.Sprintf("users:\n  %s:\n    displayname: Tester\n    password: '%s'\n    email: tester@example.com\n    groups: []\n",
		username, argon2Hash(t, password))
	dir := t.TempDir()
	files := map[string]string{"configuration.yml": cfg, "users.yml": users, "cert.pem": string(certPEM), "key.pem": string(certKeyPEM)}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started: true,
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        image,
			ExposedPorts: []string{"9091/tcp"},
			Files: []testcontainers.ContainerFile{
				{HostFilePath: filepath.Join(dir, "configuration.yml"), ContainerFilePath: "/config/configuration.yml", FileMode: 0o644},
				{HostFilePath: filepath.Join(dir, "users.yml"), ContainerFilePath: "/config/users.yml", FileMode: 0o644},
				{HostFilePath: filepath.Join(dir, "cert.pem"), ContainerFilePath: "/config/tls/cert.pem", FileMode: 0o644},
				{HostFilePath: filepath.Join(dir, "key.pem"), ContainerFilePath: "/config/tls/key.pem", FileMode: 0o644},
			},
			// the issuer is baked into the config, so the host port must be known up front
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.PortBindings = network.PortMap{network.MustParsePort("9091/tcp"): {{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: strconv.Itoa(port)}}}
			},
			WaitingFor: wait.ForHTTP("/api/health").WithPort("9091/tcp").WithTLS(true, &tls.Config{InsecureSkipVerify: true}).
				WithStartupTimeout(90 * time.Second),
		},
	})
	testcontainers.CleanupContainer(t, c)
	t.Cleanup(func() {
		if !t.Failed() || c == nil {
			return
		}
		if rc, err := c.Logs(context.Background()); err == nil {
			var b bytes.Buffer
			b.ReadFrom(rc)
			rc.Close()
			t.Logf("authelia logs:\n%s", b.String())
		}
	})
	if err != nil {
		t.Fatalf("start authelia: %v", err)
	}
	return issuer, client
}

func selfSigned(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "authelia test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func argon2Hash(t *testing.T, pw string) string {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	hash := argon2.IDKey([]byte(pw), salt, 3, 64*1024, 4, 32)
	enc := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s", enc(salt), enc(hash))
}

// browser stands in for the user's browser: it keeps authelia's session
// cookies and never follows redirects, so every hop can be inspected.
type browser struct {
	base    string
	client  *http.Client
	cookies map[string]*http.Cookie
}

func newBrowser(t *testing.T, client *http.Client) *browser {
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{client: &c, cookies: map[string]*http.Cookie{}}
}

func (b *browser) do(t *testing.T, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	for _, c := range res.Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	var buf bytes.Buffer
	buf.ReadFrom(res.Body)
	return res, buf.Bytes()
}

// follow issues GETs until authelia redirects back to the client callback
func (b *browser) follow(t *testing.T, ctx context.Context, u string) *url.URL {
	t.Helper()
	for i := 0; i < 8; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		res, body := b.do(t, req)
		loc, err := res.Location()
		if err != nil {
			t.Fatalf("GET %s: %d, no redirect: %s", u, res.StatusCode, body)
		}
		t.Logf("hop %d: GET %s -> %d %s", i, u, res.StatusCode, loc)
		if strings.HasPrefix(loc.String(), callbackURL) {
			return loc
		}
		q := loc.Query()
		switch {
		case strings.HasPrefix(loc.Path, "/consent/openid/decision"):
			// offline_access always needs explicit consent, even in implicit mode
			u = b.consent(t, ctx, flowID(q))
		case q.Get("flow") == "openid_connect" || q.Get("workflow") == "openid_connect":
			u = b.firstFactor(t, ctx, flowID(q))
		default:
			u = loc.String()
		}
	}
	t.Fatal("authelia never redirected to the callback")
	return nil
}

func flowID(q url.Values) string {
	if id := q.Get("flow_id"); id != "" {
		return id
	}
	return q.Get("workflow_id")
}

func (b *browser) firstFactor(t *testing.T, ctx context.Context, flowID string) string {
	t.Helper()
	return b.postJSON(t, ctx, "/api/firstfactor", map[string]any{
		"username": username, "password": password, "keepMeLoggedIn": true,
		"flow": "openid_connect", "flowID": flowID,
		"workflow": "openid_connect", "workflowID": flowID,
	}, "redirect")
}

func (b *browser) consent(t *testing.T, ctx context.Context, flowID string) string {
	t.Helper()
	return b.postJSON(t, ctx, "/api/oidc/consent", map[string]any{
		"flow_id": flowID, "client_id": "codex", "consent": true, "pre_configure": false,
	}, "redirect_uri")
}

// postJSON calls an authelia api and returns the named field of data
func (b *browser) postJSON(t *testing.T, ctx context.Context, path string, in map[string]any, field string) string {
	t.Helper()
	payload, _ := json.Marshal(in)
	req, _ := http.NewRequestWithContext(ctx, "POST", b.base+path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Original-URL", b.base+"/")
	res, body := b.do(t, req)
	var out struct {
		Status string            `json:"status"`
		Data   map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil || res.StatusCode != 200 || out.Status != "OK" {
		t.Fatalf("POST %s: %d %s", path, res.StatusCode, body)
	}
	if out.Data[field] == "" {
		t.Fatalf("POST %s: no %s in %s", path, field, body)
	}
	return out.Data[field]
}

// login runs the authorization code flow with PKCE and a resource indicator,
// exactly as an MCP client would, and exchanges the code
func (b *browser) login(t *testing.T, ctx context.Context, conf *oauth2.Config) *oauth2.Token {
	t.Helper()
	b.base = strings.TrimSuffix(conf.Endpoint.AuthURL, "/api/oidc/authorization")
	verifier := oauth2.GenerateVerifier()
	state := "state-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	authURL := conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("resource", resource))
	cb := b.follow(t, ctx, authURL)
	if got := cb.Query().Get("state"); got != state {
		t.Fatalf("state mismatch: %q", got)
	}
	if e := cb.Query().Get("error"); e != "" {
		t.Fatalf("authorization error: %s: %s", e, cb.Query().Get("error_description"))
	}
	tok, err := conf.Exchange(ctx, cb.Query().Get("code"), oauth2.VerifierOption(verifier), oauth2.SetAuthURLParam("resource", resource))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return tok
}
