package upstreamauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jegork/rusty-gateway/internal/supervisor"
)

// fakeAS is a minimal authorization server plus an OAuth-protected MCP
// endpoint: DCR, PKCE-less code grant, refresh, and revocation on demand.
type fakeAS struct {
	srv *httptest.Server
	mu  sync.Mutex

	codes    map[string]bool
	access   map[string]time.Time
	refresh  map[string]bool
	revoked  bool
	tokenTTL time.Duration
	clients  int
	refreshN int
}

func newFakeAS(t *testing.T) *fakeAS {
	t.Helper()
	f := &fakeAS{codes: map[string]bool{}, access: map[string]time.Time{}, refresh: map[string]bool{}, tokenTTL: time.Hour}
	mcpSrv := mcp.NewServer(&mcp.Implementation{Name: "notion-ish", Version: "0"}, nil)
	mcpSrv.AddTool(&mcp.Tool{Name: "search", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "found"}}}, nil
		})
	mcpH := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpSrv }, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"resource": f.srv.URL + "/mcp", "authorization_servers": []string{f.srv.URL}, "scopes_supported": []string{"default"}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"registration_endpoint": f.srv.URL + "/register", "response_types_supported": []string{"code"},
			"grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none"}, "scopes_supported": []string{"default", "offline_access"},
			"authorization_response_iss_parameter_supported": true,
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.clients++
		f.mu.Unlock()
		var md map[string]any
		json.NewDecoder(r.Body).Decode(&md)
		md["client_id"] = "dcr-client"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(md)
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// the "user" approves instantly
		code := rnd()
		f.mu.Lock()
		f.codes[code] = true
		f.mu.Unlock()
		q := r.URL.Query()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state"))+"&iss="+url.QueryEscape(f.srv.URL), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if !f.codes[r.Form.Get("code")] {
				oauthError(w, "invalid_grant")
				return
			}
			delete(f.codes, r.Form.Get("code"))
		case "refresh_token":
			f.refreshN++
			if f.revoked || !f.refresh[r.Form.Get("refresh_token")] {
				oauthError(w, "invalid_grant")
				return
			}
			delete(f.refresh, r.Form.Get("refresh_token"))
		default:
			oauthError(w, "unsupported_grant_type")
			return
		}
		at, rt := rnd(), rnd()
		f.access[at] = time.Now().Add(f.tokenTTL)
		f.refresh[rt] = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": at, "refresh_token": rt, "token_type": "Bearer", "expires_in": int(f.tokenTTL.Seconds())})
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		exp, ok := f.access[tok]
		ok = ok && !f.revoked && time.Now().Before(exp)
		f.mu.Unlock()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+f.srv.URL+`/.well-known/oauth-protected-resource/mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mcpH.ServeHTTP(w, r)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func oauthError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	w.Write([]byte(`{"error":"` + code + `"}`))
}

func rnd() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type harness struct {
	as    *fakeAS
	store *Store
	mgr   *Manager
	gw    *httptest.Server // hosts callback + client metadata
	sup   *supervisor.Supervisor
}

func newHarness(t *testing.T, as *fakeAS, storePath string) *harness {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	store, err := OpenStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h := &harness{as: as, store: store}

	// the manager needs its public url before it exists; use a mux that we fill in after
	mux := http.NewServeMux()
	h.gw = httptest.NewServer(mux)
	t.Cleanup(h.gw.Close)
	h.mgr, err = New(h.gw.URL, store, []Upstream{{ID: "p/notion", URL: as.srv.URL + "/mcp"}}, log)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("GET "+CallbackPath, h.mgr.CallbackHandler())
	mux.Handle("GET "+ClientMetadataPath, h.mgr.ClientMetadataHandler())

	h.sup = supervisor.New([]supervisor.Spec{{ID: "p/notion", URL: as.srv.URL + "/mcp", OAuth: true}}, supervisor.Options{
		PingInterval: 100 * time.Millisecond, StartTimeout: 5 * time.Second, BackoffMin: 20 * time.Millisecond,
		BackoffMax: 50 * time.Millisecond, StableAfter: time.Hour, MaxFailures: 3, OAuth: h.mgr, Logger: log,
	})
	return h
}

func (h *harness) state() string { return h.sup.Statuses()[0].State }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// browse follows the authorization url like a browser would, ending at the gateway callback
func browse(t *testing.T, authURL string) {
	t.Helper()
	res, err := http.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("callback status %d", res.StatusCode)
	}
}

func TestLoginThenConnectThenRestartWithoutLogin(t *testing.T) {
	as := newFakeAS(t)
	path := t.TempDir() + "/state.db"
	h := newHarness(t, as, path)

	// supervisor start blocks until first state; needs_login counts, so run it async
	started := make(chan struct{})
	go func() { h.sup.Start(context.Background()); close(started) }()
	waitFor(t, "needs_login", func() bool { return h.state() == "needs_login" })
	if _, err := h.mgr.Handler("p/notion"); err != ErrLoginRequired {
		t.Fatalf("handler before login: %v", err)
	}

	authURL, err := h.mgr.StartLogin(context.Background(), "p/notion")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(authURL, as.srv.URL+"/authorize") {
		t.Fatalf("unexpected auth url %s", authURL)
	}
	if _, err := h.mgr.StartLogin(context.Background(), "p/notion"); err == nil {
		t.Error("second concurrent login should be refused")
	}
	browse(t, authURL)
	<-started
	waitFor(t, "ready", func() bool { return h.state() == "ready" })
	u, _ := h.sup.Get("p/notion")
	res, err := u.CallTool(context.Background(), &mcp.CallToolParams{Name: "search"})
	if err != nil || res.Content[0].(*mcp.TextContent).Text != "found" {
		t.Fatalf("call: %v", err)
	}
	if as.clients != 1 {
		t.Errorf("expected one dcr registration, got %d", as.clients)
	}
	h.sup.Stop()

	// a fresh process with the same store must come up without a browser
	h2 := newHarness(t, as, path)
	h2.sup.Start(context.Background())
	defer h2.sup.Stop()
	if h2.state() != "ready" {
		t.Fatalf("after restart: %s (%s)", h2.state(), h2.sup.Statuses()[0].Error)
	}
	if as.clients != 1 {
		t.Errorf("restart re-registered the client: %d", as.clients)
	}
}

func TestRefreshPersistsAndRevocationNeedsLogin(t *testing.T) {
	as := newFakeAS(t)
	as.tokenTTL = 2 * time.Second // oauth2 refreshes when within 10s of expiry, so every call refreshes
	path := t.TempDir() + "/state.db"
	h := newHarness(t, as, path)
	go h.sup.Start(context.Background())
	waitFor(t, "needs_login", func() bool { return h.state() == "needs_login" })
	authURL, err := h.mgr.StartLogin(context.Background(), "p/notion")
	if err != nil {
		t.Fatal(err)
	}
	browse(t, authURL)
	waitFor(t, "ready", func() bool { return h.state() == "ready" })
	defer h.sup.Stop()

	u, _ := h.sup.Get("p/notion")
	before, _ := h.store.Load(context.Background(), "p/notion")
	if _, err := u.CallTool(context.Background(), &mcp.CallToolParams{Name: "search"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "refresh persisted", func() bool {
		after, _ := h.store.Load(context.Background(), "p/notion")
		return after != nil && after.Token.AccessToken != before.Token.AccessToken
	})
	if as.refreshN == 0 {
		t.Fatal("no refresh happened")
	}

	as.mu.Lock()
	as.revoked = true
	as.mu.Unlock()
	u.CallTool(context.Background(), &mcp.CallToolParams{Name: "search"})
	waitFor(t, "needs_login after revocation", func() bool { return h.state() == "needs_login" })
	if _, err := h.store.Load(context.Background(), "p/notion"); err != errNotFound {
		t.Errorf("revoked credentials should be deleted, got %v", err)
	}
}

func TestCallbackRejectsUnknownState(t *testing.T) {
	as := newFakeAS(t)
	h := newHarness(t, as, t.TempDir()+"/state.db")
	res, err := http.Get(h.gw.URL + CallbackPath + "?code=x&state=nope")
	if err != nil || res.StatusCode != 400 {
		t.Fatalf("unknown state: %v %d", err, res.StatusCode)
	}
	res, _ = http.Get(h.gw.URL + ClientMetadataPath)
	var doc map[string]any
	json.NewDecoder(res.Body).Decode(&doc)
	if doc["client_id"] != h.gw.URL+ClientMetadataPath || doc["token_endpoint_auth_method"] != "none" {
		t.Errorf("client metadata: %v", doc)
	}
	_ = sdkauth.ErrInvalidToken
}
