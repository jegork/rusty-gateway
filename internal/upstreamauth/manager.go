// Package upstreamauth makes the gateway an OAuth client toward remote
// upstreams that require it: it runs the browser authorization once, stores
// the resulting credentials, and hands the supervisor a refreshing token
// source afterwards.
package upstreamauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"github.com/jegork/rusty-gateway/internal/supervisor"
)

const (
	CallbackPath       = "/oauth/callback"
	ClientMetadataPath = "/oauth/client.json"
	loginTimeout       = 10 * time.Minute
)

// ErrLoginRequired is the supervisor's sentinel so the two packages agree.
var ErrLoginRequired = supervisor.ErrLoginRequired

// LoginPath is the authenticated endpoint that starts a login for upstream id.
func LoginPath(id string) string { return "/oauth/upstream/" + id + "/login" }

// Upstream describes one OAuth-protected remote server.
type Upstream struct {
	ID  string
	URL string
	// Preregistered, if set, is used instead of CIMD/DCR.
	Preregistered *oauthex.ClientCredentials
}

type Manager struct {
	publicURL string
	store     *Store
	log       *slog.Logger
	http      *http.Client

	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	up      Upstream
	handler sdkauth.OAuthHandler // nil until credentials exist
	ready   chan struct{}        // closed when handler becomes non-nil

	// pending interactive login, if any
	loginState string
	code       chan sdkauth.AuthorizationResult
}

func New(publicURL string, store *Store, upstreams []Upstream, log *slog.Logger) (*Manager, error) {
	m := &Manager{
		publicURL: publicURL, store: store, log: log,
		http:    &http.Client{Timeout: 30 * time.Second},
		entries: map[string]*entry{},
	}
	for _, up := range upstreams {
		e := &entry{up: up, ready: make(chan struct{})}
		creds, err := store.Load(context.Background(), up.ID)
		switch {
		case err == nil:
			e.handler = m.handlerFor(e, creds)
			close(e.ready)
			log.Info("upstream oauth credentials loaded", "upstream", up.ID)
		case errors.Is(err, errNotFound):
			log.Warn("upstream needs login", "upstream", up.ID, "login", "GET "+publicURL+LoginPath(up.ID))
		default:
			return nil, fmt.Errorf("load credentials for %s: %w", up.ID, err)
		}
		m.entries[up.ID] = e
	}
	return m, nil
}

// Handler implements supervisor.OAuthProvider.
func (m *Manager) Handler(id string) (sdkauth.OAuthHandler, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[id]
	if !ok {
		return nil, fmt.Errorf("%s: not an oauth upstream", id)
	}
	if e.handler == nil {
		return nil, ErrLoginRequired
	}
	return e.handler, nil
}

// Wait implements supervisor.OAuthProvider: it blocks until credentials for
// id exist or ctx ends.
func (m *Manager) Wait(ctx context.Context, id string) error {
	m.mu.Lock()
	e, ok := m.entries[id]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("%s: not an oauth upstream", id)
	}
	select {
	case <-e.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// handlerFor builds a handler that only ever refreshes; if the server demands
// a new authorization the stored credentials are dropped and the upstream
// goes back to needing an interactive login.
func (m *Manager) handlerFor(e *entry, creds *Credentials) sdkauth.OAuthHandler {
	cfg := creds.config()
	refreshCtx := context.WithValue(context.Background(), oauth2.HTTPClient, m.http)
	h, err := sdkauth.NewAuthorizationCodeHandler(&sdkauth.AuthorizationCodeHandlerConfig{
		PreregisteredClient: &oauthex.ClientCredentials{ClientID: creds.ClientID},
		RedirectURL:         m.publicURL + CallbackPath,
		AuthorizationCodeFetcher: func(context.Context, *sdkauth.AuthorizationArgs) (*sdkauth.AuthorizationResult, error) {
			m.invalidate(e)
			return nil, ErrLoginRequired
		},
		Client:             m.http,
		InitialTokenSource: m.persisting(e, cfg, cfg.TokenSource(refreshCtx, creds.Token), creds.Token),
	})
	if err != nil {
		// config is static, so this is a programming error
		panic(err)
	}
	return h
}

func (m *Manager) invalidate(e *entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.handler == nil {
		return
	}
	e.handler = nil
	e.ready = make(chan struct{})
	if err := m.store.Delete(context.Background(), e.up.ID); err != nil {
		m.log.Error("deleting upstream credentials", "upstream", e.up.ID, "err", err)
	}
	m.log.Warn("upstream credentials rejected, login required again", "upstream", e.up.ID)
}

// persisting wraps a token source so refreshed tokens are written back and
// a rejected refresh token sends the upstream back to needing a login.
func (m *Manager) persisting(e *entry, cfg *oauth2.Config, inner oauth2.TokenSource, last *oauth2.Token) oauth2.TokenSource {
	return &persistingSource{m: m, e: e, cfg: cfg, inner: inner, last: last}
}

type persistingSource struct {
	m     *Manager
	e     *entry
	cfg   *oauth2.Config
	inner oauth2.TokenSource
	mu    sync.Mutex
	last  *oauth2.Token
}

func (p *persistingSource) Token() (*oauth2.Token, error) {
	tok, err := p.inner.Token()
	if err != nil {
		// invalid_grant, or a 400/401 from a server that does not label its
		// errors, means the refresh token is dead
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && (re.ErrorCode == "invalid_grant" ||
			(re.ErrorCode == "" && re.Response != nil && (re.Response.StatusCode == 400 || re.Response.StatusCode == 401))) {
			p.m.invalidate(p.e)
			return nil, fmt.Errorf("%w: refresh rejected: %v", ErrLoginRequired, err)
		}
		return nil, err
	}
	p.mu.Lock()
	changed := p.last == nil || tok.AccessToken != p.last.AccessToken || tok.RefreshToken != p.last.RefreshToken
	p.last = tok
	p.mu.Unlock()
	if changed {
		creds := &Credentials{
			ClientID: p.cfg.ClientID, ClientSecret: p.cfg.ClientSecret, Scopes: p.cfg.Scopes,
			AuthURL: p.cfg.Endpoint.AuthURL, TokenURL: p.cfg.Endpoint.TokenURL, AuthStyle: p.cfg.Endpoint.AuthStyle,
			Token: tok,
		}
		if err := p.m.store.Save(context.Background(), p.e.up.ID, creds); err != nil {
			p.m.log.Error("saving refreshed upstream token", "upstream", p.e.up.ID, "err", err)
		}
	}
	return tok, nil
}

// StartLogin runs the authorization flow for an upstream in the background
// and returns the URL the user must open. The flow completes when the
// authorization server redirects to CallbackPath.
func (m *Manager) StartLogin(ctx context.Context, id string) (string, error) {
	m.mu.Lock()
	e, ok := m.entries[id]
	if ok && e.code != nil {
		m.mu.Unlock()
		return "", errors.New("a login is already in progress")
	}
	if ok {
		e.code = make(chan sdkauth.AuthorizationResult, 1)
	}
	m.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("%s: not an oauth upstream", id)
	}

	// the sdk needs the server's 401 challenge to discover its authorization server
	probe, err := http.NewRequestWithContext(ctx, http.MethodPost, e.up.URL, nil)
	if err != nil {
		return "", err
	}
	probe.Header.Set("Content-Type", "application/json")
	probe.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := m.http.Do(probe)
	if err != nil {
		m.clearLogin(e)
		return "", fmt.Errorf("probe %s: %w", e.up.URL, err)
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		m.clearLogin(e)
		return "", fmt.Errorf("probe %s: expected 401, got %d", e.up.URL, resp.StatusCode)
	}

	urlCh := make(chan string, 1)
	cfg := &sdkauth.AuthorizationCodeHandlerConfig{
		RedirectURL:         m.publicURL + CallbackPath,
		RequestRefreshToken: true,
		Client:              m.http,
		AuthorizationCodeFetcher: func(ctx context.Context, args *sdkauth.AuthorizationArgs) (*sdkauth.AuthorizationResult, error) {
			u, err := url.Parse(args.URL)
			if err != nil {
				return nil, err
			}
			m.mu.Lock()
			e.loginState = u.Query().Get("state")
			m.mu.Unlock()
			urlCh <- args.URL
			select {
			case res := <-e.code:
				return &res, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		NewTokenSource: func(ctx context.Context, cfg *oauth2.Config, tok *oauth2.Token) (oauth2.TokenSource, error) {
			creds := &Credentials{
				ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Scopes: cfg.Scopes,
				AuthURL: cfg.Endpoint.AuthURL, TokenURL: cfg.Endpoint.TokenURL, AuthStyle: cfg.Endpoint.AuthStyle,
				Token: tok,
			}
			if err := m.store.Save(ctx, id, creds); err != nil {
				return nil, err
			}
			return m.persisting(e, cfg, cfg.TokenSource(ctx, tok), tok), nil
		},
	}
	if e.up.Preregistered != nil {
		cfg.PreregisteredClient = e.up.Preregistered
	} else {
		// CIMD requires an https client id; over plain http only DCR is possible
		if strings.HasPrefix(m.publicURL, "https://") {
			cfg.ClientIDMetadataDocumentConfig = &sdkauth.ClientIDMetadataDocumentConfig{URL: m.publicURL + ClientMetadataPath}
		}
		cfg.DynamicClientRegistrationConfig = &sdkauth.DynamicClientRegistrationConfig{Metadata: m.clientMetadata()}
	}
	h, err := sdkauth.NewAuthorizationCodeHandler(cfg)
	if err != nil {
		resp.Body.Close()
		m.clearLogin(e)
		return "", err
	}

	loginCtx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	go func() {
		defer cancel()
		defer m.clearLogin(e)
		if err := h.Authorize(loginCtx, probe, resp); err != nil {
			m.log.Error("upstream login failed", "upstream", id, "err", err)
			select {
			case urlCh <- "":
			default:
			}
			return
		}
		m.mu.Lock()
		e.handler = h
		close(e.ready)
		m.mu.Unlock()
		m.log.Info("upstream login complete", "upstream", id)
	}()

	select {
	case u := <-urlCh:
		if u == "" {
			return "", errors.New("authorization could not be started; see log")
		}
		return u, nil
	case <-ctx.Done():
		cancel()
		return "", ctx.Err()
	}
}

func (m *Manager) clearLogin(e *entry) {
	m.mu.Lock()
	e.code, e.loginState = nil, ""
	m.mu.Unlock()
}

// CallbackHandler receives the authorization server's redirect.
func (m *Manager) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		state := q.Get("state")
		m.mu.Lock()
		var target *entry
		for _, e := range m.entries {
			if e.code != nil && state != "" && e.loginState == state {
				target = e
				break
			}
		}
		m.mu.Unlock()
		if target == nil {
			http.Error(w, "no login in progress for this state", http.StatusBadRequest)
			return
		}
		if e := q.Get("error"); e != "" {
			http.Error(w, "authorization server returned "+e+": "+q.Get("error_description"), http.StatusBadRequest)
			return
		}
		select {
		case target.code <- sdkauth.AuthorizationResult{Code: q.Get("code"), State: state, Iss: q.Get("iss")}:
		default:
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "login for %s received, you can close this tab\n", target.up.ID)
	})
}

// LoginHandler serves GET /oauth/upstream/{ns}/{server}/login and returns
// the URL to open.
func (m *Manager) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := m.StartLogin(r.Context(), r.PathValue("ns")+"/"+r.PathValue("server"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"open": u})
	})
}

// ClientMetadataHandler serves the gateway's Client ID Metadata Document.
func (m *Manager) ClientMetadataHandler() http.Handler {
	md := m.clientMetadata()
	doc := map[string]any{
		"client_id": m.publicURL + ClientMetadataPath, "client_name": md.ClientName, "client_uri": md.ClientURI,
		"redirect_uris": md.RedirectURIs, "grant_types": md.GrantTypes, "response_types": md.ResponseTypes,
		"token_endpoint_auth_method": md.TokenEndpointAuthMethod,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
}

func (m *Manager) clientMetadata() *oauthex.ClientRegistrationMetadata {
	return &oauthex.ClientRegistrationMetadata{
		ClientName:              "rusty-gateway",
		ClientURI:               m.publicURL,
		RedirectURIs:            []string{m.publicURL + CallbackPath},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}
}
