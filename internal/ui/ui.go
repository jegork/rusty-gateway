// Package ui is the operator dashboard: a few server-rendered pages kept
// live over SSE with Datastar. It is read-mostly; the only action is
// following an upstream's OAuth login link.
package ui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jegork/rusty-gateway/internal/audit"
	"github.com/jegork/rusty-gateway/internal/gateway"
	"github.com/jegork/rusty-gateway/internal/supervisor"
	"github.com/jegork/rusty-gateway/internal/upstreamauth"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

const (
	cookieName = "rg_session"
	sessionTTL = 7 * 24 * time.Hour
	refresh    = 2 * time.Second
)

type Deps struct {
	Supervisor *supervisor.Supervisor
	Gateway    *gateway.Gateway
	Audit      *audit.Store          // optional
	OAuth      *upstreamauth.Manager // optional
	Sessions   func() int            // live mcp client sessions, optional
	Token      string                // the static gateway token doubles as the dashboard password
	Version    string
	Logger     *slog.Logger
}

type UI struct {
	d Deps
	// one template set per page, since each page defines its own "content"
	pages map[string]*template.Template

	mu       sync.Mutex
	sessions map[string]time.Time
}

func New(d Deps) (*UI, error) {
	if d.Token == "" {
		return nil, fmt.Errorf("ui needs auth.static_token_env so there is something to sign in with")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	pages := map[string]*template.Template{}
	for _, name := range []string{"overview", "tools", "audit"} {
		t, err := template.ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		pages[name] = t
	}
	login, err := template.ParseFS(templateFS, "templates/login.html")
	if err != nil {
		return nil, err
	}
	pages["login"] = login
	return &UI{d: d, pages: pages, sessions: map[string]time.Time{}}, nil
}

// Handler serves everything under /ui/.
func (u *UI) Handler() http.Handler {
	static, _ := fs.Sub(staticFS, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /ui/static/", http.StripPrefix("/ui/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /ui/login", u.loginPage)
	mux.HandleFunc("POST /ui/login", u.login)
	mux.HandleFunc("POST /ui/logout", u.logout)
	mux.Handle("GET /ui/{$}", u.auth(u.overview))
	mux.Handle("GET /ui/events/overview", u.auth(u.overviewEvents))
	mux.Handle("GET /ui/tools", u.auth(u.toolsPage))
	mux.Handle("GET /ui/tools/list", u.auth(u.toolsList))
	mux.Handle("GET /ui/audit", u.auth(u.auditPage))
	mux.Handle("GET /ui/audit/rows", u.auth(u.auditRows))
	return mux
}

// auth requires a session cookie; pages redirect to login, streams get 401.
func (u *UI) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(cookieName); err == nil && u.validSession(c.Value) {
			next(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/ui/events/") || strings.HasPrefix(r.URL.Path, "/ui/tools/list") || strings.HasPrefix(r.URL.Path, "/ui/audit/rows") {
			http.Error(w, "session expired, reload the page", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
	})
}

func (u *UI) validSession(id string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	exp, ok := u.sessions[id]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(u.sessions, id)
		return false
	}
	return true
}

func (u *UI) loginPage(w http.ResponseWriter, r *http.Request) {
	u.render(w, "login", map[string]any{"Error": ""})
}

func (u *UI) login(w http.ResponseWriter, r *http.Request) {
	tok := r.FormValue("token")
	if subtle.ConstantTimeCompare([]byte(tok), []byte(u.d.Token)) != 1 {
		u.d.Logger.Warn("ui login failed", "remote", r.RemoteAddr)
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusUnauthorized)
		u.render(w, "login", map[string]any{"Error": "wrong token"})
		return
	}
	b := make([]byte, 32)
	rand.Read(b)
	id := hex.EncodeToString(b)
	u.mu.Lock()
	u.sessions[id] = time.Now().Add(sessionTTL)
	u.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: id, Path: "/ui", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", MaxAge: int(sessionTTL.Seconds()),
	})
	u.d.Logger.Info("ui login", "remote", r.RemoteAddr)
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
}

func (u *UI) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		u.mu.Lock()
		delete(u.sessions, c.Value)
		u.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/ui", MaxAge: -1})
	http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
}

// render writes a full page: the named page's layout, or the login page.
func (u *UI) render(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	tmpl, entry := u.pages[name], "layout"
	if name == "login" {
		entry = "login"
	}
	if err := tmpl.ExecuteTemplate(&buf, entry, data); err != nil {
		u.d.Logger.Error("render", "template", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

// fragment renders a named block from the page that defines it.
func (u *UI) fragment(page, name string, data any) (string, error) {
	var buf bytes.Buffer
	err := u.pages[page].ExecuteTemplate(&buf, name, data)
	return buf.String(), err
}

func (u *UI) page(title, page string, extra map[string]any) map[string]any {
	m := map[string]any{"Title": title, "Page": page, "Version": u.d.Version}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// overview

type upstreamRow struct {
	ID, Kind, State, Breaker, Error, RSS string
	PID, Tools, Restarts                 int
}

type loginRow struct{ ID, URL string }

func (u *UI) overviewData() map[string]any {
	breakers := u.d.Gateway.Breakers()
	var rows []upstreamRow
	var logins []loginRow
	for _, st := range u.d.Supervisor.Statuses() {
		rows = append(rows, upstreamRow{
			ID: st.ID, Kind: st.Kind, State: st.State, Breaker: breakers[st.ID], Error: st.Error,
			RSS: humanBytes(st.RSSBytes), PID: st.PID, Tools: st.Tools, Restarts: st.Restarts,
		})
		if st.State == "needs_login" && u.d.OAuth != nil {
			if url := u.d.OAuth.PendingLogin(st.ID); url != "" {
				logins = append(logins, loginRow{st.ID, url})
			}
		}
	}
	sessions := 0
	if u.d.Sessions != nil {
		sessions = u.d.Sessions()
	}
	return map[string]any{"Upstreams": rows, "Logins": logins, "Now": time.Now().Format("15:04:05"), "Sessions": sessions}
}

func (u *UI) overview(w http.ResponseWriter, r *http.Request) {
	u.render(w, "overview", u.page("overview", "overview", u.overviewData()))
}

func (u *UI) overviewEvents(w http.ResponseWriter, r *http.Request) {
	u.stream(w, r, func() (string, error) { return u.fragment("overview", "upstreams", u.overviewData()) })
}

// stream re-renders a fragment every refresh interval until the client leaves.
func (u *UI) stream(w http.ResponseWriter, r *http.Request, render func() (string, error)) {
	sse, err := newSSE(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t := time.NewTicker(refresh)
	defer t.Stop()
	for {
		html, err := render()
		if err != nil {
			u.d.Logger.Error("ui stream render", "err", err)
			return
		}
		if err := sse.patchElements(html); err != nil {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
		}
	}
}

// tools

type toolRow struct {
	Name, Title, Description, Schema string
}

func (u *UI) toolsPage(w http.ResponseWriter, r *http.Request) {
	nss := u.d.Gateway.Namespaces()
	ns := ""
	if len(nss) > 0 {
		ns = nss[0]
	}
	u.render(w, "tools", u.page("tools", "tools", map[string]any{"Namespaces": nss, "Namespace": ns}))
}

func (u *UI) toolsList(w http.ResponseWriter, r *http.Request) {
	var sig struct {
		NS string `json:"ns"`
		Q  string `json:"q"`
	}
	if err := readSignals(r, &sig); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var rows []toolRow
	for _, t := range u.d.Gateway.Tools(sig.NS, sig.Q, 50) {
		schema, _ := json.MarshalIndent(t.InputSchema, "", "  ")
		rows = append(rows, toolRow{Name: t.Name, Title: t.Title, Description: t.Description, Schema: string(schema)})
	}
	html, err := u.fragment("tools", "tools", map[string]any{"Tools": rows, "Query": strings.TrimSpace(sig.Q), "Namespace": sig.NS})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s, err := newSSE(w, r); err == nil {
		s.patchElements(html)
	}
}

// audit

type auditRow struct {
	audit.Row
	Time string
}

func (u *UI) auditPage(w http.ResponseWriter, r *http.Request) {
	u.render(w, "audit", u.page("audit", "audit", nil))
}

// auditRows answers one patch per request; the page polls it so filter
// changes take effect on the next tick.
func (u *UI) auditRows(w http.ResponseWriter, r *http.Request) {
	var sig struct {
		NS, Server, Tool, Status string
	}
	readSignals(r, &sig)
	html, err := u.auditFragment(r.Context(), sig.NS, sig.Server, sig.Tool, sig.Status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s, err := newSSE(w, r); err == nil {
		s.patchElements(html)
	}
}

func (u *UI) auditFragment(ctx context.Context, ns, server, tool, status string) (string, error) {
	if u.d.Audit == nil {
		return u.fragment("audit", "audit", map[string]any{"Rows": nil, "Note": "audit.path is not configured."})
	}
	f := audit.Filter{Namespace: ns, Server: server, Tool: tool, Status: status, Limit: 100}
	rows, err := u.d.Audit.Query(ctx, f)
	if err != nil {
		return "", err
	}
	out := make([]auditRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, auditRow{Row: row, Time: time.UnixMilli(row.TS).Format("Jan 02 15:04:05")})
	}
	filtered := ns != "" || server != "" || tool != "" || status != ""
	return u.fragment("audit", "audit", map[string]any{"Rows": out, "Filtered": filtered, "Note": fmt.Sprintf("Showing up to 100 rows, refreshed every %s.", refresh)})
}

func humanBytes(b uint64) string {
	switch {
	case b == 0:
		return "–"
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(b)/(1<<20))
	default:
		return fmt.Sprintf("%.0f KB", float64(b)/(1<<10))
	}
}
