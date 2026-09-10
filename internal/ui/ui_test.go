package ui

import (
	"bufio"
	"context"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jegork/rusty-gateway/internal/audit"
	"github.com/jegork/rusty-gateway/internal/fakeserver"
	"github.com/jegork/rusty-gateway/internal/gateway"
	"github.com/jegork/rusty-gateway/internal/supervisor"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeserver.EnvFlag) != "" {
		fakeserver.Main()
	}
	os.Exit(m.Run())
}

func newServer(t *testing.T) (*httptest.Server, *audit.Store) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cmd, args, env := fakeserver.Spec(map[string]string{"RG_TOOLS": "quote"})
	var gw *gateway.Gateway
	sup := supervisor.New([]supervisor.Spec{{ID: "p/tv", Command: cmd, Args: args, Env: env}},
		supervisor.Options{Logger: log, OnChange: func(id string) { gw.Refresh(id) }})
	gw = gateway.New(sup, []gateway.Namespace{{Name: "p", Servers: []string{"tv"}}}, gateway.Options{Logger: log})
	sup.Start(context.Background())
	t.Cleanup(sup.Stop)
	gw.RefreshAll()
	store, err := audit.Open(t.TempDir() + "/a.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	u, err := New(Deps{Supervisor: sup, Gateway: gw, Audit: store, Token: "t0k", Version: "test", Logger: log, Sessions: gw.SessionCount})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/ui/", u.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, store
}

func client(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// firstEvent reads one SSE patch and returns its html payload
func firstEvent(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	var sb strings.Builder
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "data: elements ") {
			sb.WriteString(strings.TrimPrefix(line, "data: elements "))
			sb.WriteByte('\n')
		} else if !strings.HasPrefix(line, "event: datastar-patch-elements") {
			t.Fatalf("unexpected sse line %q", line)
		}
	}
	return sb.String()
}

func TestLoginAndPages(t *testing.T) {
	srv, store := newServer(t)
	c := client(t)

	res, _ := c.Get(srv.URL + "/ui/")
	if res.StatusCode != 303 || res.Header.Get("Location") != "/ui/login" {
		t.Fatalf("unauthenticated page should redirect to login: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = c.Get(srv.URL + "/ui/events/overview")
	if res.StatusCode != 401 {
		t.Fatalf("unauthenticated stream: %d", res.StatusCode)
	}
	res, _ = c.PostForm(srv.URL+"/ui/login", url.Values{"token": {"wrong"}})
	if res.StatusCode != 401 {
		t.Fatalf("wrong token: %d", res.StatusCode)
	}
	res, _ = c.PostForm(srv.URL+"/ui/login", url.Values{"token": {"t0k"}})
	if res.StatusCode != 303 {
		t.Fatalf("login: %d", res.StatusCode)
	}

	res, _ = c.Get(srv.URL + "/ui/")
	body := readAll(res)
	if res.StatusCode != 200 || !strings.Contains(body, `p/tv`) || !strings.Contains(body, "datastar.js") {
		t.Fatalf("overview: %d %s", res.StatusCode, body[:200])
	}
	frag := firstEvent(t, c, srv.URL+"/ui/events/overview")
	if !strings.Contains(frag, `id="upstreams"`) || !strings.Contains(frag, "state-ready") {
		t.Errorf("overview fragment: %s", frag)
	}

	sig := url.QueryEscape(`{"ns":"p","q":"quo"}`)
	frag = firstEvent(t, c, srv.URL+"/ui/tools/list?datastar="+sig)
	if !strings.Contains(frag, "tv__quote") || strings.Contains(frag, "tv__echo") {
		t.Errorf("tool search fragment: %s", frag)
	}
	frag = firstEvent(t, c, srv.URL+"/ui/tools/list?datastar="+url.QueryEscape(`{"ns":"p","q":""}`))
	if !strings.Contains(frag, "tv__echo") || !strings.Contains(frag, "tv__slow") {
		t.Errorf("tool list fragment: %s", frag)
	}

	store.Insert(context.Background(), audit.Row{TS: time.Now().UnixMilli(), Namespace: "p", Server: "tv", Tool: "quote", Status: "ok", DurationMS: 3, ArgsJSON: `{"s":"AAPL"}`})
	store.Insert(context.Background(), audit.Row{TS: time.Now().UnixMilli(), Namespace: "p", Server: "tv", Tool: "echo", Status: "error", DurationMS: 1, Error: "boom"})
	frag = firstEvent(t, c, srv.URL+"/ui/audit/rows")
	if !strings.Contains(frag, "quote") || !strings.Contains(frag, "boom") {
		t.Errorf("audit fragment: %s", frag)
	}
	frag = firstEvent(t, c, srv.URL+"/ui/audit/rows?datastar="+url.QueryEscape(`{"status":"error"}`))
	if strings.Contains(frag, "AAPL") || !strings.Contains(frag, "boom") {
		t.Errorf("audit filter fragment: %s", frag)
	}

	res, _ = c.Post(srv.URL+"/ui/logout", "", nil)
	res, _ = c.Get(srv.URL + "/ui/")
	if res.StatusCode != 303 {
		t.Errorf("after logout: %d", res.StatusCode)
	}
	if res, _ := c.Get(srv.URL + "/ui/static/datastar.js"); res.StatusCode != 200 {
		t.Errorf("static without session should be public: %d", res.StatusCode)
	}
}

func readAll(res *http.Response) string {
	defer res.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 8192)
	for {
		n, err := res.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			return sb.String()
		}
	}
}

func TestSessionsSurviveRestartAndRejectTampering(t *testing.T) {
	a, _ := New(Deps{Token: "t0k"})
	b, _ := New(Deps{Token: "t0k"})
	other, _ := New(Deps{Token: "different"})
	c := a.newSession()
	if !a.validSession(c) || !b.validSession(c) {
		t.Fatal("a session must be valid for any instance with the same token")
	}
	if other.validSession(c) {
		t.Error("a different token must not accept the cookie")
	}
	if a.validSession(c[:len(c)-1]+"0") || a.validSession("") || a.validSession("garbage") {
		t.Error("tampered or malformed cookies must be rejected")
	}
	body := "1." + strings.Repeat("0", 32)
	if a.validSession(body + "." + a.sign(body)) {
		t.Error("expired session must be rejected even with a valid signature")
	}
}
