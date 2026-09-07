package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jegork/rusty-gateway/internal/fakeserver"
	"github.com/jegork/rusty-gateway/internal/supervisor"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeserver.EnvFlag) != "" {
		fakeserver.Main()
	}
	os.Exit(m.Run())
}

func spec(id string, env map[string]string) supervisor.Spec {
	cmd, args, e := fakeserver.Spec(env)
	return supervisor.Spec{ID: id, Command: cmd, Args: args, Env: e}
}

type fixture struct {
	sup     *supervisor.Supervisor
	gw      *Gateway
	http    *httptest.Server
	calls   chan Call
	limits  Limits
	breaker BreakerConfig
}

func setup(t *testing.T, namespaces []Namespace, specs []supervisor.Spec, opts ...func(*fixture)) *fixture {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	f := &fixture{calls: make(chan Call, 64)}
	for _, o := range opts {
		o(f)
	}
	var gw *Gateway
	f.sup = supervisor.New(specs, supervisor.Options{
		PingInterval: 200 * time.Millisecond, BackoffMin: 20 * time.Millisecond,
		BackoffMax: 100 * time.Millisecond, StableAfter: time.Hour, MaxFailures: 2,
		Logger:   log,
		OnChange: func(id string) { gw.Refresh(id) },
	})
	gw = New(f.sup, namespaces, Options{Version: "test", Logger: log, Limits: f.limits, Breaker: f.breaker})
	gw.Observe = func(_ context.Context, c Call) { f.calls <- c }
	f.gw = gw
	f.sup.Start(context.Background())
	gw.RefreshAll()
	mux := http.NewServeMux()
	mux.Handle("/mcp/{ns}", gw.Handler())
	f.http = httptest.NewServer(mux)
	t.Cleanup(func() { f.http.Close(); f.sup.Stop() })
	return f
}

func (f *fixture) connect(t *testing.T, ns string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	s, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: f.http.URL + "/mcp/" + ns}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func toolNames(t *testing.T, s *mcp.ClientSession) []string {
	t.Helper()
	res, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

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

func TestNamespacesPrefixToolsAndShareProcesses(t *testing.T) {
	f := setup(t, []Namespace{
		{Name: "personal", Servers: []string{"tv", "hevy"}},
		{Name: "ops", Servers: []string{"dokploy"}},
	}, []supervisor.Spec{
		spec("personal/tv", map[string]string{"RG_TOOLS": "quote"}),
		spec("personal/hevy", nil),
		spec("ops/dokploy", map[string]string{"RG_TOOLS": "deploy,logs"}),
	})
	before := f.sup.LivePIDs()
	if len(before) != 3 {
		t.Fatalf("live children: %v", before)
	}

	// many sessions, connected and dropped, must never change the process table
	var sessions []*mcp.ClientSession
	for i := 0; i < 5; i++ {
		sessions = append(sessions, f.connect(t, "personal"), f.connect(t, "ops"))
	}
	for _, s := range sessions[:6] {
		s.Close()
	}
	for i := 0; i < 3; i++ {
		f.connect(t, "personal").Close()
	}
	if after := f.sup.LivePIDs(); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("process table changed with sessions: before %v after %v", before, after)
	}

	personal := sessions[8]
	ops := sessions[9]
	if got := toolNames(t, personal); strings.Join(got, ",") != "hevy__echo,hevy__slow,tv__echo,tv__quote,tv__slow" {
		t.Errorf("personal tools: %v", got)
	}
	if got := toolNames(t, ops); strings.Join(got, ",") != "dokploy__deploy,dokploy__echo,dokploy__logs,dokploy__slow" {
		t.Errorf("ops tools: %v", got)
	}

	res, err := personal.CallTool(context.Background(), &mcp.CallToolParams{Name: "tv__echo", Arguments: map[string]any{"sym": "AAPL"}})
	if err != nil || res.IsError || res.Content[0].(*mcp.TextContent).Text != `{"sym":"AAPL"}` {
		t.Fatalf("call: %v %+v", err, res)
	}
	select {
	case c := <-f.calls:
		if c.Namespace != "personal" || c.Server != "tv" || c.Tool != "echo" || c.Err != nil || string(c.Args) != `{"sym":"AAPL"}` {
			t.Errorf("observed call: %+v", c)
		}
	case <-time.After(time.Second):
		t.Error("Observe not called")
	}

	if _, err := ops.CallTool(context.Background(), &mcp.CallToolParams{Name: "tv__echo"}); err == nil {
		t.Error("tool from another namespace must not be callable")
	}
	if _, err := personal.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo"}); err == nil {
		t.Error("unprefixed name must not resolve")
	}
}

func TestUnknownNamespaceIs404AndFailedUpstreamHidesTools(t *testing.T) {
	f := setup(t, []Namespace{{Name: "p", Servers: []string{"ok", "broken"}}}, []supervisor.Spec{
		spec("p/ok", nil),
		spec("p/broken", map[string]string{"RG_FAIL_START": "1"}),
	})
	res, err := http.Post(f.http.URL+"/mcp/nope", "application/json", strings.NewReader("{}"))
	if err != nil || res.StatusCode != 404 {
		t.Fatalf("unknown ns: %v %v", err, res.StatusCode)
	}
	waitFor(t, "broken to fail", func() bool { return f.sup.Statuses()[1].State == "failed" })
	s := f.connect(t, "p")
	defer s.Close()
	if got := toolNames(t, s); strings.Join(got, ",") != "ok__echo,ok__slow" {
		t.Errorf("tools: %v", got)
	}
}

func TestToolsReappearAfterCrashRestart(t *testing.T) {
	f := setup(t, []Namespace{{Name: "p", Servers: []string{"c"}}}, []supervisor.Spec{
		spec("p/c", map[string]string{"RG_CRASH_AFTER_MS": "300", "RG_CRASH_ONCE": t.TempDir() + "/crashed"}),
	})
	first := f.sup.LivePIDs()[0]
	s := f.connect(t, "p")
	defer s.Close()
	waitFor(t, "restart", func() bool {
		st := f.sup.Statuses()[0]
		return st.State == "ready" && st.PID != first
	})
	waitFor(t, "tools back", func() bool { return len(toolNames(t, s)) == 2 })
	if st := f.sup.Statuses()[0]; st.Restarts != 1 || st.State != "ready" {
		t.Errorf("%+v", st)
	}
}
