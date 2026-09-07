package supervisor

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jegork/rusty-gateway/internal/fakeserver"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeserver.EnvFlag) != "" {
		fakeserver.Main()
	}
	os.Exit(m.Run())
}

func fakeSpec(t *testing.T, id string, env map[string]string) Spec {
	t.Helper()
	cmd, args, e := fakeserver.Spec(env)
	return Spec{ID: id, Command: cmd, Args: args, Env: e}
}

func fastOpts() Options {
	return Options{
		PingInterval: 200 * time.Millisecond,
		StartTimeout: 5 * time.Second,
		BackoffMin:   20 * time.Millisecond,
		BackoffMax:   100 * time.Millisecond,
		StableAfter:  time.Hour,
		MaxFailures:  3,
	}
}

func alive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
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

func TestOneChildPerUpstreamAndCleanStop(t *testing.T) {
	pidFile := t.TempDir() + "/child.pid"
	specs := []Spec{
		fakeSpec(t, "ns/a", map[string]string{"RG_CHILD_PID_FILE": pidFile}),
		fakeSpec(t, "ns/b", nil),
		fakeSpec(t, "ns/c", nil),
	}
	s := New(specs, fastOpts())
	s.Start(context.Background())

	pids := s.LivePIDs()
	if len(pids) != len(specs) {
		t.Fatalf("want %d live children, got %v", len(specs), pids)
	}
	for _, st := range s.Statuses() {
		if st.State != "ready" || st.Tools != 2 || st.RSSBytes == 0 {
			t.Errorf("%+v", st)
		}
	}
	u, _ := s.Get("ns/a")
	res, err := u.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"x": 1}})
	if err != nil || res.Content[0].(*mcp.TextContent).Text != `{"x":1}` {
		t.Fatalf("call: %v %+v", err, res)
	}

	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	grandchild, _ := strconv.Atoi(string(raw))
	if !alive(grandchild) {
		t.Fatal("grandchild should be alive before stop")
	}

	s.Stop()
	if got := s.LivePIDs(); len(got) != 0 {
		t.Errorf("live pids after stop: %v", got)
	}
	for _, pid := range pids {
		waitFor(t, fmt.Sprintf("pid %d to die", pid), func() bool { return !alive(pid) })
	}
	waitFor(t, "grandchild to die", func() bool { return !alive(grandchild) })
	for _, st := range s.Statuses() {
		if st.State != "stopped" {
			t.Errorf("%+v", st)
		}
	}
}

func TestRestartsAfterCrashWithNewPid(t *testing.T) {
	changes := make(chan string, 64)
	opts := fastOpts()
	opts.OnChange = func(id string) { changes <- id }
	s := New([]Spec{fakeSpec(t, "ns/crashy", map[string]string{"RG_CRASH_AFTER_MS": "150", "RG_CRASH_ONCE": t.TempDir() + "/crashed"})}, opts)
	s.Start(context.Background())
	defer s.Stop()

	first := s.LivePIDs()
	if len(first) != 1 {
		t.Fatalf("got %v", first)
	}
	waitFor(t, "child to die", func() bool { return !alive(first[0]) })
	waitFor(t, "restart", func() bool {
		st := s.Statuses()[0]
		return st.State == "ready" && st.Restarts >= 1 && st.PID != first[0]
	})
	if len(changes) == 0 {
		t.Error("OnChange never fired")
	}
	if got := s.LivePIDs(); len(got) != 1 {
		t.Errorf("want exactly one child after restart: %v", got)
	}
}

func TestGivesUpAfterMaxFailures(t *testing.T) {
	s := New([]Spec{fakeSpec(t, "ns/broken", map[string]string{"RG_FAIL_START": "1"})}, fastOpts())
	s.Start(context.Background())
	defer s.Stop()

	waitFor(t, "failed state", func() bool { return s.Statuses()[0].State == "failed" })
	st := s.Statuses()[0]
	if st.Restarts != 3 || st.Error == "" {
		t.Errorf("%+v", st)
	}
	if got := s.LivePIDs(); len(got) != 0 {
		t.Errorf("failed upstream still has children: %v", got)
	}
	u, _ := s.Get("ns/broken")
	if len(u.Tools()) != 0 {
		t.Error("failed upstream should expose no tools")
	}
	if _, err := u.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo"}); err == nil {
		t.Error("call on failed upstream should error")
	}
}

func TestComposeEnvIsExplicit(t *testing.T) {
	t.Setenv("PATH", "/bin")
	t.Setenv("HOME", "/home/x")
	t.Setenv("LEAKY_SECRET", "nope")
	env := composeEnv([]string{"PATH", "HOME", "UNSET_VAR"}, map[string]string{"B": "2", "A": "1"})
	want := []string{"PATH=/bin", "HOME=/home/x", "A=1", "B=2"}
	if fmt.Sprint(env) != fmt.Sprint(want) {
		t.Errorf("got %v want %v", env, want)
	}
	red := redactEnv([]string{"API_TOKEN=abc", "PATH=/bin", "x=y=z"})
	if red[0] != "API_TOKEN=«redacted»" || red[1] != "PATH=/bin" || red[2] != "x=y=z" {
		t.Errorf("%v", red)
	}
}
