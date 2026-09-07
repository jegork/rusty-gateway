// Package supervisor owns the child process table: one long-lived stdio MCP
// server per configured upstream, shared by every client session.
package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/shirou/gopsutil/v4/process"
)

type State int

const (
	Starting State = iota
	Ready
	Failed
	Stopped
)

func (s State) String() string {
	switch s {
	case Starting:
		return "starting"
	case Ready:
		return "ready"
	case Failed:
		return "failed"
	case Stopped:
		return "stopped"
	}
	return "unknown"
}

// Spec describes one upstream: a stdio command or a remote streamable HTTP
// endpoint. ID is the stable key ("personal/tradingview"), never derived from
// the command string.
type Spec struct {
	ID      string
	Command string
	Args    []string
	Env     map[string]string
	URL     string
	Headers map[string]string
	// StderrLevel is the slog level child stderr lines are logged at.
	// nil means debug; StderrDiscard drops them.
	StderrLevel *slog.Level
}

// StderrDiscard as StderrLevel drops the child's stderr entirely.
var StderrDiscard = slog.Level(1000)

func (s Spec) Remote() bool { return s.URL != "" }

type Options struct {
	PingInterval time.Duration
	StartTimeout time.Duration
	BackoffMin   time.Duration
	BackoffMax   time.Duration
	// StableAfter is how long a child must stay up before its consecutive
	// failure counter resets.
	StableAfter time.Duration
	// MaxFailures is the number of consecutive failed runs before an upstream
	// is marked Failed and no longer restarted.
	MaxFailures int
	// BaseEnv is the allowlist of host environment variables passed to every child.
	BaseEnv []string
	// OnChange is called whenever an upstream's state or tool list changes.
	OnChange func(id string)
	Logger   *slog.Logger
}

func (o *Options) defaults() {
	if o.PingInterval == 0 {
		o.PingInterval = 30 * time.Second
	}
	if o.StartTimeout == 0 {
		o.StartTimeout = 30 * time.Second
	}
	if o.BackoffMin == 0 {
		o.BackoffMin = time.Second
	}
	if o.BackoffMax == 0 {
		o.BackoffMax = 60 * time.Second
	}
	if o.StableAfter == 0 {
		o.StableAfter = 60 * time.Second
	}
	if o.MaxFailures == 0 {
		o.MaxFailures = 5
	}
	if o.BaseEnv == nil {
		o.BaseEnv = []string{"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER", "LOGNAME", "TZ"}
	}
	if o.OnChange == nil {
		o.OnChange = func(string) {}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

type Upstream struct {
	spec Spec
	sup  *Supervisor

	mu       sync.RWMutex
	state    State
	lastErr  error
	session  *mcp.ClientSession
	cmd      *exec.Cmd
	tools    []*mcp.Tool
	restarts int
	failures int
	pid      int

	done chan struct{}
}

type Status struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	State    string `json:"state"`
	PID      int    `json:"pid,omitempty"`
	Restarts int    `json:"restarts"`
	Tools    int    `json:"tools"`
	RSSBytes uint64 `json:"rss_bytes,omitempty"`
	Error    string `json:"error,omitempty"`
}

type Supervisor struct {
	opts      Options
	upstreams map[string]*Upstream
	order     []string
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func New(specs []Spec, opts Options) *Supervisor {
	opts.defaults()
	s := &Supervisor{opts: opts, upstreams: map[string]*Upstream{}}
	for _, sp := range specs {
		s.upstreams[sp.ID] = &Upstream{spec: sp, sup: s, done: make(chan struct{})}
		s.order = append(s.order, sp.ID)
	}
	return s
}

// Start launches every upstream and returns once each has either reached
// Ready or failed its first start. Failed first starts are not fatal; the
// run loop keeps retrying with backoff.
func (s *Supervisor) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	var first sync.WaitGroup
	for _, id := range s.order {
		u := s.upstreams[id]
		first.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			u.run(ctx, first.Done)
		}()
	}
	first.Wait()
}

// Stop terminates every child and waits for the run loops to exit.
func (s *Supervisor) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

func (s *Supervisor) Get(id string) (*Upstream, bool) {
	u, ok := s.upstreams[id]
	return u, ok
}

func (s *Supervisor) Statuses() []Status {
	out := make([]Status, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.upstreams[id].Status())
	}
	return out
}

// LivePIDs returns the pids of children currently believed to be running.
func (s *Supervisor) LivePIDs() []int {
	var pids []int
	for _, id := range s.order {
		u := s.upstreams[id]
		u.mu.RLock()
		if u.pid != 0 {
			pids = append(pids, u.pid)
		}
		u.mu.RUnlock()
	}
	sort.Ints(pids)
	return pids
}

func (u *Upstream) ID() string { return u.spec.ID }

func (u *Upstream) Status() Status {
	u.mu.RLock()
	defer u.mu.RUnlock()
	st := Status{ID: u.spec.ID, Kind: "stdio", State: u.state.String(), Restarts: u.restarts, Tools: len(u.tools)}
	if u.spec.Remote() {
		st.Kind = "http"
	}
	if u.state == Ready && !u.spec.Remote() {
		st.PID = u.pid
		st.RSSBytes = groupRSS(u.pid)
	}
	if u.lastErr != nil {
		st.Error = u.lastErr.Error()
	}
	return st
}

// Tools returns the cached tool list; empty unless Ready.
func (u *Upstream) Tools() []*mcp.Tool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.state != Ready {
		return nil
	}
	return u.tools
}

var ErrNotReady = errors.New("upstream not ready")

func (u *Upstream) CallTool(ctx context.Context, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	u.mu.RLock()
	sess, state := u.session, u.state
	u.mu.RUnlock()
	if state != Ready || sess == nil {
		return nil, fmt.Errorf("%s: %w (%s)", u.spec.ID, ErrNotReady, state)
	}
	return sess.CallTool(ctx, params)
}

func (u *Upstream) setState(st State, err error) {
	u.mu.Lock()
	u.state, u.lastErr = st, err
	u.mu.Unlock()
	u.sup.opts.OnChange(u.spec.ID)
}

func (u *Upstream) run(ctx context.Context, firstDone func()) {
	defer close(u.done)
	log := u.sup.opts.Logger.With("upstream", u.spec.ID)
	opts := u.sup.opts
	signalFirst := func() {
		if firstDone != nil {
			firstDone()
			firstDone = nil
		}
	}
	defer signalFirst()

	for {
		started := time.Now()
		err := u.runOnce(ctx, log, signalFirst)
		if ctx.Err() != nil {
			u.setState(Stopped, nil)
			return
		}
		u.mu.Lock()
		if time.Since(started) >= opts.StableAfter {
			u.failures = 0
		}
		u.failures++
		u.restarts++
		failures := u.failures
		u.mu.Unlock()

		if failures >= opts.MaxFailures {
			log.Error("upstream failed too many times, giving up", "failures", failures, "err", err)
			u.setState(Failed, err)
			return
		}
		delay := min(opts.BackoffMin<<(failures-1), opts.BackoffMax)
		log.Warn("upstream exited, restarting", "err", err, "failures", failures, "backoff", delay)
		u.setState(Starting, err)
		select {
		case <-ctx.Done():
			u.setState(Stopped, nil)
			return
		case <-time.After(delay):
		}
	}
}

// runOnce starts the child, serves it until it dies or a ping fails, then
// tears down the whole process group. It returns the reason the run ended.
func (u *Upstream) runOnce(ctx context.Context, log *slog.Logger, onReady func()) error {
	opts := u.sup.opts
	var transport mcp.Transport
	var cmd *exec.Cmd
	if u.spec.Remote() {
		log.Debug("connecting upstream", "url", u.spec.URL, "headers", slices.Sorted(maps.Keys(u.spec.Headers)))
		transport = &mcp.StreamableClientTransport{
			Endpoint:   u.spec.URL,
			HTTPClient: &http.Client{Transport: headerTransport{headers: u.spec.Headers}},
		}
	} else {
		cmd = exec.Command(u.spec.Command, u.spec.Args...)
		cmd.Env = composeEnv(opts.BaseEnv, u.spec.Env)
		cmd.Stderr = newStderrLogger(log, u.spec.StderrLevel)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		log.Debug("starting upstream", "command", u.spec.Command, "args", u.spec.Args, "env", redactEnv(cmd.Env))
		transport = &mcp.CommandTransport{Command: cmd}
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "rusty-gateway", Version: "dev"}, &mcp.ClientOptions{
		ToolListChangedHandler: func(ctx context.Context, _ *mcp.ToolListChangedRequest) {
			if err := u.refreshTools(ctx); err != nil {
				log.Warn("refreshing tools after list_changed", "err", err)
			}
		},
	})
	startCtx, cancel := context.WithTimeout(ctx, opts.StartTimeout)
	sess, err := client.Connect(startCtx, transport, nil)
	cancel()
	if err != nil {
		if cmd != nil && cmd.Process != nil {
			killGroup(cmd.Process.Pid)
		}
		return fmt.Errorf("connect: %w", err)
	}
	pid := 0
	if cmd != nil {
		pid = cmd.Process.Pid
	}
	u.mu.Lock()
	u.session, u.cmd, u.pid = sess, cmd, pid
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		u.session, u.cmd, u.pid = nil, nil, 0
		u.tools = nil
		u.mu.Unlock()
	}()

	if err := u.refreshTools(ctx); err != nil {
		u.shutdown(sess, pid)
		return fmt.Errorf("tools/list: %w", err)
	}
	u.setState(Ready, nil)
	log.Info("upstream ready", "pid", pid, "tools", len(u.Tools()))
	onReady()

	exited := make(chan error, 1)
	go func() { exited <- sess.Wait() }()
	ticker := time.NewTicker(opts.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			u.setState(Stopped, nil)
			u.shutdown(sess, pid)
			return ctx.Err()
		case err := <-exited:
			killGroup(pid)
			return fmt.Errorf("process exited: %w", errors.Join(err, errors.New("unexpected exit")))
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(ctx, opts.PingInterval)
			err := sess.Ping(pctx, nil)
			cancel()
			if err != nil && ctx.Err() == nil && !isMethodNotFound(err) {
				u.shutdown(sess, pid)
				return fmt.Errorf("ping: %w", err)
			}
		}
	}
}

func (u *Upstream) refreshTools(ctx context.Context) error {
	u.mu.RLock()
	sess := u.session
	u.mu.RUnlock()
	if sess == nil {
		return ErrNotReady
	}
	var tools []*mcp.Tool
	var cursor string
	for {
		res, err := sess.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return err
		}
		tools = append(tools, res.Tools...)
		if res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
	}
	u.mu.Lock()
	u.tools = tools
	ready := u.state == Ready
	u.mu.Unlock()
	if ready {
		u.sup.opts.OnChange(u.spec.ID)
	}
	return nil
}

// shutdown terminates the child and everything it spawned. The SDK's Close
// only signals the direct child, so the process group is swept afterwards
// to catch grandchildren left behind by uvx/npx style wrappers. Remote
// upstreams only close the session.
func (u *Upstream) shutdown(sess *mcp.ClientSession, pid int) {
	if pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGTERM)
	}
	_ = sess.Close()
	killGroup(pid)
}

// stderrLogger turns a child's stderr into one structured log record per
// line so upstream chatter never interleaves raw with the gateway's own log.
type stderrLogger struct {
	log   *slog.Logger
	level slog.Level
	buf   []byte
}

const maxStderrLine = 4096

func newStderrLogger(log *slog.Logger, level *slog.Level) io.Writer {
	l := slog.LevelDebug
	if level != nil {
		l = *level
	}
	if l == StderrDiscard {
		return io.Discard
	}
	return &stderrLogger{log: log, level: l}
}

func (w *stderrLogger) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.emit(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	// a partial line with no newline in sight is flushed rather than held forever
	if len(w.buf) > maxStderrLine {
		w.emit(w.buf)
		w.buf = w.buf[:0]
	}
	return len(p), nil
}

func (w *stderrLogger) emit(line []byte) {
	line = bytes.TrimRight(line, "\r")
	if len(bytes.TrimSpace(line)) == 0 {
		return
	}
	if len(line) > maxStderrLine {
		line = line[:maxStderrLine]
	}
	w.log.Log(context.Background(), w.level, "upstream stderr", "line", string(line))
}

type headerTransport struct {
	headers map[string]string
}

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.headers {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// some servers never implement ping; a method-not-found reply still proves
// the process is alive and answering
func isMethodNotFound(err error) bool {
	var je *jsonrpc.Error
	return errors.As(err, &je) && je.Code == jsonrpc.CodeMethodNotFound
}

func killGroup(pid int) {
	if pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
}

// groupRSS sums resident memory of the child and its descendants, so wrapper
// launchers like uvx report the interpreter they spawned, not just themselves.
func groupRSS(pid int) uint64 {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0
	}
	var total uint64
	if m, err := p.MemoryInfo(); err == nil {
		total += m.RSS
	}
	if kids, err := p.Children(); err == nil {
		for _, k := range kids {
			total += groupRSS(int(k.Pid))
		}
	}
	return total
}

func composeEnv(base []string, extra map[string]string) []string {
	var env []string
	for _, k := range base {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+extra[k])
	}
	return env
}

var secretKey = regexp.MustCompile(`(?i)(token|key|secret|password|auth|credential)`)

func redactEnv(env []string) []string {
	out := make([]string, len(env))
	for i, kv := range env {
		k, _, _ := cutEq(kv)
		if secretKey.MatchString(k) {
			out[i] = k + "=«redacted»"
		} else {
			out[i] = kv
		}
	}
	return out
}

func cutEq(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
