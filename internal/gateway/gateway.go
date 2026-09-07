// Package gateway exposes one MCP server per namespace whose tool list is the
// union of that namespace's ready upstreams, prefixed as server__tool.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jegork/rusty-gateway/internal/auth"
	"github.com/jegork/rusty-gateway/internal/supervisor"
)

const Separator = "__"

type Namespace struct {
	Name    string
	Servers []string
}

type Options struct {
	Version string
	Logger  *slog.Logger
	Limits  Limits
	Breaker BreakerConfig
}

// Call is one completed tool dispatch, handed to Observe after the fact.
type Call struct {
	Namespace string
	Server    string
	Tool      string
	SessionID string
	Args      json.RawMessage
	Result    *mcp.CallToolResult
	Err       error
	Duration  time.Duration
	Started   time.Time
}

type Gateway struct {
	sup    *supervisor.Supervisor
	log    *slog.Logger
	limits Limits
	global semaphore
	// Observe, if set, is called after every tool call. It must not block.
	Observe func(context.Context, Call)

	mu       sync.Mutex
	servers  map[string]*nsServer
	perSrv   map[string]semaphore
	breakers map[string]*breaker
}

type nsServer struct {
	ns     Namespace
	server *mcp.Server
	sem    semaphore
	// registered maps prefixed tool name to the JSON of the tool it was
	// registered with, so unchanged tools are not re-added (which would spam
	// list_changed notifications)
	registered map[string]string
}

func New(sup *supervisor.Supervisor, namespaces []Namespace, opts Options) *Gateway {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	g := &Gateway{
		sup: sup, log: opts.Logger, limits: opts.Limits,
		global:   newSemaphore(opts.Limits.MaxConcurrent),
		servers:  map[string]*nsServer{},
		perSrv:   map[string]semaphore{},
		breakers: map[string]*breaker{},
	}
	for _, ns := range namespaces {
		nsLog := opts.Logger.With("namespace", ns.Name)
		g.servers[ns.Name] = &nsServer{
			ns: ns,
			server: mcp.NewServer(&mcp.Implementation{Name: "rusty-gateway/" + ns.Name, Version: opts.Version},
				&mcp.ServerOptions{Logger: opts.Logger.With("namespace", ns.Name)}),
			sem:        newSemaphore(opts.Limits.namespaceLimit(ns.Name)),
			registered: map[string]string{},
		}
		g.servers[ns.Name].server.AddReceivingMiddleware(requestLogger(nsLog))
		for _, srv := range ns.Servers {
			id := UpstreamID(ns.Name, srv)
			g.perSrv[id] = newSemaphore(opts.Limits.serverLimit(id))
			g.breakers[id] = newBreaker(opts.Breaker)
		}
	}
	return g
}

// Breakers reports the circuit state per upstream ID.
func (g *Gateway) Breakers() map[string]string {
	out := make(map[string]string, len(g.breakers))
	for id, b := range g.breakers {
		out[id] = b.state()
	}
	return out
}

// requestLogger records session lifecycle at info and every other method at
// debug, so a client that never sends notifications/initialized still shows up.
func requestLogger(log *slog.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			attrs := []any{"method", method, "session", req.GetSession().ID(), "client_id", auth.ClientID(ctx)}
			if err != nil {
				attrs = append(attrs, "err", err)
			}
			if method == "initialize" {
				if p, ok := req.GetParams().(*mcp.InitializeParams); ok && p.ClientInfo != nil {
					attrs = append(attrs, "client", p.ClientInfo.Name, "client_version", p.ClientInfo.Version, "protocol", p.ProtocolVersion)
				}
				log.Log(ctx, slog.LevelInfo, "session initialize", attrs...)
				return res, err
			}
			log.Log(ctx, slog.LevelDebug, "mcp request", attrs...)
			return res, err
		}
	}
}

// UpstreamID is the supervisor key for a server within a namespace.
func UpstreamID(namespace, server string) string { return namespace + "/" + server }

// Refresh re-syncs the tool set of every namespace that includes the upstream.
func (g *Gateway) Refresh(upstreamID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, ns := range g.servers {
		for _, srv := range ns.ns.Servers {
			if UpstreamID(ns.ns.Name, srv) == upstreamID {
				g.syncLocked(ns)
				break
			}
		}
	}
}

// RefreshAll syncs every namespace; used once after the supervisor starts.
func (g *Gateway) RefreshAll() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, ns := range g.servers {
		g.syncLocked(ns)
	}
}

func (g *Gateway) syncLocked(ns *nsServer) {
	want := map[string]string{}
	added := 0
	for _, srvName := range ns.ns.Servers {
		u, ok := g.sup.Get(UpstreamID(ns.ns.Name, srvName))
		if !ok {
			continue
		}
		for _, t := range u.Tools() {
			name := srvName + Separator + t.Name
			pt := *t
			pt.Name = name
			// clients display the title, so the provenance has to be there too
			title := t.Title
			if title == "" && t.Annotations != nil {
				title = t.Annotations.Title
			}
			if title == "" {
				title = t.Name
			}
			pt.Title = srvName + ": " + title
			enc, _ := json.Marshal(&pt)
			want[name] = string(enc)
			if ns.registered[name] == want[name] {
				continue
			}
			ns.server.AddTool(&pt, g.handler(ns, srvName, t.Name, u))
			added++
		}
	}
	var stale []string
	for name := range ns.registered {
		if _, ok := want[name]; !ok {
			stale = append(stale, name)
		}
	}
	if len(stale) > 0 {
		ns.server.RemoveTools(stale...)
	}
	ns.registered = want
	g.log.Debug("namespace synced", "namespace", ns.ns.Name, "tools", len(want), "added", added, "removed", len(stale))
}

func (g *Gateway) handler(ns *nsServer, server, tool string, u *supervisor.Upstream) mcp.ToolHandler {
	namespace := ns.ns.Name
	id := UpstreamID(namespace, server)
	srvSem, brk := g.perSrv[id], g.breakers[id]
	timeout := g.limits.timeout(id)
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		started := time.Now()
		args := req.Params.Arguments
		if len(args) == 0 {
			args = json.RawMessage(`{}`)
		}
		res, err := g.dispatch(ctx, ns, srvSem, brk, timeout, u, &mcp.CallToolParams{
			Name:           tool,
			Arguments:      args,
			InputResponses: req.Params.InputResponses,
			RequestState:   req.Params.RequestState,
		})
		if g.Observe != nil {
			g.Observe(ctx, Call{
				Namespace: namespace, Server: server, Tool: tool, SessionID: req.Session.ID(),
				Args: args, Result: res, Err: err,
				Duration: time.Since(started), Started: started,
			})
		}
		if err != nil {
			return nil, fmt.Errorf("%s%s%s: %w", server, Separator, tool, err)
		}
		return res, nil
	}
}

// dispatch applies the breaker, the three concurrency limits (queue time
// counts against the call deadline) and the timeout around one upstream call.
func (g *Gateway) dispatch(ctx context.Context, ns *nsServer, srvSem semaphore, brk *breaker, timeout time.Duration,
	u *supervisor.Upstream, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	if !brk.allow() {
		return nil, ErrCircuitOpen
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	for _, sem := range []semaphore{g.global, ns.sem, srvSem} {
		if err := sem.acquire(ctx); err != nil {
			return nil, fmt.Errorf("waiting for capacity: %w", err)
		}
		defer sem.release()
	}
	res, err := u.CallTool(ctx, params)
	switch {
	case err == nil:
		brk.success()
	case errors.Is(err, supervisor.ErrNotReady):
		// the supervisor already tracks this; not a breaker signal
	default:
		brk.failure()
	}
	return res, err
}

// Handler serves streamable HTTP for one namespace. Mount it at /mcp/{name}.
func (g *Gateway) Handler(name string) http.Handler {
	g.mu.Lock()
	ns, ok := g.servers[name]
	g.mu.Unlock()
	if !ok {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unknown namespace: "+name, http.StatusNotFound)
		})
	}
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return ns.server },
		&mcp.StreamableHTTPOptions{Logger: g.log, SessionTimeout: 30 * time.Minute})
}

// Namespaces lists configured namespace names in stable order.
func (g *Gateway) Namespaces() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	names := make([]string, 0, len(g.servers))
	for n := range g.servers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
