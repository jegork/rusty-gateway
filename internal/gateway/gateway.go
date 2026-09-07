// Package gateway exposes one MCP server per namespace whose tool list is the
// union of that namespace's ready upstreams, prefixed as server__tool.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jegork/rusty-gateway/internal/supervisor"
)

const Separator = "__"

type Namespace struct {
	Name    string
	Servers []string
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
	sup     *supervisor.Supervisor
	log     *slog.Logger
	version string
	// Observe, if set, is called after every tool call. It must not block.
	Observe func(context.Context, Call)

	mu      sync.Mutex
	servers map[string]*nsServer
}

type nsServer struct {
	ns     Namespace
	server *mcp.Server
	// registered maps prefixed tool name to the JSON of the tool it was
	// registered with, so unchanged tools are not re-added (which would spam
	// list_changed notifications)
	registered map[string]string
}

func New(sup *supervisor.Supervisor, namespaces []Namespace, version string, log *slog.Logger) *Gateway {
	g := &Gateway{sup: sup, log: log, version: version, servers: map[string]*nsServer{}}
	for _, ns := range namespaces {
		g.servers[ns.Name] = &nsServer{
			ns: ns,
			server: mcp.NewServer(&mcp.Implementation{Name: "rusty-gateway/" + ns.Name, Version: version},
				&mcp.ServerOptions{Logger: log.With("namespace", ns.Name)}),
			registered: map[string]string{},
		}
	}
	return g
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
			if pt.Title == "" {
				pt.Title = t.Name
			}
			enc, _ := json.Marshal(&pt)
			want[name] = string(enc)
			if ns.registered[name] == want[name] {
				continue
			}
			ns.server.AddTool(&pt, g.handler(ns.ns.Name, srvName, t.Name, u))
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

func (g *Gateway) handler(namespace, server, tool string, u *supervisor.Upstream) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		started := time.Now()
		args := req.Params.Arguments
		if len(args) == 0 {
			args = json.RawMessage(`{}`)
		}
		res, err := u.CallTool(ctx, &mcp.CallToolParams{
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

// Handler serves POST/GET/DELETE /mcp/{ns} with streamable HTTP.
func (g *Gateway) Handler() http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		g.mu.Lock()
		defer g.mu.Unlock()
		if ns, ok := g.servers[r.PathValue("ns")]; ok {
			return ns.server
		}
		return nil
	}, &mcp.StreamableHTTPOptions{Logger: g.log, SessionTimeout: 30 * time.Minute})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("ns")
		g.mu.Lock()
		_, ok := g.servers[name]
		g.mu.Unlock()
		if !ok {
			http.Error(w, "unknown namespace: "+name, http.StatusNotFound)
			return
		}
		streamable.ServeHTTP(w, r)
	})
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
