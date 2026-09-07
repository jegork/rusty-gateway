package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Discovery selects how a namespace exposes its upstream tools.
type Discovery string

const (
	// DiscoveryFull lists every server__tool directly.
	DiscoveryFull Discovery = "full"
	// DiscoveryConnector lists {server}__list_tools and {server}__call per
	// upstream, so a client loads only the servers it touches.
	DiscoveryConnector Discovery = "connector"
	// DiscoverySearch lists search_tools and call_tool for the namespace.
	DiscoverySearch Discovery = "search"
)

const objectSchema = `{"type":"object"}`

// toolInfo is what list_tools and search_tools return for one tool.
type toolInfo struct {
	Name        string `json:"name"`
	Server      string `json:"server"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	InputSchema any    `json:"inputSchema"`
}

func (g *Gateway) registerMetaTools(ns *nsServer) {
	switch ns.ns.Discovery {
	case DiscoveryConnector:
		for _, srv := range ns.ns.Servers {
			srv := srv
			ns.server.AddTool(&mcp.Tool{
				Name:  srv + Separator + "list_tools",
				Title: srv + ": list tools",
				Description: fmt.Sprintf("List the tools of the %s server with their input schemas. Call one with %s%scall.",
					srv, srv, Separator),
				InputSchema: json.RawMessage(objectSchema),
			}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return jsonResult(g.toolInfos(ns, srv))
			})
			ns.server.AddTool(&mcp.Tool{
				Name:        srv + Separator + "call",
				Title:       srv + ": call tool",
				Description: fmt.Sprintf("Call a tool of the %s server by name, with its arguments object.", srv),
				InputSchema: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string","description":"tool name as returned by list_tools"},"arguments":{"type":"object"}},"required":["name"]}`),
			}, g.metaCall(ns, srv))
		}
	case DiscoverySearch:
		ns.server.AddTool(&mcp.Tool{
			Name:        "search_tools",
			Title:       "Search tools",
			Description: "Find tools across all servers in this namespace by keywords in name, description or parameters. Returns matches with input schemas; call one with call_tool.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":50}},"required":["query"]}`),
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var in struct {
				Query string `json:"query"`
				Limit int    `json:"limit"`
			}
			if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
				return nil, fmt.Errorf("invalid arguments: %w", err)
			}
			if in.Limit <= 0 || in.Limit > 50 {
				in.Limit = 10
			}
			return jsonResult(g.search(ns, in.Query, in.Limit))
		})
		ns.server.AddTool(&mcp.Tool{
			Name:        "call_tool",
			Title:       "Call tool",
			Description: "Call a tool by its full name (server__tool) as returned by search_tools, with its arguments object.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"},"arguments":{"type":"object"}},"required":["name"]}`),
		}, g.metaCall(ns, ""))
	}
}

// metaCall resolves a name to an upstream tool and dispatches it like a
// direct call. With server set the name is the bare upstream tool name;
// otherwise it is the prefixed server__tool form.
func (g *Gateway) metaCall(ns *nsServer, server string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var in struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
		srv, tool := server, in.Name
		if srv == "" {
			var ok bool
			srv, tool, ok = strings.Cut(in.Name, Separator)
			if !ok {
				return nil, fmt.Errorf("tool name %q must be server%stool", in.Name, Separator)
			}
		}
		u, ok := g.sup.Get(UpstreamID(ns.ns.Name, srv))
		if !ok {
			return nil, fmt.Errorf("unknown server %q in namespace %s", srv, ns.ns.Name)
		}
		found := false
		for _, t := range u.Tools() {
			if t.Name == tool {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("server %q has no tool %q (or is not ready)", srv, tool)
		}
		if len(in.Arguments) == 0 {
			in.Arguments = json.RawMessage(`{}`)
		}
		// the inner request carries the resolved arguments so the regular
		// handler path (limits, breaker, audit) sees exactly a direct call
		inner := *req
		params := *req.Params
		params.Name = srv + Separator + tool
		params.Arguments = in.Arguments
		inner.Params = &params
		return g.handler(ns, srv, tool, u)(ctx, &inner)
	}
}

func (g *Gateway) toolInfos(ns *nsServer, server string) []toolInfo {
	var out []toolInfo
	for _, srv := range ns.ns.Servers {
		if server != "" && srv != server {
			continue
		}
		u, ok := g.sup.Get(UpstreamID(ns.ns.Name, srv))
		if !ok {
			continue
		}
		for _, t := range u.Tools() {
			out = append(out, toolInfo{Name: srv + Separator + t.Name, Server: srv, Title: displayTitle(t), Description: t.Description, InputSchema: t.InputSchema})
		}
	}
	return out
}

// search ranks tools by how many query tokens hit their name, title,
// description and parameter names, name hits counting most.
func (g *Gateway) search(ns *nsServer, query string, limit int) []toolInfo {
	tokens := strings.Fields(strings.ToLower(query))
	if len(tokens) == 0 {
		return nil
	}
	type scored struct {
		info  toolInfo
		score int
	}
	var hits []scored
	for _, info := range g.toolInfos(ns, "") {
		name := strings.ToLower(strings.ReplaceAll(info.Name, "_", " "))
		title := strings.ToLower(info.Title)
		desc := strings.ToLower(info.Description)
		params := strings.ToLower(schemaKeys(info.InputSchema))
		score := 0
		for _, tok := range tokens {
			switch {
			case strings.Contains(name, tok):
				score += 3
			case strings.Contains(title, tok):
				score += 2
			case strings.Contains(params, tok):
				score += 2
			case strings.Contains(desc, tok):
				score++
			}
		}
		if score > 0 {
			hits = append(hits, scored{info, score})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return hits[i].info.Name < hits[j].info.Name
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}
	out := make([]toolInfo, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.info)
	}
	return out
}

func schemaKeys(schema any) string {
	m, ok := schema.(map[string]any)
	if !ok {
		return ""
	}
	props, ok := m["properties"].(map[string]any)
	if !ok {
		return ""
	}
	keys := make([]string, 0, len(props))
	for k, v := range props {
		keys = append(keys, strings.ReplaceAll(k, "_", " "))
		if pm, ok := v.(map[string]any); ok {
			if d, ok := pm["description"].(string); ok {
				keys = append(keys, d)
			}
		}
	}
	return strings.Join(keys, " ")
}

func displayTitle(t *mcp.Tool) string {
	if t.Title != "" {
		return t.Title
	}
	if t.Annotations != nil && t.Annotations.Title != "" {
		return t.Annotations.Title
	}
	return t.Name
}

func jsonResult(v any) (*mcp.CallToolResult, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}, StructuredContent: v}, nil
}
