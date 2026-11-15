package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
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
	// DiscoverySearch lists list_tools, search_tools, describe_tools and call_tool.
	DiscoverySearch Discovery = "search"
	// DiscoveryHybrid adds explicitly pinned native tools to search discovery.
	DiscoveryHybrid Discovery = "hybrid"
)

const objectSchema = `{"type":"object"}`

// ToolInfo describes a tool; compact search results omit its input schema.
// code_mode_allowed only says whether execute_code may call the tool; it does
// not change whether the tool can be called normally.
type ToolInfo struct {
	Name            string `json:"name"`
	Server          string `json:"server"`
	Title           string `json:"title,omitempty"`
	Description     string `json:"description,omitempty"`
	InputSchema     any    `json:"inputSchema,omitempty"`
	CodeModeAllowed bool   `json:"code_mode_allowed"`
}

const (
	defaultListLimit = 10
	maxListLimit     = 50
	maxCursorBytes   = 1024
	cursorVersion    = 1
)

// hasListTools reports whether the namespace exposes the list_tools browser:
// always with search wrappers, and with code mode so scripts can find names.
func hasListTools(ns Namespace) bool {
	return ns.Discovery == DiscoverySearch || ns.Discovery == DiscoveryHybrid || ns.CodeMode != nil
}

// overview lists the configured servers of a namespace with their configured
// descriptions. It is static so tool definitions stay stable across refreshes.
func overview(ns Namespace) string {
	var b strings.Builder
	b.WriteString("Configured integrations in this namespace (live availability may vary):")
	for _, srv := range ns.Servers {
		b.WriteString("\n- " + srv)
		if desc := strings.Join(strings.Fields(ns.ServerDescriptions[srv]), " "); desc != "" {
			b.WriteString(": " + desc)
		}
	}
	return b.String()
}

// workflow names only the tools this namespace actually exposes, so clients
// are never pointed at wrappers that are absent in their discovery mode.
func workflow(ns Namespace) string {
	if !hasListTools(ns) {
		return ""
	}
	var steps []string
	switch ns.Discovery {
	case DiscoverySearch, DiscoveryHybrid:
		steps = []string{
			"Find tools with list_tools (browse) or search_tools (keyword search).",
			"Load the schemas of the exact returned names with describe_tools.",
			"Call a tool with call_tool.",
		}
	case DiscoveryConnector:
		steps = []string{
			"Find tools with list_tools.",
			"Load the schemas of one server with {server}" + Separator + "list_tools.",
			"Call a tool with {server}" + Separator + "call. Use the bare upstream tool name, not the server" + Separator + "tool name.",
		}
	default:
		steps = []string{
			"Find tools with list_tools.",
			"Call the native server" + Separator + "tool tool. Its schema is in the tool list.",
		}
	}
	if ns.CodeMode != nil {
		steps = append(steps, "Optional: call tools that have code_mode_allowed true from execute_code. Use the full server"+Separator+
			"tool name. tools.call returns the full MCP result, not only the payload.")
	}
	var b strings.Builder
	b.WriteString("Workflow:")
	for i, step := range steps {
		fmt.Fprintf(&b, "\n%d. %s", i+1, step)
	}
	return b.String()
}

func instructions(ns Namespace) string {
	if w := workflow(ns); w != "" {
		return overview(ns) + "\n\n" + w
	}
	return overview(ns)
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
	case DiscoverySearch, DiscoveryHybrid:
		ns.server.AddTool(&mcp.Tool{
			Name:        "search_tools",
			Title:       "Search tools",
			Description: "Find tools by keywords in name, description or parameters. Returns compact summaries without schemas. Use describe_tools for selected tools before calling call_tool. Optionally filter by server.\n\n" + instructions(ns.ns),
			InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"},"server":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":50}},"required":["query"]}`),
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var in struct {
				Query  string `json:"query"`
				Server string `json:"server"`
				Limit  int    `json:"limit"`
			}
			if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
				return nil, fmt.Errorf("invalid arguments: %w", err)
			}
			if in.Limit <= 0 || in.Limit > 50 {
				in.Limit = 10
			}
			hits := g.search(ns, in.Query, in.Server, in.Limit)
			for i := range hits {
				hits[i].InputSchema = nil
			}
			return jsonResult(hits)
		})
		ns.server.AddTool(&mcp.Tool{
			Name:        "describe_tools",
			Title:       "Describe tools",
			Description: "Load full input schemas for selected tools by their exact server__tool names from search_tools. Returns descriptions in requested order; unknown or unavailable tools fail the request.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"names":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":50}},"required":["names"]}`),
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var in struct {
				Names []string `json:"names"`
			}
			if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
				return nil, fmt.Errorf("invalid arguments: %w", err)
			}
			if len(in.Names) == 0 || len(in.Names) > 50 {
				return nil, fmt.Errorf("names must contain between 1 and 50 tool names")
			}
			catalog := g.toolInfos(ns, "")
			byName := make(map[string]ToolInfo, len(catalog))
			for _, info := range catalog {
				byName[info.Name] = info
			}
			infos := make([]ToolInfo, 0, len(in.Names))
			for _, name := range in.Names {
				info, ok := byName[name]
				if !ok {
					return nil, fmt.Errorf("unknown or unavailable tool %q in namespace %s", name, ns.ns.Name)
				}
				infos = append(infos, info)
			}
			return jsonResult(infos)
		})
		ns.server.AddTool(&mcp.Tool{
			Name:        "call_tool",
			Title:       "Call tool",
			Description: "Call a tool by its full name (server__tool), with arguments matching the schema from describe_tools. Discovery is optional if you already know its schema.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"},"arguments":{"type":"object"}},"required":["name"]}`),
		}, g.metaCall(ns, ""))
	}
	if hasListTools(ns.ns) {
		g.registerListTools(ns)
	}
}

// listPage is one page of list_tools; NextCursor is empty on the last page.
type listPage struct {
	Tools      []ToolInfo `json:"tools"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

// listCursor is a keyset position: the last full tool name returned, bound to
// the namespace and server filter it was issued for.
type listCursor struct {
	Version   int    `json:"v"`
	Namespace string `json:"ns"`
	Server    string `json:"server"`
	After     string `json:"after"`
}

var errInvalidCursor = errors.New("invalid cursor: pass next_cursor unchanged with the same server filter, or omit it to start over")

func encodeCursor(c listCursor) string {
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeCursor(cursor, namespace, server string) (string, error) {
	if len(cursor) > maxCursorBytes {
		return "", errInvalidCursor
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", errInvalidCursor
	}
	var c listCursor
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return "", errInvalidCursor
	}
	// dec.More() misses a trailing closing token, so require a clean EOF instead
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return "", errInvalidCursor
	}
	if c.Version != cursorVersion || c.Namespace != namespace || c.Server != server || c.After == "" {
		return "", errInvalidCursor
	}
	return c.After, nil
}

func eligibilityNote(ns Namespace) string {
	if ns.CodeMode == nil {
		return "Code mode is off in this namespace, so code_mode_allowed is always false."
	}
	return "code_mode_allowed true means that execute_code can call the tool. It does not change normal calls."
}

func (g *Gateway) registerListTools(ns *nsServer) {
	ns.server.AddTool(&mcp.Tool{
		Name:  "list_tools",
		Title: "List tools",
		Description: fmt.Sprintf("Browse the ready upstream tools of this namespace. "+
			"The result is compact summaries without input schemas, sorted by full name. "+
			"Use server to filter by one server. limit defaults to %d. The maximum is %d. "+
			"To get the next page, pass next_cursor as cursor with the same server. "+
			"The listing is live. Tools added before the cursor appear only when you start again without a cursor. %s\n\n%s",
			defaultListLimit, maxListLimit, eligibilityNote(ns.ns), instructions(ns.ns)),
		InputSchema: json.RawMessage(fmt.Sprintf(`{"type":"object","properties":{"server":{"type":"string"},"cursor":{"type":"string","description":"next_cursor from a previous page"},"limit":{"type":"integer","minimum":0,"maximum":%d}}}`, maxListLimit)),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var in struct {
			Server string `json:"server"`
			Cursor string `json:"cursor"`
			Limit  int    `json:"limit"`
		}
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
				return nil, fmt.Errorf("invalid arguments: %w", err)
			}
		}
		if in.Limit < 0 || in.Limit > maxListLimit {
			return nil, fmt.Errorf("limit must be between 0 and %d, got %d", maxListLimit, in.Limit)
		}
		if in.Limit == 0 {
			in.Limit = defaultListLimit
		}
		if in.Server != "" && !slices.Contains(ns.ns.Servers, in.Server) {
			return nil, fmt.Errorf("unknown server %q in namespace %s", in.Server, ns.ns.Name)
		}
		after := ""
		if in.Cursor != "" {
			var err error
			if after, err = decodeCursor(in.Cursor, ns.ns.Name, in.Server); err != nil {
				return nil, err
			}
		}
		infos := g.toolInfos(ns, in.Server)
		sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
		page := listPage{Tools: infos[sort.Search(len(infos), func(i int) bool { return infos[i].Name > after }):]}
		if len(page.Tools) > in.Limit {
			page.Tools = page.Tools[:in.Limit]
			page.NextCursor = encodeCursor(listCursor{
				Version: cursorVersion, Namespace: ns.ns.Name, Server: in.Server, After: page.Tools[len(page.Tools)-1].Name,
			})
		}
		if page.Tools == nil {
			page.Tools = []ToolInfo{}
		}
		for i := range page.Tools {
			page.Tools[i].InputSchema = nil
		}
		return jsonResult(page)
	})
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
		if !slices.Contains(ns.ns.Servers, srv) {
			return nil, fmt.Errorf("unknown server %q in namespace %s", srv, ns.ns.Name)
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

// Tools lists the tools of a namespace, or searches them when query is set.
func (g *Gateway) Tools(namespace, query string, limit int) []ToolInfo {
	g.mu.Lock()
	ns, ok := g.servers[namespace]
	g.mu.Unlock()
	if !ok {
		return nil
	}
	if strings.TrimSpace(query) == "" {
		return g.toolInfos(ns, "")
	}
	return g.search(ns, query, "", limit)
}

func (g *Gateway) toolInfos(ns *nsServer, server string) []ToolInfo {
	var out []ToolInfo
	for _, srv := range ns.ns.Servers {
		if server != "" && srv != server {
			continue
		}
		u, ok := g.sup.Get(UpstreamID(ns.ns.Name, srv))
		if !ok {
			continue
		}
		for _, t := range u.Tools() {
			name := srv + Separator + t.Name
			out = append(out, ToolInfo{
				Name: name, Server: srv, Title: displayTitle(t), Description: t.Description, InputSchema: t.InputSchema,
				CodeModeAllowed: ns.ns.CodeMode != nil && slices.Contains(ns.ns.CodeMode.AllowedTools, name),
			})
		}
	}
	return out
}

// search ranks tools by how many query tokens hit their name, title,
// description and parameter names, name hits counting most.
func (g *Gateway) search(ns *nsServer, query, server string, limit int) []ToolInfo {
	tokens := strings.Fields(strings.ToLower(query))
	if len(tokens) == 0 {
		return nil
	}
	type scored struct {
		info  ToolInfo
		score int
	}
	var hits []scored
	for _, info := range g.toolInfos(ns, server) {
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
	out := make([]ToolInfo, 0, len(hits))
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
