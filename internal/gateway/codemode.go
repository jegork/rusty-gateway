package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jegork/rusty-gateway/internal/codemode"
)

type CodeMode struct {
	AllowedTools  []string
	Limits        codemode.Limits
	MaxConcurrent int
}

func (g *Gateway) registerCodeMode(ns *nsServer) {
	if ns.ns.CodeMode == nil {
		return
	}
	options := ns.ns.CodeMode
	capacity := options.MaxConcurrent
	if capacity <= 0 {
		capacity = 1
	}
	sem := newSemaphore(capacity)
	limits := options.Limits.Defaults()
	ns.server.AddTool(&mcp.Tool{
		Name:        "execute_code",
		Title:       "Execute JavaScript",
		Description: "Execute a JavaScript async function body in a fresh sandbox. Use return for the JSON result and await tools.call(name, arguments) for tool calls. tools.call returns the full MCP result (content and optional structuredContent); tool errors throw. No packages, filesystem, environment, process, or direct network access. Calls are sequential, even in Promise.all. Earlier calls are not rolled back on failure; never blindly retry writes. Allowed tools: " + strings.Join(options.AllowedTools, ", "),
		InputSchema: json.RawMessage(`{"type":"object","properties":{"code":{"type":"string","description":"JavaScript async function body; use return for the result"}},"required":["code"]}`),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var in struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
		ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
		defer cancel()
		if err := sem.acquire(ctx); err != nil {
			return codeModeError(fmt.Errorf("waiting for code execution capacity: %w", err)), nil
		}
		defer sem.release()
		call := g.metaCall(ns, "")
		out, err := codemode.Execute(ctx, in.Code, limits, func(ctx context.Context, name string, args json.RawMessage) (any, error) {
			if !slices.Contains(options.AllowedTools, name) {
				return nil, fmt.Errorf("tool %q is not allowed in code mode", name)
			}
			raw, err := json.Marshal(struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}{name, args})
			if err != nil {
				return nil, err
			}
			inner := *req
			params := *req.Params
			params.Arguments = raw
			inner.Params = &params
			result, err := call(ctx, &inner)
			if err != nil {
				return nil, err
			}
			if result.IsError {
				var message strings.Builder
				for _, content := range result.Content {
					if text, ok := content.(*mcp.TextContent); ok {
						message.WriteString(text.Text)
					}
				}
				return nil, fmt.Errorf("tool %q failed: %s", name, message.String())
			}
			return result, nil
		})
		if err != nil {
			return codeModeError(err), nil
		}
		return jsonResult(struct {
			Result json.RawMessage `json:"result"`
		}{out})
	})
}

func codeModeError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
	}
}
