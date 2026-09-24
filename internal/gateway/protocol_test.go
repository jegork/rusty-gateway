package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jegork/rusty-gateway/internal/supervisor"
)

// post sends one JSON-RPC message the way an HTTP MCP client does and returns
// the status, the response headers and the first SSE data payload (or raw body)
func post(t *testing.T, url string, headers map[string]string, msg any) (int, http.Header, string) {
	t.Helper()
	body, _ := json.Marshal(msg)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// the new protocol wants the method mirrored in a header
	if m, ok := msg.(map[string]any); ok && headers["Mcp-Protocol-Version"] == "2026-07-28" {
		req.Header.Set("Mcp-Method", m["method"].(string))
		if params, ok := m["params"].(map[string]any); ok {
			if name, ok := params["name"].(string); ok {
				req.Header.Set("Mcp-Name", name)
			}
		}
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := string(raw)
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "data: ") {
			out = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	return res.StatusCode, res.Header, out
}

// hosted clients (chatgpt, claude.ai) probe with server/discover and only
// proceed when 2026-07-28 is listed; older clients still initialize first.
// both must work against the same endpoint.
func TestServesCurrentAndLegacyProtocols(t *testing.T) {
	f := setup(t, []Namespace{{Name: "p", Servers: []string{"s"}}},
		[]supervisor.Spec{spec("p/s", map[string]string{"RG_TOOLS": "quote"})})
	url := f.http.URL + "/mcp/p"
	meta := map[string]any{
		"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "openai-mcp", "version": "1.0.0"},
	}
	newHeaders := map[string]string{"Mcp-Protocol-Version": "2026-07-28"}

	t.Run("discover lists 2026-07-28", func(t *testing.T) {
		code, _, body := post(t, url, newHeaders, map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": map[string]any{"_meta": meta},
		})
		if code != 200 || !strings.Contains(body, `"2026-07-28"`) {
			t.Fatalf("discover: %d %s", code, body)
		}
	})

	t.Run("sessionless tools/list and call", func(t *testing.T) {
		code, hdr, body := post(t, url, newHeaders, map[string]any{
			"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{"_meta": meta},
		})
		if code != 200 || !strings.Contains(body, `"s__quote"`) {
			t.Fatalf("tools/list: %d %s", code, body)
		}
		if hdr.Get("Mcp-Session-Id") != "" {
			t.Errorf("sessionless response carried a session id")
		}
		code, _, body = post(t, url, newHeaders, map[string]any{
			"jsonrpc": "2.0", "id": 3, "method": "tools/call",
			"params": map[string]any{"_meta": meta, "name": "s__quote", "arguments": map[string]any{}},
		})
		if code != 200 || strings.Contains(body, `"error"`) {
			t.Fatalf("tools/call: %d %s", code, body)
		}
	})

	t.Run("sdk client negotiates 2026-07-28", func(t *testing.T) {
		s := f.connect(t, "p")
		if got := s.InitializeResult().ProtocolVersion; got != "2026-07-28" {
			t.Fatalf("negotiated %q", got)
		}
		if _, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: "s__quote", Arguments: map[string]any{}}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("legacy initialize flow still works", func(t *testing.T) {
		code, hdr, body := post(t, url, nil, map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "initialize",
			"params": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{},
				"clientInfo": map[string]any{"name": "claude-code", "version": "2"}},
		})
		if code != 200 || !strings.Contains(body, `"protocolVersion":"2025-11-25"`) {
			t.Fatalf("initialize: %d %s", code, body)
		}
		legacy := map[string]string{"Mcp-Protocol-Version": "2025-11-25"}
		if sid := hdr.Get("Mcp-Session-Id"); sid != "" {
			legacy["Mcp-Session-Id"] = sid
		}
		if code, _, _ := post(t, url, legacy, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); code != 202 {
			t.Fatalf("initialized notification: %d", code)
		}
		code, _, body = post(t, url, legacy, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{}})
		if code != 200 || !strings.Contains(body, `"s__quote"`) {
			t.Fatalf("legacy tools/list: %d %s", code, body)
		}
	})
}
