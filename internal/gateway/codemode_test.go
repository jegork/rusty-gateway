package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jegork/rusty-gateway/internal/supervisor"
)

func TestCodeModeDispatchAndAllowlist(t *testing.T) {
	f := setup(t, []Namespace{{
		Name: "p", Servers: []string{"tv", "hevy"}, Discovery: DiscoverySearch,
		CodeMode: &CodeMode{AllowedTools: []string{"tv__echo", "hevy__echo"}},
	}}, []supervisor.Spec{spec("p/tv", nil), spec("p/hevy", nil), spec("other/tv", nil)})
	s := f.connect(t, "p")
	out, err := callJSON(t, s, "execute_code", map[string]any{"code": `
		const a = await tools.call("tv__echo", {values: [1, 2]});
		const b = await tools.call("hevy__echo", {values: [3, 4]});
		return [...JSON.parse(a.content[0].text).values, ...JSON.parse(b.content[0].text).values].reduce((a, b) => a + b, 0);
	`})
	if err != nil || out != `{"result":10}` {
		t.Fatalf("multi-server execution: %s, %v", out, err)
	}
	for _, server := range []string{"tv", "hevy"} {
		call := <-f.calls
		if call.Namespace != "p" || call.Server != server || call.Tool != "echo" || call.Err != nil {
			t.Fatalf("resolved audit: %+v", call)
		}
	}
	for _, name := range []string{"tv__slow", "other__echo", "execute_code", "call_tool"} {
		code := `await tools.call(` + quote(name) + `, {}); return true;`
		if _, err := callJSON(t, s, "execute_code", map[string]any{"code": code}); err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("expected allowlist denial for %s, got %v", name, err)
		}
	}
	select {
	case call := <-f.calls:
		t.Fatalf("denied tool reached dispatcher: %+v", call)
	default:
	}
}

func TestCodeModeOptInAcrossDiscoveryModes(t *testing.T) {
	for _, mode := range []Discovery{DiscoveryFull, DiscoveryConnector, DiscoverySearch, DiscoveryHybrid} {
		t.Run(string(mode), func(t *testing.T) {
			f := setup(t, []Namespace{
				{Name: "on", Servers: []string{"s"}, Discovery: mode, CodeMode: &CodeMode{AllowedTools: []string{"s__echo"}}},
				{Name: "off", Servers: []string{"s"}, Discovery: mode},
			}, []supervisor.Spec{spec("on/s", nil), spec("off/s", nil)})
			for _, ns := range []string{"on", "off"} {
				s := f.connect(t, ns)
				names := "," + strings.Join(toolNames(t, s), ",") + ","
				if strings.Contains(names, ",execute_code,") != (ns == "on") {
					t.Fatalf("%s catalog: %s", ns, names)
				}
			}
		})
	}
}

func TestCodeModePartialFailureAndTimeout(t *testing.T) {
	f := setup(t, []Namespace{{Name: "p", Servers: []string{"s"}, CodeMode: &CodeMode{
		AllowedTools: []string{"s__echo", "s__slow"},
	}}}, []supervisor.Spec{spec("p/s", nil)}, func(f *fixture) {
		f.limits = Limits{CallTimeout: 50 * time.Millisecond, PerNamespace: 1, PerServer: 1}
	})
	s := f.connect(t, "p")
	_, err := callJSON(t, s, "execute_code", map[string]any{"code": `
		await tools.call("s__echo", {first: "completed"});
		await tools.call("s__slow", {ms: 1000});
		return "unreachable";
	`})
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("expected upstream timeout: %v", err)
	}
	var calls [2]Call
	for i := range calls {
		select {
		case calls[i] = <-f.calls:
		default:
			t.Fatal("expected both completed and failed calls to be audited")
		}
	}
	first, second := calls[0], calls[1]
	if first.Tool != "echo" || first.Err != nil || string(first.Args) != `{"first":"completed"}` || second.Tool != "slow" || second.Err == nil {
		t.Fatalf("partial execution audit: %+v, %+v", first, second)
	}
}

func quote(text string) string {
	raw, _ := json.Marshal(text)
	return string(raw)
}

func TestCodeModeErrorsPreserveTheSession(t *testing.T) {
	f := setup(t, []Namespace{{Name: "p", Servers: []string{"s"},
		CodeMode: &CodeMode{AllowedTools: []string{"s__echo"}},
	}}, []supervisor.Spec{spec("p/s", nil)})
	s := f.connect(t, "p")
	result, err := s.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "execute_code", Arguments: map[string]any{"code": `throw new Error("script failed")`},
	})
	if err != nil || !result.IsError {
		t.Fatalf("script failure must be a tool error, not a protocol error: %+v, %v", result, err)
	}
	out, err := callJSON(t, s, "execute_code", map[string]any{"code": `return 42`})
	if err != nil || out != `{"result":42}` {
		t.Fatalf("session must remain usable after script failure: %s, %v", out, err)
	}
}

func TestCodeModeCapacityExpiryIsAToolError(t *testing.T) {
	f := setup(t, []Namespace{{Name: "p", Servers: []string{"s"}, CodeMode: &CodeMode{
		AllowedTools: []string{"s__echo", "s__slow"}, MaxConcurrent: 1,
	}}}, []supervisor.Spec{spec("p/s", nil)})
	var calls atomic.Int32
	f.gw.servers["p"].server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/call" && calls.Add(1) == 2 {
				// expire the server-side wait without cancelling the client's response
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
			}
			return next(ctx, method, req)
		}
	})
	s := f.connect(t, "p")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan struct{})
	go func() {
		defer close(first)
		s.CallTool(ctx, &mcp.CallToolParams{Name: "execute_code", Arguments: map[string]any{
			"code": `await tools.call("s__echo", {}); await tools.call("s__slow", {ms: 3000});`,
		}})
	}()
	select {
	case <-f.calls:
	case <-first:
		t.Fatal("first execution exited before holding capacity")
	case <-time.After(15 * time.Second):
		t.Fatal("first execution never reached its tool call")
	}
	result, err := s.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "execute_code", Arguments: map[string]any{"code": `return 42`},
	})
	<-first
	if err != nil || !result.IsError {
		t.Fatalf("capacity expiry must be a tool error: %+v, %v", result, err)
	}
	out, err := callJSON(t, s, "execute_code", map[string]any{"code": `return 42`})
	if err != nil || out != `{"result":42}` {
		t.Fatalf("session and capacity must recover: %s, %v", out, err)
	}
}
