package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jegork/rusty-gateway/internal/supervisor"
)

func callJSON(t *testing.T, s *mcp.ClientSession, name string, args map[string]any) (string, error) {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return "", err
	}
	if res.IsError {
		return "", &toolErr{res.Content[0].(*mcp.TextContent).Text}
	}
	return res.Content[0].(*mcp.TextContent).Text, nil
}

type toolErr struct{ msg string }

func (e *toolErr) Error() string { return e.msg }

func TestConnectorDiscovery(t *testing.T) {
	f := setup(t, []Namespace{{Name: "p", Servers: []string{"tv", "hevy"}, Discovery: DiscoveryConnector}}, []supervisor.Spec{
		spec("p/tv", map[string]string{"RG_TOOLS": "quote"}),
		spec("p/hevy", nil),
	})
	s := f.connect(t, "p")
	if got := strings.Join(toolNames(t, s), ","); got != "hevy__call,hevy__list_tools,tv__call,tv__list_tools" {
		t.Fatalf("connector tools: %s", got)
	}
	out, err := callJSON(t, s, "tv__list_tools", nil)
	if err != nil {
		t.Fatal(err)
	}
	var infos []ToolInfo
	json.Unmarshal([]byte(out), &infos)
	names := []string{}
	for _, i := range infos {
		names = append(names, i.Name)
		if i.Server != "tv" || i.InputSchema == nil {
			t.Errorf("bad info %+v", i)
		}
	}
	if strings.Join(names, ",") != "tv__echo,tv__quote,tv__slow" {
		t.Errorf("list_tools: %v", names)
	}

	out, err = callJSON(t, s, "tv__call", map[string]any{"name": "echo", "arguments": map[string]any{"x": 1}})
	if err != nil || out != `{"x":1}` {
		t.Fatalf("call via meta: %v %q", err, out)
	}
	c := <-f.calls
	if c.Server != "tv" || c.Tool != "echo" || string(c.Args) != `{"x":1}` {
		t.Errorf("audit should record the resolved tool, got %+v", c)
	}
	if _, err := callJSON(t, s, "tv__call", map[string]any{"name": "nope"}); err == nil {
		t.Error("unknown tool via meta should fail")
	}
	if _, err := callJSON(t, s, "hevy__call", map[string]any{"name": "quote"}); err == nil {
		t.Error("tool from another server must not resolve")
	}
	if _, err := callJSON(t, s, "tv__echo", nil); err == nil {
		t.Error("direct names are not exposed in connector mode")
	}
}

func TestSearchDiscovery(t *testing.T) {
	f := setup(t, []Namespace{{Name: "p", Servers: []string{"tv", "hevy"}, Discovery: DiscoverySearch}}, []supervisor.Spec{
		spec("p/tv", map[string]string{"RG_TOOLS": "quote,candles"}),
		spec("p/hevy", map[string]string{"RG_TOOLS": "workouts"}),
	})
	s := f.connect(t, "p")
	if got := strings.Join(toolNames(t, s), ","); got != "call_tool,describe_tools,search_tools" {
		t.Fatalf("search tools: %s", got)
	}
	search := func(q string) []string {
		out, err := callJSON(t, s, "search_tools", map[string]any{"query": q})
		if err != nil {
			t.Fatal(err)
		}
		var infos []ToolInfo
		if err := json.Unmarshal([]byte(out), &infos); err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, i := range infos {
			names = append(names, i.Name)
			if i.InputSchema != nil {
				t.Errorf("search must not load schemas: %+v", i)
			}
		}
		return names
	}
	if got := search("quote"); strings.Join(got, ",") != "tv__quote" {
		t.Errorf("search quote: %v", got)
	}
	if got := search("workout"); strings.Join(got, ",") != "hevy__workouts" {
		t.Errorf("search workout: %v", got)
	}
	// "slow" matches one tool per server; "ms" matches the slow tool's parameter
	if got := search("slow ms"); len(got) != 2 || got[0] != "hevy__slow" || got[1] != "tv__slow" {
		t.Errorf("search slow: %v", got)
	}
	if got := search("zzz"); len(got) != 0 {
		t.Errorf("no match should be empty: %v", got)
	}
	if got := search(""); len(got) != 0 {
		t.Errorf("empty query should be empty: %v", got)
	}

	out, err := callJSON(t, s, "search_tools", map[string]any{"query": "echo", "server": "tv", "limit": 1})
	if err != nil {
		t.Fatal(err)
	}
	var infos []ToolInfo
	if err := json.Unmarshal([]byte(out), &infos); err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "tv__echo" || infos[0].Server != "tv" {
		t.Fatalf("server-filtered search: %s", out)
	}
	out, err = callJSON(t, s, "describe_tools", map[string]any{"names": []string{"hevy__workouts", "tv__quote"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(out), &infos); err != nil {
		t.Fatal(err)
	}
	if len(infos) != 2 || infos[0].Name != "hevy__workouts" || infos[1].Name != "tv__quote" {
		t.Fatalf("descriptions must preserve selection order: %s", out)
	}
	for _, info := range infos {
		schema, _ := json.Marshal(info.InputSchema)
		if string(schema) != `{"type":"object"}` {
			t.Errorf("missing upstream schema for %s: %s", info.Name, schema)
		}
	}
	for _, names := range [][]string{nil, {"echo"}, {"tv__missing"}, {"other__echo"}, {"tv__quote", "other__echo"}} {
		if _, err := callJSON(t, s, "describe_tools", map[string]any{"names": names}); err == nil {
			t.Errorf("invalid selection must fail: %v", names)
		}
	}

	out, err = callJSON(t, s, "call_tool", map[string]any{"name": "hevy__echo", "arguments": map[string]any{"a": "b"}})
	if err != nil || out != `{"a":"b"}` {
		t.Fatalf("call_tool: %v %q", err, out)
	}
	c := <-f.calls
	if c.Server != "hevy" || c.Tool != "echo" {
		t.Errorf("audit: %+v", c)
	}
	if _, err := callJSON(t, s, "call_tool", map[string]any{"name": "echo"}); err == nil {
		t.Error("unprefixed name must be rejected")
	}
}

func TestHybridDiscovery(t *testing.T) {
	f := setup(t, []Namespace{{
		Name: "p", Servers: []string{"tv", "hevy", "broken"}, Discovery: DiscoveryHybrid,
		PinnedTools: []string{"tv__echo", "broken__echo", "tv__missing"},
	}}, []supervisor.Spec{
		spec("p/tv", map[string]string{"RG_TOOLS": "quote"}),
		spec("p/hevy", nil),
		spec("p/broken", map[string]string{"RG_FAIL_START": "1"}),
		spec("p/excluded", nil),
	})
	s := f.connect(t, "p")
	if got := strings.Join(toolNames(t, s), ","); got != "call_tool,describe_tools,search_tools,tv__echo" {
		t.Fatalf("only available pins should be native: %s", got)
	}
	for _, name := range []string{"tv__echo", "call_tool"} {
		args := map[string]any{"value": "same"}
		if name == "call_tool" {
			args = map[string]any{"name": "tv__echo", "arguments": args}
		}
		out, err := callJSON(t, s, name, args)
		if err != nil || out != `{"value":"same"}` {
			t.Fatalf("%s: %q, %v", name, out, err)
		}
		c := <-f.calls
		if c.Server != "tv" || c.Tool != "echo" || string(c.Args) != `{"value":"same"}` {
			t.Fatalf("resolved dispatch: %+v", c)
		}
	}
	out, err := callJSON(t, s, "search_tools", map[string]any{"query": "quote"})
	if err != nil || !strings.Contains(out, `"name":"tv__quote"`) || strings.Contains(out, "inputSchema") {
		t.Fatalf("unpinned search: %s, %v", out, err)
	}
	out, err = callJSON(t, s, "describe_tools", map[string]any{"names": []string{"tv__quote"}})
	if err != nil || !strings.Contains(out, `"inputSchema":{"type":"object"}`) {
		t.Fatalf("unpinned description: %s, %v", out, err)
	}
	out, err = callJSON(t, s, "call_tool", map[string]any{"name": "tv__quote", "arguments": map[string]any{"symbol": "AAPL"}})
	if err != nil || out != `{"symbol":"AAPL"}` {
		t.Fatalf("unpinned call: %s, %v", out, err)
	}
	<-f.calls
	for _, name := range []string{"broken__echo", "tv__missing", "excluded__echo", "other__echo"} {
		if _, err := callJSON(t, s, "call_tool", map[string]any{"name": name}); err == nil {
			t.Errorf("unavailable or excluded call must fail: %s", name)
		}
		if _, err := callJSON(t, s, "describe_tools", map[string]any{"names": []string{name}}); err == nil {
			t.Errorf("unavailable or excluded description must fail: %s", name)
		}
	}
	out, err = callJSON(t, s, "search_tools", map[string]any{"query": "echo", "server": "excluded"})
	if err != nil || out != "[]" {
		t.Fatalf("excluded search must be empty: %s, %v", out, err)
	}
	if _, err := callJSON(t, s, "tv__quote", nil); err == nil {
		t.Fatal("unpinned tools must not be native")
	}
}
