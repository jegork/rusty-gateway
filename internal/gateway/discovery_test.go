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
	var infos []toolInfo
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
	if got := strings.Join(toolNames(t, s), ","); got != "call_tool,search_tools" {
		t.Fatalf("search tools: %s", got)
	}
	search := func(q string) []string {
		out, err := callJSON(t, s, "search_tools", map[string]any{"query": q})
		if err != nil {
			t.Fatal(err)
		}
		var infos []toolInfo
		json.Unmarshal([]byte(out), &infos)
		var names []string
		for _, i := range infos {
			names = append(names, i.Name)
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

	out, err := callJSON(t, s, "call_tool", map[string]any{"name": "hevy__echo", "arguments": map[string]any{"a": "b"}})
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
