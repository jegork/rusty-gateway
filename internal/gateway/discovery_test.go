package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
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
	if got := strings.Join(toolNames(t, s), ","); got != "call_tool,describe_tools,list_tools,search_tools" {
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
	if got := strings.Join(toolNames(t, s), ","); got != "call_tool,describe_tools,list_tools,search_tools,tv__echo" {
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

func listPageOf(t *testing.T, s *mcp.ClientSession, args map[string]any) (listPage, error) {
	t.Helper()
	params := &mcp.CallToolParams{Name: "list_tools"}
	if args != nil {
		params.Arguments = args
	}
	res, err := s.CallTool(context.Background(), params)
	if err != nil {
		return listPage{}, err
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if res.IsError {
		return listPage{}, &toolErr{text}
	}
	if strings.Contains(text, "inputSchema") || strings.Contains(text, `"tools":null`) {
		t.Fatalf("list page must be compact and never null: %s", text)
	}
	var page listPage
	if err := json.Unmarshal([]byte(text), &page); err != nil {
		t.Fatal(err)
	}
	return page, nil
}

func TestListToolsPaginationAndEligibility(t *testing.T) {
	f := setup(t, []Namespace{
		{Name: "p", Servers: []string{"tv", "hevy", "broken"}, Discovery: DiscoverySearch,
			CodeMode: &CodeMode{AllowedTools: []string{"tv__a", "hevy__echo"}}},
		{Name: "q", Servers: []string{"tv"}, Discovery: DiscoverySearch},
	}, []supervisor.Spec{
		spec("p/tv", map[string]string{"RG_TOOLS": "d,c,b,a"}),
		spec("p/hevy", nil),
		spec("p/broken", map[string]string{"RG_FAIL_START": "1"}),
		spec("p/excluded", nil),
		spec("q/tv", nil),
	})
	s := f.connect(t, "p")
	want := "hevy__echo,hevy__slow,tv__a,tv__b,tv__c,tv__d,tv__echo,tv__slow"

	// absent arguments, an empty object and an explicit zero all use the default page
	for _, args := range []map[string]any{nil, {}, {"limit": 0}} {
		page, err := listPageOf(t, s, args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		var names []string
		for _, info := range page.Tools {
			names = append(names, info.Name)
		}
		if strings.Join(names, ",") != want || page.NextCursor != "" {
			t.Fatalf("default page %v: %v cursor=%q", args, names, page.NextCursor)
		}
	}

	var names []string
	var cursors []string
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 5 {
			t.Fatal("pagination did not terminate")
		}
		args := map[string]any{"limit": 3}
		if cursor != "" {
			args["cursor"] = cursor
		}
		page, err := listPageOf(t, s, args)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Tools) > 3 {
			t.Fatalf("page exceeds limit: %+v", page)
		}
		for _, info := range page.Tools {
			names = append(names, info.Name)
			allowed := info.Name == "tv__a" || info.Name == "hevy__echo"
			if info.CodeModeAllowed != allowed {
				t.Errorf("code_mode_allowed for %s = %v", info.Name, info.CodeModeAllowed)
			}
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		cursors = append(cursors, cursor)
	}
	if strings.Join(names, ",") != want || len(cursors) != 2 {
		t.Fatalf("paged listing: %v, cursors %d", names, len(cursors))
	}

	// a removed last-seen tool neither skips nor repeats the remaining ones
	gone := encodeCursor(listCursor{Version: cursorVersion, Namespace: "p", After: "tv__b0"})
	page, err := listPageOf(t, s, map[string]any{"cursor": gone, "limit": 2})
	if err != nil || len(page.Tools) != 2 || page.Tools[0].Name != "tv__c" || page.Tools[1].Name != "tv__d" {
		t.Fatalf("keyset resume after removal: %+v, %v", page, err)
	}

	page, err = listPageOf(t, s, map[string]any{"server": "hevy", "limit": 1})
	if err != nil || len(page.Tools) != 1 || page.Tools[0].Name != "hevy__echo" || page.NextCursor == "" {
		t.Fatalf("server filter: %+v, %v", page, err)
	}
	hevyCursor := page.NextCursor
	page, err = listPageOf(t, s, map[string]any{"server": "hevy", "cursor": hevyCursor})
	if err != nil || len(page.Tools) != 1 || page.Tools[0].Name != "hevy__slow" || page.NextCursor != "" {
		t.Fatalf("server filter continuation: %+v, %v", page, err)
	}
	page, err = listPageOf(t, s, map[string]any{"server": "broken"})
	if err != nil || len(page.Tools) != 0 || page.NextCursor != "" {
		t.Fatalf("unavailable configured server should be an empty page: %+v, %v", page, err)
	}

	foreign := encodeCursor(listCursor{Version: cursorVersion, Namespace: "q", After: "tv__a"})
	future := encodeCursor(listCursor{Version: cursorVersion + 1, Namespace: "p", After: "tv__a"})
	empty := encodeCursor(listCursor{Version: cursorVersion, Namespace: "p"})
	valid, _ := json.Marshal(listCursor{Version: cursorVersion, Namespace: "p", After: "tv__a"})
	trailing := base64.RawURLEncoding.EncodeToString(append(valid, '}'))
	for _, args := range []map[string]any{
		{"server": "excluded"},
		{"server": "other"},
		{"limit": -1},
		{"limit": 51},
		{"cursor": "not a cursor"},
		{"cursor": strings.Repeat("A", 4096)},
		{"cursor": hevyCursor},
		{"cursor": cursors[0], "server": "tv"},
		{"cursor": foreign},
		{"cursor": future},
		{"cursor": empty},
		{"cursor": trailing},
	} {
		if page, err := listPageOf(t, s, args); err == nil {
			t.Errorf("must reject %v, got %+v", args, page)
		}
	}

	out, err := callJSON(t, s, "search_tools", map[string]any{"query": "echo"})
	if err != nil {
		t.Fatal(err)
	}
	var infos []ToolInfo
	json.Unmarshal([]byte(out), &infos)
	if len(infos) != 2 || !infos[0].CodeModeAllowed || infos[0].Name != "hevy__echo" || infos[1].CodeModeAllowed {
		t.Fatalf("search eligibility: %s", out)
	}
	out, err = callJSON(t, s, "describe_tools", map[string]any{"names": []string{"tv__a", "tv__b"}})
	if err != nil {
		t.Fatal(err)
	}
	var described []ToolInfo
	json.Unmarshal([]byte(out), &described)
	if len(described) != 2 || !described[0].CodeModeAllowed || described[1].CodeModeAllowed || described[0].InputSchema == nil {
		t.Fatalf("describe eligibility: %s", out)
	}
	if ui := f.gw.Tools("p", "", 0); len(ui) == 0 || ui[0].InputSchema == nil {
		t.Fatalf("dashboard catalog must keep schemas: %+v", ui)
	}

	// without code mode nothing is scriptable, but everything stays listed
	page, err = listPageOf(t, f.connect(t, "q"), nil)
	if err != nil || len(page.Tools) != 2 {
		t.Fatalf("code mode off listing: %+v, %v", page, err)
	}
	for _, info := range page.Tools {
		if info.CodeModeAllowed {
			t.Errorf("code mode off must not mark %s eligible", info.Name)
		}
	}
}

func TestDiscoveryGuidanceMatchesExposedTools(t *testing.T) {
	wrappers := []string{"search_tools", "describe_tools", "call_tool", "list_tools", "execute_code"}
	for _, mode := range []Discovery{DiscoveryFull, DiscoveryConnector, DiscoverySearch, DiscoveryHybrid} {
		for _, code := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/code=%v", mode, code), func(t *testing.T) {
				p := Namespace{Name: "p", Servers: []string{"tv", "hevy"}, Discovery: mode,
					ServerDescriptions: map[string]string{"hevy": "Strength   training\nlog"}}
				if code {
					p.CodeMode = &CodeMode{AllowedTools: []string{"hevy__echo"}}
				}
				f := setup(t, []Namespace{p,
					{Name: "q", Servers: []string{"notion"}, Discovery: mode, ServerDescriptions: map[string]string{"notion": "Private wiki"}},
				}, []supervisor.Spec{
					spec("p/tv", map[string]string{"RG_TOOLS": "zebra_feed"}),
					spec("p/hevy", nil),
					spec("q/notion", nil),
				})
				s := f.connect(t, "p")
				res, err := s.ListTools(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				exposed := map[string]int{}
				texts := map[string]string{"instructions": s.InitializeResult().Instructions}
				for _, tool := range res.Tools {
					exposed[tool.Name]++
					if slices.Contains(wrappers, tool.Name) {
						texts[tool.Name] = tool.Description
					}
				}
				// only these carry the overview; describe_tools and call_tool stay short
				carriers := []string{"instructions", "search_tools", "list_tools", "execute_code"}
				if browse := exposed["list_tools"]; browse != 0 != (code || mode == DiscoverySearch || mode == DiscoveryHybrid) {
					t.Fatalf("list_tools exposure: %v", exposed)
				}
				for source, text := range texts {
					for _, name := range wrappers {
						if strings.Contains(text, name) && exposed[name] == 0 &&
							!(mode == DiscoveryConnector && name == "list_tools" && strings.Contains(text, "__list_tools")) {
							t.Errorf("%s mentions absent %s: %q", source, name, text)
						}
					}
					if slices.Contains(carriers, source) && (!strings.Contains(text, "hevy: Strength training log") || !strings.Contains(text, "- tv")) {
						t.Errorf("%s must list configured servers and descriptions: %q", source, text)
					}
					for _, leak := range []string{"Private wiki", "notion", "zebra_feed", "inputSchema"} {
						if strings.Contains(text, leak) {
							t.Errorf("%s leaked %q: %q", source, leak, text)
						}
					}
				}
			})
		}
	}
}
