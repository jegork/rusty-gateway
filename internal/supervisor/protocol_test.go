package supervisor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// newProtocolServer serves the 2026-07-28 protocol the way hosted servers
// such as notion do: stateless, with per-request envelopes and Mcp-Method
// headers enforced by the sdk. It is the guard against sdk upgrades
// changing wire behaviour under us.
func newProtocolServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "modern", Version: "0"}, nil)
	srv.AddTool(&mcp.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(req.Params.Arguments)}}}, nil
		})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{Stateless: true})
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

func TestModernProtocolUpstream(t *testing.T) {
	ts := newProtocolServer(t)
	s := New([]Spec{{ID: "ns/modern", URL: ts.URL}}, fastOpts())
	s.Start(context.Background())
	defer s.Stop()

	u, _ := s.Get("ns/modern")
	st := u.Status()
	if st.State != "ready" || st.Tools != 1 {
		t.Fatalf("%+v", st)
	}
	u.mu.RLock()
	negotiated := u.session.InitializeResult().ProtocolVersion
	u.mu.RUnlock()
	if negotiated != "2026-07-28" {
		t.Fatalf("negotiated %s; the test must run on the newest protocol to mean anything", negotiated)
	}

	res, err := u.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"a": 1}})
	if err != nil || res.Content[0].(*mcp.TextContent).Text != `{"a":1}` {
		t.Fatalf("call on new protocol: %v %+v", err, res)
	}

	// several ping intervals: the envelope we build by hand must satisfy the
	// sdk server, or the upstream restarts / disables pings
	time.Sleep(600 * time.Millisecond)
	st = u.Status()
	u.mu.RLock()
	broken := u.pingBroken
	u.mu.RUnlock()
	if st.Restarts != 0 || st.State != "ready" || broken {
		t.Fatalf("ping on new protocol not accepted: restarts=%d state=%s pingBroken=%v err=%s", st.Restarts, st.State, broken, st.Error)
	}
}

func TestStopReturnsWhenRemoteServerIsGone(t *testing.T) {
	ts := newProtocolServer(t)
	s := New([]Spec{{ID: "ns/modern", URL: ts.URL}}, fastOpts())
	s.Start(context.Background())
	ts.CloseClientConnections()
	ts.Close()
	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop hung after the remote server went away")
	}
}
