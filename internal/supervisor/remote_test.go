package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func remoteServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "remote", Version: "0"}, nil)
	srv.AddTool(&mcp.Tool{Name: "ping", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "pong"}}}, nil
		})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "k1" {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		// like notion: ping is answered with an http 404 carrying a json-rpc error
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if bytes.Contains(body, []byte(`"method":"ping"`)) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`))
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestRemoteUpstream(t *testing.T) {
	ts := remoteServer(t)
	s := New([]Spec{
		{ID: "ns/remote", URL: ts.URL, Headers: map[string]string{"X-Api-Key": "k1"}},
		{ID: "ns/badkey", URL: ts.URL, Headers: map[string]string{"X-Api-Key": "wrong"}},
	}, fastOpts())
	s.Start(context.Background())
	defer s.Stop()

	if pids := s.LivePIDs(); len(pids) != 0 {
		t.Errorf("remote upstreams must not own processes: %v", pids)
	}
	st := s.Statuses()
	if st[0].State != "ready" || st[0].Kind != "http" || st[0].Tools != 1 || st[0].PID != 0 {
		t.Errorf("%+v", st[0])
	}
	u, _ := s.Get("ns/remote")
	res, err := u.CallTool(context.Background(), &mcp.CallToolParams{Name: "ping"})
	if err != nil || res.Content[0].(*mcp.TextContent).Text != "pong" {
		t.Fatalf("%v %+v", err, res)
	}
	// the sdk drops the session on the 404 once; after that pings are off and
	// the upstream stays up
	time.Sleep(700 * time.Millisecond)
	if st := s.Statuses()[0]; st.State != "ready" || st.Restarts > 1 {
		t.Errorf("remote upstream keeps restarting on unsupported ping: %+v", st)
	}
	waitFor(t, "bad key upstream to fail", func() bool { return s.Statuses()[1].State == "failed" })
	if e := s.Statuses()[1].Error; e == "" {
		t.Error("failed upstream should carry an error")
	}
}
