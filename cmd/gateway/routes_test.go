package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jegork/rusty-gateway/internal/auth"
	"github.com/jegork/rusty-gateway/internal/config"
	"github.com/jegork/rusty-gateway/internal/fakeserver"
	"github.com/jegork/rusty-gateway/internal/gateway"
	"github.com/jegork/rusty-gateway/internal/supervisor"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeserver.EnvFlag) != "" {
		fakeserver.Main()
	}
	os.Exit(m.Run())
}

// the wiring in main is exercised exactly as deployed: real config, real auth
// middleware, real routes, a real mcp client
func TestRoutesEndToEnd(t *testing.T) {
	cmd, args, env := fakeserver.Spec(nil)
	toml := `
[server]
public_url = "http://gw.test"
[auth]
static_token_env = "TOK"
required_scope = "mcp:use"
[[namespace]]
name = "personal"
servers = ["fake"]
[servers.fake]
command = "` + cmd + `"
args = ["` + strings.Join(args, `", "`) + `"]
[servers.fake.env]
` + fakeserver.EnvFlag + ` = "1"
`
	_ = env
	cfg, err := config.Parse([]byte(toml), func(k string) (string, bool) { return "s3cret", k == "TOK" })
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	authn, err := auth.New(context.Background(), auth.Config{
		PublicURL: cfg.Server.PublicURL, StaticToken: cfg.Auth.StaticToken, RequiredScope: cfg.Auth.RequiredScope,
		Resources: []string{"/mcp/personal"}, Logger: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	var gw *gateway.Gateway
	sup := supervisor.New([]supervisor.Spec{{ID: "personal/fake", Command: cmd, Args: args, Env: env}},
		supervisor.Options{Logger: log, OnChange: func(id string) { gw.Refresh(id) }})
	gw = gateway.New(sup, []gateway.Namespace{{Name: "personal", Servers: []string{"fake"}}}, gateway.Options{Logger: log})
	sup.Start(context.Background())
	defer sup.Stop()
	gw.RefreshAll()

	srv := httptest.NewServer(newMux(cfg, authn, gw, sup, nil, nil))
	defer srv.Close()

	get := func(path, token string) (int, string) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := res.Body.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return res.StatusCode, sb.String()
	}
	if code, body := get("/healthz", ""); code != 200 || !strings.Contains(body, `"personal/fake"`) {
		t.Errorf("healthz: %d %s", code, body)
	}
	if code, body := get("/.well-known/oauth-protected-resource/mcp/personal", ""); code != 200 || !strings.Contains(body, `"resource":"http://gw.test/mcp/personal"`) {
		t.Errorf("metadata: %d %s", code, body)
	}
	if code, _ := get("/mcp/personal", ""); code != 401 {
		t.Errorf("unauthenticated mcp: %d", code)
	}
	if code, _ := get("/mcp/nope", "s3cret"); code != 404 {
		t.Errorf("unknown namespace: %d", code)
	}

	c := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	hc := &http.Client{Transport: bearer{"s3cret"}}
	sess, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: srv.URL + "/mcp/personal", HTTPClient: hc}, nil)
	if err != nil {
		t.Fatalf("mcp connect through real routes: %v", err)
	}
	defer sess.Close()
	tools, err := sess.ListTools(context.Background(), nil)
	if err != nil || len(tools.Tools) != 2 || tools.Tools[0].Name != "fake__echo" {
		t.Fatalf("tools: %v %+v", err, tools)
	}
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "fake__echo", Arguments: map[string]any{"a": 1}})
	if err != nil || res.Content[0].(*mcp.TextContent).Text != `{"a":1}` {
		t.Fatalf("call: %v %+v", err, res)
	}
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}
