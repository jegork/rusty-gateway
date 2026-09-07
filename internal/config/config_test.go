package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeExec(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "srv")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func lookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func minimal(cmd string) string {
	return `
[server]
public_url = "https://gw.example"
[auth]
static_token_env = "TOK"
[[namespace]]
name = "personal"
servers = ["a"]
[servers.a]
command = "` + cmd + `"
env = { KEY = "${SECRET}" }
`
}

func TestParseExpandsEnvAndStaticToken(t *testing.T) {
	cmd := writeExec(t)
	c, err := Parse([]byte(minimal(cmd)), lookup(map[string]string{"TOK": "t0k", "SECRET": "s3"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Servers["a"].Env["KEY"] != "s3" {
		t.Errorf("env not expanded: %v", c.Servers["a"].Env)
	}
	if c.Auth.StaticToken != "t0k" {
		t.Errorf("static token not resolved")
	}
	if c.Server.Listen != ":8080" || c.Audit.RetentionDays != 90 {
		t.Errorf("defaults not applied: %+v", c)
	}
}

func TestParseErrors(t *testing.T) {
	cmd := writeExec(t)
	ok := map[string]string{"TOK": "t", "SECRET": "s"}
	cases := []struct {
		name   string
		src    string
		env    map[string]string
		wantIn string
	}{
		{"missing env var", minimal(cmd), map[string]string{"TOK": "t"}, "unset environment variables: SECRET"},
		{"empty static token", minimal(cmd), map[string]string{"SECRET": "s"}, "TOK is unset"},
		{"command not in PATH", minimal("definitely-not-a-binary-xyz"), ok, "not found in PATH"},
		{"missing binary", minimal(filepath.Join(t.TempDir(), "nope")), ok, "no such file"},
		{"unknown server", strings.Replace(minimal(cmd), `servers = ["a"]`, `servers = ["a", "b"]`, 1), ok, `unknown server "b"`},
		{"unknown field", minimal(cmd) + "\n[bogus]\nx = 1\n", ok, "bogus"},
		{"bad namespace name", strings.Replace(minimal(cmd), `name = "personal"`, `name = "Per Sonal"`, 1), ok, "must match"},
		{"no auth", strings.Replace(minimal(cmd), `static_token_env = "TOK"`, ``, 1), ok, "auth: set"},
		{"url with command", minimal(cmd) + "\n[servers.r]\nurl = \"https://r.example/mcp\"\ncommand = \"/bin/x\"\n", ok, "mutually exclusive"},
		{"bad url", minimal(cmd) + "\n[servers.r]\nurl = \"r.example/mcp\"\n", ok, "absolute http(s) url"},
		{"headers on stdio", strings.Replace(minimal(cmd), `env = { KEY = "${SECRET}" }`, `headers = { X = "1" }`, 1), ok, "headers only apply"},
		{"bad duration", minimal(cmd) + "\n[limits]\ncall_timeout = \"soon\"\n", ok, "invalid duration"},
		{"negative limit", minimal(cmd) + "\n[limits]\nmax_concurrent = -1\n", ok, "not be negative"},
		{"issuer without audience", strings.Replace(minimal(cmd), `static_token_env = "TOK"`, `issuer = "https://idp"`, 1), ok, "auth.audience is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src), lookup(tc.env))
			if err == nil || !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("want error containing %q, got %v", tc.wantIn, err)
			}
		})
	}
}

func TestBareCommandResolvedThroughPath(t *testing.T) {
	dir := filepath.Dir(writeExec(t))
	t.Setenv("PATH", dir)
	c, err := Parse([]byte(minimal("srv")), lookup(map[string]string{"TOK": "t", "SECRET": "s"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Servers["a"].Command; got != filepath.Join(dir, "srv") {
		t.Errorf("command not pinned to absolute path: %q", got)
	}
}

func TestSyntaxErrorReportsLine(t *testing.T) {
	src := "[server]\npublic_url = \"x\"\n[servers.a]\nargs = [\"--from\" \"pkg\"]\n"
	_, err := Parse([]byte(src), lookup(nil))
	if err == nil || !strings.Contains(err.Error(), "line 4") || !strings.Contains(err.Error(), "args = ") {
		t.Fatalf("want line number and context, got: %v", err)
	}
}

func TestNonExecutableCommandRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "srv")
	os.WriteFile(p, []byte(""), 0o644)
	_, err := Parse([]byte(minimal(p)), lookup(map[string]string{"TOK": "t", "SECRET": "s"}))
	if err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("got %v", err)
	}
}

func TestRemoteServerAndLimits(t *testing.T) {
	cmd := writeExec(t)
	src := minimal(cmd) + `
[limits]
call_timeout = "5s"
max_concurrent = 10
[breaker]
failures = 3
[servers.r]
url = "https://r.example/mcp"
headers = { Authorization = "Bearer ${RTOK}" }
max_concurrent = 2
call_timeout = "90s"
`
	c, err := Parse([]byte(src), lookup(map[string]string{"TOK": "t", "SECRET": "s", "RTOK": "rt"}))
	if err != nil {
		t.Fatal(err)
	}
	r := c.Servers["r"]
	if !r.Remote() || r.Headers["Authorization"] != "Bearer rt" || r.MaxConcurrent != 2 || r.CallTimeout.Duration != 90*time.Second {
		t.Errorf("%+v", r)
	}
	if c.Limits.CallTimeout.Duration != 5*time.Second || c.Limits.MaxConcurrent != 10 {
		t.Errorf("%+v", c.Limits)
	}
	if c.Breaker.Failures != 3 || c.Breaker.Cooldown.Duration != 30*time.Second {
		t.Errorf("breaker default cooldown: %+v", c.Breaker)
	}
	c2, _ := Parse([]byte(minimal(cmd)), lookup(map[string]string{"TOK": "t", "SECRET": "s"}))
	if c2.Limits.CallTimeout.Duration != 60*time.Second || c2.Breaker.Failures != 0 {
		t.Errorf("defaults: %+v %+v", c2.Limits, c2.Breaker)
	}
}
