package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		{"relative command", minimal("uvx"), ok, "absolute path"},
		{"missing binary", minimal(filepath.Join(t.TempDir(), "nope")), ok, "no such file"},
		{"unknown server", strings.Replace(minimal(cmd), `servers = ["a"]`, `servers = ["a", "b"]`, 1), ok, `unknown server "b"`},
		{"unknown field", minimal(cmd) + "\n[bogus]\nx = 1\n", ok, "bogus"},
		{"bad namespace name", strings.Replace(minimal(cmd), `name = "personal"`, `name = "Per Sonal"`, 1), ok, "must match"},
		{"no auth", strings.Replace(minimal(cmd), `static_token_env = "TOK"`, ``, 1), ok, "auth: set"},
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

func TestNonExecutableCommandRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "srv")
	os.WriteFile(p, []byte(""), 0o644)
	_, err := Parse([]byte(minimal(p)), lookup(map[string]string{"TOK": "t", "SECRET": "s"}))
	if err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("got %v", err)
	}
}
