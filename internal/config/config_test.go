package config

import (
	"os"
	"path/filepath"
	"slices"
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
		{"bad discovery", strings.Replace(minimal(cmd), `servers = ["a"]`, "servers = [\"a\"]\ndiscovery = \"magic\"", 1), ok, "discovery must be"},
		{"bad stderr level", minimal(cmd) + "\nstderr_level = \"loud\"\n", ok, "stderr_level must be"},
		{"negative limit", minimal(cmd) + "\n[limits]\nmax_concurrent = -1\n", ok, "not be negative"},
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

func TestDataDirDefaultsNextToAudit(t *testing.T) {
	cmd := writeExec(t)
	c, _ := Parse([]byte(minimal(cmd)+"\n[audit]\npath = \"/data/audit.db\"\n"), lookup(map[string]string{"TOK": "t", "SECRET": "s"}))
	if c.Server.DataDir != "/data" {
		t.Errorf("data_dir = %q", c.Server.DataDir)
	}
	c, _ = Parse([]byte(minimal(cmd)), lookup(map[string]string{"TOK": "t", "SECRET": "s"}))
	if c.Server.DataDir != "." {
		t.Errorf("data_dir without audit = %q", c.Server.DataDir)
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

func TestAdvertisedScopesDefault(t *testing.T) {
	base := `
[server]
public_url = "http://gw.test"
[[namespace]]
name = "n"
servers = ["s"]
[servers.s]
command = "` + writeExec(t) + `"
`
	cases := []struct {
		name, auth string
		want       []string
	}{
		{"issuer adds offline_access", "[auth]\nissuer = \"http://idp\"\nrequired_scope = \"mcp:use\"\n", []string{"mcp:use", "offline_access"}},
		{"issuer without required scope", "[auth]\nissuer = \"http://idp\"\n", []string{"offline_access"}},
		{"static token only", "[auth]\nstatic_token_env = \"TOK\"\nrequired_scope = \"mcp:use\"\n", []string{"mcp:use"}},
		{"explicit list wins", "[auth]\nissuer = \"http://idp\"\nrequired_scope = \"mcp:use\"\nscopes = [\"mcp:use\"]\n", []string{"mcp:use"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(base+tc.auth), func(k string) (string, bool) { return "x", k == "TOK" })
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(cfg.Auth.Scopes, tc.want) {
				t.Errorf("scopes = %v, want %v", cfg.Auth.Scopes, tc.want)
			}
		})
	}
}

func TestCloudflareConfiguration(t *testing.T) {
	base := minimal(writeExec(t))
	for _, tc := range []struct {
		name, fields string
		valid        bool
	}{
		{"configured", `team_domain = "https://rusty-rocket.cloudflareaccess.com"
audience = "dashboard-audience"`, true},
		{"trailing slash", `team_domain = "https://rusty-rocket.cloudflareaccess.com/"
audience = "dashboard-audience"`, true},
		{"missing audience", `team_domain = "https://rusty-rocket.cloudflareaccess.com"`, false},
		{"missing domain", `audience = "dashboard-audience"`, false},
		{"blank audience", `team_domain = "https://rusty-rocket.cloudflareaccess.com"
audience = " "`, false},
		{"insecure domain", `team_domain = "http://rusty-rocket.cloudflareaccess.com"
audience = "dashboard-audience"`, false},
		{"domain with path", `team_domain = "https://rusty-rocket.cloudflareaccess.com/login"
audience = "dashboard-audience"`, false},
		{"domain with query", `team_domain = "https://rusty-rocket.cloudflareaccess.com?team=other"
audience = "dashboard-audience"`, false},
		{"domain with userinfo", `team_domain = "https://user@rusty-rocket.cloudflareaccess.com"
audience = "dashboard-audience"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(base+"\n[ui.cloudflare]\n"+tc.fields), lookup(map[string]string{"TOK": "t", "SECRET": "s"}))
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid && (err == nil || !strings.Contains(err.Error(), "ui.cloudflare")) {
				t.Fatalf("want Cloudflare configuration error, got %v", err)
			}
		})
	}
}

func TestCloudflareMCPModeIsExclusive(t *testing.T) {
	base := minimal(writeExec(t))
	for _, legacy := range []string{
		"",
		`issuer = "https://auth.example"`,
		`static_token_env = "TOK"`,
		`audience = "legacy-audience"`,
		`required_scope = "mcp:use"`,
		`scopes = ["mcp:use"]`,
	} {
		t.Run(legacy, func(t *testing.T) {
			src := strings.Replace(base, `static_token_env = "TOK"`, legacy, 1) + `
[auth.cloudflare]
team_domain = "https://rusty-rocket.cloudflareaccess.com"
audience = "mcp-audience"
`
			_, err := Parse([]byte(src), lookup(map[string]string{"TOK": "t", "SECRET": "s"}))
			if legacy == "" && err != nil {
				t.Fatal(err)
			}
			if legacy != "" && (err == nil || !strings.Contains(err.Error(), "mutually exclusive")) {
				t.Fatalf("must reject ambiguous auth modes, got %v", err)
			}
		})
	}
}

func TestHybridPinsRejectInvalidConfiguration(t *testing.T) {
	base := minimal(writeExec(t))
	for _, tc := range []struct {
		name, settings, want string
	}{
		{"wrong mode", "discovery = \"search\"\npinned_tools = [\"a__echo\"]", "requires hybrid"},
		{"default mode", "pinned_tools = [\"a__echo\"]", "requires hybrid"},
		{"unprefixed", "discovery = \"hybrid\"\npinned_tools = [\"echo\"]", "must be server__tool"},
		{"empty tool", "discovery = \"hybrid\"\npinned_tools = [\"a__\"]", "must be server__tool"},
		{"excluded server", "discovery = \"hybrid\"\npinned_tools = [\"b__echo\"]", "outside the namespace"},
		{"duplicate", "discovery = \"hybrid\"\npinned_tools = [\"a__echo\", \"a__echo\"]", "duplicate pinned tool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := strings.Replace(base, `servers = ["a"]`, "servers = [\"a\"]\n"+tc.settings, 1)
			_, err := Parse([]byte(src), lookup(map[string]string{"TOK": "t", "SECRET": "s"}))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}
