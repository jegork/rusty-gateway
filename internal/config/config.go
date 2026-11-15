package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Server     Server             `toml:"server"`
	Auth       Auth               `toml:"auth"`
	Audit      Audit              `toml:"audit"`
	UI         UI                 `toml:"ui"`
	Limits     Limits             `toml:"limits"`
	Breaker    Breaker            `toml:"breaker"`
	Namespaces []Namespace        `toml:"namespace"`
	Servers    map[string]Server_ `toml:"servers"`
}

// UI serves the dashboard at /ui when enabled.
type UI struct {
	Enabled    *bool            `toml:"enabled"`
	Cloudflare CloudflareAccess `toml:"cloudflare"`
}

type CloudflareAccess struct {
	TeamDomain string `toml:"team_domain"`
	Audience   string `toml:"audience"`
}

func (c CloudflareAccess) Validate() error {
	if c.TeamDomain == "" && c.Audience == "" {
		return nil
	}
	if c.TeamDomain == "" || strings.TrimSpace(c.Audience) == "" {
		return errors.New("team_domain and audience are both required")
	}
	u, err := url.Parse(c.TeamDomain)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("team_domain must be an https origin, e.g. https://rusty-rocket.cloudflareaccess.com")
	}
	return nil
}

func (u UI) On() bool { return u.Enabled == nil || *u.Enabled }

// Limits bounds in-flight tool calls. Zero means unlimited for the
// concurrency fields; CallTimeout zero means no deadline.
type Limits struct {
	CallTimeout   Duration `toml:"call_timeout"`
	MaxConcurrent int      `toml:"max_concurrent"`
	PerNamespace  int      `toml:"max_concurrent_per_namespace"`
	PerServer     int      `toml:"max_concurrent_per_server"`
}

// Breaker opens an upstream's circuit after Failures consecutive errors or
// timeouts and lets one trial call through after Cooldown. Failures zero
// disables the breaker.
type Breaker struct {
	Failures int      `toml:"failures"`
	Cooldown Duration `toml:"cooldown"`
}

// Duration parses TOML strings like "30s" or "2m".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

type Server struct {
	Listen    string `toml:"listen"`
	PublicURL string `toml:"public_url"`
	// DataDir holds gateway state such as upstream OAuth credentials.
	DataDir string `toml:"data_dir"`
}

type Auth struct {
	Issuer        string `toml:"issuer"`
	Audience      string `toml:"audience"`
	RequiredScope string `toml:"required_scope"`
	// Scopes is what clients are told to request (RFC 9728
	// scopes_supported). Defaults to required_scope plus offline_access,
	// since without offline_access most IdPs issue no refresh token.
	Scopes         []string         `toml:"scopes"`
	StaticTokenEnv string           `toml:"static_token_env"`
	Cloudflare     CloudflareAccess `toml:"cloudflare"`

	// resolved from StaticTokenEnv at load; never serialized
	StaticToken string `toml:"-"`
}

type Audit struct {
	Path          string `toml:"path"`
	RetentionDays int    `toml:"retention_days"`
	MaxPayloadKB  int    `toml:"max_payload_kb"`
}

type Namespace struct {
	Name          string   `toml:"name"`
	Servers       []string `toml:"servers"`
	MaxConcurrent int      `toml:"max_concurrent"` // overrides limits.max_concurrent_per_namespace
	// discovery is full (default), connector, search, or hybrid
	Discovery   string   `toml:"discovery"`
	PinnedTools []string `toml:"pinned_tools"`
	// code mode opts this namespace into sandboxed JS execution of its
	// allowed tools; zero resource values select runtime defaults
	CodeMode *CodeMode `toml:"code_mode"`
}

// code mode bounds the sandboxed execution environment; zero selects the
// built-in default and negative values are invalid
type CodeMode struct {
	Enabled        *bool    `toml:"enabled"`
	AllowedTools   []string `toml:"allowed_tools"`
	Timeout        Duration `toml:"timeout"`
	MemoryMB       int      `toml:"memory_mb"`
	MaxCalls       int      `toml:"max_calls"`
	MaxOutputBytes int      `toml:"max_output_bytes"`
	MaxCodeBytes   int      `toml:"max_code_bytes"`
	MaxConcurrent  int      `toml:"max_concurrent"`
}

// on reports whether this namespace opted into code mode
func (m CodeMode) On() bool { return m.Enabled != nil && *m.Enabled }

// reject negative bounds even when disabled; nonzero memory must be 2–256 MiB
func (m CodeMode) validate() error {
	var errs []error
	if m.Timeout.Duration < 0 || m.MemoryMB < 0 || m.MaxCalls < 0 ||
		m.MaxOutputBytes < 0 || m.MaxCodeBytes < 0 || m.MaxConcurrent < 0 {
		errs = append(errs, errors.New("values must not be negative"))
	}
	if m.MemoryMB == 1 {
		errs = append(errs, errors.New("memory_mb must be at least 2"))
	}
	if m.MemoryMB > 256 {
		errs = append(errs, errors.New("memory_mb must not exceed 256"))
	}
	return errors.Join(errs...)
}

var discoveryModes = map[string]bool{"": true, "full": true, "connector": true, "search": true, "hybrid": true}

// Server_ is an upstream MCP server: either a stdio command or a remote
// streamable HTTP url. The trailing underscore avoids clashing with the
// [server] listen block.
type Server_ struct {
	Command string            `toml:"command"`
	Args    []string          `toml:"args"`
	Env     map[string]string `toml:"env"`
	URL     string            `toml:"url"`
	Headers map[string]string `toml:"headers"`
	// OAuth makes the gateway obtain bearer tokens for this url server
	// through an interactive login; optional pre-registered client.
	OAuth                bool   `toml:"oauth"`
	OAuthClientID        string `toml:"oauth_client_id"`
	OAuthClientSecretEnv string `toml:"oauth_client_secret_env"`
	OAuthClientSecret    string `toml:"-"`

	MaxConcurrent int      `toml:"max_concurrent"` // overrides limits.max_concurrent_per_server
	CallTimeout   Duration `toml:"call_timeout"`   // overrides limits.call_timeout
	// StderrLevel is where the child's stderr goes: debug (default), info,
	// warn, error, or discard.
	StderrLevel string `toml:"stderr_level"`
	// Ping can be set to false for servers that do not implement ping.
	Ping *bool `toml:"ping"`
}

func (s Server_) PingEnabled() bool { return s.Ping == nil || *s.Ping }

var stderrLevels = map[string]bool{"": true, "debug": true, "info": true, "warn": true, "error": true, "discard": true}

func (s Server_) Remote() bool { return s.URL != "" }

var (
	envRef   = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	nameRule = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
)

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw, os.LookupEnv)
}

// Parse decodes TOML, expands ${VAR} references via lookup, and validates.
func Parse(raw []byte, lookup func(string) (string, bool)) (*Config, error) {
	var c Config
	dec := toml.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			return nil, fmt.Errorf("parse config: unknown fields:\n%s", strict.String())
		}
		var de *toml.DecodeError
		if errors.As(err, &de) {
			row, col := de.Position()
			return nil, fmt.Errorf("parse config: line %d column %d: %s\n%s", row, col, de.Error(), de.String())
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.expand(lookup); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = ":8080"
	}
	// state lives next to the audit db unless told otherwise
	if c.Server.DataDir == "" {
		if c.Audit.Path != "" {
			c.Server.DataDir = filepath.Dir(c.Audit.Path)
		} else {
			c.Server.DataDir = "."
		}
	}
	if len(c.Auth.Scopes) == 0 {
		if c.Auth.RequiredScope != "" {
			c.Auth.Scopes = append(c.Auth.Scopes, c.Auth.RequiredScope)
		}
		if c.Auth.Issuer != "" {
			c.Auth.Scopes = append(c.Auth.Scopes, "offline_access")
		}
	}
	if c.Audit.RetentionDays == 0 {
		c.Audit.RetentionDays = 90
	}
	if c.Audit.MaxPayloadKB == 0 {
		c.Audit.MaxPayloadKB = 8
	}
	if c.Limits.CallTimeout.Duration == 0 {
		c.Limits.CallTimeout.Duration = 60 * time.Second
	}
	if c.Breaker.Failures > 0 && c.Breaker.Cooldown.Duration == 0 {
		c.Breaker.Cooldown.Duration = 30 * time.Second
	}
}

func (c *Config) expand(lookup func(string) (string, bool)) error {
	var missing []string
	expandOne := func(s string) string {
		return envRef.ReplaceAllStringFunc(s, func(m string) string {
			name := envRef.FindStringSubmatch(m)[1]
			v, ok := lookup(name)
			if !ok {
				missing = append(missing, name)
			}
			return v
		})
	}
	for name, srv := range c.Servers {
		for k, v := range srv.Env {
			srv.Env[k] = expandOne(v)
		}
		for k, v := range srv.Headers {
			srv.Headers[k] = expandOne(v)
		}
		if srv.OAuthClientSecretEnv != "" {
			if v, ok := lookup(srv.OAuthClientSecretEnv); ok {
				srv.OAuthClientSecret = v
			} else {
				missing = append(missing, srv.OAuthClientSecretEnv)
			}
		}
		c.Servers[name] = srv
	}
	if c.Auth.StaticTokenEnv != "" {
		if v, ok := lookup(c.Auth.StaticTokenEnv); ok && v != "" {
			c.Auth.StaticToken = v
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("config references unset environment variables: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (c *Config) validate() error {
	var errs []error
	if c.Server.PublicURL == "" {
		errs = append(errs, errors.New("server.public_url is required"))
	}
	if c.Auth.Issuer == "" && c.Auth.StaticTokenEnv == "" && c.Auth.Cloudflare.TeamDomain == "" {
		errs = append(errs, errors.New("auth: set auth.issuer, auth.static_token_env, or auth.cloudflare"))
	}
	if c.Auth.StaticTokenEnv != "" && c.Auth.StaticToken == "" {
		errs = append(errs, fmt.Errorf("auth.static_token_env: %s is unset or empty", c.Auth.StaticTokenEnv))
	}
	if err := c.Auth.Cloudflare.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("auth.cloudflare: %w", err))
	}
	if c.Auth.Cloudflare.TeamDomain != "" && (c.Auth.Issuer != "" || c.Auth.Audience != "" ||
		c.Auth.RequiredScope != "" || len(c.Auth.Scopes) != 0 || c.Auth.StaticTokenEnv != "") {
		errs = append(errs, errors.New("auth.cloudflare is mutually exclusive with issuer, audience, required_scope, scopes, and static_token_env"))
	}
	if err := c.UI.Cloudflare.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("ui.cloudflare: %w", err))
	}
	if c.Limits.MaxConcurrent < 0 || c.Limits.PerNamespace < 0 || c.Limits.PerServer < 0 || c.Limits.CallTimeout.Duration < 0 {
		errs = append(errs, errors.New("limits: values must not be negative"))
	}
	if c.Breaker.Failures < 0 || c.Breaker.Cooldown.Duration < 0 {
		errs = append(errs, errors.New("breaker: values must not be negative"))
	}
	if len(c.Namespaces) == 0 {
		errs = append(errs, errors.New("at least one [[namespace]] is required"))
	}
	seen := map[string]bool{}
	for _, ns := range c.Namespaces {
		if !nameRule.MatchString(ns.Name) {
			errs = append(errs, fmt.Errorf("namespace %q: name must match %s", ns.Name, nameRule))
		}
		if seen[ns.Name] {
			errs = append(errs, fmt.Errorf("namespace %q: duplicate", ns.Name))
		}
		seen[ns.Name] = true
		if ns.MaxConcurrent < 0 {
			errs = append(errs, fmt.Errorf("namespace %q: negative max_concurrent", ns.Name))
		}
		if !discoveryModes[ns.Discovery] {
			errs = append(errs, fmt.Errorf("namespace %q: discovery must be full, connector, search or hybrid", ns.Name))
		}
		if len(ns.PinnedTools) > 0 && ns.Discovery != "hybrid" {
			errs = append(errs, fmt.Errorf("namespace %q: pinned_tools requires hybrid discovery", ns.Name))
		}
		pins := make(map[string]bool, len(ns.PinnedTools))
		for _, name := range ns.PinnedTools {
			server, tool, ok := strings.Cut(name, "__")
			if !ok || tool == "" {
				errs = append(errs, fmt.Errorf("namespace %q: pinned tool %q must be server__tool", ns.Name, name))
			} else {
				found := false
				for _, s := range ns.Servers {
					if s == server {
						found = true
						break
					}
				}
				if !found {
					errs = append(errs, fmt.Errorf("namespace %q: pinned tool %q references a server outside the namespace", ns.Name, name))
				}
			}
			if pins[name] {
				errs = append(errs, fmt.Errorf("namespace %q: duplicate pinned tool %q", ns.Name, name))
			}
			pins[name] = true
		}
		if ns.CodeMode != nil {
			if err := ns.CodeMode.validate(); err != nil {
				errs = append(errs, fmt.Errorf("namespace %q: code_mode: %w", ns.Name, err))
			}
			if ns.CodeMode.On() && len(ns.CodeMode.AllowedTools) == 0 {
				errs = append(errs, fmt.Errorf("namespace %q: code_mode enabled requires at least one allowed_tool", ns.Name))
			}
			tools := make(map[string]bool, len(ns.CodeMode.AllowedTools))
			for _, name := range ns.CodeMode.AllowedTools {
				server, tool, ok := strings.Cut(name, "__")
				switch {
				case !ok || tool == "":
					errs = append(errs, fmt.Errorf("namespace %q: code_mode allowed tool %q must be server__tool", ns.Name, name))
				case strings.ContainsAny(name, "*?["):
					errs = append(errs, fmt.Errorf("namespace %q: code_mode allowed tool %q must be an exact name; wildcards are not supported", ns.Name, name))
				default:
					found := false
					for _, s := range ns.Servers {
						if s == server {
							found = true
							break
						}
					}
					if !found {
						errs = append(errs, fmt.Errorf("namespace %q: code_mode allowed tool %q references a server outside the namespace", ns.Name, name))
					}
				}
				if tools[name] {
					errs = append(errs, fmt.Errorf("namespace %q: duplicate code_mode allowed tool %q", ns.Name, name))
				}
				tools[name] = true
			}
		}
		if len(ns.Servers) == 0 {
			errs = append(errs, fmt.Errorf("namespace %q: no servers", ns.Name))
		}
		for _, s := range ns.Servers {
			if _, ok := c.Servers[s]; !ok {
				errs = append(errs, fmt.Errorf("namespace %q: unknown server %q", ns.Name, s))
			}
		}
	}
	for name, srv := range c.Servers {
		if !nameRule.MatchString(name) {
			errs = append(errs, fmt.Errorf("server %q: name must match %s", name, nameRule))
		}
		if srv.MaxConcurrent < 0 || srv.CallTimeout.Duration < 0 {
			errs = append(errs, fmt.Errorf("server %q: negative limit", name))
		}
		if !stderrLevels[srv.StderrLevel] {
			errs = append(errs, fmt.Errorf("server %q: stderr_level must be debug, info, warn, error or discard", name))
		}
		if srv.Remote() {
			if srv.Command != "" || len(srv.Args) > 0 || len(srv.Env) > 0 {
				errs = append(errs, fmt.Errorf("server %q: url and command/args/env are mutually exclusive", name))
			}
			u, err := url.Parse(srv.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				errs = append(errs, fmt.Errorf("server %q: url must be an absolute http(s) url, got %q", name, srv.URL))
			}
			if !srv.OAuth && (srv.OAuthClientID != "" || srv.OAuthClientSecretEnv != "") {
				errs = append(errs, fmt.Errorf("server %q: oauth_client_id/oauth_client_secret_env need oauth = true", name))
			}
			if srv.OAuth && srv.OAuthClientSecretEnv != "" && srv.OAuthClientID == "" {
				errs = append(errs, fmt.Errorf("server %q: oauth_client_secret_env needs oauth_client_id", name))
			}
			continue
		}
		if srv.OAuth {
			errs = append(errs, fmt.Errorf("server %q: oauth only applies to url servers", name))
		}
		if len(srv.Headers) > 0 {
			errs = append(errs, fmt.Errorf("server %q: headers only apply to url servers", name))
		}
		if srv.Command == "" {
			errs = append(errs, fmt.Errorf("server %q: command or url is required", name))
			continue
		}
		// bare names are resolved through PATH once here and pinned, so a
		// later PATH change cannot silently swap the binary
		if !filepath.IsAbs(srv.Command) {
			resolved, err := exec.LookPath(srv.Command)
			if err != nil {
				errs = append(errs, fmt.Errorf("server %q: command %q not found in PATH", name, srv.Command))
				continue
			}
			srv.Command = resolved
			c.Servers[name] = srv
		}
		if err := checkExecutable(srv.Command); err != nil {
			errs = append(errs, fmt.Errorf("server %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func checkExecutable(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	if _, err := exec.LookPath(path); err != nil {
		return fmt.Errorf("%s is not executable", path)
	}
	return nil
}
