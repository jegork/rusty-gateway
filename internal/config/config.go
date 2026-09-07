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
	Limits     Limits             `toml:"limits"`
	Breaker    Breaker            `toml:"breaker"`
	Namespaces []Namespace        `toml:"namespace"`
	Servers    map[string]Server_ `toml:"servers"`
}

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
}

type Auth struct {
	Issuer         string `toml:"issuer"`
	Audience       string `toml:"audience"`
	RequiredScope  string `toml:"required_scope"`
	StaticTokenEnv string `toml:"static_token_env"`

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
}

// Server_ is an upstream MCP server: either a stdio command or a remote
// streamable HTTP url. The trailing underscore avoids clashing with the
// [server] listen block.
type Server_ struct {
	Command string            `toml:"command"`
	Args    []string          `toml:"args"`
	Env     map[string]string `toml:"env"`
	URL     string            `toml:"url"`
	Headers map[string]string `toml:"headers"`

	MaxConcurrent int      `toml:"max_concurrent"` // overrides limits.max_concurrent_per_server
	CallTimeout   Duration `toml:"call_timeout"`   // overrides limits.call_timeout
}

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
	if c.Auth.Issuer == "" && c.Auth.StaticTokenEnv == "" {
		errs = append(errs, errors.New("auth: set auth.issuer, auth.static_token_env, or both"))
	}
	if c.Auth.Issuer != "" && c.Auth.Audience == "" {
		errs = append(errs, errors.New("auth.audience is required when auth.issuer is set"))
	}
	if c.Auth.StaticTokenEnv != "" && c.Auth.StaticToken == "" {
		errs = append(errs, fmt.Errorf("auth.static_token_env: %s is unset or empty", c.Auth.StaticTokenEnv))
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
		if srv.Remote() {
			if srv.Command != "" || len(srv.Args) > 0 || len(srv.Env) > 0 {
				errs = append(errs, fmt.Errorf("server %q: url and command/args/env are mutually exclusive", name))
			}
			u, err := url.Parse(srv.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				errs = append(errs, fmt.Errorf("server %q: url must be an absolute http(s) url, got %q", name, srv.URL))
			}
			continue
		}
		if len(srv.Headers) > 0 {
			errs = append(errs, fmt.Errorf("server %q: headers only apply to url servers", name))
		}
		if srv.Command == "" {
			errs = append(errs, fmt.Errorf("server %q: command or url is required", name))
			continue
		}
		if !filepath.IsAbs(srv.Command) {
			errs = append(errs, fmt.Errorf("server %q: command must be an absolute path, got %q", name, srv.Command))
			continue
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
