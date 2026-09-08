package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jegork/rusty-gateway/internal/audit"
	"github.com/jegork/rusty-gateway/internal/auth"
	"github.com/jegork/rusty-gateway/internal/config"
	"github.com/jegork/rusty-gateway/internal/gateway"
	"github.com/jegork/rusty-gateway/internal/supervisor"
	"github.com/jegork/rusty-gateway/internal/ui"
	"github.com/jegork/rusty-gateway/internal/upstreamauth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// set by goreleaser / ldflags
var version = "dev"

func main() {
	if len(os.Args) > 2 && os.Args[1] == "healthcheck" {
		if err := runHealthcheck(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "audit" {
		if err := runAudit(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	cfgPath := flag.String("config", "gateway.toml", "path to TOML config")
	debug := flag.Bool("debug", false, "debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	if err := run(*cfgPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath string, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var resources []string
	for _, ns := range cfg.Namespaces {
		resources = append(resources, "/mcp/"+ns.Name)
	}
	authn, err := auth.New(ctx, auth.Config{
		PublicURL: cfg.Server.PublicURL, Issuer: cfg.Auth.Issuer, Audience: cfg.Auth.Audience,
		RequiredScope: cfg.Auth.RequiredScope, StaticToken: cfg.Auth.StaticToken, Resources: resources, Logger: log,
	})
	if err != nil {
		return err
	}

	var specs []supervisor.Spec
	var namespaces []gateway.Namespace
	var oauthUpstreams []upstreamauth.Upstream
	limits := gateway.Limits{
		CallTimeout: cfg.Limits.CallTimeout.Duration, MaxConcurrent: cfg.Limits.MaxConcurrent,
		PerNamespace: cfg.Limits.PerNamespace, PerServer: cfg.Limits.PerServer,
		NamespaceConcurrency: map[string]int{}, ServerConcurrency: map[string]int{}, ServerTimeout: map[string]time.Duration{},
	}
	for _, ns := range cfg.Namespaces {
		namespaces = append(namespaces, gateway.Namespace{Name: ns.Name, Servers: ns.Servers, Discovery: gateway.Discovery(ns.Discovery)})
		limits.NamespaceConcurrency[ns.Name] = ns.MaxConcurrent
		for _, name := range ns.Servers {
			srv := cfg.Servers[name]
			id := gateway.UpstreamID(ns.Name, name)
			specs = append(specs, supervisor.Spec{
				ID: id, Command: srv.Command, Args: srv.Args, Env: srv.Env, URL: srv.URL, Headers: srv.Headers,
				OAuth: srv.OAuth, StderrLevel: stderrLevel(srv.StderrLevel),
			})
			if srv.OAuth {
				up := upstreamauth.Upstream{ID: id, URL: srv.URL}
				if srv.OAuthClientID != "" {
					up.Preregistered = &oauthex.ClientCredentials{ClientID: srv.OAuthClientID}
					if srv.OAuthClientSecret != "" {
						up.Preregistered.ClientSecretAuth = &oauthex.ClientSecretAuth{ClientSecret: srv.OAuthClientSecret}
					}
				}
				oauthUpstreams = append(oauthUpstreams, up)
			}
			limits.ServerConcurrency[id] = srv.MaxConcurrent
			limits.ServerTimeout[id] = srv.CallTimeout.Duration
		}
	}

	var ua *upstreamauth.Manager
	if len(oauthUpstreams) > 0 {
		if err := os.MkdirAll(cfg.Server.DataDir, 0o750); err != nil {
			return fmt.Errorf("create data_dir %s: %w", cfg.Server.DataDir, err)
		}
		statePath := filepath.Join(cfg.Server.DataDir, "state.db")
		st, err := upstreamauth.OpenStore(statePath)
		if err != nil {
			return fmt.Errorf("open state db %s (is server.data_dir writable?): %w", statePath, err)
		}
		defer st.Close()
		ua, err = upstreamauth.New(cfg.Server.PublicURL, st, oauthUpstreams, log)
		if err != nil {
			return err
		}
	}

	var gw *gateway.Gateway
	supOpts := supervisor.Options{
		Logger:   log,
		OnChange: func(id string) { gw.Refresh(id) },
	}
	if ua != nil {
		supOpts.OAuth = ua
	}
	sup := supervisor.New(specs, supOpts)
	gw = gateway.New(sup, namespaces, gateway.Options{
		Version: version, Logger: log, Limits: limits,
		Breaker: gateway.BreakerConfig{Failures: cfg.Breaker.Failures, Cooldown: cfg.Breaker.Cooldown.Duration},
	})

	var store *audit.Store
	if cfg.Audit.Path == "" {
		log.Warn("audit.path not set, tool calls are not being recorded")
	} else {
		store, err = audit.Open(cfg.Audit.Path)
		if err != nil {
			return fmt.Errorf("open audit db: %w", err)
		}
		defer store.Close()
		sink := audit.NewSink(store, audit.SinkOptions{MaxPayloadBytes: cfg.Audit.MaxPayloadKB * 1024, Logger: log})
		defer sink.Close()
		gw.Observe = sink.Observe
		go audit.Retention(ctx, store, time.Duration(cfg.Audit.RetentionDays)*24*time.Hour, log)
	}

	sup.Start(ctx)
	gw.RefreshAll()
	defer sup.Stop()
	if ua != nil {
		ua.AutoLogin(ctx)
	}

	var dash *ui.UI
	switch {
	case !cfg.UI.On():
	case cfg.Auth.StaticToken == "":
		log.Warn("ui disabled: set auth.static_token_env to enable sign-in")
	default:
		dash, err = ui.New(ui.Deps{
			Supervisor: sup, Gateway: gw, Audit: store, OAuth: ua, Sessions: gw.SessionCount,
			Token: cfg.Auth.StaticToken, Version: version, Logger: log,
		})
		if err != nil {
			return err
		}
		log.Info("ui enabled", "url", cfg.Server.PublicURL+"/ui/")
	}

	mux := newMux(cfg, authn, gw, sup, store, ua, dash)

	srv := &http.Server{Addr: cfg.Server.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Server.Listen, "public_url", cfg.Server.PublicURL, "version", version)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

func stderrLevel(name string) *slog.Level {
	var l slog.Level
	switch name {
	case "":
		return nil
	case "discard":
		l = supervisor.StderrDiscard
	default:
		// validated by config; slog understands debug/info/warn/error
		_ = l.UnmarshalText([]byte(name))
	}
	return &l
}
