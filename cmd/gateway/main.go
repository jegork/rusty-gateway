package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jegork/rusty-gateway/internal/audit"
	"github.com/jegork/rusty-gateway/internal/auth"
	"github.com/jegork/rusty-gateway/internal/config"
	"github.com/jegork/rusty-gateway/internal/gateway"
	"github.com/jegork/rusty-gateway/internal/supervisor"
)

// set by goreleaser / ldflags
var version = "dev"

func main() {
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

	authn, err := auth.New(ctx, auth.Config{
		PublicURL: cfg.Server.PublicURL, Issuer: cfg.Auth.Issuer, Audience: cfg.Auth.Audience,
		RequiredScope: cfg.Auth.RequiredScope, StaticToken: cfg.Auth.StaticToken, Logger: log,
	})
	if err != nil {
		return err
	}

	var specs []supervisor.Spec
	var namespaces []gateway.Namespace
	limits := gateway.Limits{
		CallTimeout: cfg.Limits.CallTimeout.Duration, MaxConcurrent: cfg.Limits.MaxConcurrent,
		PerNamespace: cfg.Limits.PerNamespace, PerServer: cfg.Limits.PerServer,
		NamespaceConcurrency: map[string]int{}, ServerConcurrency: map[string]int{}, ServerTimeout: map[string]time.Duration{},
	}
	for _, ns := range cfg.Namespaces {
		namespaces = append(namespaces, gateway.Namespace{Name: ns.Name, Servers: ns.Servers})
		limits.NamespaceConcurrency[ns.Name] = ns.MaxConcurrent
		for _, name := range ns.Servers {
			srv := cfg.Servers[name]
			id := gateway.UpstreamID(ns.Name, name)
			specs = append(specs, supervisor.Spec{
				ID: id, Command: srv.Command, Args: srv.Args, Env: srv.Env, URL: srv.URL, Headers: srv.Headers,
			})
			limits.ServerConcurrency[id] = srv.MaxConcurrent
			limits.ServerTimeout[id] = srv.CallTimeout.Duration
		}
	}

	var gw *gateway.Gateway
	sup := supervisor.New(specs, supervisor.Options{
		Logger:   log,
		OnChange: func(id string) { gw.Refresh(id) },
	})
	gw = gateway.New(sup, namespaces, gateway.Options{
		Version: version, Logger: log, Limits: limits,
		Breaker: gateway.BreakerConfig{Failures: cfg.Breaker.Failures, Cooldown: cfg.Breaker.Cooldown.Duration},
	})

	mux := http.NewServeMux()
	if cfg.Audit.Path == "" {
		log.Warn("audit.path not set, tool calls are not being recorded")
	} else {
		store, err := audit.Open(cfg.Audit.Path)
		if err != nil {
			return fmt.Errorf("open audit db: %w", err)
		}
		defer store.Close()
		sink := audit.NewSink(store, audit.SinkOptions{MaxPayloadBytes: cfg.Audit.MaxPayloadKB * 1024, Logger: log})
		defer sink.Close()
		gw.Observe = sink.Observe
		go audit.Retention(ctx, store, time.Duration(cfg.Audit.RetentionDays)*24*time.Hour, log)
		mux.Handle("GET /audit", authn.Middleware()(audit.Handler(store)))
	}

	sup.Start(ctx)
	gw.RefreshAll()
	defer sup.Stop()

	mux.Handle("/mcp/{ns}", authn.Middleware()(gw.Handler()))
	mux.Handle(auth.MetadataPath, authn.MetadataHandler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		statuses := sup.Statuses()
		code := http.StatusOK
		for _, s := range statuses {
			if s.State == "failed" {
				code = http.StatusServiceUnavailable
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]any{
			"version": version, "namespaces": gw.Namespaces(), "upstreams": statuses, "breakers": gw.Breakers(),
		})
	})

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
