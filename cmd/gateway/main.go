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

	"github.com/jegork/rusty-gateway/internal/auth"
	"github.com/jegork/rusty-gateway/internal/config"
	"github.com/jegork/rusty-gateway/internal/gateway"
	"github.com/jegork/rusty-gateway/internal/supervisor"
)

// set by goreleaser / ldflags
var version = "dev"

func main() {
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
	for _, ns := range cfg.Namespaces {
		namespaces = append(namespaces, gateway.Namespace{Name: ns.Name, Servers: ns.Servers})
		for _, name := range ns.Servers {
			srv := cfg.Servers[name]
			specs = append(specs, supervisor.Spec{
				ID: gateway.UpstreamID(ns.Name, name), Command: srv.Command, Args: srv.Args, Env: srv.Env,
			})
		}
	}

	var gw *gateway.Gateway
	sup := supervisor.New(specs, supervisor.Options{
		Logger:   log,
		OnChange: func(id string) { gw.Refresh(id) },
	})
	gw = gateway.New(sup, namespaces, version, log)
	gw.Observe = func(_ context.Context, c gateway.Call) {
		status := "ok"
		if c.Err != nil {
			status = "error"
		} else if c.Result != nil && c.Result.IsError {
			status = "tool_error"
		}
		log.Info("tool call", "namespace", c.Namespace, "server", c.Server, "tool", c.Tool,
			"status", status, "duration_ms", c.Duration.Milliseconds())
	}

	sup.Start(ctx)
	gw.RefreshAll()
	defer sup.Stop()

	mux := http.NewServeMux()
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
			"version": version, "namespaces": gw.Namespaces(), "upstreams": statuses,
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
