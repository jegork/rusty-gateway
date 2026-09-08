package main

import (
	"encoding/json"
	"net/http"

	"github.com/jegork/rusty-gateway/internal/audit"
	"github.com/jegork/rusty-gateway/internal/auth"
	"github.com/jegork/rusty-gateway/internal/config"
	"github.com/jegork/rusty-gateway/internal/gateway"
	"github.com/jegork/rusty-gateway/internal/supervisor"
	"github.com/jegork/rusty-gateway/internal/ui"
	"github.com/jegork/rusty-gateway/internal/upstreamauth"
)

// newMux wires every HTTP route; kept separate from run so the wiring itself
// is covered by tests.
func newMux(cfg *config.Config, authn *auth.Authenticator, gw *gateway.Gateway, sup *supervisor.Supervisor, store *audit.Store, ua *upstreamauth.Manager, dash *ui.UI) *http.ServeMux {
	mux := http.NewServeMux()
	if dash != nil {
		mux.Handle("/ui/", dash.Handler())
	}
	if ua != nil {
		mux.Handle("GET "+upstreamauth.CallbackPath, ua.CallbackHandler())
		mux.Handle("GET "+upstreamauth.ClientMetadataPath, ua.ClientMetadataHandler())
		mux.Handle("GET /oauth/upstream/{ns}/{server}/login", authn.Middleware("")(ua.LoginHandler()))
	}
	for _, ns := range cfg.Namespaces {
		r := "/mcp/" + ns.Name
		mux.Handle(r, authn.Middleware(r)(gw.Handler(ns.Name)))
	}
	mux.Handle(auth.MetadataPath, authn.MetadataHandler())
	mux.Handle(auth.MetadataPath+"/", authn.MetadataHandler())
	if store != nil {
		mux.Handle("GET /audit", authn.Middleware("")(audit.Handler(store)))
	}
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
	return mux
}
