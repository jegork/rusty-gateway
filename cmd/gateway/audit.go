package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jegork/rusty-gateway/internal/audit"
	"github.com/jegork/rusty-gateway/internal/config"
)

// runAudit implements `gateway audit tail`: print recent rows as JSON lines
// and optionally keep following the log.
func runAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	cfgPath := fs.String("config", "gateway.toml", "path to TOML config")
	n := fs.Int("n", 50, "number of rows")
	follow := fs.Bool("f", false, "follow new rows")
	ns := fs.String("namespace", "", "filter by namespace")
	tool := fs.String("tool", "", "filter by tool")
	status := fs.String("status", "", "filter by status")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gateway audit tail [-config gateway.toml] [-n 50] [-f] [-namespace x] [-tool y] [-status ok|error|tool_error|timeout]")
		fs.PrintDefaults()
	}
	if len(args) == 0 || args[0] != "tail" {
		fs.Usage()
		return fmt.Errorf("unknown audit subcommand")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Audit.Path == "" {
		return fmt.Errorf("audit.path is not set in %s", *cfgPath)
	}
	store, err := audit.Open(cfg.Audit.Path)
	if err != nil {
		return err
	}
	defer store.Close()

	ctx := context.Background()
	enc := json.NewEncoder(os.Stdout)
	base := audit.Filter{Namespace: *ns, Tool: *tool, Status: *status}
	f := base
	f.Limit = *n
	rows, err := store.Query(ctx, f)
	if err != nil {
		return err
	}
	var last int64
	for i := len(rows) - 1; i >= 0; i-- {
		enc.Encode(rows[i])
		last = max(last, rows[i].ID)
	}
	if !*follow {
		return nil
	}
	for {
		time.Sleep(time.Second)
		f := base
		f.AfterID = max(last, 1)
		f.Limit = 1000
		rows, err := store.Query(ctx, f)
		if err != nil {
			return err
		}
		for _, r := range rows {
			enc.Encode(r)
			last = r.ID
		}
	}
}
