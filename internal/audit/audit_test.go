package audit

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jegork/rusty-gateway/internal/gateway"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir() + "/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func call(tool string, args string, err error, isErr bool) gateway.Call {
	c := gateway.Call{
		Namespace: "personal", Server: "tv", Tool: tool, SessionID: "sess1",
		Args: json.RawMessage(args), Err: err, Duration: 42 * time.Millisecond, Started: time.Now(),
	}
	if err == nil {
		c.Result = &mcp.CallToolResult{IsError: isErr, Content: []mcp.Content{&mcp.TextContent{Text: `{"api_key":"sk_live_abcdefghijk","price":1}`}}}
	}
	return c
}

func TestSinkRedactsAndRecordsStatuses(t *testing.T) {
	store := openTemp(t)
	sink := NewSink(store, SinkOptions{MaxPayloadBytes: 8192, Logger: slog.New(slog.NewTextHandler(os.Stderr, nil))})
	ctx := context.Background()
	sink.Observe(ctx, call("quote", `{"symbol":"AAPL","api_token":"abc"}`, nil, false))
	sink.Observe(ctx, call("quote", `{}`, nil, true))
	sink.Observe(ctx, call("quote", `{}`, errors.New("upstream not ready"), false))
	sink.Observe(ctx, call("quote", `{}`, context.DeadlineExceeded, false))
	sink.Close()

	rows, err := store.Query(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("rows: %d", len(rows))
	}
	// newest first
	if rows[0].Status != "timeout" || rows[1].Status != "error" || rows[2].Status != "tool_error" || rows[3].Status != "ok" {
		t.Errorf("statuses: %s %s %s %s", rows[0].Status, rows[1].Status, rows[2].Status, rows[3].Status)
	}
	ok := rows[3]
	if ok.ArgsJSON != `{"api_token":"«redacted»","symbol":"AAPL"}` {
		t.Errorf("args not redacted: %s", ok.ArgsJSON)
	}
	if strings.Contains(ok.ResultJSON, "sk_live") {
		t.Errorf("result leaked secret: %s", ok.ResultJSON)
	}
	if ok.ResultSize == 0 || ok.DurationMS != 42 || ok.SessionID != "sess1" || ok.Namespace != "personal" {
		t.Errorf("%+v", ok)
	}
	if rows[1].Error != "upstream not ready" || rows[1].ResultJSON != "" {
		t.Errorf("%+v", rows[1])
	}
}

func TestSinkTruncatesButKeepsTrueSize(t *testing.T) {
	store := openTemp(t)
	sink := NewSink(store, SinkOptions{MaxPayloadBytes: 64})
	c := call("big", `{"q":"`+strings.Repeat("x y ", 200)+`"}`, nil, false)
	c.Result = &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("r s ", 500)}}}
	sink.Observe(context.Background(), c)
	sink.Close()
	rows, _ := store.Query(context.Background(), Filter{})
	if len(rows[0].ArgsJSON) > 70 || len(rows[0].ResultJSON) > 70 {
		t.Errorf("not truncated: %d %d", len(rows[0].ArgsJSON), len(rows[0].ResultJSON))
	}
	if rows[0].ResultSize < 2000 {
		t.Errorf("true size lost: %d", rows[0].ResultSize)
	}
}

func TestSinkDropsWhenFullInsteadOfBlocking(t *testing.T) {
	store := openTemp(t)
	sink := NewSink(store, SinkOptions{BufferSize: 2, Logger: slog.New(slog.DiscardHandler)})
	// no writer contention trick: pause by filling faster than sqlite can drain
	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			sink.Observe(context.Background(), call("t", `{}`, nil, false))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Observe blocked")
	}
	sink.Close()
	rows, _ := store.Query(context.Background(), Filter{Limit: 1000})
	if int64(len(rows))+sink.Dropped() != 500 {
		t.Errorf("rows %d + dropped %d != 500", len(rows), sink.Dropped())
	}
	if sink.Dropped() == 0 {
		t.Log("nothing dropped; sqlite kept up, which is fine but the drop path was not exercised")
	}
}

func TestQueryFiltersAndFollow(t *testing.T) {
	store := openTemp(t)
	ctx := context.Background()
	now := time.Now()
	ins := func(ts time.Time, ns, srv, tool, status string) {
		if err := store.Insert(ctx, Row{TS: ts.UnixMilli(), Namespace: ns, Server: srv, Tool: tool, Status: status, DurationMS: 1}); err != nil {
			t.Fatal(err)
		}
	}
	ins(now.Add(-2*time.Hour), "personal", "tv", "quote", "ok")
	ins(now.Add(-time.Hour), "personal", "hevy", "workouts", "error")
	ins(now, "ops", "dokploy", "deploy", "ok")

	got := func(f Filter) []string {
		rows, err := store.Query(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, r := range rows {
			names = append(names, r.Tool)
		}
		return names
	}
	if s := strings.Join(got(Filter{Namespace: "personal"}), ","); s != "workouts,quote" {
		t.Errorf("namespace: %s", s)
	}
	if s := strings.Join(got(Filter{Status: "error"}), ","); s != "workouts" {
		t.Errorf("status: %s", s)
	}
	if s := strings.Join(got(Filter{Since: now.Add(-90 * time.Minute)}), ","); s != "deploy,workouts" {
		t.Errorf("since: %s", s)
	}
	if s := strings.Join(got(Filter{Limit: 1}), ","); s != "deploy" {
		t.Errorf("limit: %s", s)
	}
	if s := strings.Join(got(Filter{AfterID: 1}), ","); s != "workouts,deploy" {
		t.Errorf("after id should be oldest first: %s", s)
	}
	if s := strings.Join(got(Filter{Namespace: "nope"}), ","); s != "" {
		t.Errorf("no match: %s", s)
	}
}

func TestPrune(t *testing.T) {
	store := openTemp(t)
	ctx := context.Background()
	now := time.Now()
	for _, age := range []time.Duration{100 * 24 * time.Hour, 91 * 24 * time.Hour, 89 * 24 * time.Hour, 0} {
		store.Insert(ctx, Row{TS: now.Add(-age).UnixMilli(), Namespace: "n", Server: "s", Tool: "t", Status: "ok"})
	}
	n, err := store.Prune(ctx, now.Add(-90*24*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	rows, _ := store.Query(ctx, Filter{})
	if len(rows) != 2 {
		t.Errorf("remaining %d", len(rows))
	}
	if n, _ := store.Prune(ctx, now.Add(-90*24*time.Hour)); n != 0 {
		t.Errorf("second prune deleted %d", n)
	}
}
