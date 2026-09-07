package audit

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jegork/rusty-gateway/internal/auth"
	"github.com/jegork/rusty-gateway/internal/gateway"
	"github.com/jegork/rusty-gateway/internal/redact"
)

// Sink buffers rows through a bounded channel to a single writer goroutine so
// audit I/O never blocks a tool call. When the buffer is full, rows are
// dropped and counted rather than applying backpressure.
type Sink struct {
	store      *Store
	log        *slog.Logger
	maxPayload int
	ch         chan Row
	dropped    atomic.Int64
	wg         sync.WaitGroup
	closeOnce  sync.Once
}

type SinkOptions struct {
	MaxPayloadBytes int
	BufferSize      int
	Logger          *slog.Logger
}

func NewSink(store *Store, opts SinkOptions) *Sink {
	if opts.BufferSize <= 0 {
		opts.BufferSize = 1024
	}
	if opts.MaxPayloadBytes <= 0 {
		opts.MaxPayloadBytes = 8 * 1024
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Sink{store: store, log: opts.Logger, maxPayload: opts.MaxPayloadBytes, ch: make(chan Row, opts.BufferSize)}
	s.wg.Add(1)
	go s.writer()
	return s
}

func (s *Sink) writer() {
	defer s.wg.Done()
	for r := range s.ch {
		if err := s.store.Insert(context.Background(), r); err != nil {
			s.log.Error("audit insert failed", "err", err, "tool", r.Server+"__"+r.Tool)
		}
	}
}

// Observe satisfies gateway.Gateway.Observe.
func (s *Sink) Observe(ctx context.Context, c gateway.Call) {
	select {
	case s.ch <- s.row(ctx, c):
	default:
		n := s.dropped.Add(1)
		if n == 1 || n%100 == 0 {
			s.log.Warn("audit buffer full, dropping rows", "dropped_total", n)
		}
	}
}

func (s *Sink) Dropped() int64 { return s.dropped.Load() }

// Close flushes buffered rows. Observe must not be called after Close.
func (s *Sink) Close() {
	s.closeOnce.Do(func() {
		close(s.ch)
		s.wg.Wait()
	})
}

func (s *Sink) row(ctx context.Context, c gateway.Call) Row {
	r := Row{
		TS: c.Started.UnixMilli(), Namespace: c.Namespace, Server: c.Server, Tool: c.Tool,
		ClientID: auth.ClientID(ctx), SessionID: c.SessionID, DurationMS: c.Duration.Milliseconds(),
		Status: "ok",
	}
	args, _ := redact.JSON(c.Args, s.maxPayload)
	r.ArgsJSON = string(args)
	switch {
	case errors.Is(c.Err, context.DeadlineExceeded):
		r.Status, r.Error = "timeout", c.Err.Error()
	case errors.Is(c.Err, gateway.ErrCircuitOpen):
		r.Status, r.Error = "rejected", c.Err.Error()
	case c.Err != nil:
		r.Status, r.Error = "error", c.Err.Error()
	case c.Result != nil && c.Result.IsError:
		r.Status = "tool_error"
	}
	if c.Result != nil {
		raw, err := json.Marshal(c.Result)
		if err == nil {
			res, size := redact.JSON(raw, s.maxPayload)
			r.ResultJSON, r.ResultSize = string(res), int64(size)
		}
	}
	return r
}

// Retention deletes rows older than keep once a day until ctx is done.
func Retention(ctx context.Context, store *Store, keep time.Duration, log *slog.Logger) {
	run := func() {
		n, err := store.Prune(ctx, time.Now().Add(-keep))
		if err != nil && ctx.Err() == nil {
			log.Error("audit retention failed", "err", err)
		} else if n > 0 {
			log.Info("audit retention pruned rows", "rows", n)
		}
	}
	run()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
