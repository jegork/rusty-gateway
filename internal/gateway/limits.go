package gateway

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Limits bounds in-flight tool calls. Zero values mean unlimited (or no
// deadline for CallTimeout). Overrides are keyed by namespace name and
// upstream ID respectively.
type Limits struct {
	CallTimeout   time.Duration
	MaxConcurrent int
	PerNamespace  int
	PerServer     int

	NamespaceConcurrency map[string]int
	ServerConcurrency    map[string]int
	ServerTimeout        map[string]time.Duration
}

func (l Limits) namespaceLimit(ns string) int {
	if v, ok := l.NamespaceConcurrency[ns]; ok && v > 0 {
		return v
	}
	return l.PerNamespace
}

func (l Limits) serverLimit(id string) int {
	if v, ok := l.ServerConcurrency[id]; ok && v > 0 {
		return v
	}
	return l.PerServer
}

func (l Limits) timeout(id string) time.Duration {
	if v, ok := l.ServerTimeout[id]; ok && v > 0 {
		return v
	}
	return l.CallTimeout
}

// semaphore is a nil-safe counting semaphore; nil means unlimited.
type semaphore chan struct{}

func newSemaphore(n int) semaphore {
	if n <= 0 {
		return nil
	}
	return make(semaphore, n)
}

func (s semaphore) acquire(ctx context.Context) error {
	if s == nil {
		return nil
	}
	select {
	case s <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s semaphore) release() {
	if s != nil {
		<-s
	}
}

var ErrCircuitOpen = errors.New("circuit open")

// BreakerConfig opens an upstream after Failures consecutive transport
// errors or timeouts and allows one trial call after Cooldown. Failures
// zero disables breaking.
type BreakerConfig struct {
	Failures int
	Cooldown time.Duration
}

type breaker struct {
	cfg BreakerConfig
	now func() time.Time

	mu       sync.Mutex
	failures int
	openedAt time.Time
	trial    bool
}

func newBreaker(cfg BreakerConfig) *breaker {
	return &breaker{cfg: cfg, now: time.Now}
}

// allow reports whether a call may proceed. In the open state exactly one
// trial call is let through once the cooldown has passed.
func (b *breaker) allow() bool {
	if b.cfg.Failures <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openedAt.IsZero() {
		return true
	}
	if b.now().Sub(b.openedAt) < b.cfg.Cooldown || b.trial {
		return false
	}
	b.trial = true
	return true
}

func (b *breaker) success() {
	if b.cfg.Failures <= 0 {
		return
	}
	b.mu.Lock()
	b.failures, b.openedAt, b.trial = 0, time.Time{}, false
	b.mu.Unlock()
}

func (b *breaker) failure() {
	if b.cfg.Failures <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	b.trial = false
	if b.failures >= b.cfg.Failures {
		b.openedAt = b.now()
	}
}

func (b *breaker) state() string {
	if b.cfg.Failures <= 0 {
		return "disabled"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.openedAt.IsZero():
		return "closed"
	case b.trial:
		return "half-open"
	default:
		return "open"
	}
}
