package gateway

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jegork/rusty-gateway/internal/supervisor"
)

func TestBreakerStateMachine(t *testing.T) {
	now := time.Unix(0, 0)
	b := newBreaker(BreakerConfig{Failures: 2, Cooldown: 10 * time.Second})
	b.now = func() time.Time { return now }

	if !b.allow() || b.state() != "closed" {
		t.Fatal("fresh breaker should allow")
	}
	b.failure()
	if !b.allow() {
		t.Fatal("one failure below threshold should still allow")
	}
	b.success()
	b.failure()
	b.failure()
	if b.allow() || b.state() != "open" {
		t.Fatal("two consecutive failures should open")
	}
	now = now.Add(9 * time.Second)
	if b.allow() {
		t.Fatal("should stay open during cooldown")
	}
	now = now.Add(2 * time.Second)
	if !b.allow() || b.state() != "half-open" {
		t.Fatal("first call after cooldown should be allowed as trial")
	}
	if b.allow() {
		t.Fatal("only one trial call at a time")
	}
	b.failure()
	if b.allow() || b.state() != "open" {
		t.Fatal("failed trial should reopen")
	}
	now = now.Add(11 * time.Second)
	if !b.allow() {
		t.Fatal("trial after second cooldown")
	}
	b.success()
	if !b.allow() || !b.allow() || b.state() != "closed" {
		t.Fatal("successful trial should close")
	}

	off := newBreaker(BreakerConfig{})
	off.failure()
	off.failure()
	if !off.allow() || off.state() != "disabled" {
		t.Fatal("disabled breaker must always allow")
	}
}

func TestSemaphoreNilIsUnlimited(t *testing.T) {
	var s semaphore
	for i := 0; i < 100; i++ {
		if err := s.acquire(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	s.release()
	one := newSemaphore(1)
	one.acquire(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := one.acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("saturated semaphore should time out: %v", err)
	}
}

func slowCall(t *testing.T, s *mcp.ClientSession, ms int) error {
	t.Helper()
	_, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: "c__slow", Arguments: map[string]any{"ms": ms}})
	return err
}

func TestCallTimeoutIsRecordedAsTimeout(t *testing.T) {
	f := setup(t, []Namespace{{Name: "p", Servers: []string{"c"}}}, []supervisor.Spec{spec("p/c", nil)},
		func(f *fixture) { f.limits = Limits{CallTimeout: 100 * time.Millisecond} })
	s := f.connect(t, "p")
	started := time.Now()
	err := slowCall(t, s, 5000)
	if err == nil || time.Since(started) > 2*time.Second {
		t.Fatalf("expected fast timeout error, got %v after %s", err, time.Since(started))
	}
	c := <-f.calls
	if !errors.Is(c.Err, context.DeadlineExceeded) {
		t.Errorf("observed err = %v", c.Err)
	}
	if err := slowCall(t, s, 10); err != nil {
		t.Errorf("fast call after a timeout should work: %v", err)
	}
}

func TestPerServerConcurrencySerializesCalls(t *testing.T) {
	run := func(limits Limits) time.Duration {
		f := setup(t, []Namespace{{Name: "p", Servers: []string{"c"}}}, []supervisor.Spec{spec("p/c", nil)},
			func(f *fixture) { f.limits = limits })
		s := f.connect(t, "p")
		started := time.Now()
		var wg sync.WaitGroup
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); slowCall(t, s, 300) }()
		}
		wg.Wait()
		return time.Since(started)
	}
	if d := run(Limits{}); d > 800*time.Millisecond {
		t.Errorf("unlimited calls should overlap, took %s", d)
	}
	if d := run(Limits{PerServer: 1}); d < 900*time.Millisecond {
		t.Errorf("limit 1 should serialize, took %s", d)
	}
	if d := run(Limits{MaxConcurrent: 1}); d < 900*time.Millisecond {
		t.Errorf("global limit 1 should serialize, took %s", d)
	}
	if d := run(Limits{PerNamespace: 5, NamespaceConcurrency: map[string]int{"p": 1}}); d < 900*time.Millisecond {
		t.Errorf("namespace override 1 should serialize, took %s", d)
	}
}

func TestQueuedCallTimesOutWhileWaiting(t *testing.T) {
	f := setup(t, []Namespace{{Name: "p", Servers: []string{"c"}}}, []supervisor.Spec{spec("p/c", nil)},
		func(f *fixture) { f.limits = Limits{PerServer: 1, CallTimeout: 300 * time.Millisecond} })
	s := f.connect(t, "p")
	go slowCall(t, s, 250)
	time.Sleep(50 * time.Millisecond)
	if err := slowCall(t, s, 250); err == nil {
		t.Error("second call should exceed its deadline (queue + run)")
	}
}

func TestBreakerOpensOnTimeoutsAndRecovers(t *testing.T) {
	f := setup(t, []Namespace{{Name: "p", Servers: []string{"c"}}}, []supervisor.Spec{spec("p/c", nil)},
		func(f *fixture) {
			f.limits = Limits{CallTimeout: 80 * time.Millisecond}
			f.breaker = BreakerConfig{Failures: 2, Cooldown: 300 * time.Millisecond}
		})
	s := f.connect(t, "p")
	slowCall(t, s, 1000)
	slowCall(t, s, 1000)
	if st := f.gw.Breakers()["p/c"]; st != "open" {
		t.Fatalf("breaker = %s", st)
	}
	started := time.Now()
	err := slowCall(t, s, 1)
	if err == nil || time.Since(started) > 50*time.Millisecond {
		t.Fatalf("open circuit should reject immediately: %v after %s", err, time.Since(started))
	}
	<-f.calls
	<-f.calls
	if c := <-f.calls; !errors.Is(c.Err, ErrCircuitOpen) {
		t.Errorf("observed err = %v", c.Err)
	}
	time.Sleep(350 * time.Millisecond)
	if err := slowCall(t, s, 1); err != nil {
		t.Fatalf("trial call after cooldown should pass: %v", err)
	}
	if st := f.gw.Breakers()["p/c"]; st != "closed" {
		t.Errorf("breaker after successful trial = %s", st)
	}
}
