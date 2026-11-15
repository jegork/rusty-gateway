package codemode

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecutionIsolation(t *testing.T) {
	for _, tc := range []struct{ code, want string }{
		{`return [1, 2, 3].map(x => x * x)`, `[1,4,9]`},
		{`return await Promise.resolve({answer: 42})`, `{"answer":42}`},
		{`return [typeof process, typeof require, typeof fetch, typeof std, typeof os, typeof loadScript]`, `["undefined","undefined","undefined","undefined","undefined","undefined"]`},
		{`globalThis.secret = "previous execution"; return true`, `true`},
		{`return typeof globalThis.secret`, `"undefined"`},
	} {
		out, err := Execute(context.Background(), tc.code, Limits{}, nil)
		if err != nil || string(out) != tc.want {
			t.Fatalf("%s: got %s, %v; want %s", tc.code, out, err, tc.want)
		}
	}
}

func TestExecutionBounds(t *testing.T) {
	for _, tc := range []struct {
		name, code, want string
		limits           Limits
	}{
		{"memory", `return new Uint8Array(100 * 1024 * 1024).length`, "out of memory", Limits{MemoryMB: 8}},
		{"output", `return "x".repeat(1000)`, "exceeds 20 byte limit", Limits{MaxOutputBytes: 20}},
		{"source", `return 1234567890`, "code must contain", Limits{MaxCodeBytes: 10}},
		{"serialization", `const x = {}; x.self = x; return x`, "circular reference", Limits{}},
		{"exception", `throw new Error("failed")`, "Error: failed", Limits{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Execute(context.Background(), tc.code, tc.limits, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}

func TestToolCallBudget(t *testing.T) {
	calls := 0
	tool := func(ctx context.Context, name string, args json.RawMessage) (any, error) {
		calls++
		return map[string]int{"total": calls}, nil
	}
	out, err := Execute(context.Background(), `
		const a = await tools.call("counter__increment", {});
		const b = await tools.call("counter__increment", {});
		try { await tools.call("counter__increment", {}); } catch (e) {
			return {total: a.total + b.total, error: e.message};
		}
	`, Limits{MaxCalls: 2}, tool)
	if err != nil || calls != 2 || !strings.Contains(string(out), `"total":3`) || !strings.Contains(string(out), "tool call limit of 2 exceeded") {
		t.Fatalf("call budget: output %s, calls %d, error %v", out, calls, err)
	}
}

func TestHostCapabilitiesAreNotAvailable(t *testing.T) {
	t.Setenv("CODEMODE_CANARY", "must-not-leak")
	path := filepath.Join(t.TempDir(), "canary.js")
	if err := os.WriteFile(path, []byte(`export default "must-not-leak"`), 0600); err != nil {
		t.Fatal(err)
	}
	filename, _ := json.Marshal(path)
	for _, code := range []string{
		`return await import(` + string(filename) + `)`,
		`return await import("https://example.com/remote.js")`,
		`const os = await import("qjs:os"); return os.exec(["sh", "-c", "echo must-not-leak"])`,
	} {
		out, err := Execute(context.Background(), code, Limits{Timeout: 2 * time.Second}, nil)
		if err == nil {
			t.Fatalf("host capability must be inaccessible: %s returned %s", code, out)
		}
	}
	for _, code := range []string{
		`const std = await import("qjs:std"); return std.getenv("CODEMODE_CANARY")`,
		`const std = await import("qjs:std"); return std.open(` + string(filename) + `, "r")`,
	} {
		out, err := Execute(context.Background(), code, Limits{}, nil)
		if err != nil || string(out) != "null" {
			t.Fatalf("host resource must be absent: %s returned %s, %v", code, out, err)
		}
	}
}

func TestCancellationInterruptsRunningJavaScript(t *testing.T) {
	for _, code := range []string{
		`while (true) {}`,
		`for (;;) { try { while (true) {} } catch (_) {} }`,
		`return await new Promise(() => {})`,
		`return {toJSON() { while (true) {} }}`,
	} {
		ctx, cancel := context.WithCancel(context.Background())
		reachedBridge := false
		_, err := Execute(ctx, `await tools.call("ready", {}); `+code, Limits{}, func(context.Context, string, json.RawMessage) (any, error) {
			reachedBridge = true
			time.AfterFunc(100*time.Millisecond, cancel)
			return nil, nil
		})
		cancel()
		if !reachedBridge || !errors.Is(err, context.Canceled) {
			t.Fatalf("running script must be interrupted: reached bridge %v, error %v", reachedBridge, err)
		}
	}
}

func TestCancellationBeforeInitialization(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Execute(ctx, `return 1`, Limits{}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("startup cancellation must preserve its cause: %v", err)
	}
}

func TestToolErrorEnvelopesHonorOutputLimit(t *testing.T) {
	for _, limit := range []int{16, 64} {
		called := false
		out, err := Execute(context.Background(), `
			try { await tools.call("large_result", {}); } catch (_) { return "caught"; }
			return "unexpected success";
		`, Limits{MaxOutputBytes: limit}, func(context.Context, string, json.RawMessage) (any, error) {
			called = true
			return strings.Repeat("x", 100), nil
		})
		if !called {
			t.Fatalf("limit %d: execution failed before the tool call: %v", limit, err)
		}
		if limit == 16 {
			if err == nil || out != nil {
				t.Fatalf("oversized error must abort before guest delivery: %s, %v", out, err)
			}
		} else if err != nil || string(out) != `"caught"` {
			t.Fatalf("an error that fits must remain catchable: %s, %v", out, err)
		}
	}
}
