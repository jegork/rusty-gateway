// Package fakeserver is a stdio MCP server used by tests. Test binaries call
// Main from TestMain when RG_FAKE_SERVER is set, so the test executable
// itself can be launched as an upstream.
package fakeserver

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const EnvFlag = "RG_FAKE_SERVER"

// Main never returns. Behaviour is driven by env vars:
//
//	RG_FAIL_START=1        exit 3 immediately
//	RG_CHILD_PID_FILE=path spawn `sleep 300` and write its pid to path
//	RG_CRASH_AFTER_MS=n    exit 4 after n milliseconds
//	RG_CRASH_ONCE=path     with RG_CRASH_AFTER_MS, only crash if path does not exist, creating it
//	RG_TOOLS=a,b           extra no-op tool names beyond "echo"
func Main() {
	if os.Getenv("RG_FAIL_START") != "" {
		os.Exit(3)
	}
	if f := os.Getenv("RG_CHILD_PID_FILE"); f != "" {
		child := exec.Command("sleep", "300")
		if err := child.Start(); err != nil {
			panic(err)
		}
		os.WriteFile(f, []byte(strconv.Itoa(child.Process.Pid)), 0o644)
	}
	if ms := os.Getenv("RG_CRASH_AFTER_MS"); ms != "" && shouldCrash() {
		d, _ := strconv.Atoi(ms)
		go func() { time.Sleep(time.Duration(d) * time.Millisecond); os.Exit(4) }()
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "0"}, nil)
	echo := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(req.Params.Arguments)}}}, nil
	}
	srv.AddTool(&mcp.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}, echo)
	// slow sleeps for {"ms": n} before answering, honoring cancellation
	srv.AddTool(&mcp.Tool{Name: "slow", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var in struct{ MS int `json:"ms"` }
			json.Unmarshal(req.Params.Arguments, &in)
			select {
			case <-time.After(time.Duration(in.MS) * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "done"}}}, nil
		})
	if names := os.Getenv("RG_TOOLS"); names != "" {
		for _, n := range strings.Split(names, ",") {
			srv.AddTool(&mcp.Tool{Name: n, InputSchema: json.RawMessage(`{"type":"object"}`)}, echo)
		}
	}
	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		os.Exit(5)
	}
	os.Exit(0)
}

func shouldCrash() bool {
	marker := os.Getenv("RG_CRASH_ONCE")
	if marker == "" {
		return true
	}
	if _, err := os.Stat(marker); err == nil {
		return false
	}
	os.WriteFile(marker, nil, 0o644)
	return true
}

// Spec builds a supervisor-compatible launch of the current test binary.
func Spec(env map[string]string) (command string, args []string, fullEnv map[string]string) {
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}
	fullEnv = map[string]string{EnvFlag: "1"}
	for k, v := range env {
		fullEnv[k] = v
	}
	return exe, []string{"-test.run=^$"}, fullEnv
}
