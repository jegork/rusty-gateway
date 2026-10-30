package codemode

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// upstream artifact and build provenance are recorded in quickjs.LICENSE
//
//go:embed quickjs.wasm
var quickJS []byte

var compilationCache = sync.OnceValue(wazero.NewCompilationCache)

type Limits struct {
	Timeout        time.Duration
	MemoryMB       int
	MaxCalls       int
	MaxOutputBytes int
	MaxCodeBytes   int
}

func (l Limits) Defaults() Limits {
	if l.Timeout == 0 {
		l.Timeout = 10 * time.Second
	}
	if l.MemoryMB == 0 {
		l.MemoryMB = 32
	}
	if l.MaxCalls == 0 {
		l.MaxCalls = 20
	}
	if l.MaxOutputBytes == 0 {
		l.MaxOutputBytes = 64 << 10
	}
	if l.MaxCodeBytes == 0 {
		l.MaxCodeBytes = 64 << 10
	}
	return l
}

type CallTool func(context.Context, string, json.RawMessage) (any, error)

// execute runs a function body in a fresh WebAssembly instance with no host
// filesystem, environment, arguments, network, or process capabilities.
func Execute(ctx context.Context, code string, limits Limits, call CallTool) (result json.RawMessage, err error) {
	limits = limits.Defaults()
	if limits.Timeout <= 0 || limits.MemoryMB < 2 || limits.MemoryMB > 256 || limits.MaxCalls <= 0 || limits.MaxOutputBytes <= 0 || limits.MaxCodeBytes <= 0 {
		return nil, errors.New("invalid code mode limits")
	}
	if strings.TrimSpace(code) == "" || len(code) > limits.MaxCodeBytes {
		return nil, fmt.Errorf("code must contain between 1 and %d bytes", limits.MaxCodeBytes)
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	defer func() {
		if ctx.Err() != nil {
			result = nil
			err = fmt.Errorf("code execution interrupted: %w", ctx.Err())
		}
	}()
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithCompilationCache(compilationCache()).
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(uint32(limits.MemoryMB*16)))
	defer rt.Close(context.Background())
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		return nil, err
	}
	vm := &machine{ctx: ctx, limits: limits, tool: call}
	if _, err := rt.NewHostModuleBuilder("env").NewFunctionBuilder().WithFunc(vm.callTool).Export("jsFunctionProxy").Instantiate(ctx); err != nil {
		return nil, err
	}
	mod, err := rt.InstantiateWithConfig(ctx, quickJS, wazero.NewModuleConfig().
		WithStartFunctions().
		WithSysWalltime().
		WithSysNanotime())
	if err != nil {
		return nil, fmt.Errorf("instantiate JavaScript sandbox: %w", err)
	}
	vm.module = mod
	handle, err := vm.invoke("New_QJS", uint64(limits.MemoryMB<<19), 256<<10, 0, 0)
	if err != nil {
		return nil, err
	}
	if handle == 0 {
		return nil, errors.New("JavaScript sandbox allocation failed")
	}
	vm.jsctx, err = vm.invoke("QJS_GetContext", handle)
	if err != nil {
		return nil, err
	}
	proxy, err := vm.invoke("QJS_CreateFunctionProxy", vm.jsctx, 0, 0, 0)
	if err != nil {
		return nil, err
	}
	global, err := vm.invoke("JS_GetGlobalObject", vm.jsctx)
	if err != nil {
		return nil, err
	}
	name, err := vm.alloc("__gateway_call")
	if err != nil {
		return nil, err
	}
	if _, err := vm.invoke("JS_SetPropertyStr", vm.jsctx, global, name, proxy); err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(code)
	value, err := vm.eval(`(() => {
		const host = globalThis.__gateway_call;
		delete globalThis.__gateway_call;
		for (const key of ["std", "os", "bjson", "scriptArgs", "print", "loadScript", "setTimeout", "setInterval", "clearTimeout", "clearInterval"]) delete globalThis[key];
		const stringify = JSON.stringify.bind(JSON);
		const parse = JSON.parse.bind(JSON);
		const AsyncFunction = Object.getPrototypeOf(async function() {}).constructor;
		const tools = Object.freeze({call: async (name, args = {}) => {
			const reply = parse(host(stringify({name, arguments: args})));
			if (reply.error !== undefined) throw new Error(reply.error);
			return reply.value;
		}});
		return new AsyncFunction("tools", ` + string(encoded) + `)(tools).then(value => {
			const result = stringify(value === undefined ? null : value);
			if (result === undefined) throw new Error("return value must be JSON serializable");
			return result;
		});
	})()`)
	if err != nil {
		return nil, fmt.Errorf("JavaScript execution: %w", err)
	}
	text, err := vm.text(value, limits.MaxOutputBytes)
	if err != nil {
		return nil, err
	}
	if !json.Valid([]byte(text)) {
		return nil, errors.New("return value must be JSON serializable")
	}
	return json.RawMessage(text), nil
}

type machine struct {
	ctx    context.Context
	module api.Module
	jsctx  uint64
	limits Limits
	tool   CallTool
	calls  int
}

func (m *machine) invoke(name string, args ...uint64) (uint64, error) {
	result, err := m.module.ExportedFunction(name).Call(m.ctx, args...)
	if err != nil {
		return 0, err
	}
	if len(result) == 0 {
		return 0, nil
	}
	return result[0], nil
}

func (m *machine) alloc(text string) (uint64, error) {
	ptr, err := m.invoke("malloc", uint64(len(text)+1))
	if err != nil {
		return 0, err
	}
	if ptr == 0 || !m.module.Memory().WriteString(uint32(ptr), text) || !m.module.Memory().WriteByte(uint32(ptr)+uint32(len(text)), 0) {
		return 0, errors.New("JavaScript sandbox memory exhausted")
	}
	return ptr, nil
}

func (m *machine) eval(code string) (uint64, error) {
	ptr, err := m.alloc(code)
	if err != nil {
		return 0, err
	}
	filename, err := m.alloc("code-mode.js")
	if err != nil {
		return 0, err
	}
	opts, err := m.invoke("QJS_CreateEvalOption", ptr, 0, 0, filename, 8)
	if err != nil {
		return 0, err
	}
	value, err := m.invoke("QJS_Eval", m.jsctx, opts)
	if err != nil {
		return 0, err
	}
	failed, err := m.invoke("JS_HasException", m.jsctx)
	if err != nil {
		return 0, err
	}
	if failed != 0 {
		exception, err := m.invoke("JS_GetException", m.jsctx)
		if err != nil {
			return 0, err
		}
		message, err := m.text(exception, m.limits.MaxOutputBytes)
		if err != nil {
			return 0, err
		}
		return 0, errors.New(message)
	}
	return value, nil
}

func (m *machine) text(value uint64, limit int) (string, error) {
	ptr, err := m.invoke("QJS_ToCString", m.jsctx, value)
	if err != nil {
		return "", err
	}
	if ptr == 0 {
		return "", errors.New("cannot serialize JavaScript value")
	}
	packed, ok := m.module.Memory().ReadUint64Le(uint32(ptr))
	if !ok {
		return "", errors.New("invalid JavaScript string")
	}
	length, addr := uint32(packed), uint32(packed>>32)
	defer m.invoke("free", ptr)
	defer m.invoke("JS_FreeCString", m.jsctx, uint64(addr))
	if uint64(length) > uint64(limit) {
		return "", fmt.Errorf("JavaScript value exceeds %d byte limit", limit)
	}
	data, ok := m.module.Memory().Read(addr, length)
	if !ok {
		return "", errors.New("invalid JavaScript string")
	}
	return string(data), nil
}

func (m *machine) callTool(ctx context.Context, mod api.Module, jsctx uint32, this uint64, argc, argv uint32) uint64 {
	// the proxy supplies four internal arguments before the user's JSON string
	if argc != 5 {
		panic("invalid tool bridge invocation")
	}
	value, ok := mod.Memory().ReadUint64Le(argv + 4*8)
	if !ok {
		panic("invalid tool bridge arguments")
	}
	request, err := m.text(value, m.limits.MaxCodeBytes)
	var result any
	if err == nil {
		var in struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		err = json.Unmarshal([]byte(request), &in)
		if err == nil {
			m.calls++
			switch {
			case ctx.Err() != nil:
				err = ctx.Err()
			case m.calls > m.limits.MaxCalls:
				err = fmt.Errorf("tool call limit of %d exceeded", m.limits.MaxCalls)
			case m.tool == nil:
				err = errors.New("tool calls unavailable")
			case len(in.Arguments) == 0 || in.Arguments[0] != '{':
				err = errors.New("tool arguments must be an object")
			default:
				result, err = m.tool(ctx, in.Name, in.Arguments)
			}
		}
	}
	envelope := map[string]any{"value": result}
	if err != nil {
		envelope = map[string]any{"error": err.Error()}
	}
	data, err := json.Marshal(envelope)
	if err == nil && len(data) > m.limits.MaxOutputBytes {
		err = fmt.Errorf("tool result exceeds %d byte limit", m.limits.MaxOutputBytes)
	}
	if err != nil {
		data, _ = json.Marshal(map[string]string{"error": err.Error()})
		if len(data) > m.limits.MaxOutputBytes {
			// an error that cannot fit must abort, not bypass the guest's limit
			panic(err)
		}
	}
	ptr, err := m.alloc(string(data))
	if err != nil {
		panic(err)
	}
	defer m.invoke("free", ptr)
	out, err := m.invoke("QJS_NewString", m.jsctx, ptr)
	if err != nil {
		panic(err)
	}
	return out
}
