package wasmib

import (
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"

	wasmibpb "github.com/lukeod/wasmib/wasmib-go/proto"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"google.golang.org/protobuf/proto"
)

//go:embed embed/wasmib.wasm
var wasmBytes []byte

// Error codes from WASM
const (
	errSuccess        = 0
	errInvalidPointer = 1
	errParseError     = 2
	errResolveError   = 3
	errNoModel        = 4
	errInternalError  = 5
)

// Compiler manages the WASM runtime for parsing MIB files.
//
// Compiler is NOT safe for concurrent use. Each goroutine that needs to
// parse MIB files should create its own Compiler instance. However, the
// resulting Model IS safe for concurrent read access.
type Compiler struct {
	ctx     context.Context
	runtime wazero.Runtime
	module  api.Module

	// Cached function exports
	fnAlloc          api.Function
	fnDealloc        api.Function
	fnLoadModule     api.Function
	fnResolve        api.Function
	fnGetModel       api.Function
	fnGetDiagnostics api.Function
	fnGetError       api.Function
	fnReset          api.Function
}

// NewCompiler creates a new WASM compiler instance.
//
// The context is used for the lifetime of the compiler. Call Close() when done.
func NewCompiler(ctx context.Context) (*Compiler, error) {
	if len(wasmBytes) == 0 {
		return nil, fmt.Errorf("wasmib.wasm not embedded - ensure embed/wasmib.wasm exists")
	}

	runtime := wazero.NewRuntime(ctx)

	module, err := runtime.Instantiate(ctx, wasmBytes)
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("instantiating wasm: %w", err)
	}

	c := &Compiler{
		ctx:              ctx,
		runtime:          runtime,
		module:           module,
		fnAlloc:          module.ExportedFunction("wasmib_alloc"),
		fnDealloc:        module.ExportedFunction("wasmib_dealloc"),
		fnLoadModule:     module.ExportedFunction("wasmib_load_module"),
		fnResolve:        module.ExportedFunction("wasmib_resolve"),
		fnGetModel:       module.ExportedFunction("wasmib_get_model"),
		fnGetDiagnostics: module.ExportedFunction("wasmib_get_diagnostics"),
		fnGetError:       module.ExportedFunction("wasmib_get_error"),
		fnReset:          module.ExportedFunction("wasmib_reset"),
	}

	// Validate all exports exist
	var missing []string
	if c.fnAlloc == nil {
		missing = append(missing, "wasmib_alloc")
	}
	if c.fnDealloc == nil {
		missing = append(missing, "wasmib_dealloc")
	}
	if c.fnLoadModule == nil {
		missing = append(missing, "wasmib_load_module")
	}
	if c.fnResolve == nil {
		missing = append(missing, "wasmib_resolve")
	}
	if c.fnGetModel == nil {
		missing = append(missing, "wasmib_get_model")
	}
	if c.fnGetDiagnostics == nil {
		missing = append(missing, "wasmib_get_diagnostics")
	}
	if c.fnGetError == nil {
		missing = append(missing, "wasmib_get_error")
	}
	if c.fnReset == nil {
		missing = append(missing, "wasmib_reset")
	}
	if len(missing) > 0 {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("missing required WASM exports: %v", missing)
	}

	return c, nil
}

// Close releases resources associated with the compiler.
func (c *Compiler) Close() error {
	return c.runtime.Close(c.ctx)
}

// LoadModule parses a MIB file and adds it to the staging area.
//
// The source should be the raw bytes of a MIB file. Call this for each
// MIB file, then call Resolve() to build the model.
func (c *Compiler) LoadModule(source []byte) error {
	if len(source) == 0 {
		return nil // Empty source is a no-op
	}

	// Allocate memory in WASM
	results, err := c.fnAlloc.Call(c.ctx, uint64(len(source)))
	if err != nil {
		return fmt.Errorf("alloc failed: %w", err)
	}
	ptr := uint32(results[0])
	if ptr == 0 {
		return fmt.Errorf("allocation failed (out of memory?)")
	}

	// Write source to WASM memory
	if !c.module.Memory().Write(ptr, source) {
		// Dealloc errors ignored: we're already returning an error, and memory
		// will be reclaimed when the WASM instance is closed regardless.
		_, _ = c.fnDealloc.Call(c.ctx, uint64(ptr), uint64(len(source)))
		return fmt.Errorf("memory write failed")
	}

	// Call load_module
	results, err = c.fnLoadModule.Call(c.ctx, uint64(ptr), uint64(len(source)))
	if err != nil {
		_, _ = c.fnDealloc.Call(c.ctx, uint64(ptr), uint64(len(source)))
		return fmt.Errorf("load_module call failed: %w", err)
	}

	// Deallocate source buffer. Errors ignored: memory will be reclaimed when
	// the WASM instance is closed, and there's no recovery action available.
	_, _ = c.fnDealloc.Call(c.ctx, uint64(ptr), uint64(len(source)))

	errCode := uint32(results[0])
	if errCode != errSuccess {
		errMsg := c.getErrorMessage()
		return fmt.Errorf("parse error (code %d): %s", errCode, errMsg)
	}

	return nil
}

// Resolve resolves all staged modules and returns the model.
//
// After calling this, the staging area is cleared and you can load more
// modules for a new resolution.
func (c *Compiler) Resolve() (*Model, error) {
	results, err := c.fnResolve.Call(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve call failed: %w", err)
	}

	errCode := uint32(results[0])
	if errCode != errSuccess {
		errMsg := c.getErrorMessage()
		return nil, fmt.Errorf("resolve error (code %d): %s", errCode, errMsg)
	}

	// Get serialized model
	results, err = c.fnGetModel.Call(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("get_model call failed: %w", err)
	}

	modelPtr := uint32(results[0])
	if modelPtr == 0 {
		return nil, fmt.Errorf("no model available")
	}

	// Read length-prefixed data
	lenBytes, ok := c.module.Memory().Read(modelPtr, 4)
	if !ok {
		return nil, fmt.Errorf("failed to read model length")
	}
	modelLen := binary.LittleEndian.Uint32(lenBytes)

	modelBytes, ok := c.module.Memory().Read(modelPtr+4, modelLen)
	if !ok {
		return nil, fmt.Errorf("failed to read model data")
	}

	// Make a copy since WASM memory may be invalidated
	modelBytesCopy := make([]byte, len(modelBytes))
	copy(modelBytesCopy, modelBytes)

	return Deserialize(modelBytesCopy)
}

// GetDiagnostics returns any diagnostics (warnings/errors) from parsing and resolution.
func (c *Compiler) GetDiagnostics() ([]Diagnostic, error) {
	results, err := c.fnGetDiagnostics.Call(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("get_diagnostics call failed: %w", err)
	}

	ptr := uint32(results[0])
	if ptr == 0 {
		return nil, nil // No diagnostics
	}

	// Read length-prefixed protobuf data
	lenBytes, ok := c.module.Memory().Read(ptr, 4)
	if !ok {
		return nil, fmt.Errorf("failed to read diagnostics length")
	}
	dataLen := binary.LittleEndian.Uint32(lenBytes)

	if dataLen == 0 {
		return nil, nil
	}

	protoBytes, ok := c.module.Memory().Read(ptr+4, dataLen)
	if !ok {
		return nil, fmt.Errorf("failed to read diagnostics data")
	}

	// Make a copy since WASM memory may be invalidated
	protoBytesCopy := make([]byte, len(protoBytes))
	copy(protoBytesCopy, protoBytes)

	// Decode protobuf
	var diagnostics wasmibpb.Diagnostics
	if err := proto.Unmarshal(protoBytesCopy, &diagnostics); err != nil {
		return nil, fmt.Errorf("failed to decode diagnostics: %w", err)
	}

	// Convert to Go types
	result := make([]Diagnostic, len(diagnostics.Items))
	for i, d := range diagnostics.Items {
		result[i] = Diagnostic{
			Severity: Severity(d.Severity),
			Message:  d.Message,
			Start:    d.Start,
			End:      d.End,
		}
	}

	return result, nil
}

// Reset clears the staging area and model.
//
// Call this to free memory and start fresh without creating a new Compiler.
func (c *Compiler) Reset() {
	_, _ = c.fnReset.Call(c.ctx)
}

// getErrorMessage reads the last error message from WASM.
func (c *Compiler) getErrorMessage() string {
	results, err := c.fnGetError.Call(c.ctx)
	if err != nil || results[0] == 0 {
		return "unknown error"
	}

	msg, err := c.readLengthPrefixedString(uint32(results[0]))
	if err != nil {
		return "unknown error"
	}
	return msg
}

// readLengthPrefixedString reads a length-prefixed string from WASM memory.
func (c *Compiler) readLengthPrefixedString(ptr uint32) (string, error) {
	lenBytes, ok := c.module.Memory().Read(ptr, 4)
	if !ok {
		return "", fmt.Errorf("failed to read string length")
	}
	strLen := binary.LittleEndian.Uint32(lenBytes)

	strBytes, ok := c.module.Memory().Read(ptr+4, strLen)
	if !ok {
		return "", fmt.Errorf("failed to read string data")
	}

	return string(strBytes), nil
}
