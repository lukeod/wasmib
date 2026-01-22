package wasmib

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Load parses MIB files and returns a resolved model.
//
// This is the simplest way to load MIBs - just provide paths to MIB files.
// For more control, use NewCompiler directly.
//
// Example:
//
//	model, err := wasmib.Load(ctx, "IF-MIB", "SNMPv2-MIB", "/path/to/vendor.mib")
func Load(ctx context.Context, paths ...string) (*Model, error) {
	compiler, err := NewCompiler(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = compiler.Close() }()

	for _, path := range paths {
		source, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		if err := compiler.LoadModule(source); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
	}

	return compiler.Resolve()
}

// LoadBytes parses MIB sources from byte slices and returns a resolved model.
//
// Use this when you have MIB content in memory rather than files.
//
// Example:
//
//	sources := map[string][]byte{
//	    "IF-MIB":     ifMibBytes,
//	    "SNMPv2-MIB": snmpv2MibBytes,
//	}
//	model, err := wasmib.LoadBytes(ctx, sources)
func LoadBytes(ctx context.Context, sources map[string][]byte) (*Model, error) {
	compiler, err := NewCompiler(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = compiler.Close() }()

	for name, source := range sources {
		if err := compiler.LoadModule(source); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
	}

	return compiler.Resolve()
}

// LoadDir parses all MIB files in a directory and returns a resolved model.
//
// This walks the directory recursively and attempts to parse every file.
// Files that fail to parse are silently ignored (they may not be MIB files).
//
// Example:
//
//	model, err := wasmib.LoadDir(ctx, "/usr/share/snmp/mibs")
func LoadDir(ctx context.Context, dir string) (*Model, error) {
	return LoadDirWithOptions(ctx, dir, LoadDirOptions{})
}

// LoadDirOptions configures LoadDirWithOptions behavior.
type LoadDirOptions struct {
	// Extensions filters files by extension. If empty, all files are tried.
	// Extensions should include the dot, e.g., []string{".mib", ".txt"}
	Extensions []string

	// Recursive controls whether subdirectories are walked.
	// Default is true (walk subdirectories).
	Recursive bool

	// OnError is called for each file that fails to parse.
	// If nil, parse errors are silently ignored.
	OnError func(path string, err error)
}

// LoadDirWithOptions parses MIB files in a directory with custom options.
func LoadDirWithOptions(ctx context.Context, dir string, opts LoadDirOptions) (*Model, error) {
	compiler, err := NewCompiler(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = compiler.Close() }()

	extSet := make(map[string]bool)
	for _, ext := range opts.Extensions {
		extSet[ext] = true
	}

	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Ignore permission errors, etc.
		}

		if d.IsDir() {
			if !opts.Recursive && path != dir {
				return fs.SkipDir
			}
			return nil
		}

		// Check extension if filter is set
		if len(extSet) > 0 {
			ext := filepath.Ext(path)
			if !extSet[ext] {
				return nil
			}
		}

		source, err := os.ReadFile(path)
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(path, err)
			}
			return nil
		}

		if err := compiler.LoadModule(source); err != nil {
			if opts.OnError != nil {
				opts.OnError(path, err)
			}
			// Don't fail on parse errors - file might not be a MIB
		}

		return nil
	}

	if err := filepath.WalkDir(dir, walkFn); err != nil {
		return nil, fmt.Errorf("walking directory: %w", err)
	}

	return compiler.Resolve()
}

// LoadFS parses MIB files from an fs.FS (e.g., embed.FS).
//
// Example with embedded files:
//
//	//go:embed mibs/*
//	var mibsFS embed.FS
//
//	model, err := wasmib.LoadFS(ctx, mibsFS, "mibs")
func LoadFS(ctx context.Context, fsys fs.FS, root string) (*Model, error) {
	return LoadFSWithOptions(ctx, fsys, root, LoadFSOptions{})
}

// LoadFSOptions configures LoadFSWithOptions behavior.
type LoadFSOptions struct {
	// OnError is called for each file that fails to read or parse.
	// If nil, errors are silently ignored (file might not be a MIB).
	OnError func(path string, err error)
}

// LoadFSWithOptions parses MIB files from an fs.FS with custom options.
func LoadFSWithOptions(ctx context.Context, fsys fs.FS, root string, opts LoadFSOptions) (*Model, error) {
	compiler, err := NewCompiler(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = compiler.Close() }()

	err = fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(path, err)
			}
			return nil
		}

		if d.IsDir() {
			return nil
		}

		source, err := fs.ReadFile(fsys, path)
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(path, err)
			}
			return nil
		}

		if err := compiler.LoadModule(source); err != nil {
			if opts.OnError != nil {
				opts.OnError(path, err)
			}
			// Don't fail on parse errors - file might not be a MIB
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking fs: %w", err)
	}

	return compiler.Resolve()
}

// Severity indicates the severity level of a diagnostic.
type Severity uint32

const (
	// SeverityError indicates a fatal error.
	SeverityError Severity = 0
	// SeverityWarning indicates a non-fatal warning.
	SeverityWarning Severity = 1
)

// String returns a human-readable representation of the severity.
func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	default:
		return "unknown"
	}
}

// Diagnostic represents a parse or resolution diagnostic.
type Diagnostic struct {
	Severity Severity // Error or warning
	Message  string   // Human-readable message
	Start    uint32   // Byte offset in source
	End      uint32   // Byte offset in source
}

// MustLoad is like Load but panics on error.
// Useful for tests or when you know the MIBs are valid.
func MustLoad(ctx context.Context, paths ...string) *Model {
	model, err := Load(ctx, paths...)
	if err != nil {
		panic(fmt.Sprintf("wasmib.MustLoad: %v", err))
	}
	return model
}
