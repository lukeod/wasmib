# wasmib-go

Go bindings for the wasmib MIB parser.

wasmib parses SNMP MIB definition files (SMIv1/SMIv2) and provides a queryable
model. Parsing and resolution are performed in Rust/WASM for correctness and
compatibility with vendor MIBs, while all queries run as native Go code for
high throughput.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Go (native)                                                     │
│                                                                 │
│  File I/O ─────► Load MIB bytes                                 │
│  (disk, embed,      │                                           │
│   network)          │                                           │
└─────────────────────┼───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│ Rust/WASM                                                       │
│                                                                 │
│  MIB bytes → Lexer → Parser → Resolver → Model                  │
│                                             │                   │
│                                             ▼                   │
│                                  serialize (protobuf)           │
└─────────────────────────────────────────────┬───────────────────┘
                                              │
                                  One-time transfer
                                              │
┌─────────────────────────────────────────────▼───────────────────┐
│ Go (native)                                                     │
│                                                                 │
│  Deserialize → Model (read-only)                                │
│                   │                                             │
│       ┌───────────┼───────────┬───────────┐                     │
│       ▼           ▼           ▼           ▼                     │
│   Goroutine   Goroutine   Goroutine   Goroutine                 │
│                                                                 │
│   All queries are native Go — no WASM calls                     │
└─────────────────────────────────────────────────────────────────┘
```

wasmib uses a "serialize to host" pattern:

1. **Go handles all I/O**: reading MIB files from disk, embedded filesystems,
   or any other source. The raw bytes are passed to WASM for parsing.

2. **Rust/WASM** handles the complex work: lexing, parsing, cross-module
   resolution, OID tree construction, and semantic analysis. The WASM module
   has no filesystem access.

3. **The resolved Model is serialized** and transferred back to Go as a
   single blob. This includes the full OID tree, all type definitions,
   object metadata, and an interned string table.

4. **Go deserializes into native structs** and builds lookup indices. From
   this point on, all queries are pure Go with no WASM calls.

This design enables unlimited concurrent queries from any number of goroutines
without contention.

## Installation

```bash
go get github.com/lukeod/wasmib/wasmib-go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/lukeod/wasmib/wasmib-go"
)

func main() {
    ctx := context.Background()

    // Load MIB files
    model, err := wasmib.Load(ctx, "/usr/share/snmp/mibs/IF-MIB")
    if err != nil {
        log.Fatal(err)
    }

    // Query by OID
    node := model.GetNodeByOID("1.3.6.1.2.1.2.2.1.1")
    if node != nil {
        obj := model.GetObject(node)
        fmt.Printf("OID: %s\n", model.GetOID(node))
        fmt.Printf("Name: %s\n", model.GetStr(obj.Name))
        fmt.Printf("Type: %s\n", model.GetType(obj.TypeID).Base)
    }
}
```

## Loading MIBs

wasmib provides several ways to load MIB files:

### From Files

```go
// Load specific files
model, err := wasmib.Load(ctx, "IF-MIB", "SNMPv2-MIB", "/path/to/vendor.mib")

// Panic on error (useful for tests)
model := wasmib.MustLoad(ctx, "IF-MIB", "SNMPv2-MIB")
```

### From a Directory

```go
// Load all MIBs in a directory (recursive)
model, err := wasmib.LoadDir(ctx, "/usr/share/snmp/mibs")

// With options
model, err := wasmib.LoadDirWithOptions(ctx, "/usr/share/snmp/mibs", wasmib.LoadDirOptions{
    Extensions: []string{".mib", ".txt"},  // Filter by extension
    Recursive:  true,                       // Walk subdirectories
    OnError: func(path string, err error) {
        log.Printf("Warning: %s: %v", path, err)
    },
})
```

### From Memory

```go
// Load from byte slices
sources := map[string][]byte{
    "IF-MIB":     ifMibBytes,
    "SNMPv2-MIB": snmpv2MibBytes,
}
model, err := wasmib.LoadBytes(ctx, sources)
```

### From Embedded Files

```go
//go:embed mibs/*
var mibsFS embed.FS

model, err := wasmib.LoadFS(ctx, mibsFS, "mibs")
```

### Using the Compiler Directly

For more control, use the `Compiler` directly:

```go
compiler, err := wasmib.NewCompiler(ctx)
if err != nil {
    return err
}
defer compiler.Close()

// Load modules one by one
for _, path := range mibPaths {
    source, _ := os.ReadFile(path)
    if err := compiler.LoadModule(source); err != nil {
        log.Printf("Warning: %s: %v", path, err)
    }
}

// Resolve all modules together
model, err := compiler.Resolve()
```

## Querying the Model

### Lookup by OID

```go
// Dotted string lookup
node := model.GetNodeByOID("1.3.6.1.2.1.2.2.1.1")

// Numeric slice lookup
node := model.GetNodeByOIDSlice([]uint32{1, 3, 6, 1, 2, 1, 2, 2, 1, 1})

// Get OID as numeric slice
arcs := model.GetOIDSlice(node) // []uint32{1, 3, 6, 1, 2, 1, 2, 2, 1, 1}
```

### Lookup by Name

```go
// Returns all nodes with this name (may be multiple if defined in several modules)
nodes := model.GetNodesByName("ifIndex")

// Qualified lookup for disambiguation
node := model.GetNodeByQualifiedName("IF-MIB", "ifIndex")
```

### Traversing the Tree

```go
// Walk from a specific node
model.Walk(nodeID, func(n *wasmib.Node) bool {
    fmt.Println(model.GetStr(n.Definitions[0].Label))
    return true // continue walking
})

// Walk the entire tree
model.WalkAll(func(n *wasmib.Node) bool {
    return true
})
```

### Getting Object Details

```go
node := model.GetNodeByOID("1.3.6.1.2.1.2.2.1.4")
obj := model.GetObject(node)
if obj != nil {
    fmt.Printf("Name: %s\n", model.GetStr(obj.Name))
    fmt.Printf("Access: %s\n", obj.Access)
    fmt.Printf("Status: %s\n", obj.Status)
    fmt.Printf("Description: %s\n", model.GetStr(obj.Description))
    fmt.Printf("Units: %s\n", model.GetStr(obj.Units))
}
```

### Getting Type Information

```go
t := model.GetType(obj.TypeID)
fmt.Printf("Type: %s\n", model.GetStr(t.Name))
fmt.Printf("Base: %s\n", t.Base)
fmt.Printf("Is TC: %v\n", t.IsTC)

// Get display hint (walks type chain)
hint := model.GetEffectiveHint(obj.TypeID)

// Enumeration values
for _, ev := range t.EnumValues {
    fmt.Printf("  %d = %s\n", ev.Value, model.GetStr(ev.Name))
}
```

### Table Structure

```go
node := model.GetNodeByQualifiedName("IF-MIB", "ifEntry")
obj := model.GetObject(node)

if obj.Index != nil {
    for _, idx := range obj.Index.Items {
        idxNode := model.GetNode(idx.Object)
        idxObj := model.GetObject(idxNode)
        fmt.Printf("Index: %s (implied=%v)\n", model.GetStr(idxObj.Name), idx.Implied)
    }
}

if obj.Augments != 0 {
    augNode := model.GetNode(obj.Augments)
    fmt.Printf("Augments: %s\n", model.GetOID(augNode))
}
```

## Node Kinds

Nodes have a `Kind` field indicating their semantic type:

| Kind | Description |
|------|-------------|
| `NodeKindInternal` | Path node without definition (e.g., `mgmt`) |
| `NodeKindNode` | OBJECT-IDENTITY, MODULE-IDENTITY |
| `NodeKindScalar` | OBJECT-TYPE not in table context |
| `NodeKindTable` | OBJECT-TYPE with SYNTAX SEQUENCE OF |
| `NodeKindRow` | OBJECT-TYPE with INDEX or AUGMENTS |
| `NodeKindColumn` | OBJECT-TYPE whose parent is a row |
| `NodeKindNotification` | NOTIFICATION-TYPE or TRAP-TYPE |
| `NodeKindGroup` | OBJECT-GROUP or NOTIFICATION-GROUP |
| `NodeKindCompliance` | MODULE-COMPLIANCE |
| `NodeKindCapabilities` | AGENT-CAPABILITIES |

```go
if node.Kind.IsObjectType() {
    // scalar, table, row, or column
}
if node.Kind.IsConformance() {
    // group, compliance, or capabilities
}
```

## String Table

The Rust parser interns all strings into a deduplicated table for memory
efficiency. This structure is preserved in Go: string fields store `uint32`
IDs that must be looked up via `model.GetStr()`:

```go
obj := model.GetObject(node)
name := model.GetStr(obj.Name)           // "ifIndex"
desc := model.GetStr(obj.Description)    // "A unique value..."
units := model.GetStr(obj.Units)         // "" if not set
```

A zero ID always returns an empty string.

## Concurrency

- **Compiler**: NOT safe for concurrent use. Each goroutine should create
  its own `Compiler` instance.
- **Model**: Safe for concurrent read access from any number of goroutines.
  No locks needed.

```go
model, _ := wasmib.Load(ctx, paths...)

// Safe: concurrent reads
var wg sync.WaitGroup
for i := 0; i < 100; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        node := model.GetNodeByOID("1.3.6.1.2.1.1.1")
        _ = model.GetObject(node)
    }()
}
wg.Wait()
```

## Performance

| Operation | Latency |
|-----------|---------|
| `GetNodeByOID` | ~20-50ns |
| `GetObject` | ~10ns |
| `GetEffectiveHint` | ~30-100ns |

Throughput: >10M lookups/sec single-threaded, >50M lookups/sec with 8 goroutines.

Initialization (one-time per model):
- Parsing: ~1-10ms per MIB file
- Resolution: ~100-500ms for typical workloads
- Deserialization: ~20-100ms

## Error Handling

wasmib is lenient by design. It parses non-compliant vendor MIBs without
failing, collecting warnings instead of errors where possible.

```go
// Check if all references were resolved
if !model.IsComplete() {
    imports, types, oids, indexes, notifs := model.UnresolvedCounts()
    log.Printf("Unresolved: imports=%d types=%d oids=%d indexes=%d notifs=%d",
        imports, types, oids, indexes, notifs)
}

// Get detailed diagnostics (JSON)
compiler, _ := wasmib.NewCompiler(ctx)
compiler.LoadModule(source)
model, _ := compiler.Resolve()
diags, _ := compiler.GetDiagnostics()
fmt.Println(diags) // [{"severity":"warning","message":"..."}]
```

## Built-in Modules

wasmib includes synthetic implementations of the standard SMI base modules.
You do NOT need to provide these files:

- `SNMPv2-SMI` - SMIv2 base types and OID roots
- `SNMPv2-TC` - Textual conventions
- `SNMPv2-CONF` - Conformance macros
- `RFC1155-SMI` / `RFC1065-SMI` - SMIv1 base types
- `RFC1213-MIB` - MIB-II legacy definitions
- `RFC-1212` / `RFC-1215` - Macro definitions

If you accidentally include these files, they are automatically skipped.

## License

See the [LICENSE](../LICENSE) file.
