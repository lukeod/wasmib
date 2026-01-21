// Package wasmib provides Go bindings for parsing SNMP MIB definition files.
//
// wasmib parses SMIv1 and SMIv2 MIB files and produces a queryable model with
// resolved cross-references, OID tree, type information, and semantic analysis.
// Parsing is performed in Rust/WASM for correctness and broad vendor MIB
// compatibility, while all queries execute as native Go code.
//
// # Quick Start
//
// The simplest way to use wasmib is with the Load function:
//
//	model, err := wasmib.Load(ctx, "/usr/share/snmp/mibs/IF-MIB")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Query by OID
//	node := model.GetNodeByOID("1.3.6.1.2.1.2.2.1.1")
//	obj := model.GetObject(node)
//	fmt.Println(model.GetStr(obj.Name)) // "ifIndex"
//
// # Loading MIBs
//
// Several loading functions are available:
//
//   - [Load] loads MIBs from file paths
//   - [LoadDir] recursively loads all MIBs in a directory
//   - [LoadBytes] loads from in-memory byte slices
//   - [LoadFS] loads from an [fs.FS] (e.g., embed.FS)
//   - [NewCompiler] provides low-level control over parsing
//
// # String Interning
//
// All strings in the model are interned for memory efficiency. String fields
// store uint32 IDs that must be resolved via [Model.GetStr]:
//
//	name := model.GetStr(obj.Name)        // "ifIndex"
//	desc := model.GetStr(obj.Description) // "A unique value..."
//
// A zero ID always returns an empty string.
//
// # Concurrency
//
// The [Compiler] type is NOT safe for concurrent use. Each goroutine that
// needs to parse MIBs should create its own instance.
//
// The [Model] type IS safe for concurrent read access from any number of
// goroutines without synchronization.
//
// # Node Kinds
//
// Nodes have semantic types determined by their role in the MIB structure:
//
//   - [NodeKindScalar]: OBJECT-TYPE not in a table context
//   - [NodeKindTable]: OBJECT-TYPE with SYNTAX SEQUENCE OF
//   - [NodeKindRow]: OBJECT-TYPE with INDEX or AUGMENTS
//   - [NodeKindColumn]: OBJECT-TYPE whose parent is a row
//   - [NodeKindNotification]: NOTIFICATION-TYPE or TRAP-TYPE
//   - [NodeKindGroup]: OBJECT-GROUP or NOTIFICATION-GROUP
//   - [NodeKindNode]: OBJECT-IDENTITY, MODULE-IDENTITY, value assignments
//   - [NodeKindInternal]: Path nodes without definitions
//
// # Built-in Modules
//
// wasmib includes synthetic implementations of SMI base modules (SNMPv2-SMI,
// SNMPv2-TC, RFC1155-SMI, etc.). You do not need to provide these files; they
// are automatically available and user-provided versions are skipped.
//
// # Error Handling
//
// wasmib is lenient by design. It successfully parses most vendor MIBs even
// when they deviate from the SMI specifications. Partial results are returned
// when some references cannot be resolved. Use [Model.IsComplete] and
// [Model.UnresolvedCounts] to check resolution status.
package wasmib
