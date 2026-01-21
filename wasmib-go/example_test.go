package wasmib_test

import (
	"context"
	"fmt"

	wasmib "github.com/lukeod/wasmib/wasmib-go"
)

func Example() {
	ctx := context.Background()

	// Load MIB files and resolve
	model, err := wasmib.Load(ctx, "testdata/IF-MIB")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Query by OID
	node := model.GetNodeByOID("1.3.6.1.2.1.2.2.1.1")
	if node != nil {
		obj := model.GetObject(node)
		fmt.Printf("Name: %s\n", model.GetStr(obj.Name))
		fmt.Printf("Kind: %s\n", node.Kind)
	}
	// Output:
	// Name: ifIndex
	// Kind: column
}

func ExampleLoad() {
	ctx := context.Background()

	// Load one or more MIB files
	model, err := wasmib.Load(ctx, "testdata/IF-MIB", "testdata/SNMPv2-MIB")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Modules: %d\n", model.ModuleCount())
	fmt.Printf("Nodes: %d\n", model.NodeCount())
	// Output:
	// Modules: 10
	// Nodes: 180
}

func ExampleModel_GetNodeByOID() {
	ctx := context.Background()
	model, _ := wasmib.Load(ctx, "testdata/IF-MIB")

	// Look up sysDescr's parent (system)
	node := model.GetNodeByOID("1.3.6.1.2.1.2.2.1.4")
	if node != nil {
		obj := model.GetObject(node)
		fmt.Printf("Name: %s\n", model.GetStr(obj.Name))
		fmt.Printf("Access: %s\n", obj.Access)
	}
	// Output:
	// Name: ifMtu
	// Access: read-only
}

func ExampleModel_GetNodesByName() {
	ctx := context.Background()
	model, _ := wasmib.Load(ctx, "testdata/IF-MIB")

	// Multiple nodes may share a name
	nodes := model.GetNodesByName("ifIndex")
	for _, n := range nodes {
		fmt.Printf("OID: %s, Kind: %s\n", model.GetOID(n), n.Kind)
	}
	// Output:
	// OID: 1.3.6.1.2.1.2.2.1.1, Kind: column
}

func ExampleModel_GetNodeByQualifiedName() {
	ctx := context.Background()
	model, _ := wasmib.Load(ctx, "testdata/IF-MIB")

	// Disambiguate with module name
	node := model.GetNodeByQualifiedName("IF-MIB", "ifIndex")
	if node != nil {
		fmt.Printf("OID: %s\n", model.GetOID(node))
	}
	// Output:
	// OID: 1.3.6.1.2.1.2.2.1.1
}

func ExampleModel_Walk() {
	ctx := context.Background()
	model, _ := wasmib.Load(ctx, "testdata/IF-MIB")

	// Find the interfaces node (1.3.6.1.2.1.2)
	interfaces := model.GetNodeByOID("1.3.6.1.2.1.2")
	if interfaces == nil {
		return
	}

	// Walk depth-first and print table/row structure
	ifID := model.GetNodeID(interfaces)
	model.Walk(ifID, func(n *wasmib.Node) bool {
		if n.Kind == wasmib.NodeKindTable || n.Kind == wasmib.NodeKindRow {
			name := ""
			if len(n.Definitions) > 0 {
				name = model.GetStr(n.Definitions[0].Label)
			}
			fmt.Printf("%s (%s)\n", name, n.Kind)
		}
		// Return false for rows to skip column details
		return n.Kind != wasmib.NodeKindRow
	})
	// Output:
	// ifTable (table)
	// ifEntry (row)
}

func ExampleModel_GetType() {
	ctx := context.Background()
	model, _ := wasmib.Load(ctx, "testdata/IF-MIB")

	node := model.GetNodeByQualifiedName("IF-MIB", "ifDescr")
	obj := model.GetObject(node)
	if obj == nil {
		return
	}

	t := model.GetType(obj.TypeID)
	if t != nil {
		fmt.Printf("Type: %s\n", model.GetStr(t.Name))
		fmt.Printf("Base: %s\n", t.Base)
		fmt.Printf("Is TC: %v\n", t.IsTC)
	}
	// Output:
	// Type: DisplayString
	// Base: OCTET STRING
	// Is TC: true
}

func ExampleModel_GetEffectiveHint() {
	ctx := context.Background()
	model, _ := wasmib.Load(ctx, "testdata/IF-MIB")

	node := model.GetNodeByQualifiedName("IF-MIB", "ifPhysAddress")
	obj := model.GetObject(node)
	if obj == nil {
		return
	}

	// GetEffectiveHint walks the type chain to find the display hint
	hint := model.GetEffectiveHint(obj.TypeID)
	fmt.Printf("Hint: %s\n", hint)
	// Output:
	// Hint: 1x:
}

func ExampleCompiler() {
	ctx := context.Background()

	// Create a compiler for more control
	compiler, err := wasmib.NewCompiler(ctx)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer compiler.Close()

	// Load modules individually
	source := []byte(`
TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises
        FROM SNMPv2-SMI;

testMIB MODULE-IDENTITY
    LAST-UPDATED "202501210000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "test@example.com"
    DESCRIPTION "Test MIB"
    ::= { enterprises 99999 }

testObject OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A test object"
    ::= { testMIB 1 }
END
`)

	if err := compiler.LoadModule(source); err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}

	model, err := compiler.Resolve()
	if err != nil {
		fmt.Printf("Resolve error: %v\n", err)
		return
	}

	node := model.GetNodeByQualifiedName("TEST-MIB", "testObject")
	if node != nil {
		fmt.Printf("Found: %s\n", model.GetOID(node))
	}
	// Output:
	// Found: 1.3.6.1.4.1.99999.1
}

func ExampleNodeKind() {
	ctx := context.Background()
	model, _ := wasmib.Load(ctx, "testdata/IF-MIB")

	// Check node kinds
	ifTable := model.GetNodeByQualifiedName("IF-MIB", "ifTable")
	ifEntry := model.GetNodeByQualifiedName("IF-MIB", "ifEntry")
	ifIndex := model.GetNodeByQualifiedName("IF-MIB", "ifIndex")

	fmt.Printf("ifTable kind: %s (is table: %v)\n", ifTable.Kind, ifTable.Kind == wasmib.NodeKindTable)
	fmt.Printf("ifEntry kind: %s (is row: %v)\n", ifEntry.Kind, ifEntry.Kind == wasmib.NodeKindRow)
	fmt.Printf("ifIndex kind: %s (is column: %v)\n", ifIndex.Kind, ifIndex.Kind == wasmib.NodeKindColumn)
	// Output:
	// ifTable kind: table (is table: true)
	// ifEntry kind: row (is row: true)
	// ifIndex kind: column (is column: true)
}

func ExampleModel_IsComplete() {
	ctx := context.Background()
	// Load IF-MIB with some but not all dependencies
	model, _ := wasmib.Load(ctx, "testdata/IF-MIB")

	// Check resolution status
	if model.IsComplete() {
		fmt.Println("All references resolved")
	} else {
		imports, types, oids, _, _ := model.UnresolvedCounts()
		fmt.Printf("Missing imports: %d, Missing types: %d, Missing OIDs: %d\n",
			imports, types, oids)
	}
	// Output:
	// Missing imports: 2, Missing types: 1, Missing OIDs: 2
}
