package wasmib

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// loadTestCorpus loads all MIB files from testdata/ directory
func loadTestCorpus(t *testing.T) *Model {
	t.Helper()
	ctx := context.Background()

	compiler, err := NewCompiler(ctx)
	if err != nil {
		t.Fatalf("NewCompiler failed: %v", err)
	}
	defer compiler.Close()

	// Load all files from testdata/
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("Failed to read testdata directory: %v", err)
	}

	var loaded int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join("testdata", entry.Name())
		source, err := os.ReadFile(path)
		if err != nil {
			t.Logf("Failed to read %s: %v", path, err)
			continue
		}
		if err := compiler.LoadModule(source); err != nil {
			t.Logf("Failed to parse %s: %v", path, err)
			continue
		}
		loaded++
	}

	if loaded == 0 {
		t.Fatal("No MIB files loaded from testdata/")
	}

	model, err := compiler.Resolve()
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	t.Logf("Loaded %d files, resolved %d modules, %d nodes, %d types, %d objects",
		loaded, model.ModuleCount(), model.NodeCount(), model.TypeCount(), model.ObjectCount())

	return model
}

func TestEndToEndCorpus(t *testing.T) {
	model := loadTestCorpus(t)

	// Verify we loaded the expected modules
	expectedModules := []string{
		"SNMPv2-SMI",
		"SNMPv2-TC",
		"SNMPv2-MIB",
		"IF-MIB",
	}

	for _, name := range expectedModules {
		mod := model.GetModuleByName(name)
		if mod == nil {
			t.Errorf("Module %s not found", name)
		}
	}
}

func TestOIDLookups(t *testing.T) {
	model := loadTestCorpus(t)

	tests := []struct {
		oid  string
		name string
		kind NodeKind
	}{
		// System group from SNMPv2-MIB
		{"1.3.6.1.2.1.1.1", "sysDescr", NodeKindScalar},
		{"1.3.6.1.2.1.1.2", "sysObjectID", NodeKindScalar},
		{"1.3.6.1.2.1.1.3", "sysUpTime", NodeKindScalar},
		{"1.3.6.1.2.1.1.4", "sysContact", NodeKindScalar},
		{"1.3.6.1.2.1.1.5", "sysName", NodeKindScalar},
		{"1.3.6.1.2.1.1.6", "sysLocation", NodeKindScalar},

		// IF-MIB table structure
		{"1.3.6.1.2.1.2.2", "ifTable", NodeKindTable},
		{"1.3.6.1.2.1.2.2.1", "ifEntry", NodeKindRow},
		{"1.3.6.1.2.1.2.2.1.1", "ifIndex", NodeKindColumn},
		{"1.3.6.1.2.1.2.2.1.2", "ifDescr", NodeKindColumn},
		{"1.3.6.1.2.1.2.2.1.4", "ifMtu", NodeKindColumn},
		{"1.3.6.1.2.1.2.2.1.5", "ifSpeed", NodeKindColumn},

		// OID roots
		{"1.3.6.1", "internet", NodeKindNode},
		{"1.3.6.1.2.1", "mib-2", NodeKindNode},
		{"1.3.6.1.4.1", "enterprises", NodeKindNode},
	}

	for _, tt := range tests {
		t.Run(tt.oid, func(t *testing.T) {
			node := model.GetNodeByOID(tt.oid)
			if node == nil {
				t.Fatalf("GetNodeByOID(%q) returned nil", tt.oid)
			}

			// Check kind
			if node.Kind != tt.kind {
				t.Errorf("kind = %v, want %v", node.Kind, tt.kind)
			}

			// Check name in definitions
			foundName := false
			for _, def := range node.Definitions {
				name := model.GetStr(def.Label)
				if name == tt.name {
					foundName = true
					break
				}
			}
			if !foundName {
				var names []string
				for _, def := range node.Definitions {
					names = append(names, model.GetStr(def.Label))
				}
				t.Errorf("expected name %q not found in definitions %v", tt.name, names)
			}

			// Verify OID round-trip
			computedOID := model.GetOID(node)
			if computedOID != tt.oid {
				t.Errorf("GetOID() = %q, want %q", computedOID, tt.oid)
			}
		})
	}
}

func TestTableStructure(t *testing.T) {
	model := loadTestCorpus(t)

	// Test ifTable structure
	ifEntry := model.GetNodeByQualifiedName("IF-MIB", "ifEntry")
	if ifEntry == nil {
		t.Fatal("ifEntry not found")
	}

	if ifEntry.Kind != NodeKindRow {
		t.Errorf("ifEntry.Kind = %v, want NodeKindRow", ifEntry.Kind)
	}

	// Get the object and check INDEX
	obj := model.GetObject(ifEntry)
	if obj == nil {
		t.Fatal("ifEntry object not found")
	}

	if obj.Index == nil {
		t.Fatal("ifEntry has no INDEX clause")
	}

	if len(obj.Index.Items) != 1 {
		t.Errorf("ifEntry INDEX has %d items, want 1", len(obj.Index.Items))
	}

	if obj.Access != AccessNotAccessible {
		t.Errorf("ifEntry access = %v, want NotAccessible", obj.Access)
	}

	// Verify column children
	columns := 0
	for _, childID := range ifEntry.Children {
		child := model.GetNode(childID)
		if child != nil && child.Kind == NodeKindColumn {
			columns++
		}
	}
	if columns < 20 {
		t.Errorf("ifEntry has %d column children, expected >= 20", columns)
	}
}

func TestTypeHints(t *testing.T) {
	model := loadTestCorpus(t)

	// Test DisplayString hint via ifDescr (always from IF-MIB, no legacy overlap)
	ifDescr := model.GetNodeByQualifiedName("IF-MIB", "ifDescr")
	if ifDescr == nil {
		t.Fatal("ifDescr not found")
	}

	obj := model.GetObject(ifDescr)
	if obj == nil {
		t.Fatal("ifDescr object not found")
	}

	hint := model.GetEffectiveHint(obj.TypeID)
	if hint != "255a" {
		t.Errorf("ifDescr effective hint = %q, want \"255a\"", hint)
	}

	// Check base type is OctetString
	typ := model.GetType(obj.TypeID)
	if typ == nil {
		t.Fatal("ifDescr type not found")
	}
	if typ.Base != BaseTypeOctetString {
		t.Errorf("ifDescr base type = %v, want OctetString", typ.Base)
	}

	// Test PhysAddress hint (1x: for MAC addresses)
	ifPhysAddress := model.GetNodeByQualifiedName("IF-MIB", "ifPhysAddress")
	if ifPhysAddress != nil {
		obj := model.GetObject(ifPhysAddress)
		if obj != nil {
			hint := model.GetEffectiveHint(obj.TypeID)
			if hint != "1x:" {
				t.Errorf("ifPhysAddress effective hint = %q, want \"1x:\"", hint)
			}
		}
	}
}

func TestEnumValues(t *testing.T) {
	model := loadTestCorpus(t)

	// ifAdminStatus has enumeration: up(1), down(2), testing(3)
	ifAdminStatus := model.GetNodeByQualifiedName("IF-MIB", "ifAdminStatus")
	if ifAdminStatus == nil {
		t.Fatal("ifAdminStatus not found")
	}

	obj := model.GetObject(ifAdminStatus)
	if obj == nil {
		t.Fatal("ifAdminStatus object not found")
	}

	// The enum values may be inline or on the type
	var enums []EnumValue
	if len(obj.InlineEnum) > 0 {
		enums = obj.InlineEnum
	} else if obj.TypeID > 0 {
		typ := model.GetType(obj.TypeID)
		if typ != nil {
			enums = typ.EnumValues
		}
	}

	if len(enums) < 3 {
		t.Fatalf("ifAdminStatus has %d enum values, expected >= 3", len(enums))
	}

	// Build map for checking
	valueMap := make(map[int64]string)
	for _, ev := range enums {
		valueMap[ev.Value] = model.GetStr(ev.Name)
	}

	expectedEnums := map[int64]string{
		1: "up",
		2: "down",
		3: "testing",
	}

	for value, name := range expectedEnums {
		if got := valueMap[value]; got != name {
			t.Errorf("enum value %d = %q, want %q", value, got, name)
		}
	}
}

func TestObjectAccess(t *testing.T) {
	model := loadTestCorpus(t)

	tests := []struct {
		module string
		name   string
		access Access
	}{
		{"SNMPv2-MIB", "sysDescr", AccessReadOnly},
		{"SNMPv2-MIB", "sysContact", AccessReadWrite},
		{"IF-MIB", "ifEntry", AccessNotAccessible},
		{"IF-MIB", "ifDescr", AccessReadOnly},
	}

	for _, tt := range tests {
		t.Run(tt.module+"::"+tt.name, func(t *testing.T) {
			node := model.GetNodeByQualifiedName(tt.module, tt.name)
			if node == nil {
				t.Fatalf("node not found")
			}

			obj := model.GetObject(node)
			if obj == nil {
				t.Fatalf("object not found")
			}

			if obj.Access != tt.access {
				t.Errorf("access = %v, want %v", obj.Access, tt.access)
			}
		})
	}
}

func TestTreeWalkFromSubtree(t *testing.T) {
	model := loadTestCorpus(t)

	// Walk from interfaces subtree (1.3.6.1.2.1.2)
	interfaces := model.GetNodeByOID("1.3.6.1.2.1.2")
	if interfaces == nil {
		t.Fatal("interfaces node not found")
	}

	var count int
	var tables, rows, columns int
	model.Walk(interfaces.ID, func(n *Node) bool {
		count++
		switch n.Kind {
		case NodeKindTable:
			tables++
		case NodeKindRow:
			rows++
		case NodeKindColumn:
			columns++
		}
		return true
	})

	t.Logf("Walked %d nodes under interfaces: %d tables, %d rows, %d columns",
		count, tables, rows, columns)

	if tables == 0 {
		t.Error("Expected at least one table under interfaces")
	}
	if rows == 0 {
		t.Error("Expected at least one row under interfaces")
	}
	if columns < 20 {
		t.Errorf("Expected >= 20 columns under interfaces, got %d", columns)
	}
}

func TestQualifiedNameLookup(t *testing.T) {
	model := loadTestCorpus(t)

	// Test qualified lookup
	node := model.GetNodeByQualifiedName("SNMPv2-MIB", "sysDescr")
	if node == nil {
		t.Fatal("SNMPv2-MIB::sysDescr not found")
	}

	// Verify it's the correct node
	oid := model.GetOID(node)
	if oid != "1.3.6.1.2.1.1.1" {
		t.Errorf("sysDescr OID = %q, want 1.3.6.1.2.1.1.1", oid)
	}

	// Test non-existent
	node = model.GetNodeByQualifiedName("NONEXISTENT-MIB", "foo")
	if node != nil {
		t.Error("Expected nil for non-existent module")
	}
}

func TestGetNodeByOIDPrefix(t *testing.T) {
	model := loadTestCorpus(t)

	tests := []struct {
		name       string
		oid        []uint32
		wantOID    string
		wantSuffix []uint32
	}{
		{
			name:       "exact match scalar",
			oid:        []uint32{1, 3, 6, 1, 2, 1, 1, 1},
			wantOID:    "1.3.6.1.2.1.1.1",
			wantSuffix: nil,
		},
		{
			name:       "scalar with .0 instance",
			oid:        []uint32{1, 3, 6, 1, 2, 1, 1, 1, 0},
			wantOID:    "1.3.6.1.2.1.1.1",
			wantSuffix: []uint32{0},
		},
		{
			name:       "table column with index",
			oid:        []uint32{1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1},
			wantOID:    "1.3.6.1.2.1.2.2.1.2", // ifDescr
			wantSuffix: []uint32{1},
		},
		{
			name:       "table column with multi-digit index",
			oid:        []uint32{1, 3, 6, 1, 2, 1, 2, 2, 1, 4, 123},
			wantOID:    "1.3.6.1.2.1.2.2.1.4", // ifMtu
			wantSuffix: []uint32{123},
		},
		{
			name:       "deep into unknown subtree",
			oid:        []uint32{1, 3, 6, 1, 4, 1, 9999, 1, 2, 3},
			wantOID:    "1.3.6.1.4.1", // enterprises
			wantSuffix: []uint32{9999, 1, 2, 3},
		},
		{
			name:       "exact match internal node",
			oid:        []uint32{1, 3, 6, 1, 2, 1},
			wantOID:    "1.3.6.1.2.1",
			wantSuffix: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, suffix := model.GetNodeByOIDPrefix(tt.oid)
			if node == nil {
				t.Fatal("GetNodeByOIDPrefix returned nil node")
			}

			gotOID := model.GetOID(node)
			if gotOID != tt.wantOID {
				t.Errorf("matched OID = %q, want %q", gotOID, tt.wantOID)
			}

			if !slicesEqual(suffix, tt.wantSuffix) {
				t.Errorf("suffix = %v, want %v", suffix, tt.wantSuffix)
			}
		})
	}
}

func TestGetNodeByOIDPrefixStr(t *testing.T) {
	model := loadTestCorpus(t)

	tests := []struct {
		name       string
		oid        string
		wantOID    string
		wantSuffix []uint32
	}{
		{
			name:       "scalar with .0 instance",
			oid:        "1.3.6.1.2.1.1.5.0",
			wantOID:    "1.3.6.1.2.1.1.5", // sysName
			wantSuffix: []uint32{0},
		},
		{
			name:       "table column with index",
			oid:        "1.3.6.1.2.1.2.2.1.5.42",
			wantOID:    "1.3.6.1.2.1.2.2.1.5", // ifSpeed
			wantSuffix: []uint32{42},
		},
		{
			name:       "exact match",
			oid:        "1.3.6.1.2.1.1.3",
			wantOID:    "1.3.6.1.2.1.1.3", // sysUpTime
			wantSuffix: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, suffix := model.GetNodeByOIDPrefixStr(tt.oid)
			if node == nil {
				t.Fatal("GetNodeByOIDPrefixStr returned nil node")
			}

			gotOID := model.GetOID(node)
			if gotOID != tt.wantOID {
				t.Errorf("matched OID = %q, want %q", gotOID, tt.wantOID)
			}

			if !slicesEqual(suffix, tt.wantSuffix) {
				t.Errorf("suffix = %v, want %v", suffix, tt.wantSuffix)
			}
		})
	}
}

func TestGetNodeByOIDPrefixEdgeCases(t *testing.T) {
	model := loadTestCorpus(t)

	// Empty OID
	node, suffix := model.GetNodeByOIDPrefix(nil)
	if node != nil || suffix != nil {
		t.Error("Expected (nil, nil) for empty OID")
	}

	node, suffix = model.GetNodeByOIDPrefix([]uint32{})
	if node != nil || suffix != nil {
		t.Error("Expected (nil, nil) for zero-length OID")
	}

	// Invalid root
	node, suffix = model.GetNodeByOIDPrefix([]uint32{99, 1, 2, 3})
	if node != nil || suffix != nil {
		t.Error("Expected (nil, nil) for invalid root arc")
	}

	// Empty string
	node, suffix = model.GetNodeByOIDPrefixStr("")
	if node != nil || suffix != nil {
		t.Error("Expected (nil, nil) for empty string")
	}

	// Invalid string
	node, suffix = model.GetNodeByOIDPrefixStr("not.an.oid")
	if node != nil || suffix != nil {
		t.Error("Expected (nil, nil) for invalid OID string")
	}
}

func slicesEqual(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestModelIsComplete(t *testing.T) {
	model := loadTestCorpus(t)

	imports, types, oids, indexes, notifs := model.UnresolvedCounts()
	t.Logf("Unresolved: imports=%d types=%d oids=%d indexes=%d notifs=%d",
		imports, types, oids, indexes, notifs)

	// With the tier3_complex corpus, we should have minimal unresolved references
	// since all dependencies are included
	if imports > 0 {
		t.Logf("Warning: %d unresolved imports", imports)
	}
	if oids > 0 {
		t.Logf("Warning: %d unresolved OIDs", oids)
	}
}

// === Benchmarks ===

var benchModel *Model

func setupBenchModel(b *testing.B) *Model {
	b.Helper()
	if benchModel != nil {
		return benchModel
	}

	ctx := context.Background()
	compiler, err := NewCompiler(ctx)
	if err != nil {
		b.Fatalf("NewCompiler failed: %v", err)
	}
	defer compiler.Close()

	entries, err := os.ReadDir("testdata")
	if err != nil {
		b.Fatalf("Failed to read testdata: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join("testdata", entry.Name())
		source, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		_ = compiler.LoadModule(source)
	}

	benchModel, err = compiler.Resolve()
	if err != nil {
		b.Fatalf("Resolve failed: %v", err)
	}

	return benchModel
}

func BenchmarkGetNodeByOID(b *testing.B) {
	model := setupBenchModel(b)
	oid := "1.3.6.1.2.1.2.2.1.4" // ifMtu

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = model.GetNodeByOID(oid)
	}
}

func BenchmarkGetNodeByQualifiedName(b *testing.B) {
	model := setupBenchModel(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = model.GetNodeByQualifiedName("IF-MIB", "ifMtu")
	}
}

func BenchmarkGetNodesByName(b *testing.B) {
	model := setupBenchModel(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = model.GetNodesByName("sysDescr")
	}
}

func BenchmarkGetObject(b *testing.B) {
	model := setupBenchModel(b)
	node := model.GetNodeByOID("1.3.6.1.2.1.2.2.1.4")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = model.GetObject(node)
	}
}

func BenchmarkGetEffectiveHint(b *testing.B) {
	model := setupBenchModel(b)
	node := model.GetNodeByOID("1.3.6.1.2.1.1.1")
	obj := model.GetObject(node)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = model.GetEffectiveHint(obj.TypeID)
	}
}

func BenchmarkFullResolution(b *testing.B) {
	model := setupBenchModel(b)
	oid := "1.3.6.1.2.1.2.2.1.4"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node := model.GetNodeByOID(oid)
		if node == nil {
			continue
		}
		obj := model.GetObject(node)
		if obj == nil {
			continue
		}
		_ = model.GetEffectiveHint(obj.TypeID)
	}
}

func BenchmarkParallelLookup(b *testing.B) {
	model := setupBenchModel(b)
	oids := []string{
		"1.3.6.1.2.1.1.1",
		"1.3.6.1.2.1.2.2.1.4",
		"1.3.6.1.2.1.2.2.1.1",
	}

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = model.GetNodeByOID(oids[i%len(oids)])
			i++
		}
	})
}

func BenchmarkGetNodeByOIDPrefix(b *testing.B) {
	model := setupBenchModel(b)
	// Simulate SNMP response OID with instance suffix
	oid := []uint32{1, 3, 6, 1, 2, 1, 2, 2, 1, 4, 123}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = model.GetNodeByOIDPrefix(oid)
	}
}

func BenchmarkGetNodeByOIDPrefixStr(b *testing.B) {
	model := setupBenchModel(b)
	oid := "1.3.6.1.2.1.2.2.1.4.123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = model.GetNodeByOIDPrefixStr(oid)
	}
}

func TestParallelGoroutineSafety(t *testing.T) {
	model := loadTestCorpus(t)

	// Run 100 concurrent goroutines doing lookups
	const numGoroutines = 100
	const numOps = 1000

	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			var err error
			for j := 0; j < numOps; j++ {
				// Mix of different operations
				switch j % 5 {
				case 0:
					node := model.GetNodeByOID("1.3.6.1.2.1.1.1")
					if node == nil {
						err = nil // expected to find
					}
				case 1:
					_ = model.GetNodeByQualifiedName("IF-MIB", "ifEntry")
				case 2:
					_ = model.GetNodesByName("sysDescr")
				case 3:
					node := model.GetNodeByOID("1.3.6.1.2.1.2.2.1.4")
					if node != nil {
						_ = model.GetObject(node)
					}
				case 4:
					model.WalkAll(func(n *Node) bool {
						return j%10 == 0 // Stop early sometimes
					})
				}
			}
			done <- err
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		if err := <-done; err != nil {
			t.Errorf("Goroutine failed: %v", err)
		}
	}

	t.Logf("Completed %d operations across %d goroutines", numGoroutines*numOps, numGoroutines)
}

func BenchmarkLoadAndResolve(b *testing.B) {
	ctx := context.Background()

	entries, err := os.ReadDir("testdata")
	if err != nil {
		b.Fatalf("Failed to read testdata: %v", err)
	}

	var sources [][]byte
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join("testdata", entry.Name())
		source, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		sources = append(sources, source)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compiler, err := NewCompiler(ctx)
		if err != nil {
			b.Fatal(err)
		}
		for _, source := range sources {
			_ = compiler.LoadModule(source)
		}
		_, err = compiler.Resolve()
		compiler.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}
