package wasmib

import (
	"context"
	"testing"
)

// Sample MIB for testing
const testMIB = `
TEST-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises
        FROM SNMPv2-SMI
    DisplayString
        FROM SNMPv2-TC;

testMIB MODULE-IDENTITY
    LAST-UPDATED "202401010000Z"
    ORGANIZATION "Test Organization"
    CONTACT-INFO "test@example.com"
    DESCRIPTION  "A test MIB for wasmib"
    ::= { enterprises 99999 }

testObjects OBJECT IDENTIFIER ::= { testMIB 1 }

testString OBJECT-TYPE
    SYNTAX      DisplayString (SIZE (0..255))
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "A test string object"
    ::= { testObjects 1 }

testInteger OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  read-write
    STATUS      current
    DESCRIPTION "A test integer object"
    DEFVAL      { 42 }
    ::= { testObjects 2 }

testTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF TestEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "A test table"
    ::= { testObjects 3 }

testEntry OBJECT-TYPE
    SYNTAX      TestEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "An entry in the test table"
    INDEX       { testIndex }
    ::= { testTable 1 }

TestEntry ::= SEQUENCE {
    testIndex   Integer32,
    testValue   DisplayString
}

testIndex OBJECT-TYPE
    SYNTAX      Integer32 (1..100)
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Index for the test table"
    ::= { testEntry 1 }

testValue OBJECT-TYPE
    SYNTAX      DisplayString
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "Value in the test table"
    ::= { testEntry 2 }

END
`

// MIB with notification for testing OBJECTS clause
const testNotificationMIB = `
TEST-NOTIF-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, NOTIFICATION-TYPE, Integer32, enterprises
        FROM SNMPv2-SMI
    DisplayString
        FROM SNMPv2-TC;

testNotifMIB MODULE-IDENTITY
    LAST-UPDATED "202401010000Z"
    ORGANIZATION "Test Organization"
    CONTACT-INFO "test@example.com"
    DESCRIPTION  "A test MIB for notification objects"
    ::= { enterprises 99998 }

testNotifObjects OBJECT IDENTIFIER ::= { testNotifMIB 1 }
testNotifEvents OBJECT IDENTIFIER ::= { testNotifMIB 2 }

-- Objects that will be referenced in notifications
notifSeverity OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "Severity level of the notification"
    ::= { testNotifObjects 1 }

notifMessage OBJECT-TYPE
    SYNTAX      DisplayString (SIZE (0..255))
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "Message associated with the notification"
    ::= { testNotifObjects 2 }

notifSource OBJECT-TYPE
    SYNTAX      DisplayString (SIZE (0..255))
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "Source of the notification"
    ::= { testNotifObjects 3 }

-- Notification with multiple objects
testEvent NOTIFICATION-TYPE
    OBJECTS     { notifSeverity, notifMessage, notifSource }
    STATUS      current
    DESCRIPTION "A test notification with three objects"
    ::= { testNotifEvents 1 }

-- Notification with no objects
testEmptyEvent NOTIFICATION-TYPE
    STATUS      current
    DESCRIPTION "A test notification with no objects"
    ::= { testNotifEvents 2 }

END
`

func TestCompilerBasic(t *testing.T) {
	ctx := context.Background()

	compiler, err := NewCompiler(ctx)
	if err != nil {
		t.Fatalf("NewCompiler failed: %v", err)
	}
	defer compiler.Close()

	// Load the test MIB
	if err := compiler.LoadModule([]byte(testMIB)); err != nil {
		t.Fatalf("LoadModule failed: %v", err)
	}

	// Resolve
	model, err := compiler.Resolve()
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// Verify basic structure
	if model.ModuleCount() == 0 {
		t.Error("Expected at least one module")
	}

	if model.NodeCount() == 0 {
		t.Error("Expected nodes to be created")
	}

	t.Logf("Loaded %d modules, %d nodes, %d types, %d objects",
		model.ModuleCount(), model.NodeCount(), model.TypeCount(), model.ObjectCount())
}

func TestModelQueries(t *testing.T) {
	ctx := context.Background()

	compiler, err := NewCompiler(ctx)
	if err != nil {
		t.Fatalf("NewCompiler failed: %v", err)
	}
	defer compiler.Close()

	if err := compiler.LoadModule([]byte(testMIB)); err != nil {
		t.Fatalf("LoadModule failed: %v", err)
	}

	model, err := compiler.Resolve()
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// Test GetModuleByName
	mod := model.GetModuleByName("TEST-MIB")
	if mod == nil {
		t.Error("GetModuleByName('TEST-MIB') returned nil")
	} else {
		name := model.GetStr(mod.Name)
		if name != "TEST-MIB" {
			t.Errorf("Module name = %q, want 'TEST-MIB'", name)
		}
	}

	// Test GetNodesByName
	nodes := model.GetNodesByName("testString")
	if len(nodes) == 0 {
		t.Error("GetNodesByName('testString') returned empty")
	} else {
		node := nodes[0]
		if node.Kind != NodeKindScalar {
			t.Errorf("testString kind = %v, want NodeKindScalar", node.Kind)
		}
	}

	// Test GetNodesByName for table
	tableNodes := model.GetNodesByName("testTable")
	if len(tableNodes) == 0 {
		t.Error("GetNodesByName('testTable') returned empty")
	} else {
		if tableNodes[0].Kind != NodeKindTable {
			t.Errorf("testTable kind = %v, want NodeKindTable", tableNodes[0].Kind)
		}
	}

	// Test GetNodesByName for row
	rowNodes := model.GetNodesByName("testEntry")
	if len(rowNodes) == 0 {
		t.Error("GetNodesByName('testEntry') returned empty")
	} else {
		if rowNodes[0].Kind != NodeKindRow {
			t.Errorf("testEntry kind = %v, want NodeKindRow", rowNodes[0].Kind)
		}
	}

	// Test GetNodeByQualifiedName
	node := model.GetNodeByQualifiedName("TEST-MIB", "testInteger")
	if node == nil {
		t.Error("GetNodeByQualifiedName('TEST-MIB', 'testInteger') returned nil")
	}

	// Test GetObject
	if node != nil {
		obj := model.GetObject(node)
		if obj == nil {
			t.Error("GetObject returned nil for testInteger")
		} else {
			if obj.Access != AccessReadWrite {
				t.Errorf("testInteger access = %v, want AccessReadWrite", obj.Access)
			}
		}
	}
}

func TestNodeKindString(t *testing.T) {
	tests := []struct {
		kind NodeKind
		want string
	}{
		{NodeKindInternal, "internal"},
		{NodeKindNode, "node"},
		{NodeKindScalar, "scalar"},
		{NodeKindTable, "table"},
		{NodeKindRow, "row"},
		{NodeKindColumn, "column"},
		{NodeKindNotification, "notification"},
		{NodeKindGroup, "group"},
		{NodeKindCompliance, "compliance"},
		{NodeKindCapabilities, "capabilities"},
		{NodeKind(255), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("NodeKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

func TestAccessString(t *testing.T) {
	tests := []struct {
		access Access
		want   string
	}{
		{AccessNotAccessible, "not-accessible"},
		{AccessAccessibleForNotify, "accessible-for-notify"},
		{AccessReadOnly, "read-only"},
		{AccessReadWrite, "read-write"},
		{AccessReadCreate, "read-create"},
		{AccessWriteOnly, "write-only"},
		{Access(255), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.access.String(); got != tt.want {
			t.Errorf("Access(%d).String() = %q, want %q", tt.access, got, tt.want)
		}
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		status Status
		want   string
	}{
		{StatusCurrent, "current"},
		{StatusDeprecated, "deprecated"},
		{StatusObsolete, "obsolete"},
		{Status(255), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("Status(%d).String() = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestBaseTypeString(t *testing.T) {
	tests := []struct {
		base BaseType
		want string
	}{
		{BaseTypeInteger32, "INTEGER"},
		{BaseTypeOctetString, "OCTET STRING"},
		{BaseTypeObjectIdentifier, "OBJECT IDENTIFIER"},
		{BaseType(255), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.base.String(); got != tt.want {
			t.Errorf("BaseType(%d).String() = %q, want %q", tt.base, got, tt.want)
		}
	}
}

func TestWalkAll(t *testing.T) {
	ctx := context.Background()

	compiler, err := NewCompiler(ctx)
	if err != nil {
		t.Fatalf("NewCompiler failed: %v", err)
	}
	defer compiler.Close()

	if err := compiler.LoadModule([]byte(testMIB)); err != nil {
		t.Fatalf("LoadModule failed: %v", err)
	}

	model, err := compiler.Resolve()
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// Count nodes via WalkAll
	count := 0
	model.WalkAll(func(n *Node) bool {
		count++
		return true
	})

	if count == 0 {
		t.Error("WalkAll visited no nodes")
	}

	if count != model.NodeCount() {
		t.Errorf("WalkAll visited %d nodes, model has %d", count, model.NodeCount())
	}
}

func TestCompilerReset(t *testing.T) {
	ctx := context.Background()

	compiler, err := NewCompiler(ctx)
	if err != nil {
		t.Fatalf("NewCompiler failed: %v", err)
	}
	defer compiler.Close()

	// Load and resolve
	if err := compiler.LoadModule([]byte(testMIB)); err != nil {
		t.Fatalf("LoadModule failed: %v", err)
	}
	_, err = compiler.Resolve()
	if err != nil {
		t.Fatalf("First Resolve failed: %v", err)
	}

	// Reset
	compiler.Reset()

	// Load and resolve again
	if err := compiler.LoadModule([]byte(testMIB)); err != nil {
		t.Fatalf("LoadModule after reset failed: %v", err)
	}
	model, err := compiler.Resolve()
	if err != nil {
		t.Fatalf("Second Resolve failed: %v", err)
	}

	if model.ModuleCount() == 0 {
		t.Error("Expected modules after reset and reload")
	}
}

func BenchmarkLoad(b *testing.B) {
	ctx := context.Background()
	source := []byte(testMIB)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compiler, err := NewCompiler(ctx)
		if err != nil {
			b.Fatal(err)
		}
		if err := compiler.LoadModule(source); err != nil {
			compiler.Close()
			b.Fatal(err)
		}
		_, err = compiler.Resolve()
		compiler.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQuery(b *testing.B) {
	ctx := context.Background()

	compiler, err := NewCompiler(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer compiler.Close()

	if err := compiler.LoadModule([]byte(testMIB)); err != nil {
		b.Fatal(err)
	}
	model, err := compiler.Resolve()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = model.GetNodesByName("testString")
		_ = model.GetNodeByQualifiedName("TEST-MIB", "testInteger")
	}
}

func TestGetNotificationObjects(t *testing.T) {
	ctx := context.Background()

	compiler, err := NewCompiler(ctx)
	if err != nil {
		t.Fatalf("NewCompiler failed: %v", err)
	}
	defer compiler.Close()

	if err := compiler.LoadModule([]byte(testNotificationMIB)); err != nil {
		t.Fatalf("LoadModule failed: %v", err)
	}

	model, err := compiler.Resolve()
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// Find the testEvent notification node
	eventNodes := model.GetNodesByName("testEvent")
	if len(eventNodes) == 0 {
		t.Fatal("GetNodesByName('testEvent') returned empty")
	}
	eventNode := eventNodes[0]

	if eventNode.Kind != NodeKindNotification {
		t.Errorf("testEvent kind = %v, want NodeKindNotification", eventNode.Kind)
	}

	// Get the notification definition
	notif := model.GetNotification(eventNode)
	if notif == nil {
		t.Fatal("GetNotification returned nil for testEvent")
	}

	// Test GetNotificationObjects
	objects := model.GetNotificationObjects(notif)
	if len(objects) != 3 {
		t.Errorf("GetNotificationObjects returned %d objects, want 3", len(objects))
	}

	// Verify the objects are the correct ones
	expectedNames := []string{"notifSeverity", "notifMessage", "notifSource"}
	for i, node := range objects {
		if node == nil {
			t.Errorf("objects[%d] is nil", i)
			continue
		}
		// Get the name from the node definition
		if len(node.Definitions) == 0 {
			t.Errorf("objects[%d] has no definitions", i)
			continue
		}
		name := model.GetStr(node.Definitions[0].Label)
		if name != expectedNames[i] {
			t.Errorf("objects[%d] name = %q, want %q", i, name, expectedNames[i])
		}
	}
}

func TestGetNotificationObjectsEmpty(t *testing.T) {
	ctx := context.Background()

	compiler, err := NewCompiler(ctx)
	if err != nil {
		t.Fatalf("NewCompiler failed: %v", err)
	}
	defer compiler.Close()

	if err := compiler.LoadModule([]byte(testNotificationMIB)); err != nil {
		t.Fatalf("LoadModule failed: %v", err)
	}

	model, err := compiler.Resolve()
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// Find the testEmptyEvent notification node (has no objects)
	eventNodes := model.GetNodesByName("testEmptyEvent")
	if len(eventNodes) == 0 {
		t.Fatal("GetNodesByName('testEmptyEvent') returned empty")
	}

	notif := model.GetNotification(eventNodes[0])
	if notif == nil {
		t.Fatal("GetNotification returned nil for testEmptyEvent")
	}

	// Test GetNotificationObjects returns empty slice for notification with no objects
	objects := model.GetNotificationObjects(notif)
	if len(objects) != 0 {
		t.Errorf("GetNotificationObjects returned %d objects, want 0", len(objects))
	}
}

func TestGetNotificationObjectsNil(t *testing.T) {
	ctx := context.Background()

	compiler, err := NewCompiler(ctx)
	if err != nil {
		t.Fatalf("NewCompiler failed: %v", err)
	}
	defer compiler.Close()

	if err := compiler.LoadModule([]byte(testMIB)); err != nil {
		t.Fatalf("LoadModule failed: %v", err)
	}

	model, err := compiler.Resolve()
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// Test GetNotificationObjects with nil returns nil
	objects := model.GetNotificationObjects(nil)
	if objects != nil {
		t.Errorf("GetNotificationObjects(nil) returned %v, want nil", objects)
	}
}
