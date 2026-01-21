package wasmib

import (
	"context"
	"testing"
)

// MIB with various index types for testing index encoding/decoding
const testIndexMIB = `
TEST-INDEX-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, Unsigned32, IpAddress, enterprises
        FROM SNMPv2-SMI
    DisplayString
        FROM SNMPv2-TC;

testIndexMIB MODULE-IDENTITY
    LAST-UPDATED "202401010000Z"
    ORGANIZATION "Test Organization"
    CONTACT-INFO "test@example.com"
    DESCRIPTION  "A test MIB for index encoding/decoding"
    ::= { enterprises 99996 }

testIndexObjects OBJECT IDENTIFIER ::= { testIndexMIB 1 }

-- Table with single integer index
intTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF IntEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Table with integer index"
    ::= { testIndexObjects 1 }

intEntry OBJECT-TYPE
    SYNTAX      IntEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Entry with integer index"
    INDEX       { intIndex }
    ::= { intTable 1 }

IntEntry ::= SEQUENCE {
    intIndex   Integer32,
    intValue   Integer32
}

intIndex OBJECT-TYPE
    SYNTAX      Integer32 (1..100)
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Integer index"
    ::= { intEntry 1 }

intValue OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "Value"
    ::= { intEntry 2 }

-- Table with string index (variable length)
strTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF StrEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Table with string index"
    ::= { testIndexObjects 2 }

strEntry OBJECT-TYPE
    SYNTAX      StrEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Entry with string index"
    INDEX       { strIndex }
    ::= { strTable 1 }

StrEntry ::= SEQUENCE {
    strIndex   DisplayString,
    strValue   Integer32
}

strIndex OBJECT-TYPE
    SYNTAX      DisplayString (SIZE (1..32))
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "String index (variable length)"
    ::= { strEntry 1 }

strValue OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "Value"
    ::= { strEntry 2 }

-- Table with IMPLIED string index
impliedStrTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF ImpliedStrEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Table with IMPLIED string index"
    ::= { testIndexObjects 3 }

impliedStrEntry OBJECT-TYPE
    SYNTAX      ImpliedStrEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Entry with IMPLIED string index"
    INDEX       { IMPLIED impliedStrIndex }
    ::= { impliedStrTable 1 }

ImpliedStrEntry ::= SEQUENCE {
    impliedStrIndex   DisplayString,
    impliedStrValue   Integer32
}

impliedStrIndex OBJECT-TYPE
    SYNTAX      DisplayString (SIZE (1..32))
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "IMPLIED string index"
    ::= { impliedStrEntry 1 }

impliedStrValue OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "Value"
    ::= { impliedStrEntry 2 }

-- Table with IpAddress index
ipTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF IpEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Table with IP address index"
    ::= { testIndexObjects 4 }

ipEntry OBJECT-TYPE
    SYNTAX      IpEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Entry with IP address index"
    INDEX       { ipIndex }
    ::= { ipTable 1 }

IpEntry ::= SEQUENCE {
    ipIndex   IpAddress,
    ipValue   Integer32
}

ipIndex OBJECT-TYPE
    SYNTAX      IpAddress
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "IP address index"
    ::= { ipEntry 1 }

ipValue OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "Value"
    ::= { ipEntry 2 }

-- Table with multiple indexes
multiTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF MultiEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Table with multiple indexes"
    ::= { testIndexObjects 5 }

multiEntry OBJECT-TYPE
    SYNTAX      MultiEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Entry with multiple indexes"
    INDEX       { multiIndex1, multiIndex2 }
    ::= { multiTable 1 }

MultiEntry ::= SEQUENCE {
    multiIndex1   Integer32,
    multiIndex2   IpAddress,
    multiValue    Integer32
}

multiIndex1 OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "First index (integer)"
    ::= { multiEntry 1 }

multiIndex2 OBJECT-TYPE
    SYNTAX      IpAddress
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Second index (IP address)"
    ::= { multiEntry 2 }

multiValue OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "Value"
    ::= { multiEntry 3 }

-- Table with multiple indexes including IMPLIED
multiImpliedTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF MultiImpliedEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Table with multiple indexes, last one IMPLIED"
    ::= { testIndexObjects 6 }

multiImpliedEntry OBJECT-TYPE
    SYNTAX      MultiImpliedEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Entry with multiple indexes, last one IMPLIED"
    INDEX       { multiImpIndex1, IMPLIED multiImpIndex2 }
    ::= { multiImpliedTable 1 }

MultiImpliedEntry ::= SEQUENCE {
    multiImpIndex1   Integer32,
    multiImpIndex2   DisplayString,
    multiImpValue    Integer32
}

multiImpIndex1 OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "First index (integer)"
    ::= { multiImpliedEntry 1 }

multiImpIndex2 OBJECT-TYPE
    SYNTAX      DisplayString (SIZE (1..32))
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Second index (IMPLIED string)"
    ::= { multiImpliedEntry 2 }

multiImpValue OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "Value"
    ::= { multiImpliedEntry 3 }

-- Table with fixed-size OCTET STRING index (no length prefix needed)
FixedStrSyntax ::= TEXTUAL-CONVENTION
    STATUS      current
    DESCRIPTION "Fixed 6-byte string (like MAC address)"
    SYNTAX      OCTET STRING (SIZE (6))

fixedStrTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF FixedStrEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Table with fixed-size string index"
    ::= { testIndexObjects 7 }

fixedStrEntry OBJECT-TYPE
    SYNTAX      FixedStrEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Entry with fixed-size string index"
    INDEX       { fixedStrIndex }
    ::= { fixedStrTable 1 }

FixedStrEntry ::= SEQUENCE {
    fixedStrIndex   FixedStrSyntax,
    fixedStrValue   Integer32
}

fixedStrIndex OBJECT-TYPE
    SYNTAX      FixedStrSyntax
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Fixed 6-byte index"
    ::= { fixedStrEntry 1 }

fixedStrValue OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "Value"
    ::= { fixedStrEntry 2 }

END
`

// loadTestIndexModel is a helper to create a model with the test index MIB
func loadTestIndexModel(t *testing.T) *Model {
	t.Helper()
	ctx := context.Background()

	compiler, err := NewCompiler(ctx)
	if err != nil {
		t.Fatalf("NewCompiler failed: %v", err)
	}
	defer compiler.Close()

	if err := compiler.LoadModule([]byte(testIndexMIB)); err != nil {
		t.Fatalf("LoadModule failed: %v", err)
	}

	model, err := compiler.Resolve()
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	return model
}

// === Decode Tests ===

func TestDecodeIndexOID_Integer(t *testing.T) {
	model := loadTestIndexModel(t)

	// Find intEntry row
	rowNodes := model.GetNodesByName("intEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('intEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for intEntry")
	}

	// Decode suffix [42] -> index value 42
	values, err := model.DecodeIndexOID(row, []uint32{42})
	if err != nil {
		t.Fatalf("DecodeIndexOID failed: %v", err)
	}

	if len(values) != 1 {
		t.Fatalf("got %d values, want 1", len(values))
	}

	if values[0].Type != IndexTypeInteger {
		t.Errorf("type = %v, want IndexTypeInteger", values[0].Type)
	}
	if values[0].Integer != 42 {
		t.Errorf("Integer = %d, want 42", values[0].Integer)
	}
}

func TestDecodeIndexOID_String(t *testing.T) {
	model := loadTestIndexModel(t)

	// Find strEntry row
	rowNodes := model.GetNodesByName("strEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('strEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for strEntry")
	}

	// Decode suffix [3, 'a', 'b', 'c'] -> string "abc"
	// Length prefix 3 followed by ASCII bytes
	values, err := model.DecodeIndexOID(row, []uint32{3, 'a', 'b', 'c'})
	if err != nil {
		t.Fatalf("DecodeIndexOID failed: %v", err)
	}

	if len(values) != 1 {
		t.Fatalf("got %d values, want 1", len(values))
	}

	if values[0].Type != IndexTypeString {
		t.Errorf("type = %v, want IndexTypeString", values[0].Type)
	}
	if string(values[0].Bytes) != "abc" {
		t.Errorf("Bytes = %q, want %q", string(values[0].Bytes), "abc")
	}
}

func TestDecodeIndexOID_ImpliedString(t *testing.T) {
	model := loadTestIndexModel(t)

	// Find impliedStrEntry row
	rowNodes := model.GetNodesByName("impliedStrEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('impliedStrEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for impliedStrEntry")
	}

	// Decode suffix ['a', 'b', 'c'] -> string "abc" (no length prefix)
	values, err := model.DecodeIndexOID(row, []uint32{'a', 'b', 'c'})
	if err != nil {
		t.Fatalf("DecodeIndexOID failed: %v", err)
	}

	if len(values) != 1 {
		t.Fatalf("got %d values, want 1", len(values))
	}

	if values[0].Type != IndexTypeString {
		t.Errorf("type = %v, want IndexTypeString", values[0].Type)
	}
	if string(values[0].Bytes) != "abc" {
		t.Errorf("Bytes = %q, want %q", string(values[0].Bytes), "abc")
	}
}

func TestDecodeIndexOID_IpAddress(t *testing.T) {
	model := loadTestIndexModel(t)

	// Find ipEntry row
	rowNodes := model.GetNodesByName("ipEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('ipEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for ipEntry")
	}

	// Decode suffix [192, 168, 1, 100] -> IP 192.168.1.100
	values, err := model.DecodeIndexOID(row, []uint32{192, 168, 1, 100})
	if err != nil {
		t.Fatalf("DecodeIndexOID failed: %v", err)
	}

	if len(values) != 1 {
		t.Fatalf("got %d values, want 1", len(values))
	}

	if values[0].Type != IndexTypeIpAddress {
		t.Errorf("type = %v, want IndexTypeIpAddress", values[0].Type)
	}
	expected := []byte{192, 168, 1, 100}
	if string(values[0].Bytes) != string(expected) {
		t.Errorf("Bytes = %v, want %v", values[0].Bytes, expected)
	}
}

func TestDecodeIndexOID_Multiple(t *testing.T) {
	model := loadTestIndexModel(t)

	// Find multiEntry row
	rowNodes := model.GetNodesByName("multiEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('multiEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for multiEntry")
	}

	// Decode suffix [7, 10, 0, 0, 1] -> integer 7, IP 10.0.0.1
	values, err := model.DecodeIndexOID(row, []uint32{7, 10, 0, 0, 1})
	if err != nil {
		t.Fatalf("DecodeIndexOID failed: %v", err)
	}

	if len(values) != 2 {
		t.Fatalf("got %d values, want 2", len(values))
	}

	// First: integer
	if values[0].Type != IndexTypeInteger {
		t.Errorf("values[0].Type = %v, want IndexTypeInteger", values[0].Type)
	}
	if values[0].Integer != 7 {
		t.Errorf("values[0].Integer = %d, want 7", values[0].Integer)
	}

	// Second: IP address
	if values[1].Type != IndexTypeIpAddress {
		t.Errorf("values[1].Type = %v, want IndexTypeIpAddress", values[1].Type)
	}
	expected := []byte{10, 0, 0, 1}
	if string(values[1].Bytes) != string(expected) {
		t.Errorf("values[1].Bytes = %v, want %v", values[1].Bytes, expected)
	}
}

func TestDecodeIndexOID_MultipleWithImplied(t *testing.T) {
	model := loadTestIndexModel(t)

	// Find multiImpliedEntry row
	rowNodes := model.GetNodesByName("multiImpliedEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('multiImpliedEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for multiImpliedEntry")
	}

	// Decode suffix [42, 't', 'e', 's', 't'] -> integer 42, string "test" (no length prefix)
	values, err := model.DecodeIndexOID(row, []uint32{42, 't', 'e', 's', 't'})
	if err != nil {
		t.Fatalf("DecodeIndexOID failed: %v", err)
	}

	if len(values) != 2 {
		t.Fatalf("got %d values, want 2", len(values))
	}

	// First: integer
	if values[0].Type != IndexTypeInteger {
		t.Errorf("values[0].Type = %v, want IndexTypeInteger", values[0].Type)
	}
	if values[0].Integer != 42 {
		t.Errorf("values[0].Integer = %d, want 42", values[0].Integer)
	}

	// Second: string (IMPLIED)
	if values[1].Type != IndexTypeString {
		t.Errorf("values[1].Type = %v, want IndexTypeString", values[1].Type)
	}
	if string(values[1].Bytes) != "test" {
		t.Errorf("values[1].Bytes = %q, want %q", string(values[1].Bytes), "test")
	}
}

func TestDecodeIndexOID_FixedSizeString(t *testing.T) {
	model := loadTestIndexModel(t)

	// Find fixedStrEntry row
	rowNodes := model.GetNodesByName("fixedStrEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('fixedStrEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for fixedStrEntry")
	}

	// Decode suffix [0x00, 0x11, 0x22, 0x33, 0x44, 0x55] -> 6-byte fixed string (no length prefix)
	values, err := model.DecodeIndexOID(row, []uint32{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	if err != nil {
		t.Fatalf("DecodeIndexOID failed: %v", err)
	}

	if len(values) != 1 {
		t.Fatalf("got %d values, want 1", len(values))
	}

	if values[0].Type != IndexTypeString {
		t.Errorf("type = %v, want IndexTypeString", values[0].Type)
	}
	expected := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	if string(values[0].Bytes) != string(expected) {
		t.Errorf("Bytes = %v, want %v", values[0].Bytes, expected)
	}
}

func TestDecodeIndexOID_EmptySuffix(t *testing.T) {
	model := loadTestIndexModel(t)

	rowNodes := model.GetNodesByName("intEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('intEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for intEntry")
	}

	// Empty suffix should fail (not enough data)
	_, err := model.DecodeIndexOID(row, []uint32{})
	if err == nil {
		t.Error("expected error for empty suffix, got nil")
	}
}

func TestDecodeIndexOID_NilRow(t *testing.T) {
	model := loadTestIndexModel(t)

	_, err := model.DecodeIndexOID(nil, []uint32{42})
	if err == nil {
		t.Error("expected error for nil row, got nil")
	}
}

// === Encode Tests ===

func TestEncodeIndexOID_Integer(t *testing.T) {
	model := loadTestIndexModel(t)

	rowNodes := model.GetNodesByName("intEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('intEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for intEntry")
	}

	// Encode integer 42 -> [42]
	suffix, err := model.EncodeIndexOID(row, []IndexValue{
		{Type: IndexTypeInteger, Integer: 42},
	})
	if err != nil {
		t.Fatalf("EncodeIndexOID failed: %v", err)
	}

	expected := []uint32{42}
	if !equalSlice(suffix, expected) {
		t.Errorf("suffix = %v, want %v", suffix, expected)
	}
}

func TestEncodeIndexOID_String(t *testing.T) {
	model := loadTestIndexModel(t)

	rowNodes := model.GetNodesByName("strEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('strEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for strEntry")
	}

	// Encode string "abc" -> [3, 'a', 'b', 'c']
	suffix, err := model.EncodeIndexOID(row, []IndexValue{
		{Type: IndexTypeString, Bytes: []byte("abc")},
	})
	if err != nil {
		t.Fatalf("EncodeIndexOID failed: %v", err)
	}

	expected := []uint32{3, 'a', 'b', 'c'}
	if !equalSlice(suffix, expected) {
		t.Errorf("suffix = %v, want %v", suffix, expected)
	}
}

func TestEncodeIndexOID_ImpliedString(t *testing.T) {
	model := loadTestIndexModel(t)

	rowNodes := model.GetNodesByName("impliedStrEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('impliedStrEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for impliedStrEntry")
	}

	// Encode string "abc" with IMPLIED -> ['a', 'b', 'c'] (no length prefix)
	suffix, err := model.EncodeIndexOID(row, []IndexValue{
		{Type: IndexTypeString, Bytes: []byte("abc")},
	})
	if err != nil {
		t.Fatalf("EncodeIndexOID failed: %v", err)
	}

	expected := []uint32{'a', 'b', 'c'}
	if !equalSlice(suffix, expected) {
		t.Errorf("suffix = %v, want %v", suffix, expected)
	}
}

func TestEncodeIndexOID_IpAddress(t *testing.T) {
	model := loadTestIndexModel(t)

	rowNodes := model.GetNodesByName("ipEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('ipEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for ipEntry")
	}

	// Encode IP 192.168.1.100 -> [192, 168, 1, 100]
	suffix, err := model.EncodeIndexOID(row, []IndexValue{
		{Type: IndexTypeIpAddress, Bytes: []byte{192, 168, 1, 100}},
	})
	if err != nil {
		t.Fatalf("EncodeIndexOID failed: %v", err)
	}

	expected := []uint32{192, 168, 1, 100}
	if !equalSlice(suffix, expected) {
		t.Errorf("suffix = %v, want %v", suffix, expected)
	}
}

func TestEncodeIndexOID_Multiple(t *testing.T) {
	model := loadTestIndexModel(t)

	rowNodes := model.GetNodesByName("multiEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('multiEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for multiEntry")
	}

	// Encode integer 7 + IP 10.0.0.1 -> [7, 10, 0, 0, 1]
	suffix, err := model.EncodeIndexOID(row, []IndexValue{
		{Type: IndexTypeInteger, Integer: 7},
		{Type: IndexTypeIpAddress, Bytes: []byte{10, 0, 0, 1}},
	})
	if err != nil {
		t.Fatalf("EncodeIndexOID failed: %v", err)
	}

	expected := []uint32{7, 10, 0, 0, 1}
	if !equalSlice(suffix, expected) {
		t.Errorf("suffix = %v, want %v", suffix, expected)
	}
}

func TestEncodeIndexOID_MultipleWithImplied(t *testing.T) {
	model := loadTestIndexModel(t)

	rowNodes := model.GetNodesByName("multiImpliedEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('multiImpliedEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for multiImpliedEntry")
	}

	// Encode integer 42 + IMPLIED string "test" -> [42, 't', 'e', 's', 't']
	suffix, err := model.EncodeIndexOID(row, []IndexValue{
		{Type: IndexTypeInteger, Integer: 42},
		{Type: IndexTypeString, Bytes: []byte("test")},
	})
	if err != nil {
		t.Fatalf("EncodeIndexOID failed: %v", err)
	}

	expected := []uint32{42, 't', 'e', 's', 't'}
	if !equalSlice(suffix, expected) {
		t.Errorf("suffix = %v, want %v", suffix, expected)
	}
}

func TestEncodeIndexOID_FixedSizeString(t *testing.T) {
	model := loadTestIndexModel(t)

	rowNodes := model.GetNodesByName("fixedStrEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('fixedStrEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for fixedStrEntry")
	}

	// Encode 6-byte fixed string -> [0x00, 0x11, 0x22, 0x33, 0x44, 0x55] (no length prefix)
	suffix, err := model.EncodeIndexOID(row, []IndexValue{
		{Type: IndexTypeString, Bytes: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}},
	})
	if err != nil {
		t.Fatalf("EncodeIndexOID failed: %v", err)
	}

	expected := []uint32{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	if !equalSlice(suffix, expected) {
		t.Errorf("suffix = %v, want %v", suffix, expected)
	}
}

func TestEncodeIndexOID_WrongCount(t *testing.T) {
	model := loadTestIndexModel(t)

	rowNodes := model.GetNodesByName("multiEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('multiEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for multiEntry")
	}

	// Provide only 1 value when 2 are required
	_, err := model.EncodeIndexOID(row, []IndexValue{
		{Type: IndexTypeInteger, Integer: 7},
	})
	if err == nil {
		t.Error("expected error for wrong value count, got nil")
	}
}

func TestEncodeIndexOID_NilRow(t *testing.T) {
	model := loadTestIndexModel(t)

	_, err := model.EncodeIndexOID(nil, []IndexValue{
		{Type: IndexTypeInteger, Integer: 42},
	})
	if err == nil {
		t.Error("expected error for nil row, got nil")
	}
}

// === Round-trip Tests ===

func TestIndexOID_RoundTrip_Integer(t *testing.T) {
	model := loadTestIndexModel(t)

	rowNodes := model.GetNodesByName("intEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('intEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for intEntry")
	}

	original := []IndexValue{{Type: IndexTypeInteger, Integer: 12345}}

	suffix, err := model.EncodeIndexOID(row, original)
	if err != nil {
		t.Fatalf("EncodeIndexOID failed: %v", err)
	}

	decoded, err := model.DecodeIndexOID(row, suffix)
	if err != nil {
		t.Fatalf("DecodeIndexOID failed: %v", err)
	}

	if len(decoded) != 1 {
		t.Fatalf("got %d values, want 1", len(decoded))
	}
	if decoded[0].Integer != original[0].Integer {
		t.Errorf("round-trip: got %d, want %d", decoded[0].Integer, original[0].Integer)
	}
}

func TestIndexOID_RoundTrip_String(t *testing.T) {
	model := loadTestIndexModel(t)

	rowNodes := model.GetNodesByName("strEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('strEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for strEntry")
	}

	original := []IndexValue{{Type: IndexTypeString, Bytes: []byte("hello world")}}

	suffix, err := model.EncodeIndexOID(row, original)
	if err != nil {
		t.Fatalf("EncodeIndexOID failed: %v", err)
	}

	decoded, err := model.DecodeIndexOID(row, suffix)
	if err != nil {
		t.Fatalf("DecodeIndexOID failed: %v", err)
	}

	if len(decoded) != 1 {
		t.Fatalf("got %d values, want 1", len(decoded))
	}
	if string(decoded[0].Bytes) != string(original[0].Bytes) {
		t.Errorf("round-trip: got %q, want %q", string(decoded[0].Bytes), string(original[0].Bytes))
	}
}

func TestIndexOID_RoundTrip_Multiple(t *testing.T) {
	model := loadTestIndexModel(t)

	rowNodes := model.GetNodesByName("multiImpliedEntry")
	if len(rowNodes) == 0 {
		t.Fatal("GetNodesByName('multiImpliedEntry') returned empty")
	}
	row := model.GetObject(rowNodes[0])
	if row == nil {
		t.Fatal("GetObject returned nil for multiImpliedEntry")
	}

	original := []IndexValue{
		{Type: IndexTypeInteger, Integer: 999},
		{Type: IndexTypeString, Bytes: []byte("interface-name")},
	}

	suffix, err := model.EncodeIndexOID(row, original)
	if err != nil {
		t.Fatalf("EncodeIndexOID failed: %v", err)
	}

	decoded, err := model.DecodeIndexOID(row, suffix)
	if err != nil {
		t.Fatalf("DecodeIndexOID failed: %v", err)
	}

	if len(decoded) != 2 {
		t.Fatalf("got %d values, want 2", len(decoded))
	}
	if decoded[0].Integer != original[0].Integer {
		t.Errorf("round-trip[0]: got %d, want %d", decoded[0].Integer, original[0].Integer)
	}
	if string(decoded[1].Bytes) != string(original[1].Bytes) {
		t.Errorf("round-trip[1]: got %q, want %q", string(decoded[1].Bytes), string(original[1].Bytes))
	}
}

// helper function
func equalSlice(a, b []uint32) bool {
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
