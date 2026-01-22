package wasmib

import (
	"errors"
	"fmt"
)

// IndexType represents the type of an index value.
type IndexType uint8

const (
	IndexTypeInteger   IndexType = 0 // INTEGER, Integer32, Unsigned32, etc.
	IndexTypeString    IndexType = 1 // OCTET STRING, DisplayString, etc.
	IndexTypeIpAddress IndexType = 2 // IpAddress (always 4 bytes)
	IndexTypeOID       IndexType = 3 // OBJECT IDENTIFIER
)

func (t IndexType) String() string {
	switch t {
	case IndexTypeInteger:
		return "integer"
	case IndexTypeString:
		return "string"
	case IndexTypeIpAddress:
		return "ipaddress"
	case IndexTypeOID:
		return "oid"
	default:
		return "unknown"
	}
}

// IndexValue represents a decoded or to-be-encoded index value.
type IndexValue struct {
	Type    IndexType // The type of this index value
	Integer uint32    // For IndexTypeInteger
	Bytes   []byte    // For IndexTypeString, IndexTypeIpAddress
	OID     []uint32  // For IndexTypeOID
}

// Common errors for index operations.
var (
	ErrNilRow             = errors.New("row object is nil")
	ErrNoIndex            = errors.New("row has no INDEX clause")
	ErrNotEnoughData      = errors.New("not enough data in OID suffix")
	ErrValueCountMismatch = errors.New("value count does not match index count")
	ErrUnsupportedType    = errors.New("unsupported index type")
	ErrInvalidIpAddress   = errors.New("IpAddress must be exactly 4 bytes")
)

// DecodeIndexOID decodes an OID suffix into typed index values for a table row.
// The row must have an INDEX clause. The suffix is the OID components after
// the row's base OID (i.e., the instance identifier portion).
//
// For example, if ifEntry has OID 1.3.6.1.2.1.2.2.1 and the full instance OID
// is 1.3.6.1.2.1.2.2.1.1.5, the suffix would be []uint32{5} representing ifIndex=5.
func (m *Model) DecodeIndexOID(row *Object, suffix []uint32) ([]IndexValue, error) {
	if row == nil {
		return nil, ErrNilRow
	}
	if row.Index == nil || len(row.Index.Items) == 0 {
		return nil, ErrNoIndex
	}

	values := make([]IndexValue, 0, len(row.Index.Items))
	pos := 0

	for i, item := range row.Index.Items {
		if pos >= len(suffix) && i < len(row.Index.Items) {
			return nil, fmt.Errorf("%w: expected %d indexes, ran out of data at index %d",
				ErrNotEnoughData, len(row.Index.Items), i)
		}

		info, err := m.getIndexColumnInfo(item, i, len(row.Index.Items))
		if err != nil {
			return nil, err
		}

		var val IndexValue
		var consumed int

		switch info.baseType {
		case BaseTypeInteger32, BaseTypeUnsigned32, BaseTypeCounter32,
			BaseTypeGauge32, BaseTypeTimeTicks, BaseTypeCounter64:
			val, consumed, err = decodeInteger(suffix[pos:])

		case BaseTypeIpAddress:
			val, consumed, err = decodeIpAddress(suffix[pos:])

		case BaseTypeOctetString:
			fixedSize := m.getFixedStringSize(info.typ)
			val, consumed, err = decodeOctetString(suffix[pos:], info.implied && info.isLast, fixedSize)

		case BaseTypeObjectIdentifier:
			val, consumed, err = decodeObjectIdentifier(suffix[pos:], info.implied && info.isLast)

		default:
			return nil, fmt.Errorf("index %d: %w: %v", i, ErrUnsupportedType, info.baseType)
		}

		if err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}

		values = append(values, val)
		pos += consumed
	}

	return values, nil
}

// EncodeIndexOID encodes typed index values into an OID suffix for a table row.
// The row must have an INDEX clause. The number of values must match the number
// of indexes defined in the INDEX clause.
func (m *Model) EncodeIndexOID(row *Object, values []IndexValue) ([]uint32, error) {
	if row == nil {
		return nil, ErrNilRow
	}
	if row.Index == nil || len(row.Index.Items) == 0 {
		return nil, ErrNoIndex
	}
	if len(values) != len(row.Index.Items) {
		return nil, fmt.Errorf("%w: got %d values, need %d",
			ErrValueCountMismatch, len(values), len(row.Index.Items))
	}

	var suffix []uint32

	for i, item := range row.Index.Items {
		info, err := m.getIndexColumnInfo(item, i, len(row.Index.Items))
		if err != nil {
			return nil, err
		}

		var components []uint32

		switch info.baseType {
		case BaseTypeInteger32, BaseTypeUnsigned32, BaseTypeCounter32,
			BaseTypeGauge32, BaseTypeTimeTicks, BaseTypeCounter64:
			components, err = encodeInteger(values[i])

		case BaseTypeIpAddress:
			components, err = encodeIpAddress(values[i])

		case BaseTypeOctetString:
			fixedSize := m.getFixedStringSize(info.typ)
			components, err = encodeOctetString(values[i], info.implied && info.isLast, fixedSize)

		case BaseTypeObjectIdentifier:
			components, err = encodeObjectIdentifier(values[i], info.implied && info.isLast)

		default:
			return nil, fmt.Errorf("index %d: %w: %v", i, ErrUnsupportedType, info.baseType)
		}

		if err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}

		suffix = append(suffix, components...)
	}

	return suffix, nil
}

// indexColumnInfo holds resolved information about an index column.
type indexColumnInfo struct {
	node     *Node
	obj      *Object
	typ      *Type
	baseType BaseType
	isLast   bool
	implied  bool
}

// getIndexColumnInfo resolves all type information for an index column.
func (m *Model) getIndexColumnInfo(item IndexItem, idx, total int) (*indexColumnInfo, error) {
	node := m.GetNode(item.Object)
	if node == nil {
		return nil, fmt.Errorf("index %d: cannot find node", idx)
	}
	obj := m.GetObject(node)
	if obj == nil {
		return nil, fmt.Errorf("index %d: cannot find object definition", idx)
	}
	return &indexColumnInfo{
		node:     node,
		obj:      obj,
		typ:      m.GetType(obj.TypeID),
		baseType: m.getEffectiveBaseType(obj.TypeID),
		isLast:   idx == total-1,
		implied:  item.Implied,
	}, nil
}

// getEffectiveBaseType walks up the type chain to find the underlying base type.
func (m *Model) getEffectiveBaseType(typeID uint32) BaseType {
	for typeID != 0 {
		t := m.GetType(typeID)
		if t == nil {
			break
		}
		if t.Base != BaseTypeUnknown {
			return t.Base
		}
		typeID = t.Parent
	}
	return BaseTypeUnknown
}

// getFixedStringSize returns the fixed size if the type has a SIZE constraint
// where min == max (e.g., SIZE (6) or SIZE (6..6)). Returns 0 for variable-length.
func (m *Model) getFixedStringSize(t *Type) int {
	if t == nil {
		return 0
	}

	// Check this type's size constraint
	if t.Size != nil && len(t.Size.Ranges) > 0 {
		// If all ranges have min == max and they're all the same value, it's fixed
		first := t.Size.Ranges[0]
		if first[0] == first[1] && len(t.Size.Ranges) == 1 {
			return int(first[0])
		}
	}

	// Walk up the parent chain
	if t.Parent != 0 {
		parent := m.GetType(t.Parent)
		return m.getFixedStringSize(parent)
	}

	return 0
}

// === Decode helpers ===

func decodeInteger(data []uint32) (IndexValue, int, error) {
	if len(data) < 1 {
		return IndexValue{}, 0, ErrNotEnoughData
	}
	return IndexValue{
		Type:    IndexTypeInteger,
		Integer: data[0],
	}, 1, nil
}

func decodeIpAddress(data []uint32) (IndexValue, int, error) {
	if len(data) < 4 {
		return IndexValue{}, 0, fmt.Errorf("%w: need 4 bytes, have %d", ErrNotEnoughData, len(data))
	}
	bytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		bytes[i] = byte(data[i])
	}
	return IndexValue{
		Type:  IndexTypeIpAddress,
		Bytes: bytes,
	}, 4, nil
}

func decodeOctetString(data []uint32, implied bool, fixedSize int) (IndexValue, int, error) {
	if fixedSize > 0 {
		// Fixed-size string: no length prefix
		if len(data) < fixedSize {
			return IndexValue{}, 0, fmt.Errorf("%w: need %d bytes, have %d",
				ErrNotEnoughData, fixedSize, len(data))
		}
		bytes := make([]byte, fixedSize)
		for i := 0; i < fixedSize; i++ {
			bytes[i] = byte(data[i])
		}
		return IndexValue{
			Type:  IndexTypeString,
			Bytes: bytes,
		}, fixedSize, nil
	}

	if implied {
		// IMPLIED: consume all remaining data (no length prefix)
		bytes := make([]byte, len(data))
		for i, v := range data {
			bytes[i] = byte(v)
		}
		return IndexValue{
			Type:  IndexTypeString,
			Bytes: bytes,
		}, len(data), nil
	}

	// Variable-length with length prefix
	if len(data) < 1 {
		return IndexValue{}, 0, ErrNotEnoughData
	}
	// Validate length before conversion to int to prevent overflow on 32-bit systems
	lengthU := data[0]
	if lengthU > uint32(len(data)-1) {
		return IndexValue{}, 0, fmt.Errorf("%w: length=%d but only %d bytes available",
			ErrNotEnoughData, lengthU, len(data)-1)
	}
	length := int(lengthU)
	bytes := make([]byte, length)
	for i := 0; i < length; i++ {
		bytes[i] = byte(data[1+i])
	}
	return IndexValue{
		Type:  IndexTypeString,
		Bytes: bytes,
	}, 1 + length, nil
}

func decodeObjectIdentifier(data []uint32, implied bool) (IndexValue, int, error) {
	if implied {
		// IMPLIED: consume all remaining data
		oid := make([]uint32, len(data))
		copy(oid, data)
		return IndexValue{
			Type: IndexTypeOID,
			OID:  oid,
		}, len(data), nil
	}

	// Variable-length with length prefix
	if len(data) < 1 {
		return IndexValue{}, 0, ErrNotEnoughData
	}
	// Validate length before conversion to int to prevent overflow on 32-bit systems
	lengthU := data[0]
	if lengthU > uint32(len(data)-1) {
		return IndexValue{}, 0, fmt.Errorf("%w: length=%d but only %d components available",
			ErrNotEnoughData, lengthU, len(data)-1)
	}
	length := int(lengthU)
	oid := make([]uint32, length)
	copy(oid, data[1:1+length])
	return IndexValue{
		Type: IndexTypeOID,
		OID:  oid,
	}, 1 + length, nil
}

// === Encode helpers ===

func encodeInteger(val IndexValue) ([]uint32, error) {
	return []uint32{val.Integer}, nil
}

func encodeIpAddress(val IndexValue) ([]uint32, error) {
	if len(val.Bytes) != 4 {
		return nil, ErrInvalidIpAddress
	}
	result := make([]uint32, 4)
	for i, b := range val.Bytes {
		result[i] = uint32(b)
	}
	return result, nil
}

func encodeOctetString(val IndexValue, implied bool, fixedSize int) ([]uint32, error) {
	if fixedSize > 0 || implied {
		// Fixed-size or IMPLIED: no length prefix
		result := make([]uint32, len(val.Bytes))
		for i, b := range val.Bytes {
			result[i] = uint32(b)
		}
		return result, nil
	}

	// Variable-length with length prefix
	result := make([]uint32, 1+len(val.Bytes))
	result[0] = uint32(len(val.Bytes))
	for i, b := range val.Bytes {
		result[1+i] = uint32(b)
	}
	return result, nil
}

func encodeObjectIdentifier(val IndexValue, implied bool) ([]uint32, error) {
	if implied {
		// IMPLIED: no length prefix
		result := make([]uint32, len(val.OID))
		copy(result, val.OID)
		return result, nil
	}

	// Variable-length with length prefix
	result := make([]uint32, 1+len(val.OID))
	result[0] = uint32(len(val.OID))
	copy(result[1:], val.OID)
	return result, nil
}
