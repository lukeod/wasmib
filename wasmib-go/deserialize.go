package wasmib

import (
	"errors"
	"fmt"
	"io"
)

var (
	// ErrUnexpectedEOF is returned when the data ends unexpectedly.
	ErrUnexpectedEOF = errors.New("unexpected end of data")
	// ErrVarintOverflow is returned when a varint is too large.
	ErrVarintOverflow = errors.New("varint overflow")
	// ErrUnsupportedVersion is returned when the schema version is not supported.
	ErrUnsupportedVersion = errors.New("unsupported schema version")
)

const (
	schemaVersion = 1
)

// Deserialize parses a postcard-encoded SerializedModel.
func Deserialize(data []byte) (*Model, error) {
	r := &postcardReader{data: data}

	// Read version
	version, err := r.readU32()
	if err != nil {
		return nil, fmt.Errorf("reading version: %w", err)
	}
	if version != schemaVersion {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrUnsupportedVersion, version, schemaVersion)
	}

	// Read fingerprint (Option<[u8; 32]>)
	hasFingerprint, err := r.readBool()
	if err != nil {
		return nil, fmt.Errorf("reading fingerprint flag: %w", err)
	}
	if hasFingerprint {
		if err := r.skip(32); err != nil {
			return nil, fmt.Errorf("skipping fingerprint: %w", err)
		}
	}

	// Read strings_data
	stringsData, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("reading strings_data: %w", err)
	}

	// Read strings_offsets
	offsetCount, err := r.readU32()
	if err != nil {
		return nil, fmt.Errorf("reading strings_offsets count: %w", err)
	}
	stringsOffsets := make([][2]uint32, offsetCount)
	for i := uint32(0); i < offsetCount; i++ {
		start, err := r.readU32()
		if err != nil {
			return nil, fmt.Errorf("reading string offset start: %w", err)
		}
		end, err := r.readU32()
		if err != nil {
			return nil, fmt.Errorf("reading string offset end: %w", err)
		}
		stringsOffsets[i] = [2]uint32{start, end}
	}

	// Build string table
	strings := make([]string, len(stringsOffsets))
	for i, offsets := range stringsOffsets {
		if int(offsets[1]) <= len(stringsData) && offsets[0] <= offsets[1] {
			strings[i] = stringsData[offsets[0]:offsets[1]]
		}
	}

	// Read modules
	modules, err := readModules(r)
	if err != nil {
		return nil, fmt.Errorf("reading modules: %w", err)
	}

	// Read nodes
	nodes, err := readNodes(r)
	if err != nil {
		return nil, fmt.Errorf("reading nodes: %w", err)
	}

	// Read types
	types, err := readTypes(r)
	if err != nil {
		return nil, fmt.Errorf("reading types: %w", err)
	}

	// Read objects
	objects, err := readObjects(r)
	if err != nil {
		return nil, fmt.Errorf("reading objects: %w", err)
	}

	// Read notifications
	notifications, err := readNotifications(r)
	if err != nil {
		return nil, fmt.Errorf("reading notifications: %w", err)
	}

	// Read roots
	rootCount, err := r.readU32()
	if err != nil {
		return nil, fmt.Errorf("reading roots count: %w", err)
	}
	roots := make([]uint32, rootCount)
	for i := uint32(0); i < rootCount; i++ {
		roots[i], err = r.readU32()
		if err != nil {
			return nil, fmt.Errorf("reading root: %w", err)
		}
	}

	// Read unresolved counts
	unresolvedImports, err := r.readU32()
	if err != nil {
		return nil, fmt.Errorf("reading unresolved_imports: %w", err)
	}
	unresolvedTypes, err := r.readU32()
	if err != nil {
		return nil, fmt.Errorf("reading unresolved_types: %w", err)
	}
	unresolvedOids, err := r.readU32()
	if err != nil {
		return nil, fmt.Errorf("reading unresolved_oids: %w", err)
	}
	unresolvedIndexes, err := r.readU32()
	if err != nil {
		return nil, fmt.Errorf("reading unresolved_indexes: %w", err)
	}
	unresolvedNotifObjects, err := r.readU32()
	if err != nil {
		return nil, fmt.Errorf("reading unresolved_notification_objects: %w", err)
	}

	m := &Model{
		version:                       version,
		strings:                       strings,
		modules:                       modules,
		nodes:                         nodes,
		types:                         types,
		objects:                       objects,
		notifications:                 notifications,
		roots:                         roots,
		unresolvedImports:             unresolvedImports,
		unresolvedTypes:               unresolvedTypes,
		unresolvedOids:                unresolvedOids,
		unresolvedIndexes:             unresolvedIndexes,
		unresolvedNotificationObjects: unresolvedNotifObjects,
	}

	m.buildIndices()
	return m, nil
}

func readModules(r *postcardReader) ([]Module, error) {
	count, err := r.readU32()
	if err != nil {
		return nil, err
	}
	modules := make([]Module, count)
	for i := uint32(0); i < count; i++ {
		mod, err := readModule(r)
		if err != nil {
			return nil, err
		}
		modules[i] = mod
	}
	return modules, nil
}

func readModule(r *postcardReader) (Module, error) {
	var m Module
	var err error

	m.Name, err = r.readU32()
	if err != nil {
		return m, err
	}
	m.LastUpdated, err = r.readU32()
	if err != nil {
		return m, err
	}
	m.ContactInfo, err = r.readU32()
	if err != nil {
		return m, err
	}
	m.Organization, err = r.readU32()
	if err != nil {
		return m, err
	}
	m.Description, err = r.readU32()
	if err != nil {
		return m, err
	}

	// Revisions
	revCount, err := r.readU32()
	if err != nil {
		return m, err
	}
	m.Revisions = make([]Revision, revCount)
	for i := uint32(0); i < revCount; i++ {
		m.Revisions[i].Date, err = r.readU32()
		if err != nil {
			return m, err
		}
		m.Revisions[i].Description, err = r.readU32()
		if err != nil {
			return m, err
		}
	}

	return m, nil
}

func readNodes(r *postcardReader) ([]Node, error) {
	count, err := r.readU32()
	if err != nil {
		return nil, err
	}
	nodes := make([]Node, count)
	for i := uint32(0); i < count; i++ {
		node, err := readNode(r)
		if err != nil {
			return nil, err
		}
		nodes[i] = node
	}
	return nodes, nil
}

func readNode(r *postcardReader) (Node, error) {
	var n Node
	var err error

	n.Subid, err = r.readU32()
	if err != nil {
		return n, err
	}
	n.Parent, err = r.readU32()
	if err != nil {
		return n, err
	}

	// Children
	childCount, err := r.readU32()
	if err != nil {
		return n, err
	}
	n.Children = make([]uint32, childCount)
	for i := uint32(0); i < childCount; i++ {
		n.Children[i], err = r.readU32()
		if err != nil {
			return n, err
		}
	}

	// Kind
	kind, err := r.readU8()
	if err != nil {
		return n, err
	}
	n.Kind = NodeKind(kind)

	// Definitions
	defCount, err := r.readU32()
	if err != nil {
		return n, err
	}
	n.Definitions = make([]NodeDef, defCount)
	for i := uint32(0); i < defCount; i++ {
		n.Definitions[i], err = readNodeDef(r)
		if err != nil {
			return n, err
		}
	}

	return n, nil
}

func readNodeDef(r *postcardReader) (NodeDef, error) {
	var d NodeDef
	var err error

	d.Module, err = r.readU32()
	if err != nil {
		return d, err
	}
	d.Label, err = r.readU32()
	if err != nil {
		return d, err
	}
	d.Object, err = r.readU32()
	if err != nil {
		return d, err
	}
	d.Notification, err = r.readU32()
	if err != nil {
		return d, err
	}

	return d, nil
}

func readTypes(r *postcardReader) ([]Type, error) {
	count, err := r.readU32()
	if err != nil {
		return nil, err
	}
	types := make([]Type, count)
	for i := uint32(0); i < count; i++ {
		t, err := readType(r)
		if err != nil {
			return nil, err
		}
		types[i] = t
	}
	return types, nil
}

func readType(r *postcardReader) (Type, error) {
	var t Type
	var err error

	t.Module, err = r.readU32()
	if err != nil {
		return t, err
	}
	t.Name, err = r.readU32()
	if err != nil {
		return t, err
	}

	base, err := r.readU8()
	if err != nil {
		return t, err
	}
	t.Base = BaseType(base)

	t.Parent, err = r.readU32()
	if err != nil {
		return t, err
	}

	status, err := r.readU8()
	if err != nil {
		return t, err
	}
	t.Status = Status(status)

	t.IsTC, err = r.readBool()
	if err != nil {
		return t, err
	}
	t.Hint, err = r.readU32()
	if err != nil {
		return t, err
	}
	t.Description, err = r.readU32()
	if err != nil {
		return t, err
	}

	// Size constraint (Option)
	t.Size, err = readOptionalConstraint(r)
	if err != nil {
		return t, err
	}

	// Range constraint (Option)
	t.Range, err = readOptionalConstraint(r)
	if err != nil {
		return t, err
	}

	// Enum values (Option<Vec>)
	t.EnumValues, err = readOptionalEnumValues(r)
	if err != nil {
		return t, err
	}

	// Bit defs (Option<Vec>)
	t.BitDefs, err = readOptionalBitDefs(r)
	if err != nil {
		return t, err
	}

	return t, nil
}

func readOptionalConstraint(r *postcardReader) (*Constraint, error) {
	hasConstraint, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if !hasConstraint {
		return nil, nil
	}

	rangeCount, err := r.readU32()
	if err != nil {
		return nil, err
	}
	ranges := make([][2]int64, rangeCount)
	for i := uint32(0); i < rangeCount; i++ {
		min, err := r.readI64()
		if err != nil {
			return nil, err
		}
		max, err := r.readI64()
		if err != nil {
			return nil, err
		}
		ranges[i] = [2]int64{min, max}
	}

	return &Constraint{Ranges: ranges}, nil
}

func readOptionalEnumValues(r *postcardReader) ([]EnumValue, error) {
	hasValues, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if !hasValues {
		return nil, nil
	}

	count, err := r.readU32()
	if err != nil {
		return nil, err
	}
	values := make([]EnumValue, count)
	for i := uint32(0); i < count; i++ {
		val, err := r.readI64()
		if err != nil {
			return nil, err
		}
		name, err := r.readU32()
		if err != nil {
			return nil, err
		}
		values[i] = EnumValue{Value: val, Name: name}
	}
	return values, nil
}

func readOptionalBitDefs(r *postcardReader) ([]BitDef, error) {
	hasDefs, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if !hasDefs {
		return nil, nil
	}

	count, err := r.readU32()
	if err != nil {
		return nil, err
	}
	defs := make([]BitDef, count)
	for i := uint32(0); i < count; i++ {
		pos, err := r.readU32()
		if err != nil {
			return nil, err
		}
		name, err := r.readU32()
		if err != nil {
			return nil, err
		}
		defs[i] = BitDef{Position: pos, Name: name}
	}
	return defs, nil
}

func readObjects(r *postcardReader) ([]Object, error) {
	count, err := r.readU32()
	if err != nil {
		return nil, err
	}
	objects := make([]Object, count)
	for i := uint32(0); i < count; i++ {
		obj, err := readObject(r)
		if err != nil {
			return nil, err
		}
		objects[i] = obj
	}
	return objects, nil
}

func readObject(r *postcardReader) (Object, error) {
	var o Object
	var err error

	o.Node, err = r.readU32()
	if err != nil {
		return o, err
	}
	o.Module, err = r.readU32()
	if err != nil {
		return o, err
	}
	o.Name, err = r.readU32()
	if err != nil {
		return o, err
	}
	o.TypeID, err = r.readU32()
	if err != nil {
		return o, err
	}

	access, err := r.readU8()
	if err != nil {
		return o, err
	}
	o.Access = Access(access)

	status, err := r.readU8()
	if err != nil {
		return o, err
	}
	o.Status = Status(status)

	o.Description, err = r.readU32()
	if err != nil {
		return o, err
	}
	o.Units, err = r.readU32()
	if err != nil {
		return o, err
	}
	o.Reference, err = r.readU32()
	if err != nil {
		return o, err
	}

	// Index (Option)
	o.Index, err = readOptionalIndex(r)
	if err != nil {
		return o, err
	}

	o.Augments, err = r.readU32()
	if err != nil {
		return o, err
	}

	// DefVal (Option)
	o.DefVal, err = readOptionalDefVal(r)
	if err != nil {
		return o, err
	}

	// InlineEnum (Option<Vec>)
	o.InlineEnum, err = readOptionalEnumValues(r)
	if err != nil {
		return o, err
	}

	// InlineBits (Option<Vec>)
	o.InlineBits, err = readOptionalBitDefs(r)
	if err != nil {
		return o, err
	}

	return o, nil
}

func readOptionalIndex(r *postcardReader) (*IndexSpec, error) {
	hasIndex, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if !hasIndex {
		return nil, nil
	}

	itemCount, err := r.readU32()
	if err != nil {
		return nil, err
	}
	items := make([]IndexItem, itemCount)
	for i := uint32(0); i < itemCount; i++ {
		obj, err := r.readU32()
		if err != nil {
			return nil, err
		}
		implied, err := r.readBool()
		if err != nil {
			return nil, err
		}
		items[i] = IndexItem{Object: obj, Implied: implied}
	}

	return &IndexSpec{Items: items}, nil
}

func readOptionalDefVal(r *postcardReader) (*DefVal, error) {
	hasDefVal, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if !hasDefVal {
		return nil, nil
	}

	kind, err := r.readU8()
	if err != nil {
		return nil, err
	}

	d := &DefVal{Kind: DefValKind(kind)}

	// int_val (Option<i64>)
	hasIntVal, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if hasIntVal {
		d.IntVal, err = r.readI64()
		if err != nil {
			return nil, err
		}
	}

	// uint_val (Option<u64>)
	hasUintVal, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if hasUintVal {
		d.UintVal, err = r.readU64()
		if err != nil {
			return nil, err
		}
	}

	// str_val (Option<u32>)
	hasStrVal, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if hasStrVal {
		d.StrID, err = r.readU32()
		if err != nil {
			return nil, err
		}
	}

	// raw_str (Option<String>)
	hasRawStr, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if hasRawStr {
		d.RawStr, err = r.readString()
		if err != nil {
			return nil, err
		}
	}

	// node_val (Option<u32>)
	hasNodeVal, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if hasNodeVal {
		d.NodeID, err = r.readU32()
		if err != nil {
			return nil, err
		}
	}

	// bits_val (Option<Vec<u32>>)
	hasBitsVal, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if hasBitsVal {
		bitsCount, err := r.readU32()
		if err != nil {
			return nil, err
		}
		d.BitsVals = make([]uint32, bitsCount)
		for i := uint32(0); i < bitsCount; i++ {
			d.BitsVals[i], err = r.readU32()
			if err != nil {
				return nil, err
			}
		}
	}

	return d, nil
}

func readNotifications(r *postcardReader) ([]Notification, error) {
	count, err := r.readU32()
	if err != nil {
		return nil, err
	}
	notifs := make([]Notification, count)
	for i := uint32(0); i < count; i++ {
		n, err := readNotification(r)
		if err != nil {
			return nil, err
		}
		notifs[i] = n
	}
	return notifs, nil
}

func readNotification(r *postcardReader) (Notification, error) {
	var n Notification
	var err error

	n.Node, err = r.readU32()
	if err != nil {
		return n, err
	}
	n.Module, err = r.readU32()
	if err != nil {
		return n, err
	}
	n.Name, err = r.readU32()
	if err != nil {
		return n, err
	}

	status, err := r.readU8()
	if err != nil {
		return n, err
	}
	n.Status = Status(status)

	n.Description, err = r.readU32()
	if err != nil {
		return n, err
	}
	n.Reference, err = r.readU32()
	if err != nil {
		return n, err
	}

	// Objects
	objCount, err := r.readU32()
	if err != nil {
		return n, err
	}
	n.Objects = make([]uint32, objCount)
	for i := uint32(0); i < objCount; i++ {
		n.Objects[i], err = r.readU32()
		if err != nil {
			return n, err
		}
	}

	return n, nil
}

// === Postcard Reader ===

type postcardReader struct {
	data []byte
	pos  int
}

func (r *postcardReader) readU8() (uint8, error) {
	if r.pos >= len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	v := r.data[r.pos]
	r.pos++
	return v, nil
}

// readU32 reads a varint-encoded u32.
func (r *postcardReader) readU32() (uint32, error) {
	var result uint32
	var shift uint
	for {
		if r.pos >= len(r.data) {
			return 0, io.ErrUnexpectedEOF
		}
		b := r.data[r.pos]
		r.pos++
		result |= uint32(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift >= 35 {
			return 0, ErrVarintOverflow
		}
	}
	return result, nil
}

// readU64 reads a varint-encoded u64.
func (r *postcardReader) readU64() (uint64, error) {
	var result uint64
	var shift uint
	for {
		if r.pos >= len(r.data) {
			return 0, io.ErrUnexpectedEOF
		}
		b := r.data[r.pos]
		r.pos++
		result |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift >= 70 {
			return 0, ErrVarintOverflow
		}
	}
	return result, nil
}

// readI64 reads a zigzag-encoded varint i64.
func (r *postcardReader) readI64() (int64, error) {
	u, err := r.readU64()
	if err != nil {
		return 0, err
	}
	// Zigzag decode
	return int64(u>>1) ^ -int64(u&1), nil
}

func (r *postcardReader) readBool() (bool, error) {
	b, err := r.readU8()
	return b != 0, err
}

func (r *postcardReader) readString() (string, error) {
	length, err := r.readU32()
	if err != nil {
		return "", err
	}
	if r.pos+int(length) > len(r.data) {
		return "", io.ErrUnexpectedEOF
	}
	s := string(r.data[r.pos : r.pos+int(length)])
	r.pos += int(length)
	return s, nil
}

func (r *postcardReader) skip(n int) error {
	if r.pos+n > len(r.data) {
		return io.ErrUnexpectedEOF
	}
	r.pos += n
	return nil
}
