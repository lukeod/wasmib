package wasmib

import (
	"fmt"
	"strconv"
	"strings"
)

// Model is the deserialized MIB model. Safe for concurrent read access.
//
// The Model is read-only after construction. All queries can be performed
// concurrently from multiple goroutines without locks.
type Model struct {
	version uint32

	// String table (1-indexed: StrId N maps to strings[N-1])
	strings []string

	// Data arrays (1-indexed: NodeId N maps to nodes[N-1])
	modules       []Module
	nodes         []Node
	types         []Type
	objects       []Object
	notifications []Notification

	// Root node IDs (typically iso=1)
	roots []uint32

	// Unresolved reference counts (for diagnostics)
	unresolvedImports             uint32
	unresolvedTypes               uint32
	unresolvedOids                uint32
	unresolvedIndexes             uint32
	unresolvedNotificationObjects uint32

	// Unresolved reference details (for debugging)
	unresolvedImportDetails []UnresolvedImport
	unresolvedTypeDetails   []UnresolvedType
	unresolvedOidDetails    []UnresolvedOid
	unresolvedIndexDetails  []UnresolvedIndex
	unresolvedNotifDetails  []UnresolvedNotificationObject

	// Lookup indices (built on deserialize)
	oidIndex    map[string]uint32   // "1.3.6.1.2.1.1.1" -> NodeId
	nameIndex   map[string][]uint32 // "sysDescr" -> []NodeId
	qualIndex   map[string]uint32   // "SNMPv2-MIB::sysDescr" -> NodeId
	moduleIndex map[string]uint32   // "SNMPv2-MIB" -> ModuleId
}

// Module represents a resolved MIB module.
type Module struct {
	Name         uint32 // StrId
	LastUpdated  uint32 // StrId, 0 = none
	ContactInfo  uint32 // StrId, 0 = none
	Organization uint32 // StrId, 0 = none
	Description  uint32 // StrId, 0 = none
	Revisions    []Revision
}

// Revision represents a module revision entry.
type Revision struct {
	Date        uint32 // StrId
	Description uint32 // StrId
}

// Node represents a position in the OID tree.
type Node struct {
	ID          uint32    // NodeId (1-indexed)
	Subid       uint32    // Arc value at this position
	Parent      uint32    // NodeId, 0 = root
	Children    []uint32  // []NodeId
	Kind        NodeKind  // Semantic type
	Definitions []NodeDef // Definitions at this OID
}

// NodeDef links a node to its definition(s).
type NodeDef struct {
	Module       uint32 // ModuleId
	Label        uint32 // StrId
	Object       uint32 // ObjectId, 0 = none
	Notification uint32 // NotificationId, 0 = none
}

// Object represents an OBJECT-TYPE definition.
type Object struct {
	Node        uint32      // NodeId
	Module      uint32      // ModuleId
	Name        uint32      // StrId
	TypeID      uint32      // TypeId, 0 = unresolved
	Access      Access      // Access level
	Status      Status      // Definition status
	Description uint32      // StrId, 0 = none
	Units       uint32      // StrId, 0 = none
	Reference   uint32      // StrId, 0 = none
	Index       *IndexSpec  // INDEX clause, nil if not a row
	Augments    uint32      // NodeId, 0 = none
	DefVal      *DefVal     // DEFVAL clause, nil if none
	InlineEnum  []EnumValue // Inline enumeration (not from type)
	InlineBits  []BitDef    // Inline BITS (not from type)
}

// IndexSpec represents an INDEX clause.
type IndexSpec struct {
	Items []IndexItem
}

// IndexItem is a single index in an INDEX clause.
type IndexItem struct {
	Object  uint32 // NodeId of index object
	Implied bool   // Whether this index is IMPLIED
}

// DefVal represents a DEFVAL clause value.
type DefVal struct {
	Kind     DefValKind // Type of default value
	IntVal   int64      // For Integer kind
	UintVal  uint64     // For Unsigned kind
	StrID    uint32     // StrId for String/Enum kinds
	RawStr   string     // For HexString/BinaryString kinds
	NodeID   uint32     // NodeId for resolved OID ref
	BitsVals []uint32   // StrIds for Bits kind
}

// Type represents a type definition.
type Type struct {
	Module      uint32      // ModuleId
	Name        uint32      // StrId
	Base        BaseType    // Base type
	Parent      uint32      // TypeId for TC inheritance, 0 = none
	Status      Status      // Definition status
	IsTC        bool        // Is textual convention
	Hint        uint32      // StrId, 0 = none
	Description uint32      // StrId, 0 = none
	Size        *Constraint // Size constraint
	Range       *Constraint // Value range constraint
	EnumValues  []EnumValue // Enumeration values
	BitDefs     []BitDef    // Bit definitions
}

// Constraint represents size or value constraints.
type Constraint struct {
	Ranges [][2]int64 // (min, max) pairs
}

// EnumValue is a named integer value.
type EnumValue struct {
	Value int64  // Integer value
	Name  uint32 // StrId
}

// BitDef is a named bit position.
type BitDef struct {
	Position uint32 // Bit position
	Name     uint32 // StrId
}

// Notification represents a NOTIFICATION-TYPE.
type Notification struct {
	Node        uint32   // NodeId
	Module      uint32   // ModuleId
	Name        uint32   // StrId
	Status      Status   // Definition status
	Description uint32   // StrId, 0 = none
	Reference   uint32   // StrId, 0 = none
	Objects     []uint32 // []NodeId - OBJECTS clause
}

// UnresolvedImport represents an import that could not be resolved.
type UnresolvedImport struct {
	ImportingModule uint32                 // ModuleId of the importing module
	FromModule      uint32                 // StrId of the module being imported from
	Symbol          uint32                 // StrId of the symbol being imported
	Reason          UnresolvedImportReason // Why it could not be resolved
}

// UnresolvedImportReason describes why an import could not be resolved.
type UnresolvedImportReason uint32

const (
	// ReasonModuleNotFound means no module with the given name was found.
	ReasonModuleNotFound UnresolvedImportReason = 0
	// ReasonSymbolNotExported means the module exists but doesn't export the symbol.
	ReasonSymbolNotExported UnresolvedImportReason = 1
)

// UnresolvedType represents a type reference that could not be resolved.
type UnresolvedType struct {
	Module     uint32 // ModuleId containing the reference
	Referrer   uint32 // StrId of the definition referencing the type
	Referenced uint32 // StrId of the type being referenced
}

// UnresolvedOid represents an OID component that could not be resolved.
type UnresolvedOid struct {
	Module     uint32 // ModuleId containing the definition
	Definition uint32 // StrId of the definition with the OID
	Component  uint32 // StrId of the unresolved component name
}

// UnresolvedIndex represents an index object that could not be resolved.
type UnresolvedIndex struct {
	Module      uint32 // ModuleId containing the row
	Row         uint32 // StrId of the row definition
	IndexObject uint32 // StrId of the unresolved index object name
}

// UnresolvedNotificationObject represents a notification object that could not be resolved.
type UnresolvedNotificationObject struct {
	Module       uint32 // ModuleId containing the notification
	Notification uint32 // StrId of the notification definition
	Object       uint32 // StrId of the unresolved object name
}

// === Query Methods ===

// GetStr returns the interned string for an ID.
// Returns empty string if ID is 0 or invalid.
func (m *Model) GetStr(id uint32) string {
	if id == 0 || int(id) > len(m.strings) {
		return ""
	}
	return m.strings[id-1]
}

// GetNodeByOID looks up a node by dotted OID string (e.g., "1.3.6.1.2.1.1.1").
// Returns nil if not found.
func (m *Model) GetNodeByOID(oid string) *Node {
	if id, ok := m.oidIndex[oid]; ok {
		return &m.nodes[id-1]
	}
	return nil
}

// GetNodesByName returns all nodes with the given name.
// Multiple nodes may share the same name (defined in different modules).
func (m *Model) GetNodesByName(name string) []*Node {
	ids, ok := m.nameIndex[name]
	if !ok {
		return nil
	}
	nodes := make([]*Node, len(ids))
	for i, id := range ids {
		nodes[i] = &m.nodes[id-1]
	}
	return nodes
}

// GetNodeByQualifiedName looks up "MODULE::name" (e.g., "SNMPv2-MIB::sysDescr").
func (m *Model) GetNodeByQualifiedName(module, name string) *Node {
	key := module + "::" + name
	if id, ok := m.qualIndex[key]; ok {
		return &m.nodes[id-1]
	}
	return nil
}

// GetModuleByName returns a module by name.
func (m *Model) GetModuleByName(name string) *Module {
	if id, ok := m.moduleIndex[name]; ok {
		return &m.modules[id-1]
	}
	return nil
}

// GetNode returns a node by ID.
func (m *Model) GetNode(id uint32) *Node {
	if id == 0 || int(id) > len(m.nodes) {
		return nil
	}
	return &m.nodes[id-1]
}

// GetModule returns a module by ID.
func (m *Model) GetModule(id uint32) *Module {
	if id == 0 || int(id) > len(m.modules) {
		return nil
	}
	return &m.modules[id-1]
}

// GetObject returns the object definition for a node.
// Returns nil if the node has no object definition.
func (m *Model) GetObject(n *Node) *Object {
	if n == nil || len(n.Definitions) == 0 {
		return nil
	}
	objID := n.Definitions[0].Object
	if objID == 0 || int(objID) > len(m.objects) {
		return nil
	}
	return &m.objects[objID-1]
}

// GetObjectByID returns an object by ID.
func (m *Model) GetObjectByID(id uint32) *Object {
	if id == 0 || int(id) > len(m.objects) {
		return nil
	}
	return &m.objects[id-1]
}

// GetType returns a type definition.
func (m *Model) GetType(id uint32) *Type {
	if id == 0 || int(id) > len(m.types) {
		return nil
	}
	return &m.types[id-1]
}

// GetNotification returns a notification definition for a node.
func (m *Model) GetNotification(n *Node) *Notification {
	if n == nil || len(n.Definitions) == 0 {
		return nil
	}
	notifID := n.Definitions[0].Notification
	if notifID == 0 || int(notifID) > len(m.notifications) {
		return nil
	}
	return &m.notifications[notifID-1]
}

// GetNotificationByID returns a notification by ID.
func (m *Model) GetNotificationByID(id uint32) *Notification {
	if id == 0 || int(id) > len(m.notifications) {
		return nil
	}
	return &m.notifications[id-1]
}

// GetNotificationObjects returns the objects (varbinds) included in a notification.
// These are the objects from the OBJECTS clause in NOTIFICATION-TYPE or
// VARIABLES clause in TRAP-TYPE definitions.
// Returns nil if the notification is nil or has no objects.
func (m *Model) GetNotificationObjects(notif *Notification) []*Node {
	if notif == nil || len(notif.Objects) == 0 {
		return nil
	}
	nodes := make([]*Node, 0, len(notif.Objects))
	for _, nodeID := range notif.Objects {
		node := m.GetNode(nodeID)
		if node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetIndexObjects returns the index column nodes for a row object.
// These are the objects from the INDEX clause that define the row's key.
// Returns nil if the object is nil or has no INDEX clause.
func (m *Model) GetIndexObjects(obj *Object) []*Node {
	if obj == nil || obj.Index == nil || len(obj.Index.Items) == 0 {
		return nil
	}
	nodes := make([]*Node, 0, len(obj.Index.Items))
	for _, item := range obj.Index.Items {
		node := m.GetNode(item.Object)
		if node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetAugmentsTarget returns the row node that this object augments.
// Returns nil if the object is nil or doesn't use AUGMENTS.
func (m *Model) GetAugmentsTarget(obj *Object) *Node {
	if obj == nil || obj.Augments == 0 {
		return nil
	}
	return m.GetNode(obj.Augments)
}

// GetParent returns the parent node in the OID tree.
// Returns nil if the node is nil or is a root node.
func (m *Model) GetParent(n *Node) *Node {
	if n == nil || n.Parent == 0 {
		return nil
	}
	return m.GetNode(n.Parent)
}

// GetChildren returns the child nodes in the OID tree.
// Returns nil if the node is nil or has no children.
func (m *Model) GetChildren(n *Node) []*Node {
	if n == nil || len(n.Children) == 0 {
		return nil
	}
	children := make([]*Node, 0, len(n.Children))
	for _, childID := range n.Children {
		child := m.GetNode(childID)
		if child != nil {
			children = append(children, child)
		}
	}
	return children
}

// GetEffectiveHint walks the type chain to find a display hint.
// Returns empty string if no hint found.
func (m *Model) GetEffectiveHint(typeID uint32) string {
	for typeID != 0 {
		t := m.GetType(typeID)
		if t == nil {
			break
		}
		if t.Hint != 0 {
			return m.GetStr(t.Hint)
		}
		typeID = t.Parent
	}
	return ""
}

// GetOID computes the full OID string for a node.
func (m *Model) GetOID(n *Node) string {
	arcs := m.GetOIDSlice(n)
	if arcs == nil {
		return ""
	}

	var b strings.Builder
	for i, arc := range arcs {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(arc), 10))
	}
	return b.String()
}

// GetOIDSlice returns the full OID as a slice of arc values.
// Returns nil if the node is nil.
func (m *Model) GetOIDSlice(n *Node) []uint32 {
	if n == nil {
		return nil
	}

	var arcs []uint32
	current := n
	for current != nil {
		arcs = append(arcs, current.Subid)
		if current.Parent == 0 {
			break
		}
		current = m.GetNode(current.Parent)
	}

	// Reverse in place
	for i, j := 0, len(arcs)-1; i < j; i, j = i+1, j-1 {
		arcs[i], arcs[j] = arcs[j], arcs[i]
	}
	return arcs
}

// GetNodeByOIDSlice looks up a node by OID arc values.
// Returns nil if not found.
func (m *Model) GetNodeByOIDSlice(oid []uint32) *Node {
	if len(oid) == 0 {
		return nil
	}

	// Find root with matching first arc
	var current *Node
	for _, rootID := range m.roots {
		root := m.GetNode(rootID)
		if root != nil && root.Subid == oid[0] {
			current = root
			break
		}
	}
	if current == nil {
		return nil
	}

	// Walk down the tree following arcs
	for _, arc := range oid[1:] {
		found := false
		for _, childID := range current.Children {
			child := m.GetNode(childID)
			if child != nil && child.Subid == arc {
				current = child
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return current
}

// GetNodeByOIDPrefix finds the node with the longest matching OID prefix.
// Returns the matching node and the unmatched suffix (instance index).
// Returns (nil, nil) if no prefix matches at all.
//
// This is useful for mapping SNMP response OIDs back to MIB definitions,
// since response OIDs include instance suffixes (e.g., sysName.0 or ifDescr.1).
func (m *Model) GetNodeByOIDPrefix(oid []uint32) (node *Node, suffix []uint32) {
	if len(oid) == 0 {
		return nil, nil
	}

	// Find root with matching first arc
	var current *Node
	for _, rootID := range m.roots {
		root := m.GetNode(rootID)
		if root != nil && root.Subid == oid[0] {
			current = root
			break
		}
	}
	if current == nil {
		return nil, nil
	}

	// Walk down the tree as far as possible
	matched := 1
	for _, arc := range oid[1:] {
		found := false
		for _, childID := range current.Children {
			child := m.GetNode(childID)
			if child != nil && child.Subid == arc {
				current = child
				matched++
				found = true
				break
			}
		}
		if !found {
			break
		}
	}

	// Return matched node and remaining suffix
	if matched < len(oid) {
		return current, oid[matched:]
	}
	return current, nil
}

// GetNodeByOIDPrefixStr is like GetNodeByOIDPrefix but takes a dotted OID string.
// Returns the matching node and the unmatched suffix as a slice.
// Returns (nil, nil) if the OID string is empty or invalid.
func (m *Model) GetNodeByOIDPrefixStr(oid string) (node *Node, suffix []uint32) {
	arcs, err := parseOIDString(oid)
	if err != nil || arcs == nil {
		return nil, nil
	}
	return m.GetNodeByOIDPrefix(arcs)
}

// parseOIDString parses a dotted OID string into arc values.
// Returns (nil, nil) for empty input, or (nil, error) for invalid input.
func parseOIDString(oid string) ([]uint32, error) {
	if oid == "" {
		return nil, nil
	}

	// Count dots to pre-allocate
	count := 1
	for i := 0; i < len(oid); i++ {
		if oid[i] == '.' {
			count++
		}
	}

	arcs := make([]uint32, 0, count)
	start := 0
	for i := 0; i <= len(oid); i++ {
		if i == len(oid) || oid[i] == '.' {
			if i > start {
				segment := oid[start:i]
				// Reject leading zeros (e.g., "01", "007") - MIB convention
				if len(segment) > 1 && segment[0] == '0' {
					return nil, fmt.Errorf("invalid OID component %q: leading zeros not allowed", segment)
				}
				n, err := strconv.ParseUint(segment, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("invalid OID component %q: %w", segment, err)
				}
				arcs = append(arcs, uint32(n))
			}
			start = i + 1
		}
	}
	return arcs, nil
}

// Walk traverses the tree depth-first from a starting node.
// The callback returns false to stop traversal.
func (m *Model) Walk(nodeID uint32, fn func(*Node) bool) {
	if nodeID == 0 || int(nodeID) > len(m.nodes) {
		return
	}
	node := &m.nodes[nodeID-1]
	if !fn(node) {
		return
	}
	for _, childID := range node.Children {
		m.Walk(childID, fn)
	}
}

// WalkAll traverses all nodes starting from the roots.
func (m *Model) WalkAll(fn func(*Node) bool) {
	for _, rootID := range m.roots {
		m.Walk(rootID, fn)
	}
}

// Roots returns a copy of the root node IDs.
// The returned slice is a copy; modifications do not affect the Model.
func (m *Model) Roots() []uint32 {
	result := make([]uint32, len(m.roots))
	copy(result, m.roots)
	return result
}

// ModuleCount returns the number of modules.
func (m *Model) ModuleCount() int {
	return len(m.modules)
}

// NodeCount returns the number of nodes.
func (m *Model) NodeCount() int {
	return len(m.nodes)
}

// TypeCount returns the number of types.
func (m *Model) TypeCount() int {
	return len(m.types)
}

// ObjectCount returns the number of objects.
func (m *Model) ObjectCount() int {
	return len(m.objects)
}

// NotificationCount returns the number of notifications.
func (m *Model) NotificationCount() int {
	return len(m.notifications)
}

// IsComplete returns true if all references were resolved.
func (m *Model) IsComplete() bool {
	return m.unresolvedImports == 0 &&
		m.unresolvedTypes == 0 &&
		m.unresolvedOids == 0 &&
		m.unresolvedIndexes == 0 &&
		m.unresolvedNotificationObjects == 0
}

// UnresolvedCounts returns counts of unresolved references.
func (m *Model) UnresolvedCounts() (imports, types, oids, indexes, notifObjects uint32) {
	return m.unresolvedImports, m.unresolvedTypes, m.unresolvedOids,
		m.unresolvedIndexes, m.unresolvedNotificationObjects
}

// UnresolvedImports returns details of all unresolved imports.
func (m *Model) UnresolvedImports() []UnresolvedImport {
	return m.unresolvedImportDetails
}

// UnresolvedTypes returns details of all unresolved type references.
func (m *Model) UnresolvedTypes() []UnresolvedType {
	return m.unresolvedTypeDetails
}

// UnresolvedOids returns details of all unresolved OID components.
func (m *Model) UnresolvedOids() []UnresolvedOid {
	return m.unresolvedOidDetails
}

// UnresolvedIndexes returns details of all unresolved index objects.
func (m *Model) UnresolvedIndexes() []UnresolvedIndex {
	return m.unresolvedIndexDetails
}

// UnresolvedNotificationObjects returns details of all unresolved notification objects.
func (m *Model) UnresolvedNotificationObjects() []UnresolvedNotificationObject {
	return m.unresolvedNotifDetails
}

// Version returns the schema version of the serialized model.
func (m *Model) Version() uint32 {
	return m.version
}

// AllModules returns a copy of all modules.
// The returned slice is a copy; modifications do not affect the Model.
func (m *Model) AllModules() []Module {
	result := make([]Module, len(m.modules))
	copy(result, m.modules)
	return result
}

// AllNodes returns a copy of all nodes.
// The returned slice is a copy; modifications do not affect the Model.
func (m *Model) AllNodes() []Node {
	result := make([]Node, len(m.nodes))
	copy(result, m.nodes)
	return result
}

// AllTypes returns a copy of all types.
// The returned slice is a copy; modifications do not affect the Model.
func (m *Model) AllTypes() []Type {
	result := make([]Type, len(m.types))
	copy(result, m.types)
	return result
}

// AllObjects returns a copy of all objects.
// The returned slice is a copy; modifications do not affect the Model.
func (m *Model) AllObjects() []Object {
	result := make([]Object, len(m.objects))
	copy(result, m.objects)
	return result
}

// AllNotifications returns a copy of all notifications.
// The returned slice is a copy; modifications do not affect the Model.
func (m *Model) AllNotifications() []Notification {
	result := make([]Notification, len(m.notifications))
	copy(result, m.notifications)
	return result
}

// === Index Building ===

func (m *Model) buildIndices() {
	m.oidIndex = make(map[string]uint32, len(m.nodes))
	m.nameIndex = make(map[string][]uint32)
	m.qualIndex = make(map[string]uint32)
	m.moduleIndex = make(map[string]uint32, len(m.modules))

	// Build module index
	for i := range m.modules {
		name := m.GetStr(m.modules[i].Name)
		if name != "" {
			m.moduleIndex[name] = uint32(i + 1)
		}
	}

	// Build node indices via tree walk, computing OIDs incrementally
	// to avoid O(n*depth) tree walks. We pass the parent's OID string
	// down to children and append each node's subid.
	for _, rootID := range m.roots {
		m.buildNodeIndices(rootID, "")
	}
}

// buildNodeIndices recursively indexes nodes, computing OIDs incrementally.
// parentOID is the OID string of the parent node (empty for roots).
func (m *Model) buildNodeIndices(nodeID uint32, parentOID string) {
	if nodeID == 0 || int(nodeID) > len(m.nodes) {
		return
	}
	node := &m.nodes[nodeID-1]

	// Compute this node's OID by appending subid to parent
	var oid string
	subidStr := strconv.FormatUint(uint64(node.Subid), 10)
	if parentOID == "" {
		oid = subidStr
	} else {
		// Use strings.Builder to avoid repeated allocations
		var b strings.Builder
		b.Grow(len(parentOID) + 1 + len(subidStr))
		b.WriteString(parentOID)
		b.WriteByte('.')
		b.WriteString(subidStr)
		oid = b.String()
	}

	// OID index
	m.oidIndex[oid] = node.ID

	// Name and qualified name indices
	for _, def := range node.Definitions {
		name := m.GetStr(def.Label)
		if name != "" {
			m.nameIndex[name] = append(m.nameIndex[name], node.ID)

			if def.Module > 0 && int(def.Module) <= len(m.modules) {
				modName := m.GetStr(m.modules[def.Module-1].Name)
				if modName != "" {
					// Use strings.Builder for qualified name construction
					var b strings.Builder
					b.Grow(len(modName) + 2 + len(name))
					b.WriteString(modName)
					b.WriteString("::")
					b.WriteString(name)
					m.qualIndex[b.String()] = node.ID
				}
			}
		}
	}

	// Recurse to children, passing this node's OID
	for _, childID := range node.Children {
		m.buildNodeIndices(childID, oid)
	}
}
