package wasmib

// NodeKind represents the semantic type of an OID node.
type NodeKind uint8

const (
	NodeKindInternal     NodeKind = 0 // Path node without definition
	NodeKindNode         NodeKind = 1 // OBJECT-IDENTITY, MODULE-IDENTITY, value assignment
	NodeKindScalar       NodeKind = 2 // OBJECT-TYPE not in table context
	NodeKindTable        NodeKind = 3 // SYNTAX SEQUENCE OF
	NodeKindRow          NodeKind = 4 // Has INDEX or AUGMENTS
	NodeKindColumn       NodeKind = 5 // Parent is Row
	NodeKindNotification NodeKind = 6 // NOTIFICATION-TYPE, TRAP-TYPE
	NodeKindGroup        NodeKind = 7 // OBJECT-GROUP, NOTIFICATION-GROUP
	NodeKindCompliance   NodeKind = 8 // MODULE-COMPLIANCE
	NodeKindCapabilities NodeKind = 9 // AGENT-CAPABILITIES
)

func (k NodeKind) String() string {
	switch k {
	case NodeKindInternal:
		return "internal"
	case NodeKindNode:
		return "node"
	case NodeKindScalar:
		return "scalar"
	case NodeKindTable:
		return "table"
	case NodeKindRow:
		return "row"
	case NodeKindColumn:
		return "column"
	case NodeKindNotification:
		return "notification"
	case NodeKindGroup:
		return "group"
	case NodeKindCompliance:
		return "compliance"
	case NodeKindCapabilities:
		return "capabilities"
	default:
		return "unknown"
	}
}

// IsObjectType returns true if this is an OBJECT-TYPE (scalar, table, row, or column).
func (k NodeKind) IsObjectType() bool {
	return k == NodeKindScalar || k == NodeKindTable || k == NodeKindRow || k == NodeKindColumn
}

// IsConformance returns true if this is a conformance definition.
func (k NodeKind) IsConformance() bool {
	return k == NodeKindGroup || k == NodeKindCompliance || k == NodeKindCapabilities
}

// Access represents SNMP access level.
type Access uint8

const (
	AccessNotAccessible       Access = 0 // not-accessible
	AccessAccessibleForNotify Access = 1 // accessible-for-notify
	AccessReadOnly            Access = 2 // read-only
	AccessReadWrite           Access = 3 // read-write
	AccessReadCreate          Access = 4 // read-create
	AccessWriteOnly           Access = 5 // write-only (rare)
)

func (a Access) String() string {
	switch a {
	case AccessNotAccessible:
		return "not-accessible"
	case AccessAccessibleForNotify:
		return "accessible-for-notify"
	case AccessReadOnly:
		return "read-only"
	case AccessReadWrite:
		return "read-write"
	case AccessReadCreate:
		return "read-create"
	case AccessWriteOnly:
		return "write-only"
	default:
		return "unknown"
	}
}

// Status represents MIB object status.
type Status uint8

const (
	StatusCurrent    Status = 0 // current (SMIv2)
	StatusDeprecated Status = 1 // deprecated
	StatusObsolete   Status = 2 // obsolete
)

func (s Status) String() string {
	switch s {
	case StatusCurrent:
		return "current"
	case StatusDeprecated:
		return "deprecated"
	case StatusObsolete:
		return "obsolete"
	default:
		return "unknown"
	}
}

// BaseType represents the underlying SNMP type.
type BaseType uint8

const (
	BaseTypeInteger32        BaseType = 0  // INTEGER, Integer32
	BaseTypeUnsigned32       BaseType = 1  // Unsigned32
	BaseTypeCounter32        BaseType = 2  // Counter32
	BaseTypeCounter64        BaseType = 3  // Counter64
	BaseTypeGauge32          BaseType = 4  // Gauge32
	BaseTypeTimeTicks        BaseType = 5  // TimeTicks
	BaseTypeIpAddress        BaseType = 6  // IpAddress
	BaseTypeOctetString      BaseType = 7  // OCTET STRING
	BaseTypeObjectIdentifier BaseType = 8  // OBJECT IDENTIFIER
	BaseTypeOpaque           BaseType = 9  // Opaque
	BaseTypeBits             BaseType = 10 // BITS
	BaseTypeUnknown          BaseType = 11 // Unknown/unresolved
)

func (b BaseType) String() string {
	names := []string{
		"INTEGER", "Unsigned32", "Counter32", "Counter64",
		"Gauge32", "TimeTicks", "IpAddress", "OCTET STRING",
		"OBJECT IDENTIFIER", "Opaque", "BITS", "unknown",
	}
	if int(b) < len(names) {
		return names[b]
	}
	return "unknown"
}

// IsInteger returns true if this is an integer-based type.
func (b BaseType) IsInteger() bool {
	return b == BaseTypeInteger32 || b == BaseTypeUnsigned32 ||
		b == BaseTypeCounter32 || b == BaseTypeCounter64 ||
		b == BaseTypeGauge32 || b == BaseTypeTimeTicks
}

// DefValKind represents the kind of default value.
type DefValKind uint8

const (
	DefValInteger      DefValKind = 0 // Signed integer
	DefValUnsigned     DefValKind = 1 // Unsigned integer
	DefValString       DefValKind = 2 // Quoted string
	DefValHexString    DefValKind = 3 // Hex string 'AB01'H
	DefValBinaryString DefValKind = 4 // Binary string '0101'B
	DefValEnum         DefValKind = 5 // Enum name
	DefValBits         DefValKind = 6 // BITS value
	DefValOidRef       DefValKind = 7 // OID reference
)
