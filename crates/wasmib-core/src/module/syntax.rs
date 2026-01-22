//! Type syntax and OID types.

use super::types::Symbol;
use crate::lexer::Span;
use alloc::boxed::Box;
use alloc::vec::Vec;

// === Named types for tuple-based types ===
//
// These provide clearer field names than raw tuples like `(Symbol, i64)`.

/// A named number in an INTEGER enumeration.
///
/// Used in `INTEGER { up(1), down(2) }` syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedNumber {
    /// The name of the enumeration value (e.g., "up", "down").
    pub name: Symbol,
    /// The numeric value assigned to this name.
    pub value: i64,
}

impl NamedNumber {
    /// Create a new named number.
    #[must_use]
    pub fn new(name: Symbol, value: i64) -> Self {
        Self { name, value }
    }
}

/// A named bit in a BITS type definition.
///
/// Used in `BITS { flag1(0), flag2(1) }` syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedBit {
    /// The name of the bit (e.g., "flag1", "flag2").
    pub name: Symbol,
    /// The bit position (0-indexed from the left).
    pub position: u32,
}

impl NamedBit {
    /// Create a new named bit.
    #[must_use]
    pub fn new(name: Symbol, position: u32) -> Self {
        Self { name, position }
    }
}

/// A field in a SEQUENCE type (used for row entry types).
///
/// Used in `SEQUENCE { ifIndex InterfaceIndex, ifDescr DisplayString }` syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SequenceField {
    /// The name of the field (e.g., "ifIndex", "ifDescr").
    pub name: Symbol,
    /// The type of the field.
    pub syntax: TypeSyntax,
}

impl SequenceField {
    /// Create a new sequence field.
    #[must_use]
    pub fn new(name: Symbol, syntax: TypeSyntax) -> Self {
        Self { name, syntax }
    }
}

/// OID assignment (unresolved).
///
/// Keeps OID components as symbols; resolution happens in the resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidAssignment {
    /// OID components.
    pub components: Vec<OidComponent>,
    /// Source span for diagnostics.
    pub span: Span,
}

impl OidAssignment {
    /// Create a new OID assignment.
    #[must_use]
    pub fn new(components: Vec<OidComponent>, span: Span) -> Self {
        Self { components, span }
    }
}

/// A component of an OID assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OidComponent {
    /// Just a name reference: `internet`, `ifEntry`
    Name(Symbol),
    /// Just a number: `1`, `31`
    Number(u32),
    /// Name with number: `org(3)` - common in well-known roots
    NamedNumber {
        /// The name.
        name: Symbol,
        /// The numeric value.
        number: u32,
    },
    /// Qualified name: `SNMPv2-SMI.enterprises`
    QualifiedName {
        /// The module name.
        module: Symbol,
        /// The symbol name.
        name: Symbol,
    },
    /// Qualified name with number: `SNMPv2-SMI.enterprises(1)`
    QualifiedNamedNumber {
        /// The module name.
        module: Symbol,
        /// The symbol name.
        name: Symbol,
        /// The numeric value.
        number: u32,
    },
}

impl OidComponent {
    /// Get the numeric value if this component has one.
    #[must_use]
    pub fn number(&self) -> Option<u32> {
        match self {
            Self::Name(_) | Self::QualifiedName { .. } => None,
            Self::Number(n)
            | Self::NamedNumber { number: n, .. }
            | Self::QualifiedNamedNumber { number: n, .. } => Some(*n),
        }
    }

    /// Get the name if this component has one.
    #[must_use]
    pub fn name(&self) -> Option<&Symbol> {
        match self {
            Self::Name(s)
            | Self::NamedNumber { name: s, .. }
            | Self::QualifiedName { name: s, .. }
            | Self::QualifiedNamedNumber { name: s, .. } => Some(s),
            Self::Number(_) => None,
        }
    }

    /// Get the module name if this is a qualified reference.
    #[must_use]
    pub fn module(&self) -> Option<&Symbol> {
        match self {
            Self::QualifiedName { module, .. } | Self::QualifiedNamedNumber { module, .. } => {
                Some(module)
            }
            _ => None,
        }
    }
}

/// Type syntax.
///
/// Type representation with symbol references (not resolved).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeSyntax {
    /// Reference to another type: `Integer32`, `DisplayString`
    TypeRef(Symbol),

    /// INTEGER with enum values: `INTEGER { up(1), down(2) }`
    IntegerEnum(Vec<NamedNumber>),

    /// BITS with named bits: `BITS { flag1(0), flag2(1) }`
    Bits(Vec<NamedBit>),

    /// Constrained type: `OCTET STRING (SIZE (0..255))`
    Constrained {
        /// Base type.
        base: Box<TypeSyntax>,
        /// Constraint.
        constraint: Constraint,
    },

    /// SEQUENCE OF `entry_type` (for tables): `SEQUENCE OF IfEntry`
    SequenceOf(Symbol),

    /// SEQUENCE with fields (for row types).
    Sequence(Vec<SequenceField>),

    /// OCTET STRING (explicit).
    OctetString,

    /// OBJECT IDENTIFIER (explicit).
    ObjectIdentifier,
}

impl TypeSyntax {
    /// Get the base type name if this is a simple type reference.
    #[must_use]
    pub fn type_name(&self) -> Option<&Symbol> {
        match self {
            Self::TypeRef(s) => Some(s),
            _ => None,
        }
    }

    /// Check if this is a SEQUENCE OF (table type).
    #[must_use]
    pub fn is_sequence_of(&self) -> bool {
        matches!(self, Self::SequenceOf(_))
    }

    /// Check if this is a SEQUENCE (row type).
    #[must_use]
    pub fn is_sequence(&self) -> bool {
        matches!(self, Self::Sequence(_))
    }
}

/// Type constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Constraint {
    /// SIZE constraint: `(SIZE (0..255))`
    Size(Vec<Range>),
    /// Value range constraint: `(0..65535)`
    Range(Vec<Range>),
}

/// A range in a constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    /// Minimum value.
    pub min: RangeValue,
    /// Maximum value (None for single value).
    pub max: Option<RangeValue>,
}

impl Range {
    /// Create a single-value range with a signed value.
    #[must_use]
    pub fn single_signed(value: i64) -> Self {
        Self {
            min: RangeValue::Signed(value),
            max: None,
        }
    }

    /// Create a single-value range with an unsigned value.
    #[must_use]
    pub fn single_unsigned(value: u64) -> Self {
        Self {
            min: RangeValue::Unsigned(value),
            max: None,
        }
    }

    /// Create a range from min to max with signed values.
    #[must_use]
    pub fn range_signed(min: i64, max: i64) -> Self {
        Self {
            min: RangeValue::Signed(min),
            max: Some(RangeValue::Signed(max)),
        }
    }

    /// Create a range from min to max with unsigned values.
    #[must_use]
    pub fn range_unsigned(min: u64, max: u64) -> Self {
        Self {
            min: RangeValue::Unsigned(min),
            max: Some(RangeValue::Unsigned(max)),
        }
    }
}

/// A value in a range constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeValue {
    /// Signed numeric value (for Integer32 ranges, can be negative).
    Signed(i64),
    /// Unsigned numeric value (for Counter64 ranges, large positive values).
    Unsigned(u64),
    /// MIN keyword.
    Min,
    /// MAX keyword.
    Max,
}

// === DEFVAL types ===

/// Default value for an OBJECT-TYPE.
///
/// This is the normalized representation of DEFVAL clause content.
/// Symbol references are kept unresolved; resolution happens in the semantic phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefVal {
    /// Integer value: `DEFVAL { 0 }`, `DEFVAL { -1 }`
    Integer(i64),

    /// Unsigned integer (for Counter64 etc): `DEFVAL { 4294967296 }`
    Unsigned(u64),

    /// String value: `DEFVAL { "public" }`, `DEFVAL { "" }`
    String(alloc::string::String),

    /// Hex string: `DEFVAL { 'FF00'H }`
    /// Stored as raw hex digits (uppercase).
    HexString(alloc::string::String),

    /// Binary string: `DEFVAL { '1010'B }`
    /// Stored as raw binary digits.
    BinaryString(alloc::string::String),

    /// Enum label reference: `DEFVAL { enabled }`, `DEFVAL { true }`
    /// The symbol refers to an enumeration value defined in the object's type.
    Enum(Symbol),

    /// BITS value (set of bit labels): `DEFVAL { { flag1, flag2 } }`, `DEFVAL { {} }`
    /// Each symbol refers to a bit name defined in the object's BITS type.
    Bits(Vec<Symbol>),

    /// OID reference: `DEFVAL { sysName }`
    /// The symbol refers to another OID in the MIB.
    OidRef(Symbol),

    /// OID value (explicit components): `DEFVAL { { iso 3 6 1 } }`
    /// Kept as OID components for resolution.
    OidValue(Vec<OidComponent>),
}
