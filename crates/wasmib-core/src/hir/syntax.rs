//! HIR type syntax and OID types.

use super::types::Symbol;
use crate::lexer::Span;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// OID assignment (unresolved).
///
/// Keeps OID components as symbols; resolution happens in the resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HirOidAssignment {
    /// OID components.
    pub components: Vec<HirOidComponent>,
    /// Source span for diagnostics.
    pub span: Span,
}

impl HirOidAssignment {
    /// Create a new OID assignment.
    #[must_use]
    pub fn new(components: Vec<HirOidComponent>, span: Span) -> Self {
        Self { components, span }
    }
}

/// A component of an OID assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HirOidComponent {
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
}

impl HirOidComponent {
    /// Get the numeric value if this component has one.
    #[must_use]
    pub fn number(&self) -> Option<u32> {
        match self {
            Self::Name(_) => None,
            Self::Number(n) | Self::NamedNumber { number: n, .. } => Some(*n),
        }
    }

    /// Get the name if this component has one.
    #[must_use]
    pub fn name(&self) -> Option<&Symbol> {
        match self {
            Self::Name(s) | Self::NamedNumber { name: s, .. } => Some(s),
            Self::Number(_) => None,
        }
    }
}

/// HIR type syntax.
///
/// Normalized type representation with symbol references (not resolved).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HirTypeSyntax {
    /// Reference to another type: `Integer32`, `DisplayString`
    TypeRef(Symbol),

    /// INTEGER with enum values: `INTEGER { up(1), down(2) }`
    IntegerEnum(Vec<(Symbol, i64)>),

    /// BITS with named bits: `BITS { flag1(0), flag2(1) }`
    Bits(Vec<(Symbol, u32)>),

    /// Constrained type: `OCTET STRING (SIZE (0..255))`
    Constrained {
        /// Base type.
        base: Box<HirTypeSyntax>,
        /// Constraint.
        constraint: HirConstraint,
    },

    /// SEQUENCE OF entry_type (for tables): `SEQUENCE OF IfEntry`
    SequenceOf(Symbol),

    /// SEQUENCE with fields (for row types).
    Sequence(Vec<(Symbol, HirTypeSyntax)>),

    /// OCTET STRING (explicit).
    OctetString,

    /// OBJECT IDENTIFIER (explicit).
    ObjectIdentifier,
}

impl HirTypeSyntax {
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
pub enum HirConstraint {
    /// SIZE constraint: `(SIZE (0..255))`
    Size(Vec<HirRange>),
    /// Value range constraint: `(0..65535)`
    Range(Vec<HirRange>),
}

/// A range in a constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HirRange {
    /// Minimum value.
    pub min: HirRangeValue,
    /// Maximum value (None for single value).
    pub max: Option<HirRangeValue>,
}

impl HirRange {
    /// Create a single-value range.
    #[must_use]
    pub fn single(value: i64) -> Self {
        Self {
            min: HirRangeValue::Number(value),
            max: None,
        }
    }

    /// Create a range from min to max.
    #[must_use]
    pub fn range(min: i64, max: i64) -> Self {
        Self {
            min: HirRangeValue::Number(min),
            max: Some(HirRangeValue::Number(max)),
        }
    }
}

/// A value in a range constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HirRangeValue {
    /// Numeric value.
    Number(i64),
    /// MIN keyword.
    Min,
    /// MAX keyword.
    Max,
}
