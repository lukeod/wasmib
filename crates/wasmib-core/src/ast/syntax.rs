//! SYNTAX clause and related AST types.

use super::{Ident, NamedNumber, QuotedString};
use crate::lexer::Span;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// SYNTAX clause specifying the type of an object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxClause {
    /// The type syntax.
    pub syntax: TypeSyntax,
    /// Source location.
    pub span: Span,
}

impl SyntaxClause {
    /// Create a new syntax clause.
    #[must_use]
    pub fn new(syntax: TypeSyntax, span: Span) -> Self {
        Self { syntax, span }
    }
}

/// Type syntax in a SYNTAX clause or type assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeSyntax {
    /// Simple type reference: `Integer32`, `DisplayString`, `IpAddress`
    TypeRef(Ident),

    /// INTEGER with named numbers: `INTEGER { up(1), down(2) }`
    IntegerEnum {
        /// Base type (usually None, inferred as INTEGER).
        base: Option<Ident>,
        /// Named number values.
        named_numbers: Vec<NamedNumber>,
        /// Source location.
        span: Span,
    },

    /// BITS with named bits: `BITS { flag1(0), flag2(1) }`
    Bits {
        /// Named bit positions.
        named_bits: Vec<NamedNumber>,
        /// Source location.
        span: Span,
    },

    /// Constrained type: `OCTET STRING (SIZE (0..255))`
    Constrained {
        /// Base type.
        base: Box<TypeSyntax>,
        /// Constraint.
        constraint: Constraint,
        /// Source location.
        span: Span,
    },

    /// SEQUENCE OF: `SEQUENCE OF IfEntry`
    SequenceOf {
        /// Entry type name.
        entry_type: Ident,
        /// Source location.
        span: Span,
    },

    /// SEQUENCE (row definition): `SEQUENCE { ifIndex INTEGER, ... }`
    Sequence {
        /// Sequence fields.
        fields: Vec<SequenceField>,
        /// Source location.
        span: Span,
    },

    /// OCTET STRING (explicit form).
    OctetString {
        /// Source location.
        span: Span,
    },

    /// OBJECT IDENTIFIER type.
    ObjectIdentifier {
        /// Source location.
        span: Span,
    },
}

impl TypeSyntax {
    /// Get the span of this type syntax.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            Self::TypeRef(ident) => ident.span,
            Self::IntegerEnum { span, .. }
            | Self::Bits { span, .. }
            | Self::Constrained { span, .. }
            | Self::SequenceOf { span, .. }
            | Self::Sequence { span, .. }
            | Self::OctetString { span }
            | Self::ObjectIdentifier { span } => *span,
        }
    }
}

/// A field in a SEQUENCE definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SequenceField {
    /// Field name.
    pub name: Ident,
    /// Field type.
    pub syntax: TypeSyntax,
    /// Source location.
    pub span: Span,
}

/// Type constraint (SIZE or range).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Constraint {
    /// SIZE constraint: `(SIZE (0..255))`
    Size {
        /// Allowed ranges.
        ranges: Vec<Range>,
        /// Source location.
        span: Span,
    },
    /// Value range constraint: `(0..65535)`
    Range {
        /// Allowed ranges.
        ranges: Vec<Range>,
        /// Source location.
        span: Span,
    },
}

impl Constraint {
    /// Get the span of this constraint.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            Self::Size { span, .. } | Self::Range { span, .. } => *span,
        }
    }
}

/// A range in a constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    /// Minimum value.
    pub min: RangeValue,
    /// Maximum value (None for single value).
    pub max: Option<RangeValue>,
    /// Source location.
    pub span: Span,
}

/// A value in a range constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeValue {
    /// Numeric value.
    Number(i64),
    /// Named value (MIN, MAX).
    Ident(Ident),
}

// === Access clause ===

/// Access clause (MAX-ACCESS or ACCESS).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessClause {
    /// Keyword used (MAX-ACCESS vs ACCESS).
    pub keyword: AccessKeyword,
    /// Access value.
    pub value: AccessValue,
    /// Source location.
    pub span: Span,
}

/// Access keyword type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessKeyword {
    /// SMIv1: `ACCESS`
    Access,
    /// SMIv2: `MAX-ACCESS`
    MaxAccess,
    /// SMIv2: `MIN-ACCESS` (in MODULE-COMPLIANCE)
    MinAccess,
    /// SPPI: `PIB-ACCESS`
    PibAccess,
}

/// Access value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessValue {
    /// `read-only`
    ReadOnly,
    /// `read-write`
    ReadWrite,
    /// `read-create`
    ReadCreate,
    /// `not-accessible`
    NotAccessible,
    /// `accessible-for-notify`
    AccessibleForNotify,
    /// `write-only` (deprecated)
    WriteOnly,
    /// `not-implemented` (AGENT-CAPABILITIES)
    NotImplemented,
    // SPPI-specific
    /// `install`
    Install,
    /// `install-notify`
    InstallNotify,
    /// `report-only`
    ReportOnly,
}

// === Status clause ===

/// Status clause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusClause {
    /// Status value.
    pub value: StatusValue,
    /// Source location.
    pub span: Span,
}

/// Status value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusValue {
    /// `current`
    Current,
    /// `deprecated`
    Deprecated,
    /// `obsolete`
    Obsolete,
    /// `mandatory` (SMIv1)
    Mandatory,
    /// `optional` (SMIv1)
    Optional,
}

// === Index clause ===

/// Index clause (INDEX or AUGMENTS).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexClause {
    /// `INDEX { ifIndex, ipAddr IMPLIED }`
    Index {
        /// Index items.
        indexes: Vec<IndexItem>,
        /// Source location.
        span: Span,
    },
    /// `PIB-INDEX { ... }` (SPPI)
    PibIndex {
        /// Index items.
        indexes: Vec<IndexItem>,
        /// Source location.
        span: Span,
    },
}

/// An item in an INDEX clause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexItem {
    /// Whether this index is IMPLIED.
    pub implied: bool,
    /// Object reference.
    pub object: Ident,
    /// Source location.
    pub span: Span,
}

/// AUGMENTS clause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AugmentsClause {
    /// Target row to augment.
    pub target: Ident,
    /// Source location.
    pub span: Span,
}

// === DEFVAL clause ===

/// DEFVAL clause.
///
/// DEFVAL values can be complex (OID values, bits, etc.) so we store
/// the raw content for now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefValClause {
    /// Source location (includes DEFVAL keyword and braces).
    pub span: Span,
    // TODO: Parse DEFVAL content properly
}

// === REVISION clause ===

/// REVISION clause in MODULE-IDENTITY.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionClause {
    /// Revision date.
    pub date: QuotedString,
    /// Revision description.
    pub description: QuotedString,
    /// Source location.
    pub span: Span,
}
