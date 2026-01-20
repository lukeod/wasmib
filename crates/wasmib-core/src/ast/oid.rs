//! OID assignment AST types.

use super::Ident;
use crate::lexer::Span;
use alloc::vec::Vec;

/// OID value assignment.
///
/// Represents the `::= { parent subid ... }` portion of an OID definition.
///
/// Examples:
/// - `{ ifEntry 1 }` - simple parent + subid
/// - `{ iso org(3) dod(6) internet(1) }` - full path with named numbers
/// - `{ mib-2 31 }` - parent reference + number
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidAssignment {
    /// The OID components.
    pub components: Vec<OidComponent>,
    /// Source location (includes braces).
    pub span: Span,
}

impl OidAssignment {
    /// Create a new OID assignment.
    #[must_use]
    pub fn new(components: Vec<OidComponent>, span: Span) -> Self {
        Self { components, span }
    }
}

/// A component of an OID value.
///
/// OID components can be:
/// - Just a name: `internet`
/// - Just a number: `1`
/// - Name with number: `org(3)`
/// - Qualified name: `SNMPv2-SMI.enterprises`
/// - Qualified name with number: `SNMPv2-SMI.enterprises(1)`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OidComponent {
    /// Named reference: `internet`, `ifEntry`
    Name(Ident),
    /// Numeric subid: `1`, `31`
    Number {
        /// The numeric value.
        value: u32,
        /// Source location.
        span: Span,
    },
    /// Named with number: `iso(1)`, `org(3)`
    NamedNumber {
        /// The name.
        name: Ident,
        /// The numeric value.
        number: u32,
        /// Source location (covers `name(number)`).
        span: Span,
    },
    /// Qualified name reference: `SNMPv2-SMI.enterprises`
    QualifiedName {
        /// The module name.
        module: Ident,
        /// The symbol name.
        name: Ident,
        /// Source location.
        span: Span,
    },
    /// Qualified name with number: `SNMPv2-SMI.enterprises(1)`
    QualifiedNamedNumber {
        /// The module name.
        module: Ident,
        /// The symbol name.
        name: Ident,
        /// The numeric value.
        number: u32,
        /// Source location.
        span: Span,
    },
}

impl OidComponent {
    /// Get the span of this component.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            Self::Name(ident) => ident.span,
            Self::Number { span, .. }
            | Self::NamedNumber { span, .. }
            | Self::QualifiedName { span, .. }
            | Self::QualifiedNamedNumber { span, .. } => *span,
        }
    }

    /// Get the numeric value if this component has one.
    #[must_use]
    pub fn number(&self) -> Option<u32> {
        match self {
            Self::Name(_) | Self::QualifiedName { .. } => None,
            Self::Number { value, .. } => Some(*value),
            Self::NamedNumber { number, .. } | Self::QualifiedNamedNumber { number, .. } => {
                Some(*number)
            }
        }
    }

    /// Get the name if this component has one.
    #[must_use]
    pub fn name(&self) -> Option<&Ident> {
        match self {
            Self::Name(ident)
            | Self::NamedNumber { name: ident, .. }
            | Self::QualifiedName { name: ident, .. }
            | Self::QualifiedNamedNumber { name: ident, .. } => Some(ident),
            Self::Number { .. } => None,
        }
    }

    /// Get the module name if this is a qualified reference.
    #[must_use]
    pub fn module(&self) -> Option<&Ident> {
        match self {
            Self::QualifiedName { module, .. } | Self::QualifiedNamedNumber { module, .. } => {
                Some(module)
            }
            _ => None,
        }
    }
}
