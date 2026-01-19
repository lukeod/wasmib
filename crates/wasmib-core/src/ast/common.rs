//! Common AST types used across modules.

use crate::lexer::Span;
use alloc::string::String;

/// Identifier with source location.
///
/// Identifiers in SMI are case-sensitive. Uppercase identifiers denote
/// module names and type references; lowercase identifiers denote object
/// names and enum labels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ident {
    /// The identifier text.
    pub name: String,
    /// Source location.
    pub span: Span,
}

impl Ident {
    /// Create a new identifier.
    #[must_use]
    pub fn new(name: String, span: Span) -> Self {
        Self { name, span }
    }

    /// Check if this is an uppercase identifier (module/type name).
    #[must_use]
    pub fn is_uppercase(&self) -> bool {
        self.name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase())
    }

    /// Check if this is a lowercase identifier (object/enum name).
    #[must_use]
    pub fn is_lowercase(&self) -> bool {
        self.name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase())
    }
}

/// Quoted string literal with source location.
///
/// The value contains the string content with quotes stripped.
/// MIB strings can contain non-ASCII characters (often Latin-1 encoded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotedString {
    /// The string content (quotes stripped).
    pub value: String,
    /// Source location (includes quotes).
    pub span: Span,
}

impl QuotedString {
    /// Create a new quoted string.
    #[must_use]
    pub fn new(value: String, span: Span) -> Self {
        Self { value, span }
    }
}

/// Named number in an enumeration or BITS definition.
///
/// Examples:
/// - `up(1)` in `INTEGER { up(1), down(2) }`
/// - `bit0(0)` in `BITS { bit0(0), bit1(1) }`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedNumber {
    /// The label name.
    pub name: Ident,
    /// The numeric value.
    pub value: i64,
    /// Source location (covers `name(value)`).
    pub span: Span,
}

impl NamedNumber {
    /// Create a new named number.
    #[must_use]
    pub fn new(name: Ident, value: i64, span: Span) -> Self {
        Self { name, value, span }
    }
}
