//! Module-level AST types.

use super::{Definition, Ident};
use crate::lexer::{Diagnostic, Span};
use alloc::vec::Vec;

/// A parsed MIB module.
///
/// Represents the top-level structure of a MIB file:
/// ```text
/// ModuleName DEFINITIONS ::= BEGIN
///     IMPORTS ... ;
///     <definitions>
/// END
/// ```
#[derive(Clone, Debug)]
pub struct Module {
    /// Module name (e.g., `IF-MIB`, `SNMPv2-SMI`).
    pub name: Ident,
    /// The kind of definitions (DEFINITIONS or PIB-DEFINITIONS).
    pub definitions_kind: DefinitionsKind,
    /// Import clauses.
    pub imports: Vec<ImportClause>,
    /// Export clause (SMIv1 only, rare).
    pub exports: Option<ExportsClause>,
    /// Module body definitions.
    pub body: Vec<Definition>,
    /// Source location (entire module).
    pub span: Span,
    /// Parse diagnostics (errors and warnings).
    pub diagnostics: Vec<Diagnostic>,
}

impl Module {
    /// Create a new module.
    #[must_use]
    pub fn new(name: Ident, definitions_kind: DefinitionsKind, span: Span) -> Self {
        Self {
            name,
            definitions_kind,
            imports: Vec::new(),
            exports: None,
            body: Vec::new(),
            span,
            diagnostics: Vec::new(),
        }
    }

    /// Check if this module has parse errors.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == crate::lexer::Severity::Error)
    }
}

/// The kind of module definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefinitionsKind {
    /// Standard MIB module: `DEFINITIONS ::= BEGIN`
    Definitions,
    /// SPPI PIB module: `PIB-DEFINITIONS ::= BEGIN`
    PibDefinitions,
}

/// An import clause specifying symbols imported from another module.
///
/// Example:
/// ```text
/// IMPORTS
///     MODULE-IDENTITY, OBJECT-TYPE
///         FROM SNMPv2-SMI
///     DisplayString
///         FROM SNMPv2-TC;
/// ```
///
/// Each `ImportClause` represents one `<symbols> FROM <module>` group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportClause {
    /// Symbols being imported.
    pub symbols: Vec<Ident>,
    /// Source module name.
    pub from_module: Ident,
    /// Source location (covers `<symbols> FROM <module>`).
    pub span: Span,
}

impl ImportClause {
    /// Create a new import clause.
    #[must_use]
    pub fn new(symbols: Vec<Ident>, from_module: Ident, span: Span) -> Self {
        Self {
            symbols,
            from_module,
            span,
        }
    }
}

/// An exports clause (SMIv1 only).
///
/// The EXPORTS keyword is handled by the lexer skip state, so this type
/// only records that an EXPORTS clause was present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportsClause {
    /// Source location.
    pub span: Span,
}
