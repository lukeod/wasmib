//! HIR module and import types.

use super::definition::HirDefinition;
use super::types::{SmiLanguage, Symbol};
use crate::lexer::{Diagnostic, Span};
use alloc::vec::Vec;

/// A normalized MIB module.
#[derive(Clone, Debug)]
pub struct HirModule {
    /// Module name.
    pub name: Symbol,
    /// Detected SMI language.
    pub language: SmiLanguage,
    /// Normalized imports.
    pub imports: Vec<HirImport>,
    /// Normalized definitions.
    pub definitions: Vec<HirDefinition>,
    /// Source span for diagnostics.
    pub span: Span,
    /// Lowering diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

impl HirModule {
    /// Create a new HIR module.
    #[must_use]
    pub fn new(name: Symbol, span: Span) -> Self {
        Self {
            name,
            language: SmiLanguage::Unknown,
            imports: Vec::new(),
            definitions: Vec::new(),
            span,
            diagnostics: Vec::new(),
        }
    }

    /// Check if this module has any errors.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == crate::lexer::Severity::Error)
    }

    /// Get all definition names.
    pub fn definition_names(&self) -> impl Iterator<Item = &Symbol> {
        self.definitions.iter().filter_map(|d| d.name())
    }
}

/// A normalized import.
///
/// Each import is flattened to individual symbols with normalized module/symbol names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HirImport {
    /// Normalized module name (e.g., `SNMPv2-SMI` not `RFC1155-SMI`).
    pub module: Symbol,
    /// Normalized symbol name (e.g., `Counter32` not `Counter`).
    pub symbol: Symbol,
    /// Original source span.
    pub span: Span,
}

impl HirImport {
    /// Create a new normalized import.
    #[must_use]
    pub fn new(module: Symbol, symbol: Symbol, span: Span) -> Self {
        Self {
            module,
            symbol,
            span,
        }
    }

    /// Check if this import is from an SMIv2 base module.
    #[must_use]
    pub fn is_smiv2_import(&self) -> bool {
        matches!(
            self.module.name.as_str(),
            "SNMPv2-SMI" | "SNMPv2-TC" | "SNMPv2-CONF" | "SNMPv2-MIB"
        )
    }

    /// Check if this import is from any base module (built-in).
    #[must_use]
    pub fn is_base_module_import(&self) -> bool {
        matches!(
            self.module.name.as_str(),
            "SNMPv2-SMI"
                | "SNMPv2-TC"
                | "SNMPv2-CONF"
                | "SNMPv2-MIB"
                | "RFC1155-SMI"
                | "RFC1065-SMI"
                | "RFC-1212"
                | "RFC-1215"
                | "RFC1213-MIB"
        )
    }

    /// Check if this import is for a MACRO (no runtime value).
    #[must_use]
    pub fn is_macro_import(&self) -> bool {
        matches!(
            self.symbol.name.as_str(),
            "MODULE-IDENTITY"
                | "OBJECT-IDENTITY"
                | "OBJECT-TYPE"
                | "NOTIFICATION-TYPE"
                | "TEXTUAL-CONVENTION"
                | "OBJECT-GROUP"
                | "NOTIFICATION-GROUP"
                | "MODULE-COMPLIANCE"
                | "AGENT-CAPABILITIES"
                | "TRAP-TYPE"
        )
    }
}
