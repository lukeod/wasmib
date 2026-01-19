//! Symbol resolution for MIB modules.
//!
//! The resolver transforms HIR modules (with unresolved symbol references) into
//! a fully resolved Model. It handles:
//!
//! - Import resolution (from built-ins and user modules)
//! - Type resolution (building inheritance chains)
//! - OID tree construction
//! - Table/index semantics
//!
//! # Pipeline
//!
//! ```text
//! HIR Modules → Resolver → Model
//! ```
//!
//! # Built-in Definitions
//!
//! The resolver is pre-seeded with built-in definitions from SMI base modules:
//!
//! - **Types**: Integer32, Counter32, etc. from SNMPv2-SMI
//! - **Textual Conventions**: DisplayString, TruthValue, etc. from SNMPv2-TC
//! - **OID Roots**: iso, internet, enterprises, etc.
//! - **MACROs**: OBJECT-TYPE, MODULE-IDENTITY, etc.
//!
//! These resolve automatically without requiring user-provided base module files.
//!
//! # Usage
//!
//! ```ignore
//! use wasmib_core::resolver::Resolver;
//! use wasmib_core::hir::HirModule;
//!
//! // Parse and lower modules to HIR
//! let hir_modules: Vec<HirModule> = /* ... */;
//!
//! // Create resolver and resolve
//! let resolver = Resolver::new();
//! let result = resolver.resolve(hir_modules);
//!
//! // Access the resolved model
//! let model = result.model;
//! for module in model.modules() {
//!     println!("Module: {}", model.get_str(module.name));
//! }
//! ```

pub mod builtins;
mod context;
mod phases;

pub use builtins::{
    resolve_builtin_symbol, BaseModule, BuiltinBaseType, BuiltinMacro,
    BuiltinOidNode, BuiltinSymbol, BuiltinTextualConvention, TcBaseSyntax, TcConstraint,
    TcSizeConstraint, BUILTIN_OID_NODES, BUILTIN_TEXTUAL_CONVENTIONS,
};

use crate::hir::HirModule;
use crate::lexer::{Diagnostic, Severity, Span};
use crate::model::Model;
use alloc::vec::Vec;
use context::ResolverContext;
use phases::{
    analyze_semantics, register_modules, resolve_imports, resolve_oids, resolve_types,
};

/// Resolver configuration.
#[derive(Clone, Debug, Default)]
pub struct ResolverConfig {
    /// Allow partial results with unresolved references. Default: true.
    pub allow_partial: bool,
}

impl ResolverConfig {
    /// Create a new default config.
    #[must_use]
    pub fn new() -> Self {
        Self { allow_partial: true }
    }

    /// Create a strict config that requires all references to resolve.
    #[must_use]
    pub fn strict() -> Self {
        Self { allow_partial: false }
    }
}

/// Resolution result.
#[derive(Debug)]
pub struct ResolveResult {
    /// The resolved model.
    pub model: Model,
    /// Resolution diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

impl ResolveResult {
    /// Check if resolution completed without unresolved references.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.model.is_complete()
    }
}

/// MIB resolver.
///
/// Transforms HIR modules into a fully resolved Model.
#[derive(Clone, Debug, Default)]
pub struct Resolver {
    config: ResolverConfig,
}

impl Resolver {
    /// Create a new resolver with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ResolverConfig::default(),
        }
    }

    /// Create a new resolver with custom configuration.
    #[must_use]
    pub fn with_config(config: ResolverConfig) -> Self {
        Self { config }
    }

    /// Resolve HIR modules into a Model.
    ///
    /// Resolution proceeds in five phases:
    /// 1. Module registration
    /// 2. Import resolution
    /// 3. Type resolution
    /// 4. OID resolution
    /// 5. Semantic analysis
    ///
    /// Unresolved references are tracked but don't fail resolution
    /// (unless `allow_partial` is false in config).
    #[must_use]
    pub fn resolve(&self, modules: Vec<HirModule>) -> ResolveResult {
        let mut ctx = ResolverContext::new(modules);

        // Phase 1: Register all modules and their definitions
        register_modules(&mut ctx);

        // Phase 2: Resolve imports
        resolve_imports(&mut ctx);

        // Phase 3: Resolve types
        resolve_types(&mut ctx);

        // Phase 4: Resolve OIDs
        resolve_oids(&mut ctx);

        // Phase 5: Semantic analysis
        analyze_semantics(&mut ctx);

        // Collect diagnostics
        let diagnostics = self.collect_diagnostics(&ctx);

        ResolveResult {
            model: ctx.model,
            diagnostics,
        }
    }

    /// Collect resolution diagnostics.
    fn collect_diagnostics(&self, ctx: &ResolverContext) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        // Add diagnostics for unresolved references
        let unresolved = ctx.model.unresolved();

        for imp in &unresolved.imports {
            let from_module = ctx.model.get_str(imp.from_module);
            let symbol = ctx.model.get_str(imp.symbol);
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                span: Span::new(0, 0),
                message: alloc::format!("Unresolved import: {}::{}", from_module, symbol),
            });
        }

        for typ in &unresolved.types {
            let referrer = ctx.model.get_str(typ.referrer);
            let referenced = ctx.model.get_str(typ.referenced);
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                span: Span::new(0, 0),
                message: alloc::format!("Unresolved type reference in {}: {}", referrer, referenced),
            });
        }

        for oid in &unresolved.oids {
            let definition = ctx.model.get_str(oid.definition);
            let component = ctx.model.get_str(oid.component);
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                span: Span::new(0, 0),
                message: alloc::format!("Unresolved OID component in {}: {}", definition, component),
            });
        }

        for idx in &unresolved.indexes {
            let row = ctx.model.get_str(idx.row);
            let index_obj = ctx.model.get_str(idx.index_object);
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                span: Span::new(0, 0),
                message: alloc::format!("Unresolved INDEX object in {}: {}", row, index_obj),
            });
        }

        diagnostics
    }
}

/// Check if a module name is a recognized base module.
#[must_use]
pub fn is_base_module(name: &str) -> bool {
    BaseModule::from_name(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{
        HirAccess, HirDefinition, HirModule, HirObjectType, HirOidAssignment, HirOidComponent,
        HirStatus, HirTypeSyntax, Symbol,
    };
    use crate::lexer::Span;
    use alloc::vec;

    fn make_test_module(name: &str, defs: Vec<HirDefinition>) -> HirModule {
        let mut module = HirModule::new(Symbol::from_str(name), Span::new(0, 0));
        module.definitions = defs;
        module
    }

    fn make_object_type(name: &str, oid_components: Vec<HirOidComponent>) -> HirDefinition {
        HirDefinition::ObjectType(HirObjectType {
            name: Symbol::from_str(name),
            syntax: HirTypeSyntax::TypeRef(Symbol::from_str("Integer32")),
            units: None,
            access: HirAccess::ReadOnly,
            status: HirStatus::Current,
            description: Some("Test object".into()),
            reference: None,
            index: None,
            augments: None,
            oid: HirOidAssignment::new(oid_components, Span::new(0, 0)),
            span: Span::new(0, 0),
        })
    }

    #[test]
    fn test_resolver_empty() {
        let resolver = Resolver::new();
        let result = resolver.resolve(vec![]);

        assert!(result.is_complete());
        assert_eq!(result.model.module_count(), 0);
    }

    #[test]
    fn test_resolver_single_module() {
        let obj = make_object_type(
            "testObject",
            vec![
                HirOidComponent::Name(Symbol::from_str("enterprises")),
                HirOidComponent::Number(1),
            ],
        );

        let modules = vec![make_test_module("TEST-MIB", vec![obj])];
        let resolver = Resolver::new();
        let result = resolver.resolve(modules);

        assert_eq!(result.model.module_count(), 1);
        assert!(result.model.get_module_by_name("TEST-MIB").is_some());

        // Check the object was resolved
        let node = result.model.get_node_by_oid_str("1.3.6.1.4.1.1");
        assert!(node.is_some());
    }

    #[test]
    fn test_resolver_builtin_types_available() {
        let modules = vec![make_test_module("TEST-MIB", vec![])];
        let resolver = Resolver::new();
        let result = resolver.resolve(modules);

        // Check built-in types are available
        assert!(result.model.type_count() > 0);
    }

    #[test]
    fn test_resolver_builtin_oids_available() {
        let modules = vec![make_test_module("TEST-MIB", vec![])];
        let resolver = Resolver::new();
        let result = resolver.resolve(modules);

        // Check built-in OIDs are available
        assert!(result.model.get_node_by_oid_str("1.3.6.1").is_some()); // internet
        assert!(result.model.get_node_by_oid_str("1.3.6.1.4.1").is_some()); // enterprises
    }

    #[test]
    fn test_resolver_tracks_unresolved() {
        let obj = make_object_type(
            "testObject",
            vec![
                HirOidComponent::Name(Symbol::from_str("unknownNode")),
                HirOidComponent::Number(1),
            ],
        );

        let modules = vec![make_test_module("TEST-MIB", vec![obj])];
        let resolver = Resolver::new();
        let result = resolver.resolve(modules);

        // Should have unresolved OID
        assert!(!result.is_complete());
        assert!(!result.diagnostics.is_empty());
    }
}
