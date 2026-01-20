//! Symbol resolution for MIB modules.
//!
//! The resolver transforms HIR modules (with unresolved symbol references) into
//! a fully resolved Model. It handles:
//!
//! - Import resolution
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
//! # Synthetic Base Modules
//!
//! The resolver automatically prepends synthetic `SNMPv2-SMI` and `SNMPv2-TC`
//! modules containing the built-in definitions:
//!
//! - **Types**: Integer32, Counter32, etc.
//! - **Textual Conventions**: DisplayString, TruthValue, etc.
//! - **OID Roots**: iso, internet, enterprises, etc.
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

mod context;
mod phases;

#[cfg(feature = "tracing")]
pub mod tracing;

use crate::hir::HirModule;
use crate::lexer::{Diagnostic, Severity, Span};
use crate::model::Model;
use alloc::vec::Vec;
use context::ResolverContext;
use phases::{analyze_semantics, deduplicate_definitions, register_modules, resolve_imports, resolve_oids, resolve_types};
#[cfg(feature = "tracing")]
use phases::{resolve_imports_traced, resolve_oids_traced};

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
pub struct Resolver;

impl Resolver {
    /// Create a new resolver.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Resolve HIR modules into a Model.
    ///
    /// Resolution proceeds in six phases:
    /// 1. Module registration
    /// 2. Import resolution
    /// 3. Type resolution
    /// 4. OID resolution
    /// 5. Semantic analysis
    /// 6. Deduplication (remove identical definitions from duplicate module files)
    ///
    /// Unresolved references are tracked but do not fail resolution.
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

        // Phase 6: Deduplicate identical definitions from duplicate module files
        deduplicate_definitions(&mut ctx.model);

        // Collect diagnostics
        let diagnostics = self.collect_diagnostics(&ctx);

        ResolveResult {
            model: ctx.model,
            diagnostics,
        }
    }

    /// Resolve HIR modules into a Model with tracing support.
    ///
    /// The tracer receives structured events during resolution, enabling
    /// debugging of OID resolution issues and import conflicts.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use wasmib_core::resolver::{Resolver, tracing::{Tracer, TraceLevel, TraceEvent}};
    ///
    /// struct StderrTracer;
    /// impl Tracer for StderrTracer {
    ///     fn trace(&mut self, level: TraceLevel, event: TraceEvent<'_>) {
    ///         eprintln!("[{:?}] {:?}", level, event);
    ///     }
    /// }
    ///
    /// let resolver = Resolver::new();
    /// let result = resolver.resolve_with_tracer(modules, &mut StderrTracer);
    /// ```
    #[must_use]
    #[cfg(feature = "tracing")]
    pub fn resolve_with_tracer<T: tracing::Tracer>(
        &self,
        modules: Vec<HirModule>,
        tracer: &mut T,
    ) -> ResolveResult {
        use tracing::{Phase, TraceEvent, TraceLevel};

        let mut ctx = ResolverContext::new(modules);

        // Phase 1: Register all modules and their definitions
        crate::trace_event!(tracer, TraceLevel::Info, TraceEvent::PhaseStart { phase: Phase::Registration });
        register_modules(&mut ctx);
        crate::trace_event!(tracer, TraceLevel::Info, TraceEvent::PhaseEnd { phase: Phase::Registration });

        // Phase 2: Resolve imports
        crate::trace_event!(tracer, TraceLevel::Info, TraceEvent::PhaseStart { phase: Phase::Imports });
        resolve_imports_traced(&mut ctx, tracer);
        crate::trace_event!(tracer, TraceLevel::Info, TraceEvent::PhaseEnd { phase: Phase::Imports });

        // Phase 3: Resolve types
        crate::trace_event!(tracer, TraceLevel::Info, TraceEvent::PhaseStart { phase: Phase::Types });
        resolve_types(&mut ctx);
        crate::trace_event!(tracer, TraceLevel::Info, TraceEvent::PhaseEnd { phase: Phase::Types });

        // Phase 4: Resolve OIDs
        crate::trace_event!(tracer, TraceLevel::Info, TraceEvent::PhaseStart { phase: Phase::Oids });
        resolve_oids_traced(&mut ctx, tracer);
        crate::trace_event!(tracer, TraceLevel::Info, TraceEvent::PhaseEnd { phase: Phase::Oids });

        // Phase 5: Semantic analysis
        crate::trace_event!(tracer, TraceLevel::Info, TraceEvent::PhaseStart { phase: Phase::Semantics });
        analyze_semantics(&mut ctx);
        crate::trace_event!(tracer, TraceLevel::Info, TraceEvent::PhaseEnd { phase: Phase::Semantics });

        // Phase 6: Deduplicate identical definitions from duplicate module files
        deduplicate_definitions(&mut ctx.model);

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
        let unresolved = ctx.model.unresolved();

        // Helper to push error diagnostic
        let mut push_error = |span: Span, message: String| {
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                span,
                message,
            });
        };

        for imp in &unresolved.imports {
            let from_module = ctx.model.get_str(imp.from_module);
            let symbol = ctx.model.get_str(imp.symbol);
            push_error(imp.span, alloc::format!("Unresolved import: {}::{}", from_module, symbol));
        }

        for typ in &unresolved.types {
            let referrer = ctx.model.get_str(typ.referrer);
            let referenced = ctx.model.get_str(typ.referenced);
            push_error(typ.span, alloc::format!("Unresolved type reference in {}: {}", referrer, referenced));
        }

        for oid in &unresolved.oids {
            let definition = ctx.model.get_str(oid.definition);
            let component = ctx.model.get_str(oid.component);
            push_error(oid.span, alloc::format!("Unresolved OID component in {}: {}", definition, component));
        }

        for idx in &unresolved.indexes {
            let row = ctx.model.get_str(idx.row);
            let index_obj = ctx.model.get_str(idx.index_object);
            push_error(idx.span, alloc::format!("Unresolved INDEX object in {}: {}", row, index_obj));
        }

        diagnostics
    }
}

/// Check if a module name is a recognized base module.
#[must_use]
pub fn is_base_module(name: &str) -> bool {
    crate::hir::is_base_module(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{
        HirAccess, HirDefinition, HirImport, HirModule, HirObjectType, HirOidAssignment, HirOidComponent,
        HirStatus, HirTypeSyntax, Symbol,
    };
    use crate::lexer::Span;
    use alloc::vec;

    fn make_test_module(name: &str, defs: Vec<HirDefinition>) -> HirModule {
        let mut module = HirModule::new(Symbol::from_str(name), Span::new(0, 0));
        module.definitions = defs;
        module
    }

    /// Create a test module with imports.
    /// imports is a list of (symbol, from_module) pairs.
    fn make_test_module_with_imports(name: &str, defs: Vec<HirDefinition>, imports: Vec<(&str, &str)>) -> HirModule {
        let mut module = HirModule::new(Symbol::from_str(name), Span::new(0, 0));
        module.definitions = defs;
        // HirImport::new takes (module, symbol, span)
        module.imports = imports
            .into_iter()
            .map(|(sym, from)| HirImport::new(Symbol::from_str(from), Symbol::from_str(sym), Span::new(0, 0)))
            .collect();
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
            defval: None,
            oid: HirOidAssignment::new(oid_components, Span::new(0, 0)),
            span: Span::new(0, 0),
        })
    }

    #[test]
    fn test_resolver_empty() {
        let resolver = Resolver::new();
        let result = resolver.resolve(vec![]);

        assert!(result.is_complete());
        // 2 base modules (SNMPv2-SMI, SNMPv2-TC) are always included
        assert_eq!(result.model.module_count(), 2);
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

        // Module must import "enterprises" from SNMPv2-SMI
        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![obj],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let resolver = Resolver::new();
        let result = resolver.resolve(modules);

        // 2 base modules (SNMPv2-SMI, SNMPv2-TC) + 1 user module
        assert_eq!(result.model.module_count(), 3);
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
