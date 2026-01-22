//! Phase 2: Import resolution.
//!
//! Verify all imports can be satisfied and record import declarations
//! for dynamic lookup during OID resolution.
//!
//! Key design: imports from a given source module name are resolved ATOMICALLY.
//! All symbols from "FOO-MIB" must come from the same candidate file, never mixed.

use crate::lexer::Span;
use crate::model::{ModuleId, UnresolvedImportReason};
use crate::module::Definition;
use crate::resolver::context::ResolverContext;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[cfg(feature = "tracing")]
use crate::resolver::tracing::{TraceEvent, TraceLevel, Tracer};

// ============================================================================
// ImportTracer trait - abstracts over tracing to eliminate code duplication
// ============================================================================

/// Trait for optional import resolution tracing.
///
/// Methods default to no-ops, enabling zero-cost abstraction when tracing is disabled.
/// This allows a single implementation of import resolution logic to serve both
/// traced and non-traced code paths.
trait ImportTracer {
    /// Called when a candidate module is scored for import resolution.
    fn trace_candidate_scored(
        &mut self,
        _from_module: &str,
        _candidate_id: ModuleId,
        _symbols_found: usize,
        _total: usize,
    ) {
    }

    /// Called when a candidate is chosen for all imports from a source module.
    fn trace_candidate_chosen(&mut self, _from_module: &str, _chosen_id: ModuleId) {}

    /// Called when an import cannot be resolved.
    fn trace_unresolved(&mut self, _importing_module: ModuleId, _from_module: &str, _symbol: &str) {
    }
}

/// No-op tracer for non-traced resolution.
struct NoopImportTracer;

impl ImportTracer for NoopImportTracer {}

/// Wrapper that adapts a `Tracer` to the `ImportTracer` trait.
#[cfg(feature = "tracing")]
struct TracingWrapper<'a, T: Tracer>(&'a mut T);

#[cfg(feature = "tracing")]
impl<T: Tracer> ImportTracer for TracingWrapper<'_, T> {
    fn trace_candidate_scored(
        &mut self,
        from_module: &str,
        candidate_id: ModuleId,
        symbols_found: usize,
        total: usize,
    ) {
        crate::trace_event!(
            self.0,
            TraceLevel::Debug,
            TraceEvent::ImportCandidateScored {
                from_module,
                candidate_id,
                symbols_found,
                total,
            }
        );
    }

    fn trace_candidate_chosen(&mut self, from_module: &str, chosen_id: ModuleId) {
        crate::trace_event!(
            self.0,
            TraceLevel::Debug,
            TraceEvent::ImportCandidateChosen {
                from_module,
                chosen_id,
            }
        );
    }

    fn trace_unresolved(&mut self, importing_module: ModuleId, from_module: &str, symbol: &str) {
        crate::trace_event!(
            self.0,
            TraceLevel::Debug,
            TraceEvent::ImportUnresolved {
                importing_module,
                from_module,
                symbol,
            }
        );
    }
}

/// An import symbol with its source span.
struct ImportSymbol {
    name: String,
    span: Span,
}

/// Resolve all imports across all modules.
pub fn resolve_imports(ctx: &mut ResolverContext) {
    resolve_imports_inner(ctx, &mut NoopImportTracer);
}

/// Resolve all imports across all modules with tracing support.
#[cfg(feature = "tracing")]
pub fn resolve_imports_traced<T: Tracer>(ctx: &mut ResolverContext, tracer: &mut T) {
    resolve_imports_inner(ctx, &mut TracingWrapper(tracer));
}

/// Core import resolution logic, parameterized over tracing.
fn resolve_imports_inner<TR: ImportTracer>(ctx: &mut ResolverContext, tracer: &mut TR) {
    // Collect all (ModuleId, hir_idx) pairs
    let module_ids: Vec<_> = ctx
        .module_id_to_hir_index
        .iter()
        .map(|(&module_id, &hir_idx)| (module_id, hir_idx))
        .collect();

    for (module_id, hir_idx) in module_ids {
        // Group imports by source module name, keeping spans
        let mut imports_by_source: BTreeMap<String, Vec<ImportSymbol>> = BTreeMap::new();
        for imp in &ctx.hir_modules[hir_idx].imports {
            imports_by_source
                .entry(imp.module.name.clone())
                .or_default()
                .push(ImportSymbol {
                    name: imp.symbol.name.clone(),
                    span: imp.span,
                });
        }

        // Resolve each source module atomically
        for (from_module_name, symbols) in imports_by_source {
            resolve_imports_from_module_inner(ctx, module_id, &from_module_name, &symbols, tracer);
        }
    }
}

/// Extract LAST-UPDATED timestamp from a module's MODULE-IDENTITY.
/// Returns None if not found. Normalizes to YYYYMMDDHHMMZ format for comparison.
fn extract_last_updated(ctx: &ResolverContext, module_id: ModuleId) -> Option<String> {
    let hir_idx = ctx.module_id_to_hir_index.get(&module_id)?;
    let hir_module = ctx.hir_modules.get(*hir_idx)?;

    for def in &hir_module.definitions {
        if let Definition::ModuleIdentity(mi) = def
            && !mi.last_updated.is_empty()
        {
            return Some(normalize_timestamp(&mi.last_updated));
        }
    }
    None
}

/// Normalize LAST-UPDATED timestamp to YYYYMMDDHHMMZ format.
/// Handles both 4-digit years (200604040000Z) and 2-digit years (9907231200Z).
fn normalize_timestamp(ts: &str) -> String {
    // Strip any trailing 'Z' for length check
    let ts_trimmed = ts.trim_end_matches('Z');

    // 4-digit year format: YYYYMMDDHHMMZ (12 chars without Z)
    // 2-digit year format: YYMMDDHHMMZ (10 chars without Z)
    if ts_trimmed.len() == 10 {
        // 2-digit year - need to expand to 4-digit
        if let Ok(yy) = ts_trimmed[0..2].parse::<u32>() {
            // Assume: 70-99 -> 1970-1999, 00-69 -> 2000-2069
            let century = if yy >= 70 { "19" } else { "20" };
            return format!("{century}{ts_trimmed}Z");
        }
    }

    // Already 4-digit year or unknown format - return as-is
    ts.to_string()
}

/// Resolve all imports from a single source module name atomically.
/// All symbols must come from the same candidate, or all are marked unresolved.
fn resolve_imports_from_module_inner<TR: ImportTracer>(
    ctx: &mut ResolverContext,
    importing_module: ModuleId,
    from_module_name: &str,
    symbols: &[ImportSymbol],
    tracer: &mut TR,
) {
    // Filter out MACROs (they don't need resolution)
    let user_symbols: Vec<_> = symbols
        .iter()
        .filter(|s| !is_macro_symbol(&s.name))
        .collect();

    // If no symbols to resolve (all MACROs), we're done
    if user_symbols.is_empty() {
        return;
    }

    // Apply base module aliasing for non-standard vendor module names
    // (e.g., SNMPv2-SMI-v1 → SNMPv2-SMI)
    let effective_module_name = base_module_import_alias(from_module_name)
        .unwrap_or(from_module_name);

    // Get candidate modules for this source name
    let from_module_name_id = ctx.model.strings().find(effective_module_name);
    let candidates: Vec<ModuleId> = from_module_name_id
        .and_then(|id| ctx.module_index.get(&id))
        .cloned()
        .unwrap_or_default();

    if candidates.is_empty() {
        // No candidates at all - mark all as unresolved
        for sym in &user_symbols {
            tracer.trace_unresolved(importing_module, from_module_name, &sym.name);
            ctx.record_unresolved_import(
                importing_module,
                from_module_name,
                &sym.name,
                UnresolvedImportReason::ModuleNotFound,
                sym.span,
            );
        }
        return;
    }

    // Score candidates by:
    // 1. How many of the required symbols they have
    // 2. LAST-UPDATED timestamp (prefer more recent - handles draft vs RFC)
    let mut scored_candidates: Vec<(ModuleId, usize, Option<String>)> = Vec::new();
    let total_symbols = user_symbols.len();

    for &candidate_id in &candidates {
        if let Some(hir_module) = ctx.get_hir_module(candidate_id) {
            // Build set of definition names once for O(1) lookup
            let def_names: BTreeSet<&str> = hir_module
                .definitions
                .iter()
                .filter_map(|def| def.name().map(|n| n.name.as_str()))
                .collect();

            // Count how many symbols this candidate has (O(symbols) instead of O(symbols × definitions))
            let symbol_count = user_symbols
                .iter()
                .filter(|sym| def_names.contains(sym.name.as_str()))
                .count();

            // Get LAST-UPDATED for tiebreaking (prefer newer modules)
            let last_updated = extract_last_updated(ctx, candidate_id);

            tracer.trace_candidate_scored(
                from_module_name,
                candidate_id,
                symbol_count,
                total_symbols,
            );

            scored_candidates.push((candidate_id, symbol_count, last_updated));
        }
    }

    // Sort by: 1) symbol count (desc), 2) last_updated (desc)
    scored_candidates.sort_by(|a, b| {
        b.1.cmp(&a.1) // More symbols first
            .then_with(|| b.2.cmp(&a.2)) // More recent LAST-UPDATED first
    });

    // Try candidates in order until we find one with ALL symbols
    for (candidate_id, symbol_count, _last_updated) in &scored_candidates {
        if *symbol_count == user_symbols.len() {
            // This candidate has all the symbols - use it for everything
            tracer.trace_candidate_chosen(from_module_name, *candidate_id);
            for sym in &user_symbols {
                let sym_id = ctx.intern(&sym.name);
                ctx.register_import(importing_module, sym_id, *candidate_id);
            }
            return;
        }
    }

    // No single candidate has all symbols.
    // Mark all as unresolved to maintain atomicity.
    for sym in &user_symbols {
        tracer.trace_unresolved(importing_module, from_module_name, &sym.name);
        ctx.record_unresolved_import(
            importing_module,
            from_module_name,
            &sym.name,
            UnresolvedImportReason::SymbolNotExported,
            sym.span,
        );
    }
}

/// Check if a symbol name is a MACRO (no runtime resolution needed).
fn is_macro_symbol(name: &str) -> bool {
    matches!(
        name,
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

/// Check if a module name should be aliased to a base module for import resolution.
///
/// Some vendor MIBs (notably Cisco) import from non-standard module names like
/// `SNMPv2-SMI-v1` that are functionally equivalent to `SNMPv2-SMI`. These files
/// typically contain the same definitions but use ASN.1 syntax that wasmib doesn't
/// parse (e.g., `[APPLICATION n] IMPLICIT` tagged types).
///
/// This alias allows imports from such modules to resolve against the synthetic
/// base modules, without treating the vendor variants as canonical base modules.
fn base_module_import_alias(name: &str) -> Option<&'static str> {
    match name {
        "SNMPv2-SMI-v1" => Some("SNMPv2-SMI"),
        "SNMPv2-TC-v1" => Some("SNMPv2-TC"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Span;
    use crate::module::{Import, Module, Symbol};
    use crate::resolver::phases::registration::register_modules;
    use alloc::vec;

    fn make_test_module_with_imports(name: &str, imports: Vec<(&str, &str)>) -> Module {
        let mut module = Module::new(Symbol::from_name(name), Span::new(0, 0));
        module.imports = imports
            .into_iter()
            .map(|(m, s)| Import::new(Symbol::from_name(m), Symbol::from_name(s), Span::new(0, 0)))
            .collect();
        module
    }

    #[test]
    fn test_resolve_builtin_import() {
        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![("SNMPv2-SMI", "Counter32"), ("SNMPv2-SMI", "enterprises")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // No unresolved imports for built-ins
        assert!(ctx.model.unresolved().imports.is_empty());
    }

    #[test]
    fn test_resolve_macro_import() {
        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![("SNMPv2-SMI", "OBJECT-TYPE")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // MACRO imports don't cause unresolved errors
        assert!(ctx.model.unresolved().imports.is_empty());
    }

    #[test]
    fn test_unresolved_import() {
        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![("UNKNOWN-MIB", "unknownSymbol")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // Should have one unresolved import
        assert_eq!(ctx.model.unresolved().imports.len(), 1);
    }

    #[test]
    fn test_cross_module_import() {
        // Create two modules where one imports from the other
        let mut dep_module = Module::new(Symbol::from_name("DEP-MIB"), Span::new(0, 0));
        dep_module
            .definitions
            .push(crate::module::Definition::ValueAssignment(
                crate::module::ValueAssignment {
                    name: Symbol::from_name("depNode"),
                    oid: crate::module::OidAssignment::new(
                        vec![crate::module::OidComponent::Name(Symbol::from_name(
                            "enterprises",
                        ))],
                        Span::new(0, 0),
                    ),
                    span: Span::new(0, 0),
                },
            ));

        let main_module = make_test_module_with_imports("MAIN-MIB", vec![("DEP-MIB", "depNode")]);

        let modules = vec![dep_module, main_module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // Cross-module import should resolve
        assert!(ctx.model.unresolved().imports.is_empty());
    }

    #[test]
    fn test_base_module_import_alias() {
        // Test that imports from SNMPv2-SMI-v1 resolve to SNMPv2-SMI
        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![
                ("SNMPv2-SMI-v1", "Counter32"),
                ("SNMPv2-SMI-v1", "enterprises"),
            ],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // Aliased imports should resolve (to synthetic SNMPv2-SMI)
        assert!(
            ctx.model.unresolved().imports.is_empty(),
            "expected SNMPv2-SMI-v1 imports to resolve via alias, got {} unresolved",
            ctx.model.unresolved().imports.len()
        );
    }

    #[test]
    fn test_base_module_import_alias_tc() {
        // Test that imports from SNMPv2-TC-v1 resolve to SNMPv2-TC
        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![("SNMPv2-TC-v1", "DisplayString")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // Aliased imports should resolve (to synthetic SNMPv2-TC)
        assert!(
            ctx.model.unresolved().imports.is_empty(),
            "expected SNMPv2-TC-v1 imports to resolve via alias, got {} unresolved",
            ctx.model.unresolved().imports.len()
        );
    }
}
