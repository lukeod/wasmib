//! Phase 2: Import resolution.
//!
//! Verify all imports can be satisfied and record import declarations
//! for dynamic lookup during OID resolution.
//!
//! Key design: imports from a given source module name are resolved ATOMICALLY.
//! All symbols from "FOO-MIB" must come from the same candidate file, never mixed.

use crate::lexer::Span;
use crate::model::{ModuleId, StrId, UnresolvedImportReason};
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

    // Get candidate modules for this source name
    let from_module_name_id = ctx.model.strings().find(from_module_name);
    let candidates: Vec<ModuleId> = from_module_name_id
        .and_then(|id| ctx.module_index.get(&id))
        .cloned()
        .unwrap_or_default();

    // Score candidates and find one with all symbols
    if let Some(chosen_id) =
        find_candidate_with_all_symbols(ctx, &candidates, &user_symbols, from_module_name, tracer)
    {
        tracer.trace_candidate_chosen(from_module_name, chosen_id);
        for sym in &user_symbols {
            let sym_id = ctx.intern(&sym.name);
            ctx.register_import(importing_module, sym_id, chosen_id);
        }
        return;
    }

    // No candidate has all symbols. Try module aliasing as fallback.
    // This handles cases like SNMPv2-SMI-v1 files that exist but lack type definitions.
    if let Some(aliased_name) = base_module_import_alias(from_module_name) {
        let aliased_name_id = ctx.model.strings().find(aliased_name);
        let alias_candidates: Vec<ModuleId> = aliased_name_id
            .and_then(|id| ctx.module_index.get(&id))
            .cloned()
            .unwrap_or_default();

        if let Some(chosen_id) = find_candidate_with_all_symbols(
            ctx,
            &alias_candidates,
            &user_symbols,
            aliased_name,
            tracer,
        ) {
            tracer.trace_candidate_chosen(from_module_name, chosen_id);
            for sym in &user_symbols {
                let sym_id = ctx.intern(&sym.name);
                ctx.register_import(importing_module, sym_id, chosen_id);
            }
            return;
        }
    }

    // Last resort: try import forwarding.
    // This handles cases where a module imports a symbol but doesn't re-export it
    // (a vendor bug, but common with CISCO-TC and Unsigned32).
    if !candidates.is_empty() {
        if let Some(forwarded_symbols) =
            try_import_forwarding(ctx, &candidates, &user_symbols, from_module_name, tracer)
        {
            // Register each forwarded symbol pointing to its actual source module
            for (sym_id, source_module_id) in forwarded_symbols {
                ctx.register_import(importing_module, sym_id, source_module_id);
            }
            return;
        }
    }

    // No candidate (original or alias) has all symbols - mark as unresolved
    let reason = if candidates.is_empty() {
        UnresolvedImportReason::ModuleNotFound
    } else {
        UnresolvedImportReason::SymbolNotExported
    };

    for sym in &user_symbols {
        tracer.trace_unresolved(importing_module, from_module_name, &sym.name);
        ctx.record_unresolved_import(
            importing_module,
            from_module_name,
            &sym.name,
            reason,
            sym.span,
        );
    }
}

/// Find the best candidate that has ALL required symbols.
/// Returns None if no candidate has all symbols.
fn find_candidate_with_all_symbols<TR: ImportTracer>(
    ctx: &ResolverContext,
    candidates: &[ModuleId],
    user_symbols: &[&ImportSymbol],
    from_module_name: &str,
    tracer: &mut TR,
) -> Option<ModuleId> {
    if candidates.is_empty() {
        return None;
    }

    // Score candidates by:
    // 1. How many of the required symbols they have
    // 2. LAST-UPDATED timestamp (prefer more recent - handles draft vs RFC)
    let mut scored_candidates: Vec<(ModuleId, usize, Option<String>)> = Vec::new();
    let total_symbols = user_symbols.len();

    for &candidate_id in candidates {
        if let Some(hir_module) = ctx.get_hir_module(candidate_id) {
            // Build set of definition names once for O(1) lookup
            let def_names: BTreeSet<&str> = hir_module
                .definitions
                .iter()
                .filter_map(|def| def.name().map(|n| n.name.as_str()))
                .collect();

            // Count how many symbols this candidate has
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

    // Return first candidate with ALL symbols
    scored_candidates
        .into_iter()
        .find(|(_, count, _)| *count == total_symbols)
        .map(|(id, _, _)| id)
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

/// Try to resolve a symbol via import forwarding.
///
/// Import forwarding handles cases where a module imports a symbol but doesn't
/// re-export it (which is technically a vendor bug). For example, CISCO-TC
/// imports Unsigned32 from SNMPv2-SMI but doesn't re-export it. When a MIB
/// tries to import Unsigned32 FROM CISCO-TC, we can forward to SNMPv2-SMI.
///
/// Returns Some((forwarded_module_id, all_symbols_forwarded)) if forwarding succeeds.
fn try_import_forwarding<TR: ImportTracer>(
    ctx: &ResolverContext,
    candidates: &[ModuleId],
    user_symbols: &[&ImportSymbol],
    _from_module_name: &str,
    _tracer: &mut TR,
) -> Option<Vec<(StrId, ModuleId)>> {
    // For each candidate, check if it imports all the required symbols
    for &candidate_id in candidates {
        if let Some(hir_module) = ctx.get_hir_module(candidate_id) {
            // Build a map of symbol name -> source module name from this module's imports
            let mut import_map: BTreeMap<&str, &str> = BTreeMap::new();
            for imp in &hir_module.imports {
                import_map.insert(&imp.symbol.name, &imp.module.name);
            }

            // Check if all required symbols are imported by this candidate
            let mut forwarded_symbols: Vec<(StrId, ModuleId)> = Vec::new();
            let mut all_found = true;

            for sym in user_symbols {
                if let Some(&source_module_name) = import_map.get(sym.name.as_str()) {
                    // This symbol is imported by the candidate - find the source module
                    let source_module_name_id = ctx.model.strings().find(source_module_name);
                    if let Some(source_name_id) = source_module_name_id {
                        if let Some(source_candidates) = ctx.module_index.get(&source_name_id) {
                            // Take the first candidate for simplicity
                            // (In practice, base modules like SNMPv2-SMI have only one instance)
                            if let Some(&source_module_id) = source_candidates.first() {
                                let sym_id =
                                    ctx.model.strings().find(&sym.name).unwrap_or_else(|| {
                                        // This shouldn't happen as symbols should be interned
                                        panic!("Symbol {} not interned", sym.name)
                                    });
                                forwarded_symbols.push((sym_id, source_module_id));
                                continue;
                            }
                        }
                    }
                }
                // Symbol not found in imports or source module not found
                all_found = false;
                break;
            }

            if all_found && !forwarded_symbols.is_empty() {
                return Some(forwarded_symbols);
            }
        }
    }

    None
}

/// Returns an alias for a module name, used as a **fallback** during import resolution.
///
/// The alias is consulted when:
/// 1. No module with the original name exists, OR
/// 2. The original module exists but doesn't export all required symbols
///
/// This handles cases like `SNMPv2-SMI-v1` files that exist in MIB corpora but
/// lack type definitions (they use ASN.1 syntax we don't parse).
///
/// Use cases:
/// - Vendor variants: `SNMPv2-SMI-v1` → `SNMPv2-SMI` (Cisco uses ASN.1 syntax we don't parse)
/// - Renamed modules: `RFC1315-MIB` → `FRAME-RELAY-DTE-MIB` (obsoleted and renamed)
/// - Typo variants: `RFC-1213` → `RFC1213-MIB` (hyphen vs no-hyphen inconsistency)
fn base_module_import_alias(name: &str) -> Option<&'static str> {
    match name {
        "SNMPv2-SMI-v1" => Some("SNMPv2-SMI"),
        "SNMPv2-TC-v1" => Some("SNMPv2-TC"),
        // RFC1315-MIB was obsoleted and renamed to FRAME-RELAY-DTE-MIB
        "RFC1315-MIB" => Some("FRAME-RELAY-DTE-MIB"),
        // DNS-SERVER-MIB uses RFC-1213 (with hyphen) instead of RFC1213-MIB
        "RFC-1213" => Some("RFC1213-MIB"),
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

    #[test]
    fn test_base_module_import_alias_rfc1315() {
        // Test that imports from RFC1315-MIB resolve to FRAME-RELAY-DTE-MIB
        // RFC1315-MIB was renamed to FRAME-RELAY-DTE-MIB

        // First create a module named FRAME-RELAY-DTE-MIB with the exported symbol
        let mut frame_relay_module =
            Module::new(Symbol::from_name("FRAME-RELAY-DTE-MIB"), Span::new(0, 0));
        frame_relay_module
            .definitions
            .push(crate::module::Definition::ValueAssignment(
                crate::module::ValueAssignment {
                    name: Symbol::from_name("frDlcmiTable"),
                    oid: crate::module::OidAssignment::new(
                        vec![crate::module::OidComponent::Name(Symbol::from_name(
                            "enterprises",
                        ))],
                        Span::new(0, 0),
                    ),
                    span: Span::new(0, 0),
                },
            ));

        // Create a test module that imports from RFC1315-MIB (the old name)
        let test_module =
            make_test_module_with_imports("TEST-MIB", vec![("RFC1315-MIB", "frDlcmiTable")]);

        let modules = vec![frame_relay_module, test_module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // Aliased imports should resolve (RFC1315-MIB -> FRAME-RELAY-DTE-MIB)
        assert!(
            ctx.model.unresolved().imports.is_empty(),
            "expected RFC1315-MIB imports to resolve via alias to FRAME-RELAY-DTE-MIB, got {} unresolved",
            ctx.model.unresolved().imports.len()
        );
    }

    #[test]
    fn test_base_module_import_alias_rfc_1213() {
        // Test that imports from RFC-1213 (with hyphen) resolve to RFC1213-MIB
        // DNS-SERVER-MIB uses this variant naming

        // First create a module named RFC1213-MIB with the exported symbol
        let mut rfc1213_module = Module::new(Symbol::from_name("RFC1213-MIB"), Span::new(0, 0));
        rfc1213_module
            .definitions
            .push(crate::module::Definition::ValueAssignment(
                crate::module::ValueAssignment {
                    name: Symbol::from_name("mib-2"),
                    oid: crate::module::OidAssignment::new(
                        vec![crate::module::OidComponent::Name(Symbol::from_name("mgmt"))],
                        Span::new(0, 0),
                    ),
                    span: Span::new(0, 0),
                },
            ));

        // Create a test module that imports from RFC-1213 (with hyphen, the typo variant)
        let test_module = make_test_module_with_imports("TEST-MIB", vec![("RFC-1213", "mib-2")]);

        let modules = vec![rfc1213_module, test_module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // Aliased imports should resolve (RFC-1213 -> RFC1213-MIB)
        assert!(
            ctx.model.unresolved().imports.is_empty(),
            "expected RFC-1213 imports to resolve via alias to RFC1213-MIB, got {} unresolved",
            ctx.model.unresolved().imports.len()
        );
    }

    #[test]
    fn test_user_module_takes_precedence_over_alias() {
        // Test that user-provided modules take precedence over alias fallback.
        // If a user has an actual RFC1315-MIB file, it should be used instead of
        // falling back to FRAME-RELAY-DTE-MIB.

        // Create user's RFC1315-MIB with a unique symbol
        let mut user_rfc1315 = Module::new(Symbol::from_name("RFC1315-MIB"), Span::new(0, 0));
        user_rfc1315
            .definitions
            .push(crate::module::Definition::ValueAssignment(
                crate::module::ValueAssignment {
                    name: Symbol::from_name("userDefinedSymbol"),
                    oid: crate::module::OidAssignment::new(
                        vec![crate::module::OidComponent::Name(Symbol::from_name(
                            "enterprises",
                        ))],
                        Span::new(0, 0),
                    ),
                    span: Span::new(0, 0),
                },
            ));

        // Create FRAME-RELAY-DTE-MIB with a different symbol
        let mut frame_relay_module =
            Module::new(Symbol::from_name("FRAME-RELAY-DTE-MIB"), Span::new(0, 0));
        frame_relay_module
            .definitions
            .push(crate::module::Definition::ValueAssignment(
                crate::module::ValueAssignment {
                    name: Symbol::from_name("frDlcmiTable"),
                    oid: crate::module::OidAssignment::new(
                        vec![crate::module::OidComponent::Name(Symbol::from_name(
                            "enterprises",
                        ))],
                        Span::new(0, 0),
                    ),
                    span: Span::new(0, 0),
                },
            ));

        // Import from RFC1315-MIB - should use user's module, not fall back to alias
        let test_module =
            make_test_module_with_imports("TEST-MIB", vec![("RFC1315-MIB", "userDefinedSymbol")]);

        let modules = vec![user_rfc1315, frame_relay_module, test_module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // Should resolve from user's RFC1315-MIB, not fall back to FRAME-RELAY-DTE-MIB
        assert!(
            ctx.model.unresolved().imports.is_empty(),
            "user-provided RFC1315-MIB should take precedence over alias, got {} unresolved",
            ctx.model.unresolved().imports.len()
        );
    }

    #[test]
    fn test_import_forwarding() {
        // Test import forwarding: when a module imports but doesn't re-export a symbol,
        // we should forward the import to the original source.
        //
        // This mimics the CISCO-TC/Unsigned32 scenario:
        // - CISCO-TC imports Unsigned32 FROM SNMPv2-SMI (but doesn't define it)
        // - USER-MIB imports Unsigned32 FROM CISCO-TC
        // - Import forwarding should resolve this by forwarding to SNMPv2-SMI

        // Create CISCO-TC which imports Unsigned32 from SNMPv2-SMI but doesn't define it
        let mut cisco_tc = Module::new(Symbol::from_name("CISCO-TC"), Span::new(0, 0));
        cisco_tc.imports.push(Import::new(
            Symbol::from_name("SNMPv2-SMI"),
            Symbol::from_name("Unsigned32"),
            Span::new(0, 0),
        ));
        // Add a local definition so CISCO-TC is a valid module
        cisco_tc
            .definitions
            .push(crate::module::Definition::ValueAssignment(
                crate::module::ValueAssignment {
                    name: Symbol::from_name("ciscoTcObjects"),
                    oid: crate::module::OidAssignment::new(
                        vec![crate::module::OidComponent::Name(Symbol::from_name(
                            "enterprises",
                        ))],
                        Span::new(0, 0),
                    ),
                    span: Span::new(0, 0),
                },
            ));

        // Create USER-MIB which imports Unsigned32 from CISCO-TC
        let user_mib = make_test_module_with_imports("USER-MIB", vec![("CISCO-TC", "Unsigned32")]);

        let modules = vec![cisco_tc, user_mib];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // Import should resolve via forwarding (CISCO-TC -> SNMPv2-SMI)
        assert!(
            ctx.model.unresolved().imports.is_empty(),
            "expected Unsigned32 import to resolve via forwarding, got {} unresolved: {:?}",
            ctx.model.unresolved().imports.len(),
            ctx.model
                .unresolved()
                .imports
                .iter()
                .map(|u| ctx.model.strings().get(u.symbol))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_import_forwarding_multiple_symbols() {
        // Test that import forwarding works when multiple symbols need to be forwarded
        // to possibly different source modules.

        // Create VENDOR-TC which imports Unsigned32 from SNMPv2-SMI and DisplayString from SNMPv2-TC
        let mut vendor_tc = Module::new(Symbol::from_name("VENDOR-TC"), Span::new(0, 0));
        vendor_tc.imports.push(Import::new(
            Symbol::from_name("SNMPv2-SMI"),
            Symbol::from_name("Unsigned32"),
            Span::new(0, 0),
        ));
        vendor_tc.imports.push(Import::new(
            Symbol::from_name("SNMPv2-TC"),
            Symbol::from_name("DisplayString"),
            Span::new(0, 0),
        ));
        // Add a local definition
        vendor_tc
            .definitions
            .push(crate::module::Definition::ValueAssignment(
                crate::module::ValueAssignment {
                    name: Symbol::from_name("vendorTcObjects"),
                    oid: crate::module::OidAssignment::new(
                        vec![crate::module::OidComponent::Name(Symbol::from_name(
                            "enterprises",
                        ))],
                        Span::new(0, 0),
                    ),
                    span: Span::new(0, 0),
                },
            ));

        // Create USER-MIB which imports both from VENDOR-TC
        let user_mib = make_test_module_with_imports(
            "USER-MIB",
            vec![("VENDOR-TC", "Unsigned32"), ("VENDOR-TC", "DisplayString")],
        );

        let modules = vec![vendor_tc, user_mib];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // Both imports should resolve via forwarding
        assert!(
            ctx.model.unresolved().imports.is_empty(),
            "expected imports to resolve via forwarding, got {} unresolved: {:?}",
            ctx.model.unresolved().imports.len(),
            ctx.model
                .unresolved()
                .imports
                .iter()
                .map(|u| ctx.model.strings().get(u.symbol))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_import_forwarding_partial_failure() {
        // Test that if only some symbols can be forwarded, the others are marked unresolved

        // Create VENDOR-TC which imports Unsigned32 but not SomethingElse
        let mut vendor_tc = Module::new(Symbol::from_name("VENDOR-TC"), Span::new(0, 0));
        vendor_tc.imports.push(Import::new(
            Symbol::from_name("SNMPv2-SMI"),
            Symbol::from_name("Unsigned32"),
            Span::new(0, 0),
        ));

        // Create USER-MIB which tries to import both
        let user_mib = make_test_module_with_imports(
            "USER-MIB",
            vec![
                ("VENDOR-TC", "Unsigned32"),
                ("VENDOR-TC", "NonExistentSymbol"),
            ],
        );

        let modules = vec![vendor_tc, user_mib];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // Both should be unresolved because atomic resolution requires all symbols
        // (import forwarding only succeeds if ALL symbols can be forwarded)
        assert_eq!(
            ctx.model.unresolved().imports.len(),
            2,
            "expected 2 unresolved imports (atomic resolution), got {}",
            ctx.model.unresolved().imports.len()
        );
    }
}
