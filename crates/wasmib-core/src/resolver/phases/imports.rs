//! Phase 2: Import resolution.
//!
//! Verify all imports can be satisfied and build import resolution table.

use crate::resolver::context::ResolverContext;

/// Resolve all imports across all modules.
pub fn resolve_imports(ctx: &mut ResolverContext) {
    // Collect module info first to avoid borrow issues
    let module_info: alloc::vec::Vec<_> = ctx
        .hir_modules
        .iter()
        .enumerate()
        .map(|(idx, m)| (idx, m.name.name.clone()))
        .collect();

    for (hir_idx, module_name) in module_info {
        let module_id = match ctx.module_index.get(&module_name) {
            Some(&id) => id,
            None => continue,
        };

        // Get imports for this module
        let imports: alloc::vec::Vec<_> = ctx.hir_modules[hir_idx]
            .imports
            .iter()
            .map(|imp| (imp.module.name.clone(), imp.symbol.name.clone()))
            .collect();

        for (from_module, symbol) in imports {
            // Try to resolve the import
            let resolved = ctx.lookup_definition(&from_module, &symbol);

            if resolved.is_none() {
                // Check if it's a MACRO import (these are acknowledged but don't resolve)
                if !is_macro_symbol(&symbol) {
                    ctx.record_unresolved_import(module_id, &from_module, &symbol);
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{HirImport, HirModule, Symbol};
    use crate::lexer::Span;
    use crate::resolver::phases::registration::register_modules;
    use alloc::vec;

    fn make_test_module_with_imports(
        name: &str,
        imports: Vec<(&str, &str)>,
    ) -> HirModule {
        let mut module = HirModule::new(Symbol::from_str(name), Span::new(0, 0));
        module.imports = imports
            .into_iter()
            .map(|(m, s)| {
                HirImport::new(
                    Symbol::from_str(m),
                    Symbol::from_str(s),
                    Span::new(0, 0),
                )
            })
            .collect();
        module
    }

    #[test]
    fn test_resolve_builtin_import() {
        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![
                ("SNMPv2-SMI", "Counter32"),
                ("SNMPv2-SMI", "enterprises"),
            ],
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
        let mut dep_module = HirModule::new(Symbol::from_str("DEP-MIB"), Span::new(0, 0));
        dep_module.definitions.push(crate::hir::HirDefinition::ValueAssignment(
            crate::hir::HirValueAssignment {
                name: Symbol::from_str("depNode"),
                oid: crate::hir::HirOidAssignment::new(
                    vec![crate::hir::HirOidComponent::Name(Symbol::from_str(
                        "enterprises",
                    ))],
                    Span::new(0, 0),
                ),
                span: Span::new(0, 0),
            },
        ));

        let main_module = make_test_module_with_imports(
            "MAIN-MIB",
            vec![("DEP-MIB", "depNode")],
        );

        let modules = vec![dep_module, main_module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);

        // Cross-module import should resolve
        assert!(ctx.model.unresolved().imports.is_empty());
    }
}
