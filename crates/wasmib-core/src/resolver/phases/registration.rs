//! Phase 1: Module registration.
//!
//! Index all modules and their definitions for subsequent lookup.

use crate::hir::create_base_modules;
use crate::model::ResolvedModule;
use crate::resolver::context::ResolverContext;

/// Register all modules and their definitions.
pub fn register_modules(ctx: &mut ResolverContext) {
    // Prepend synthetic base modules (SNMPv2-SMI, SNMPv2-TC) to the HIR modules list.
    // This ensures the built-in OID roots and types are registered before user modules.
    let base_modules = create_base_modules();

    // Insert base modules at the beginning
    let mut all_modules = base_modules;
    all_modules.append(&mut ctx.hir_modules);
    ctx.hir_modules = all_modules;

    // Collect module names first to avoid borrow issues
    let module_names: alloc::vec::Vec<_> = ctx
        .hir_modules
        .iter()
        .map(|m| m.name.name.clone())
        .collect();

    // Register each HIR module
    for (hir_idx, module_name) in module_names.into_iter().enumerate() {
        // Intern module name
        let name_str = ctx.intern(&module_name);

        // Create resolved module (ID assigned by add_module)
        let module = ResolvedModule::new(name_str);

        let module_id = ctx.model.add_module(module).unwrap();

        // Track bidirectional ModuleId <-> hir_modules index mapping
        ctx.module_id_to_hir_index.insert(module_id, hir_idx);
        ctx.hir_index_to_module_id.insert(hir_idx, module_id);

        // Append to candidates list (handles duplicate module names)
        // Uses StrId key for memory efficiency
        ctx.module_index
            .entry(name_str)
            .or_default()
            .push(module_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{HirDefinition, HirModule, Symbol};
    use crate::lexer::Span;
    use alloc::vec;

    fn make_test_module(name: &str, defs: Vec<HirDefinition>) -> HirModule {
        let mut module = HirModule::new(Symbol::from_str(name), Span::new(0, 0));
        module.definitions = defs;
        module
    }

    #[test]
    fn test_register_empty_module() {
        let modules = vec![make_test_module("TEST-MIB", vec![])];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);

        // 2 base modules (SNMPv2-SMI, SNMPv2-TC) + 1 user module
        assert_eq!(ctx.model.module_count(), 3);
        // Check modules are registered by looking them up via the model
        assert!(ctx.model.get_module_by_name("TEST-MIB").is_some());
        assert!(ctx.model.get_module_by_name("SNMPv2-SMI").is_some());
        assert!(ctx.model.get_module_by_name("SNMPv2-TC").is_some());
    }
}
