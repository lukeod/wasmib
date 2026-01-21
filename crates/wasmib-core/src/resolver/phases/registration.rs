//! Phase 1: Module registration.
//!
//! Index all modules and their definitions for subsequent lookup.

use alloc::vec::Vec;

use crate::model::ResolvedModule;
use crate::module::{create_base_modules, is_base_module};
use crate::resolver::context::ResolverContext;

/// Register all modules and their definitions.
pub fn register_modules(ctx: &mut ResolverContext) {
    // Prepend synthetic base modules to the HIR modules list.
    // This ensures the built-in OID roots and types are registered before user modules.
    let base_modules = create_base_modules();

    // Filter out user-provided base modules (they are superseded by synthetic modules)
    let user_modules: Vec<_> = ctx
        .hir_modules
        .drain(..)
        .filter(|m| {
            if is_base_module(&m.name.name) {
                // Skip user-provided base modules - synthetic modules are authoritative
                // Could emit info diagnostic here if desired
                false
            } else {
                true
            }
        })
        .collect();

    // Insert base modules at the beginning, followed by filtered user modules
    ctx.hir_modules = base_modules;
    ctx.hir_modules.extend(user_modules);

    // Register each HIR module (iterate by index to avoid borrow issues)
    for hir_idx in 0..ctx.hir_modules.len() {
        let module_name = ctx.hir_modules[hir_idx].name.name.clone();
        // Intern module name
        let name_str = ctx.intern(&module_name);

        // Create resolved module (ID assigned by add_module)
        let module = ResolvedModule::new(name_str);

        let module_id = ctx.model.add_module(module).unwrap();

        // Track SNMPv2-SMI module ID for primitive type lookup
        if module_name == "SNMPv2-SMI" {
            ctx.snmpv2_smi_module_id = Some(module_id);
        }

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
    use crate::lexer::Span;
    use crate::module::{Definition, Module, Symbol};
    use alloc::vec;

    fn make_test_module(name: &str, defs: Vec<Definition>) -> Module {
        let mut module = Module::new(Symbol::from_name(name), Span::new(0, 0));
        module.definitions = defs;
        module
    }

    #[test]
    fn test_register_empty_module() {
        let modules = vec![make_test_module("TEST-MIB", vec![])];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);

        // 8 base modules + 1 user module
        assert_eq!(ctx.model.module_count(), 9);
        // Check modules are registered by looking them up via the model
        assert!(ctx.model.get_module_by_name("TEST-MIB").is_some());
        assert!(ctx.model.get_module_by_name("SNMPv2-SMI").is_some());
        assert!(ctx.model.get_module_by_name("SNMPv2-TC").is_some());
    }
}
