//! Phase 1: Module registration.
//!
//! Index all modules and their definitions for subsequent lookup.

use crate::hir::create_base_modules;
use crate::model::ResolvedModule;
use crate::resolver::context::{DefinitionRef, ResolverContext};

/// Register all modules and their definitions.
pub fn register_modules(ctx: &mut ResolverContext) {
    // Prepend synthetic base modules (SNMPv2-SMI, SNMPv2-TC) to the HIR modules list.
    // This ensures the built-in OID roots and types are registered before user modules.
    let base_modules = create_base_modules();
    let base_count = base_modules.len();

    // Insert base modules at the beginning
    let mut all_modules = base_modules;
    all_modules.append(&mut ctx.hir_modules);
    ctx.hir_modules = all_modules;

    // Collect module info first to avoid borrow issues
    let module_info: alloc::vec::Vec<_> = ctx
        .hir_modules
        .iter()
        .enumerate()
        .map(|(idx, m)| {
            let module_name = m.name.name.clone();
            let def_names: alloc::vec::Vec<_> = m
                .definitions
                .iter()
                .enumerate()
                .filter_map(|(def_idx, def)| {
                    def.name().map(|n| (def_idx, n.name.clone()))
                })
                .collect();
            (idx, module_name, def_names, idx < base_count)
        })
        .collect();

    // Register each HIR module
    for (hir_idx, module_name, def_names, _is_base_module) in module_info {
        // Intern module name
        let name_str = ctx.intern(&module_name);

        // Create resolved module (ID assigned by add_module)
        let module = ResolvedModule::new(name_str);

        // Add to model
        let module_id = ctx.model.add_module(module);

        // Track ModuleId -> hir_modules index mapping
        ctx.module_id_to_hir_index.insert(module_id, hir_idx);

        // Append to candidates list (handles duplicate module names)
        ctx.module_index
            .entry(module_name.clone())
            .or_default()
            .push(module_id);

        // Index each definition (keyed by module name for lookup_definition)
        for (def_idx, def_name) in def_names {
            ctx.definition_index.insert(
                (module_name.clone(), def_name),
                DefinitionRef {
                    module: module_id,
                    def_index: def_idx,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{HirModule, HirObjectType, HirOidAssignment, HirOidComponent, HirTypeSyntax};
    use crate::hir::{HirAccess, HirDefinition, HirStatus, Symbol};
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
        assert!(ctx.module_index.contains_key("TEST-MIB"));
        assert!(ctx.module_index.contains_key("SNMPv2-SMI"));
        assert!(ctx.module_index.contains_key("SNMPv2-TC"));
    }

    #[test]
    fn test_register_module_with_definition() {
        let obj = HirObjectType {
            name: Symbol::from_str("testObject"),
            syntax: HirTypeSyntax::TypeRef(Symbol::from_str("Integer32")),
            units: None,
            access: HirAccess::ReadOnly,
            status: HirStatus::Current,
            description: None,
            reference: None,
            index: None,
            augments: None,
            oid: HirOidAssignment::new(
                vec![
                    HirOidComponent::Name(Symbol::from_str("enterprises")),
                    HirOidComponent::Number(1),
                ],
                Span::new(0, 0),
            ),
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::ObjectType(obj)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);

        // Check definition is indexed
        assert!(ctx
            .definition_index
            .contains_key(&("TEST-MIB".into(), "testObject".into())));
    }

    #[test]
    fn test_builtin_definitions_indexed() {
        let modules = vec![make_test_module("TEST-MIB", vec![])];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);

        // Check built-in definitions are indexed (OID nodes are created during OID resolution)
        assert!(ctx.definition_index.contains_key(&("SNMPv2-SMI".into(), "iso".into())));
        assert!(ctx.definition_index.contains_key(&("SNMPv2-SMI".into(), "internet".into())));
        assert!(ctx.definition_index.contains_key(&("SNMPv2-SMI".into(), "enterprises".into())));
        assert!(ctx.definition_index.contains_key(&("SNMPv2-SMI".into(), "mib-2".into())));
    }
}
