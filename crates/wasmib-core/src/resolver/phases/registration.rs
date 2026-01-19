//! Phase 1: Module registration.
//!
//! Index all modules and their definitions for subsequent lookup.

use crate::model::ResolvedModule;
use crate::resolver::context::{DefinitionRef, ResolverContext};

/// Register all modules and their definitions.
pub fn register_modules(ctx: &mut ResolverContext) {
    // Seed built-in OID nodes first
    ctx.seed_builtin_oids();

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
            (idx, module_name, def_names)
        })
        .collect();

    // Register each HIR module
    for (_hir_idx, module_name, def_names) in module_info {
        // Intern module name
        let name_str = ctx.intern(&module_name);

        // Create resolved module
        let module = ResolvedModule::new(
            crate::model::ModuleId::from_raw(1).unwrap(), // Will be updated
            name_str,
        );

        // Add to model
        let module_id = ctx.model.add_module(module);

        // Index by name
        ctx.module_index.insert(module_name.clone(), module_id);

        // Index each definition
        for (def_idx, def_name) in def_names {
            ctx.definition_index.insert(
                (module_name.clone(), def_name),
                DefinitionRef::User {
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

        assert_eq!(ctx.model.module_count(), 1);
        assert!(ctx.module_index.contains_key("TEST-MIB"));
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
    fn test_builtin_oids_seeded() {
        let modules = vec![make_test_module("TEST-MIB", vec![])];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);

        // Check built-in OID nodes exist
        assert!(ctx.lookup_node("iso").is_some());
        assert!(ctx.lookup_node("internet").is_some());
        assert!(ctx.lookup_node("enterprises").is_some());
        assert!(ctx.lookup_node("mib-2").is_some());
    }
}
