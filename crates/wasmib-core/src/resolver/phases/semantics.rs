//! Phase 5: Semantic analysis.
//!
//! Infer node kinds, resolve table semantics, and perform validation.

use crate::hir::{HirDefinition, HirTypeSyntax};
use crate::model::{
    Access, IndexItem, IndexSpec, NodeId, NodeKind, ResolvedObject, Status, UnresolvedIndex,
};
use crate::resolver::context::ResolverContext;
use alloc::vec::Vec;

/// Perform semantic analysis on the resolved model.
pub fn analyze_semantics(ctx: &mut ResolverContext) {
    // Infer node kinds based on syntax and context
    infer_node_kinds(ctx);

    // Resolve table semantics (INDEX, AUGMENTS)
    resolve_table_semantics(ctx);

    // Create resolved objects
    create_resolved_objects(ctx);
}

/// Infer node kinds from SYNTAX and context.
fn infer_node_kinds(ctx: &mut ResolverContext) {
    // Collect OBJECT-TYPE definitions with their syntax and module name
    let object_types: Vec<_> = ctx
        .hir_modules
        .iter()
        .flat_map(|module| {
            let module_name = module.name.name.clone();
            module
                .definitions
                .iter()
                .filter_map(move |def| {
                    if let HirDefinition::ObjectType(obj) = def {
                        Some((module_name.clone(), obj.clone()))
                    } else {
                        None
                    }
                })
        })
        .collect();

    // First pass: identify TABLEs and ROWs
    for (module_name, obj) in &object_types {
        if let Some(node_id) = ctx.lookup_node_in_module(module_name, &obj.name.name) {
            let kind = if obj.syntax.is_sequence_of() {
                NodeKind::Table
            } else if obj.index.is_some() || obj.augments.is_some() {
                NodeKind::Row
            } else {
                // Default to Scalar, will be refined below
                NodeKind::Scalar
            };

            if let Some(node) = ctx.model.get_node_mut(node_id) {
                node.kind = kind;
            }
        }
    }

    // Second pass: identify COLUMNs (children of ROWs)
    let row_children: Vec<_> = ctx
        .model
        .root_ids()
        .iter()
        .copied()
        .flat_map(|root| collect_row_children(ctx, root))
        .collect();

    for child_id in row_children {
        if let Some(node) = ctx.model.get_node_mut(child_id) {
            if matches!(node.kind, NodeKind::Scalar) {
                node.kind = NodeKind::Column;
            }
        }
    }
}

/// Collect children of ROW nodes.
fn collect_row_children(ctx: &ResolverContext, node_id: NodeId) -> Vec<NodeId> {
    let mut result = Vec::new();

    if let Some(node) = ctx.model.get_node(node_id) {
        if node.kind == NodeKind::Row {
            // All children of a ROW are COLUMNs
            result.extend(node.children.iter().copied());
        }

        // Recurse into children
        for &child_id in &node.children {
            result.extend(collect_row_children(ctx, child_id));
        }
    }

    result
}

/// Resolve table semantics (INDEX and AUGMENTS).
fn resolve_table_semantics(ctx: &mut ResolverContext) {
    // Collect OBJECT-TYPEs with INDEX or AUGMENTS
    // Iterate over all registered ModuleIds to get the correct ModuleId for each HirModule
    let table_defs: Vec<_> = ctx
        .module_id_to_hir_index
        .iter()
        .flat_map(|(&module_id, &hir_idx)| {
            ctx.hir_modules
                .get(hir_idx)
                .into_iter()
                .flat_map(move |module| {
                    module.definitions.iter().filter_map(move |def| {
                        if let HirDefinition::ObjectType(obj) = def {
                            if obj.index.is_some() || obj.augments.is_some() {
                                return Some((
                                    module_id,
                                    obj.name.name.clone(),
                                    obj.index.clone(),
                                    obj.augments.clone(),
                                ));
                            }
                        }
                        None
                    })
                })
        })
        .collect();

    for (module_id, name, index_opt, augments_opt) in table_defs {
        let module_name = match ctx.model.get_module(module_id) {
            Some(m) => ctx.model.get_str(m.name).to_string(),
            None => continue,
        };

        // Resolve INDEX objects
        if let Some(ref index_items) = index_opt {
            for item in index_items {
                // INDEX objects can be local or imported (lookup_node_in_module handles all cases)
                if ctx.lookup_node_in_module(&module_name, &item.object.name).is_none() {
                    let row_str = ctx.intern(&name);
                    let index_str = ctx.intern(&item.object.name);
                    ctx.model
                        .unresolved_mut()
                        .indexes
                        .push(UnresolvedIndex {
                            module: module_id,
                            row: row_str,
                            index_object: index_str,
                        });
                }
            }
        }

        // Resolve AUGMENTS target
        if let Some(ref augments_sym) = augments_opt {
            if ctx.lookup_node_in_module(&module_name, &augments_sym.name).is_none() {
                ctx.record_unresolved_oid(module_id, &name, &augments_sym.name);
            }
        }
    }
}

/// Create ResolvedObject entries for all OBJECT-TYPEs.
fn create_resolved_objects(ctx: &mut ResolverContext) {
    // Collect all (ModuleId, HirObjectType) pairs
    // We iterate over all registered ModuleIds to get the correct ModuleId for each HirModule
    let object_types: Vec<_> = ctx
        .module_id_to_hir_index
        .iter()
        .flat_map(|(&module_id, &hir_idx)| {
            ctx.hir_modules
                .get(hir_idx)
                .into_iter()
                .flat_map(move |module| {
                    module.definitions.iter().filter_map(move |def| {
                        if let HirDefinition::ObjectType(obj) = def {
                            Some((module_id, obj.clone()))
                        } else {
                            None
                        }
                    })
                })
        })
        .collect();

    for (module_id, obj) in object_types {
        let module_name = match ctx.model.get_module(module_id) {
            Some(m) => ctx.model.get_str(m.name).to_string(),
            None => continue,
        };

        let node_id = match ctx.lookup_node_in_module(&module_name, &obj.name.name) {
            Some(id) => id,
            None => continue,
        };

        // Find the type (may be None if unresolved)
        let type_id = resolve_type_syntax(ctx, &obj.syntax, module_id, &obj.name.name);

        let name = ctx.intern(&obj.name.name);
        let access = hir_access_to_access(obj.access);
        let status = hir_status_to_status(obj.status);

        let mut resolved = ResolvedObject::new(
            crate::model::ObjectId::from_raw(1).unwrap(), // Will be updated
            node_id,
            module_id,
            name,
            type_id,
            access,
        );

        resolved.status = status;

        if let Some(ref desc) = obj.description {
            resolved.description = Some(ctx.intern(desc));
        }

        if let Some(ref units) = obj.units {
            resolved.units = Some(ctx.intern(units));
        }

        if let Some(ref reference) = obj.reference {
            resolved.reference = Some(ctx.intern(reference));
        }

        // Handle INDEX
        if let Some(ref index_items) = obj.index {
            let items: Vec<_> = index_items
                .iter()
                .filter_map(|item| {
                    ctx.lookup_node_in_module(&module_name, &item.object.name)
                        .map(|node_id| IndexItem::new(node_id, item.implied))
                })
                .collect();
            if !items.is_empty() {
                resolved.index = Some(IndexSpec::new(items));
            }
        }

        // Handle AUGMENTS
        if let Some(ref augments_sym) = obj.augments {
            resolved.augments = ctx.lookup_node_in_module(&module_name, &augments_sym.name);
        }

        // Handle inline enums
        if let HirTypeSyntax::IntegerEnum(ref enums) = obj.syntax {
            let values: Vec<_> = enums
                .iter()
                .map(|(sym, val)| (*val, ctx.intern(&sym.name)))
                .collect();
            resolved.inline_enum = Some(crate::model::EnumValues::new(values));
        }

        // Handle inline BITS
        if let HirTypeSyntax::Bits(ref bits) = obj.syntax {
            let defs: Vec<_> = bits
                .iter()
                .map(|(sym, pos)| (*pos, ctx.intern(&sym.name)))
                .collect();
            resolved.inline_bits = Some(crate::model::BitDefinitions::new(defs));
        }

        let obj_id = ctx.model.add_object(resolved);

        // Update node with object reference (match by module AND label)
        if let Some(node) = ctx.model.get_node_mut(node_id) {
            if let Some(def) = node.definitions.iter_mut().find(|d| d.label == name && d.module == module_id) {
                def.object = Some(obj_id);
            }
        }

        // Add to module
        if let Some(module) = ctx.model.get_module_mut(module_id) {
            module.add_object(obj_id);
        }
    }
}

/// Resolve a type syntax to a TypeId.
///
/// Returns `None` if the type reference couldn't be resolved, and records
/// the unresolved type in `UnresolvedReferences`.
fn resolve_type_syntax(
    ctx: &mut ResolverContext,
    syntax: &HirTypeSyntax,
    module_id: crate::model::ModuleId,
    object_name: &str,
) -> Option<crate::model::TypeId> {
    match syntax {
        HirTypeSyntax::TypeRef(name) => {
            match ctx.lookup_type(&name.name) {
                Some(type_id) => Some(type_id),
                None => {
                    // Record the unresolved type reference
                    ctx.record_unresolved_type(module_id, object_name, &name.name);
                    None
                }
            }
        }
        HirTypeSyntax::Constrained { base, .. } => {
            resolve_type_syntax(ctx, base, module_id, object_name)
        }
        HirTypeSyntax::IntegerEnum(_) => {
            // INTEGER with enum values - base type is Integer32
            ctx.lookup_type("Integer32")
        }
        HirTypeSyntax::Bits(_) => {
            // BITS type
            ctx.lookup_type("BITS")
        }
        HirTypeSyntax::OctetString => {
            ctx.lookup_type("OCTET STRING")
        }
        HirTypeSyntax::ObjectIdentifier => {
            ctx.lookup_type("OBJECT IDENTIFIER")
        }
        HirTypeSyntax::SequenceOf(_) | HirTypeSyntax::Sequence(_) => {
            // Table/row types - these don't have a meaningful "type" in the SNMP sense
            // They're structural, not data types. Return None as there's no appropriate type.
            // (Tables and rows are identified by NodeKind, not by their type_id)
            None
        }
    }
}

fn hir_access_to_access(access: crate::hir::HirAccess) -> Access {
    match access {
        crate::hir::HirAccess::ReadOnly => Access::ReadOnly,
        crate::hir::HirAccess::ReadWrite => Access::ReadWrite,
        crate::hir::HirAccess::ReadCreate => Access::ReadCreate,
        crate::hir::HirAccess::NotAccessible => Access::NotAccessible,
        crate::hir::HirAccess::AccessibleForNotify => Access::AccessibleForNotify,
        crate::hir::HirAccess::WriteOnly => Access::WriteOnly,
    }
}

fn hir_status_to_status(status: crate::hir::HirStatus) -> Status {
    match status {
        crate::hir::HirStatus::Current => Status::Current,
        crate::hir::HirStatus::Deprecated => Status::Deprecated,
        crate::hir::HirStatus::Obsolete => Status::Obsolete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{
        HirImport, HirIndexItem, HirModule, HirObjectType, HirOidAssignment, HirOidComponent, HirTypeSyntax,
        HirAccess, HirDefinition, HirStatus, Symbol,
    };
    use crate::lexer::Span;
    use crate::resolver::phases::{imports::resolve_imports, registration::register_modules, oids::resolve_oids, types::resolve_types};
    use alloc::vec;

    fn make_object_type(
        name: &str,
        syntax: HirTypeSyntax,
        oid_components: Vec<HirOidComponent>,
        index: Option<Vec<HirIndexItem>>,
    ) -> HirDefinition {
        HirDefinition::ObjectType(HirObjectType {
            name: Symbol::from_str(name),
            syntax,
            units: None,
            access: HirAccess::ReadOnly,
            status: HirStatus::Current,
            description: Some("Test object".into()),
            reference: None,
            index,
            augments: None,
            oid: HirOidAssignment::new(oid_components, Span::new(0, 0)),
            span: Span::new(0, 0),
        })
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

    #[test]
    fn test_table_inference() {
        let table = make_object_type(
            "testTable",
            HirTypeSyntax::SequenceOf(Symbol::from_str("TestEntry")),
            vec![
                HirOidComponent::Name(Symbol::from_str("enterprises")),
                HirOidComponent::Number(1),
            ],
            None,
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![table],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Check table node kind
        if let Some(node_id) = ctx.lookup_node_in_module("TEST-MIB", "testTable") {
            if let Some(node) = ctx.model.get_node(node_id) {
                assert_eq!(node.kind, NodeKind::Table);
            }
        }
    }

    #[test]
    fn test_row_inference() {
        let row = make_object_type(
            "testEntry",
            HirTypeSyntax::TypeRef(Symbol::from_str("TestEntry")),
            vec![
                HirOidComponent::Name(Symbol::from_str("enterprises")),
                HirOidComponent::Number(1),
            ],
            Some(vec![HirIndexItem::new(Symbol::from_str("testIndex"), false)]),
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![row],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Check row node kind
        if let Some(node_id) = ctx.lookup_node_in_module("TEST-MIB", "testEntry") {
            if let Some(node) = ctx.model.get_node(node_id) {
                assert_eq!(node.kind, NodeKind::Row);
            }
        }
    }

    #[test]
    fn test_resolved_object_creation() {
        let obj = make_object_type(
            "testObject",
            HirTypeSyntax::TypeRef(Symbol::from_str("Integer32")),
            vec![
                HirOidComponent::Name(Symbol::from_str("enterprises")),
                HirOidComponent::Number(1),
            ],
            None,
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![obj],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Check object count
        assert_eq!(ctx.model.object_count(), 1);
    }

    #[test]
    fn test_unresolved_type_returns_none() {
        // Create an object with a reference to a non-existent type
        let obj = make_object_type(
            "testObject",
            HirTypeSyntax::TypeRef(Symbol::from_str("NonExistentType")),
            vec![
                HirOidComponent::Name(Symbol::from_str("enterprises")),
                HirOidComponent::Number(1),
            ],
            None,
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![obj],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Object should be created
        assert_eq!(ctx.model.object_count(), 1);

        // Get the object and verify type_id is None
        let obj = ctx.model.get_object(crate::model::ObjectId::from_raw(1).unwrap());
        assert!(obj.is_some());
        assert!(obj.unwrap().type_id.is_none(), "type_id should be None for unresolved type");
    }

    #[test]
    fn test_unresolved_type_recorded_in_unresolved_references() {
        // Create an object with a reference to a non-existent type
        let obj = make_object_type(
            "testObject",
            HirTypeSyntax::TypeRef(Symbol::from_str("FakeType")),
            vec![
                HirOidComponent::Name(Symbol::from_str("enterprises")),
                HirOidComponent::Number(1),
            ],
            None,
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![obj],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Check that the unresolved type was recorded
        let unresolved = ctx.model.unresolved();
        assert!(!unresolved.types.is_empty(), "should have recorded unresolved type");

        // Verify the unresolved type reference details
        let unresolved_type = &unresolved.types[0];
        assert_eq!(ctx.model.get_str(unresolved_type.referrer), "testObject");
        assert_eq!(ctx.model.get_str(unresolved_type.referenced), "FakeType");
    }

    #[test]
    fn test_resolved_type_has_some_type_id() {
        // Create an object with a valid type reference
        let obj = make_object_type(
            "testObject",
            HirTypeSyntax::TypeRef(Symbol::from_str("Integer32")),
            vec![
                HirOidComponent::Name(Symbol::from_str("enterprises")),
                HirOidComponent::Number(1),
            ],
            None,
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![obj],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Object should be created with a valid type_id
        let obj = ctx.model.get_object(crate::model::ObjectId::from_raw(1).unwrap());
        assert!(obj.is_some());
        assert!(obj.unwrap().type_id.is_some(), "type_id should be Some for resolved type");
    }

    #[test]
    fn test_table_type_has_none_type_id() {
        // SEQUENCE OF types (tables) have no meaningful type_id
        let table = make_object_type(
            "testTable",
            HirTypeSyntax::SequenceOf(Symbol::from_str("TestEntry")),
            vec![
                HirOidComponent::Name(Symbol::from_str("enterprises")),
                HirOidComponent::Number(1),
            ],
            None,
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![table],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Table object should have None type_id (structural, not data type)
        let obj = ctx.model.get_object(crate::model::ObjectId::from_raw(1).unwrap());
        assert!(obj.is_some());
        assert!(obj.unwrap().type_id.is_none(), "table type_id should be None");
    }

    #[test]
    fn test_inline_bits_type_has_type_id() {
        // BITS with inline definitions should have a type_id
        let obj = make_object_type(
            "testBits",
            HirTypeSyntax::Bits(vec![
                (Symbol::from_str("flag1"), 0),
                (Symbol::from_str("flag2"), 1),
            ]),
            vec![
                HirOidComponent::Name(Symbol::from_str("enterprises")),
                HirOidComponent::Number(1),
            ],
            None,
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![obj],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Object should have valid type_id pointing to BITS type
        let obj = ctx.model.get_object(crate::model::ObjectId::from_raw(1).unwrap());
        assert!(obj.is_some());
        let obj = obj.unwrap();
        assert!(obj.type_id.is_some(), "BITS type_id should be Some");

        // Check that inline_bits was populated
        assert!(obj.inline_bits.is_some(), "inline_bits should be populated");
    }
}
