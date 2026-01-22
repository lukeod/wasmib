//! Phase 5: Semantic analysis.
//!
//! Infer node kinds, resolve table semantics, and perform validation.
//!
//! # Memory Optimization
//!
//! This phase uses index references instead of cloning HIR objects.
//! Instead of `Vec<(ModuleId, ObjectType)>` which clones the entire struct
//! including `Option<String>` fields, we use `Vec<HirRef>` which stores only
//! indices and accesses the data through the context.

use crate::lexer::Span;
use crate::model::{
    Access, DefVal, IndexItem, IndexSpec, ModuleId, NodeId, NodeKind, ResolvedNotification,
    ResolvedObject, Status, UnresolvedIndex,
};
use crate::module::{DefVal as ModuleDefVal, Definition, Notification, ObjectType, TypeSyntax};
use crate::resolver::context::ResolverContext;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

/// Reference to a HIR definition by indices.
///
/// This avoids cloning entire `ObjectType` or `Notification` structs,
/// significantly reducing peak memory when processing large MIB corpora.
#[derive(Clone, Copy)]
struct HirRef {
    module_id: ModuleId,
    hir_idx: usize,
    def_idx: usize,
}

/// Perform semantic analysis on the resolved model.
pub fn analyze_semantics(ctx: &mut ResolverContext) {
    // Infer node kinds based on syntax and context
    infer_node_kinds(ctx);

    // Resolve table semantics (INDEX, AUGMENTS)
    resolve_table_semantics(ctx);

    // Create resolved objects
    create_resolved_objects(ctx);

    // Create resolved notifications
    create_resolved_notifications(ctx);
}

/// Infer node kinds from SYNTAX and context.
fn infer_node_kinds(ctx: &mut ResolverContext) {
    // Collect references to OBJECT-TYPE definitions (no cloning)
    let obj_refs = collect_object_type_refs(ctx);

    // First pass: identify TABLEs and ROWs
    for obj_ref in &obj_refs {
        if let Some(obj) = get_object_type(ctx, obj_ref)
            && let Some(node_id) = ctx.lookup_node_for_module(obj_ref.module_id, &obj.name.name)
        {
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
        if let Some(node) = ctx.model.get_node_mut(child_id)
            && matches!(node.kind, NodeKind::Scalar)
        {
            node.kind = NodeKind::Column;
        }
    }
}

/// Collect references to all OBJECT-TYPE definitions without cloning.
fn collect_object_type_refs(ctx: &ResolverContext) -> Vec<HirRef> {
    ctx.module_id_to_hir_index
        .iter()
        .flat_map(|(&module_id, &hir_idx)| {
            ctx.hir_modules
                .get(hir_idx)
                .into_iter()
                .flat_map(move |module| {
                    module
                        .definitions
                        .iter()
                        .enumerate()
                        .filter_map(move |(def_idx, def)| {
                            if matches!(def, Definition::ObjectType(_)) {
                                Some(HirRef {
                                    module_id,
                                    hir_idx,
                                    def_idx,
                                })
                            } else {
                                None
                            }
                        })
                })
        })
        .collect()
}

/// Get an OBJECT-TYPE from a reference.
fn get_object_type<'a>(ctx: &'a ResolverContext, r: &HirRef) -> Option<&'a ObjectType> {
    ctx.hir_modules
        .get(r.hir_idx)
        .and_then(|m| m.definitions.get(r.def_idx))
        .and_then(|def| {
            if let Definition::ObjectType(obj) = def {
                Some(obj)
            } else {
                None
            }
        })
}

/// Collect references to all NOTIFICATION definitions without cloning.
fn collect_notification_refs(ctx: &ResolverContext) -> Vec<HirRef> {
    ctx.module_id_to_hir_index
        .iter()
        .flat_map(|(&module_id, &hir_idx)| {
            ctx.hir_modules
                .get(hir_idx)
                .into_iter()
                .flat_map(move |module| {
                    module
                        .definitions
                        .iter()
                        .enumerate()
                        .filter_map(move |(def_idx, def)| {
                            if matches!(def, Definition::Notification(_)) {
                                Some(HirRef {
                                    module_id,
                                    hir_idx,
                                    def_idx,
                                })
                            } else {
                                None
                            }
                        })
                })
        })
        .collect()
}

/// Get a NOTIFICATION from a reference.
fn get_notification<'a>(ctx: &'a ResolverContext, r: &HirRef) -> Option<&'a Notification> {
    ctx.hir_modules
        .get(r.hir_idx)
        .and_then(|m| m.definitions.get(r.def_idx))
        .and_then(|def| {
            if let Definition::Notification(n) = def {
                Some(n)
            } else {
                None
            }
        })
}

/// Collect children of ROW nodes.
/// Uses a visited set to prevent infinite recursion if the tree has cycles.
fn collect_row_children(ctx: &ResolverContext, node_id: NodeId) -> Vec<NodeId> {
    let mut visited = BTreeSet::new();
    let mut result = Vec::new();
    collect_row_children_inner(ctx, node_id, &mut visited, &mut result);
    result
}

/// Inner recursive helper for `collect_row_children` with cycle detection.
fn collect_row_children_inner(
    ctx: &ResolverContext,
    node_id: NodeId,
    visited: &mut BTreeSet<NodeId>,
    result: &mut Vec<NodeId>,
) {
    // Cycle detection: skip if already visited
    if !visited.insert(node_id) {
        return;
    }

    if let Some(node) = ctx.model.get_node(node_id) {
        if node.kind == NodeKind::Row {
            // All children of a ROW are COLUMNs
            result.extend(node.children.iter().copied());
        }

        // Recurse into children
        for &child_id in &node.children {
            collect_row_children_inner(ctx, child_id, visited, result);
        }
    }
}

/// Resolve table semantics (INDEX and AUGMENTS).
fn resolve_table_semantics(ctx: &mut ResolverContext) {
    // Collect references to OBJECT-TYPEs with INDEX or AUGMENTS
    let table_refs: Vec<_> = ctx
        .module_id_to_hir_index
        .iter()
        .flat_map(|(&module_id, &hir_idx)| {
            ctx.hir_modules
                .get(hir_idx)
                .into_iter()
                .flat_map(move |module| {
                    module
                        .definitions
                        .iter()
                        .enumerate()
                        .filter_map(move |(def_idx, def)| {
                            if let Definition::ObjectType(obj) = def
                                && (obj.index.is_some() || obj.augments.is_some())
                            {
                                return Some(HirRef {
                                    module_id,
                                    hir_idx,
                                    def_idx,
                                });
                            }
                            None
                        })
                })
        })
        .collect();

    for table_ref in table_refs {
        // Extract data needed from the object in a single borrow scope
        let table_data = {
            let Some(obj) = get_object_type(ctx, &table_ref) else {
                continue;
            };
            TableData {
                name: obj.name.name.clone(),
                span: obj.span,
                index: obj.index.clone(),
                augments: obj.augments.clone(),
            }
        };

        let module_id = table_ref.module_id;

        // Resolve INDEX objects
        if let Some(ref index_items) = table_data.index {
            for item in index_items {
                // INDEX objects can be local or imported (lookup_node_for_module handles all cases)
                if ctx
                    .lookup_node_for_module(module_id, &item.object.name)
                    .is_none()
                {
                    let row_str = ctx.intern(&table_data.name);
                    let index_str = ctx.intern(&item.object.name);
                    ctx.model.unresolved_mut().indexes.push(UnresolvedIndex {
                        module: module_id,
                        row: row_str,
                        index_object: index_str,
                        span: table_data.span,
                    });
                }
            }
        }

        // Resolve AUGMENTS target
        if let Some(ref augments_sym) = table_data.augments
            && ctx
                .lookup_node_for_module(module_id, &augments_sym.name)
                .is_none()
        {
            ctx.record_unresolved_oid(
                module_id,
                &table_data.name,
                &augments_sym.name,
                table_data.span,
            );
        }
    }
}

/// Extracted data for table semantics processing.
struct TableData {
    name: alloc::string::String,
    span: Span,
    index: Option<Vec<crate::module::IndexItem>>,
    augments: Option<crate::module::Symbol>,
}

/// Create `ResolvedObject` entries for all OBJECT-TYPEs.
fn create_resolved_objects(ctx: &mut ResolverContext) {
    // Collect references to all OBJECT-TYPE definitions (no cloning)
    let obj_refs = collect_object_type_refs(ctx);

    for obj_ref in obj_refs {
        // Extract all data from the object in a single borrow scope
        let obj_data = {
            let Some(obj) = get_object_type(ctx, &obj_ref) else {
                continue;
            };

            // Extract all data needed for processing
            ObjectData {
                name: obj.name.name.clone(),
                syntax: obj.syntax.clone(),
                units: obj.units.clone(),
                access: obj.access,
                status: obj.status,
                description: obj.description.clone(),
                reference: obj.reference.clone(),
                index: obj.index.clone(),
                augments: obj.augments.clone(),
                defval: obj.defval.clone(),
                span: obj.span,
            }
        };

        let module_id = obj_ref.module_id;
        let Some(node_id) = ctx.lookup_node_for_module(module_id, &obj_data.name) else {
            continue;
        };

        // Find the type (may be None if unresolved)
        let type_id = resolve_type_syntax(
            ctx,
            &obj_data.syntax,
            module_id,
            &obj_data.name,
            obj_data.span,
        );

        let name = ctx.intern(&obj_data.name);
        let access = hir_access_to_access(obj_data.access);
        let status = hir_status_to_status(obj_data.status);

        let mut resolved = ResolvedObject::new(node_id, module_id, name, type_id, access);

        resolved.status = status;

        if let Some(ref desc) = obj_data.description {
            resolved.description = Some(ctx.intern(desc));
        }

        if let Some(ref units) = obj_data.units {
            resolved.units = Some(ctx.intern(units));
        }

        if let Some(ref reference) = obj_data.reference {
            resolved.reference = Some(ctx.intern(reference));
        }

        // Handle INDEX
        if let Some(ref index_items) = obj_data.index {
            let items: Vec<_> = index_items
                .iter()
                .filter_map(|item| {
                    ctx.lookup_node_for_module(module_id, &item.object.name)
                        .map(|nid| IndexItem::new(nid, item.implied))
                })
                .collect();
            if !items.is_empty() {
                resolved.index = Some(IndexSpec::new(items));
            }
        }

        // Handle AUGMENTS
        if let Some(ref augments_sym) = obj_data.augments {
            resolved.augments = ctx.lookup_node_for_module(module_id, &augments_sym.name);
        }

        // Handle DEFVAL
        if let Some(ref defval) = obj_data.defval {
            resolved.defval = Some(convert_defval(ctx, defval, module_id));
        }

        // Handle inline enums
        if let TypeSyntax::IntegerEnum(ref enums) = obj_data.syntax {
            let values: Vec<_> = enums
                .iter()
                .map(|nn| (nn.value, ctx.intern(&nn.name.name)))
                .collect();
            resolved.inline_enum = Some(crate::model::EnumValues::new(values));
        }

        // Handle inline BITS
        if let TypeSyntax::Bits(ref bits) = obj_data.syntax {
            let defs: Vec<_> = bits
                .iter()
                .map(|nb| (nb.position, ctx.intern(&nb.name.name)))
                .collect();
            resolved.inline_bits = Some(crate::model::BitDefinitions::new(defs));
        }

        let obj_id = ctx.model.add_object(resolved).unwrap();

        // Update node with object reference (match by module AND label)
        if let Some(node) = ctx.model.get_node_mut(node_id)
            && let Some(def) = node
                .definitions
                .iter_mut()
                .find(|d| d.label == name && d.module == module_id)
        {
            def.object = Some(obj_id);
        }

        // Add to module
        if let Some(module) = ctx.model.get_module_mut(module_id) {
            module.add_object(obj_id);
        }
    }
}

/// Extracted data from `ObjectType` to avoid borrow conflicts.
///
/// This struct holds a subset of the `ObjectType` data needed for creating
/// `ResolvedObject`. It allows us to drop the borrow of the `ObjectType` early
/// so we can mutate the context.
struct ObjectData {
    name: alloc::string::String,
    syntax: TypeSyntax,
    units: Option<alloc::string::String>,
    access: crate::module::Access,
    status: crate::module::Status,
    description: Option<alloc::string::String>,
    reference: Option<alloc::string::String>,
    index: Option<Vec<crate::module::IndexItem>>,
    augments: Option<crate::module::Symbol>,
    defval: Option<ModuleDefVal>,
    span: Span,
}

/// Create `ResolvedNotification` entries for all NOTIFICATION-TYPE and TRAP-TYPE definitions.
fn create_resolved_notifications(ctx: &mut ResolverContext) {
    // Collect references to all NOTIFICATION definitions (no cloning)
    let notif_refs = collect_notification_refs(ctx);

    for notif_ref in notif_refs {
        // Extract data from the notification in a single borrow scope
        let notif_data = {
            let Some(notif) = get_notification(ctx, &notif_ref) else {
                continue;
            };
            NotificationData {
                name: notif.name.name.clone(),
                status: notif.status,
                description: notif.description.clone(),
                reference: notif.reference.clone(),
                objects: notif.objects.clone(),
                span: notif.span,
            }
        };

        let module_id = notif_ref.module_id;
        let Some(node_id) = ctx.lookup_node_for_module(module_id, &notif_data.name) else {
            continue;
        };

        let name = ctx.intern(&notif_data.name);
        let status = hir_status_to_status(notif_data.status);

        let mut resolved = ResolvedNotification::new(node_id, module_id, name);
        resolved.status = status;

        if let Some(ref desc) = notif_data.description {
            resolved.description = Some(ctx.intern(desc));
        }

        if let Some(ref reference) = notif_data.reference {
            resolved.reference = Some(ctx.intern(reference));
        }

        // Resolve OBJECTS/VARIABLES references to NodeIds
        for obj_sym in &notif_data.objects {
            if let Some(obj_node_id) = ctx.lookup_node_for_module(module_id, &obj_sym.name) {
                resolved.objects.push(obj_node_id);
            } else {
                // Record the unresolved object reference for diagnostic purposes.
                // Resolution continues (lenient philosophy) but the failure is tracked.
                ctx.record_unresolved_notification_object(
                    module_id,
                    &notif_data.name,
                    &obj_sym.name,
                    notif_data.span,
                );
            }
        }

        let notif_id = ctx.model.add_notification(resolved).unwrap();

        // Update node with notification reference (match by module AND label)
        if let Some(node) = ctx.model.get_node_mut(node_id)
            && let Some(def) = node
                .definitions
                .iter_mut()
                .find(|d| d.label == name && d.module == module_id)
        {
            def.notification = Some(notif_id);
        }

        // Add to module
        if let Some(module) = ctx.model.get_module_mut(module_id) {
            module.add_notification(notif_id);
        }
    }
}

/// Extracted data for notification processing.
struct NotificationData {
    name: alloc::string::String,
    status: crate::module::Status,
    description: Option<alloc::string::String>,
    reference: Option<alloc::string::String>,
    objects: Vec<crate::module::Symbol>,
    span: Span,
}

/// Resolve a type syntax to a `TypeId`.
///
/// Returns `None` if the type reference couldn't be resolved, and records
/// the unresolved type in `UnresolvedReferences`.
///
/// For `TypeRef` syntax, uses module-scoped lookup to respect import declarations.
/// This ensures that when multiple modules define the same type name (e.g., `DisplayString`),
/// objects get assigned the type from the module they explicitly imported from.
fn resolve_type_syntax(
    ctx: &mut ResolverContext,
    syntax: &TypeSyntax,
    module_id: crate::model::ModuleId,
    object_name: &str,
    span: Span,
) -> Option<crate::model::TypeId> {
    match syntax {
        TypeSyntax::TypeRef(name) => {
            // Use module-scoped lookup to respect import declarations
            if let Some(type_id) = ctx.lookup_type_for_module(module_id, &name.name) {
                Some(type_id)
            } else {
                // Record the unresolved type reference
                ctx.record_unresolved_type(module_id, object_name, &name.name, span);
                None
            }
        }
        TypeSyntax::Constrained { base, .. } => {
            resolve_type_syntax(ctx, base, module_id, object_name, span)
        }
        TypeSyntax::IntegerEnum(_) => {
            // INTEGER with enum values - base type is Integer32
            ctx.lookup_type("Integer32")
        }
        TypeSyntax::Bits(_) => {
            // BITS type
            ctx.lookup_type("BITS")
        }
        TypeSyntax::OctetString => ctx.lookup_type("OCTET STRING"),
        TypeSyntax::ObjectIdentifier => ctx.lookup_type("OBJECT IDENTIFIER"),
        TypeSyntax::SequenceOf(_) | TypeSyntax::Sequence(_) => {
            // Table/row types - these don't have a meaningful "type" in the SNMP sense
            // They're structural, not data types. Return None as there's no appropriate type.
            // (Tables and rows are identified by NodeKind, not by their type_id)
            None
        }
        TypeSyntax::Choice(_) => {
            // CHOICE types are abstract containers used in type definitions (like ObjectSyntax).
            // They're not directly used as OBJECT-TYPE SYNTAX in real MIBs.
            None
        }
    }
}

/// Convert `ModuleDefVal` to resolved `DefVal`.
fn convert_defval(ctx: &mut ResolverContext, defval: &ModuleDefVal, module_id: ModuleId) -> DefVal {
    match defval {
        ModuleDefVal::Integer(n) => DefVal::Integer(*n),
        ModuleDefVal::Unsigned(n) => DefVal::Unsigned(*n),
        ModuleDefVal::String(s) => DefVal::String(ctx.intern(s)),
        ModuleDefVal::HexString(s) => DefVal::HexString(s.clone()),
        ModuleDefVal::BinaryString(s) => DefVal::BinaryString(s.clone()),
        ModuleDefVal::Enum(sym) => DefVal::Enum(ctx.intern(&sym.name)),
        ModuleDefVal::Bits(syms) => {
            DefVal::Bits(syms.iter().map(|s| ctx.intern(&s.name)).collect())
        }
        ModuleDefVal::OidRef(sym) => {
            // Try to resolve the OID reference
            let resolved_node = ctx.lookup_node_for_module(module_id, &sym.name);
            DefVal::OidRef {
                node: resolved_node,
                symbol: if resolved_node.is_none() {
                    Some(ctx.intern(&sym.name))
                } else {
                    None
                },
            }
        }
        ModuleDefVal::OidValue(components) => {
            // Try to resolve the OID value by looking up the first component
            // This is a best-effort resolution
            if let Some(first) = components.first()
                && let Some(name) = first.name()
                && let Some(node) = ctx.lookup_node_for_module(module_id, &name.name)
            {
                return DefVal::OidRef {
                    node: Some(node),
                    symbol: None,
                };
            }
            // If we can't resolve it, store the first symbol as unresolved
            if let Some(first) = components.first()
                && let Some(name) = first.name()
            {
                return DefVal::OidRef {
                    node: None,
                    symbol: Some(ctx.intern(&name.name)),
                };
            }
            // Fallback for numeric-only OIDs (rare in DEFVAL)
            DefVal::OidRef {
                node: None,
                symbol: None,
            }
        }
    }
}

fn hir_access_to_access(access: crate::module::Access) -> Access {
    match access {
        crate::module::Access::ReadOnly => Access::ReadOnly,
        crate::module::Access::ReadWrite => Access::ReadWrite,
        crate::module::Access::ReadCreate => Access::ReadCreate,
        crate::module::Access::NotAccessible => Access::NotAccessible,
        crate::module::Access::AccessibleForNotify => Access::AccessibleForNotify,
        crate::module::Access::WriteOnly => Access::WriteOnly,
    }
}

fn hir_status_to_status(status: crate::module::Status) -> Status {
    match status {
        crate::module::Status::Current => Status::Current,
        crate::module::Status::Deprecated => Status::Deprecated,
        crate::module::Status::Obsolete => Status::Obsolete,
    }
}

#[cfg(test)]
mod tests {
    use super::analyze_semantics;
    use crate::lexer::Span;
    use crate::model::{NodeKind, Status as ModelStatus};
    use crate::module::{
        Access, Constraint, Definition, Import, IndexItem, Module, NamedBit, Notification,
        ObjectType, OidAssignment, OidComponent, Range, RangeValue, Status, Symbol, TypeDef,
        TypeSyntax,
    };
    use crate::resolver::context::ResolverContext;
    use crate::resolver::phases::{
        imports::resolve_imports, oids::resolve_oids, registration::register_modules,
        types::resolve_types,
    };
    use alloc::boxed::Box;
    use alloc::vec;

    fn make_object_type(
        name: &str,
        syntax: TypeSyntax,
        oid_components: Vec<OidComponent>,
        index: Option<Vec<IndexItem>>,
    ) -> Definition {
        Definition::ObjectType(ObjectType {
            name: Symbol::from_name(name),
            syntax,
            units: None,
            access: Access::ReadOnly,
            status: Status::Current,
            description: Some("Test object".into()),
            reference: None,
            index,
            augments: None,
            defval: None,
            oid: OidAssignment::new(oid_components, Span::new(0, 0)),
            span: Span::new(0, 0),
        })
    }

    /// Create a test module with imports.
    /// imports is a list of (symbol, `from_module`) pairs.
    fn make_test_module_with_imports(
        name: &str,
        defs: Vec<Definition>,
        imports: Vec<(&str, &str)>,
    ) -> Module {
        let mut module = Module::new(Symbol::from_name(name), Span::new(0, 0));
        module.definitions = defs;
        // Import::new takes (module, symbol, span)
        module.imports = imports
            .into_iter()
            .map(|(sym, from)| {
                Import::new(
                    Symbol::from_name(from),
                    Symbol::from_name(sym),
                    Span::new(0, 0),
                )
            })
            .collect();
        module
    }

    #[test]
    fn test_table_inference() {
        let table = make_object_type(
            "testTable",
            TypeSyntax::SequenceOf(Symbol::from_name("TestEntry")),
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
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
        if let Some(node_id) = ctx.lookup_node_in_module("TEST-MIB", "testTable")
            && let Some(node) = ctx.model.get_node(node_id)
        {
            assert_eq!(node.kind, NodeKind::Table);
        }
    }

    #[test]
    fn test_row_inference() {
        let row = make_object_type(
            "testEntry",
            TypeSyntax::TypeRef(Symbol::from_name("TestEntry")),
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
            ],
            Some(vec![IndexItem::new(Symbol::from_name("testIndex"), false)]),
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
        if let Some(node_id) = ctx.lookup_node_in_module("TEST-MIB", "testEntry")
            && let Some(node) = ctx.model.get_node(node_id)
        {
            assert_eq!(node.kind, NodeKind::Row);
        }
    }

    #[test]
    fn test_resolved_object_creation() {
        let obj = make_object_type(
            "testObject",
            TypeSyntax::TypeRef(Symbol::from_name("Integer32")),
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
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
            TypeSyntax::TypeRef(Symbol::from_name("NonExistentType")),
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
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
        let obj = ctx
            .model
            .get_object(crate::model::ObjectId::from_raw(1).unwrap());
        assert!(obj.is_some());
        assert!(
            obj.unwrap().type_id.is_none(),
            "type_id should be None for unresolved type"
        );
    }

    #[test]
    fn test_unresolved_type_recorded_in_unresolved_references() {
        // Create an object with a reference to a non-existent type
        let obj = make_object_type(
            "testObject",
            TypeSyntax::TypeRef(Symbol::from_name("FakeType")),
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
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
        assert!(
            !unresolved.types.is_empty(),
            "should have recorded unresolved type"
        );

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
            TypeSyntax::TypeRef(Symbol::from_name("Integer32")),
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
            ],
            None,
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![obj],
            vec![("enterprises", "SNMPv2-SMI"), ("Integer32", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Object should be created with a valid type_id
        let obj = ctx
            .model
            .get_object(crate::model::ObjectId::from_raw(1).unwrap());
        assert!(obj.is_some());
        assert!(
            obj.unwrap().type_id.is_some(),
            "type_id should be Some for resolved type"
        );
    }

    #[test]
    fn test_table_type_has_none_type_id() {
        // SEQUENCE OF types (tables) have no meaningful type_id
        let table = make_object_type(
            "testTable",
            TypeSyntax::SequenceOf(Symbol::from_name("TestEntry")),
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
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
        let obj = ctx
            .model
            .get_object(crate::model::ObjectId::from_raw(1).unwrap());
        assert!(obj.is_some());
        assert!(
            obj.unwrap().type_id.is_none(),
            "table type_id should be None"
        );
    }

    #[test]
    fn test_inline_bits_type_has_type_id() {
        // BITS with inline definitions should have a type_id
        let obj = make_object_type(
            "testBits",
            TypeSyntax::Bits(vec![
                NamedBit::new(Symbol::from_name("flag1"), 0),
                NamedBit::new(Symbol::from_name("flag2"), 1),
            ]),
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
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
        let obj = ctx
            .model
            .get_object(crate::model::ObjectId::from_raw(1).unwrap());
        assert!(obj.is_some());
        let obj = obj.unwrap();
        assert!(obj.type_id.is_some(), "BITS type_id should be Some");

        // Check that inline_bits was populated
        assert!(obj.inline_bits.is_some(), "inline_bits should be populated");
    }

    fn make_notification(
        name: &str,
        objects: Vec<&str>,
        oid_components: Vec<OidComponent>,
    ) -> Definition {
        Definition::Notification(Notification {
            name: Symbol::from_name(name),
            objects: objects.into_iter().map(Symbol::from_name).collect(),
            status: Status::Current,
            description: Some("Test notification".into()),
            reference: Some("RFC-TEST".into()),
            trap_info: None,
            oid: Some(OidAssignment::new(oid_components, Span::new(0, 0))),
            span: Span::new(0, 0),
        })
    }

    #[test]
    fn test_resolved_notification_creation() {
        let notif = make_notification(
            "testNotification",
            vec![],
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
            ],
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![notif],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Check notification count
        assert_eq!(ctx.model.notification_count(), 1);

        // Get the notification and verify fields
        let notif = ctx
            .model
            .get_notification(crate::model::NotificationId::from_raw(1).unwrap());
        assert!(notif.is_some());
        let notif = notif.unwrap();
        assert_eq!(ctx.model.get_str(notif.name), "testNotification");
        assert_eq!(notif.status, ModelStatus::Current);
        assert!(notif.description.is_some());
        assert!(notif.reference.is_some());
    }

    #[test]
    fn test_notification_objects_resolved() {
        // Create an object that the notification references
        let obj = make_object_type(
            "testObject",
            TypeSyntax::TypeRef(Symbol::from_name("Integer32")),
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
            ],
            None,
        );

        // Create a notification that references the object
        let notif = make_notification(
            "testNotification",
            vec!["testObject"],
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(2),
            ],
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![obj, notif],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Check notification has one object resolved
        let notif = ctx
            .model
            .get_notification(crate::model::NotificationId::from_raw(1).unwrap());
        assert!(notif.is_some());
        let notif = notif.unwrap();
        assert_eq!(notif.objects.len(), 1);

        // Verify the object reference points to testObject
        let obj_node = ctx.model.get_node(notif.objects[0]).unwrap();
        let def = obj_node.definitions.first().unwrap();
        assert_eq!(ctx.model.get_str(def.label), "testObject");
    }

    #[test]
    fn test_notification_registered_with_module() {
        let notif = make_notification(
            "testNotification",
            vec![],
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
            ],
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![notif],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Find TEST-MIB module and check it has the notification
        let module_id = ctx.model.get_module_by_name("TEST-MIB").unwrap().id;
        let module = ctx.model.get_module(module_id).unwrap();
        assert_eq!(module.notifications.len(), 1);
    }

    #[test]
    fn test_notification_node_has_notification_id() {
        let notif = make_notification(
            "testNotification",
            vec![],
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
            ],
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![notif],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Get the node and verify it has the notification reference
        let node_id = ctx
            .lookup_node_in_module("TEST-MIB", "testNotification")
            .unwrap();
        let node = ctx.model.get_node(node_id).unwrap();
        let def = node.definitions.first().unwrap();
        assert!(
            def.notification.is_some(),
            "node definition should have notification id"
        );
    }

    #[test]
    fn test_unresolved_notification_object_recorded() {
        // Create a notification that references a non-existent object
        let notif = make_notification(
            "testNotification",
            vec!["nonExistentObject"],
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
            ],
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![notif],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Notification should still be created
        assert_eq!(ctx.model.notification_count(), 1);

        // But the unresolved object reference should be recorded
        let unresolved = ctx.model.unresolved();
        assert!(
            !unresolved.notification_objects.is_empty(),
            "should have recorded unresolved notification object"
        );

        // Verify the unresolved reference details
        let unresolved_obj = &unresolved.notification_objects[0];
        assert_eq!(
            ctx.model.get_str(unresolved_obj.notification),
            "testNotification"
        );
        assert_eq!(
            ctx.model.get_str(unresolved_obj.object),
            "nonExistentObject"
        );
    }

    #[test]
    fn test_notification_mixed_resolved_and_unresolved_objects() {
        // Create one object that exists
        let obj = make_object_type(
            "existingObject",
            TypeSyntax::TypeRef(Symbol::from_name("Integer32")),
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
            ],
            None,
        );

        // Create a notification that references both existing and non-existing objects
        let notif = make_notification(
            "testNotification",
            vec!["existingObject", "missingObject"],
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(2),
            ],
        );

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![obj, notif],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Notification should have one resolved object
        let notif = ctx
            .model
            .get_notification(crate::model::NotificationId::from_raw(1).unwrap())
            .unwrap();
        assert_eq!(notif.objects.len(), 1, "should have one resolved object");

        // And one unresolved object should be recorded
        let unresolved = ctx.model.unresolved();
        assert_eq!(
            unresolved.notification_objects.len(),
            1,
            "should have one unresolved notification object"
        );
        assert_eq!(
            ctx.model.get_str(unresolved.notification_objects[0].object),
            "missingObject"
        );
    }

    // ============================================================
    // Tests for module-scoped type resolution (issue: type resolution ignores import source)
    // ============================================================

    /// Create a type definition for testing.
    fn make_typedef(name: &str, syntax: TypeSyntax, hint: Option<&str>) -> Definition {
        Definition::TypeDef(TypeDef {
            name: Symbol::from_name(name),
            syntax,
            base_type: None,
            display_hint: hint.map(|s| s.into()),
            status: Status::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        })
    }

    #[test]
    fn test_type_resolution_respects_imports() {
        // This test verifies that when multiple modules define the same type name,
        // objects get assigned the type from the module they explicitly imported from.
        //
        // Setup:
        // - TC-A defines "MyDisplayString" with hint "255a"
        // - TC-B defines "MyDisplayString" with hint "1x:" (different)
        // - USER-MIB imports MyDisplayString FROM TC-A
        // - USER-MIB has an object using MyDisplayString
        //
        // Expected: Object's type should be TC-A::MyDisplayString (with hint "255a")

        // TC-A: defines MyDisplayString with hint "255a"
        let tc_a_typedef = make_typedef(
            "MyDisplayString",
            TypeSyntax::Constrained {
                base: Box::new(TypeSyntax::OctetString),
                constraint: Constraint::Size(vec![Range {
                    min: RangeValue::Unsigned(0),
                    max: Some(RangeValue::Unsigned(255)),
                }]),
            },
            Some("255a"),
        );
        let tc_a = make_test_module_with_imports("TC-A", vec![tc_a_typedef], vec![]);

        // TC-B: defines MyDisplayString with hint "1x:" (different)
        let tc_b_typedef = make_typedef(
            "MyDisplayString",
            TypeSyntax::Constrained {
                base: Box::new(TypeSyntax::OctetString),
                constraint: Constraint::Size(vec![Range {
                    min: RangeValue::Unsigned(0),
                    max: Some(RangeValue::Unsigned(255)),
                }]),
            },
            Some("1x:"),
        );
        let tc_b = make_test_module_with_imports("TC-B", vec![tc_b_typedef], vec![]);

        // USER-MIB: imports MyDisplayString from TC-A, uses it for an object
        let obj = make_object_type(
            "testObject",
            TypeSyntax::TypeRef(Symbol::from_name("MyDisplayString")),
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
            ],
            None,
        );
        let user_mib = make_test_module_with_imports(
            "USER-MIB",
            vec![obj],
            vec![
                ("enterprises", "SNMPv2-SMI"),
                ("MyDisplayString", "TC-A"), // Explicitly import from TC-A
            ],
        );

        // Order matters: TC-B loaded after TC-A would overwrite global index
        // if we weren't using module-scoped type lookup
        let modules = vec![tc_a, tc_b, user_mib];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Get the object and verify its type
        let obj = ctx
            .model
            .get_object(crate::model::ObjectId::from_raw(1).unwrap())
            .expect("object should exist");
        let type_id = obj.type_id.expect("object should have a type_id");
        let resolved_type = ctx.model.get_type(type_id).expect("type should exist");

        // The type should be from TC-A (with hint "255a"), not TC-B (with hint "1x:")
        let hint = resolved_type.hint.map(|h| ctx.model.get_str(h));
        assert_eq!(
            hint,
            Some("255a"),
            "Object should use TC-A::MyDisplayString (hint='255a'), not TC-B (hint='1x:')"
        );

        // Also verify the type's module
        let type_module = ctx.model.get_module(resolved_type.module).unwrap();
        assert_eq!(
            ctx.model.get_str(type_module.name),
            "TC-A",
            "Type should be from TC-A module"
        );
    }

    #[test]
    fn test_asn1_primitives_resolve_implicitly() {
        // Verify that ASN.1 primitive types (INTEGER, OCTET STRING, etc.)
        // resolve without explicit import - they're language-level constructs
        let obj = make_object_type(
            "testObject",
            TypeSyntax::TypeRef(Symbol::from_name("INTEGER")),
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
            ],
            None,
        );
        let user_mib = make_test_module_with_imports(
            "USER-MIB",
            vec![obj],
            vec![
                ("enterprises", "SNMPv2-SMI"),
                // No explicit import of INTEGER - it's an ASN.1 primitive
            ],
        );

        let modules = vec![user_mib];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);
        resolve_oids(&mut ctx);
        analyze_semantics(&mut ctx);

        // Get the object and verify its type resolved
        let obj = ctx
            .model
            .get_object(crate::model::ObjectId::from_raw(1).unwrap())
            .expect("object should exist");
        assert!(
            obj.type_id.is_some(),
            "INTEGER should resolve as ASN.1 primitive"
        );
    }
}
