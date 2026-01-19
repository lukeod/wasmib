//! Phase 4: OID resolution.
//!
//! Build the complete OID tree, extracting implicit nodes from inline OID assignments.

use crate::hir::{HirDefinition, HirOidAssignment, HirOidComponent};
use crate::model::{NodeDefinition, NodeId, NodeKind, Oid, OidNode};
use crate::resolver::context::ResolverContext;
use alloc::string::String;
use alloc::vec::Vec;

/// Resolve all OIDs across all modules.
pub fn resolve_oids(ctx: &mut ResolverContext) {
    // Multi-pass resolution to handle forward references.
    // Pass 1: Definitions with built-in roots (most definitions)
    // Pass 2+: Iterate user-rooted definitions until no more progress

    // First pass: collect all definitions with OIDs
    let oid_defs = collect_oid_definitions(ctx);

    // Sort by resolution order (built-in rooted first)
    let (builtin_rooted, user_rooted): (Vec<_>, Vec<_>) = oid_defs
        .into_iter()
        .partition(|d| is_builtin_rooted(&d.oid));

    // Process built-in rooted definitions first
    for def in builtin_rooted {
        resolve_oid_definition(ctx, &def);
    }

    // Process user-rooted definitions with multiple passes to handle forward references.
    // Keep iterating until no more definitions can be resolved.
    let mut pending = user_rooted;
    let max_iterations = 10; // Safety limit to prevent infinite loops

    for _iteration in 0..max_iterations {
        if pending.is_empty() {
            break;
        }

        let initial_count = pending.len();
        let mut still_pending = Vec::new();

        for def in pending {
            // Try to resolve - check if the first component is now resolvable
            let first_resolvable = match &def.oid.components.first() {
                Some(HirOidComponent::Name(sym)) => ctx.lookup_node(&sym.name).is_some(),
                Some(HirOidComponent::NamedNumber { .. }) => true, // Named numbers create nodes
                Some(HirOidComponent::Number(_)) => true, // Bare numbers extend from current
                None => false,
            };

            if first_resolvable {
                resolve_oid_definition(ctx, &def);
            } else {
                still_pending.push(def);
            }
        }

        // No progress made - remaining definitions have unresolvable references
        if still_pending.len() == initial_count {
            // Record unresolved for remaining definitions
            for def in still_pending {
                if let Some(HirOidComponent::Name(sym)) = def.oid.components.first() {
                    if let Some(&module_id) = ctx.module_index.get(&def.module_name) {
                        ctx.record_unresolved_oid(module_id, &def.def_name, &sym.name);
                    }
                }
            }
            break;
        }

        pending = still_pending;
    }
}

/// An OID definition pending resolution.
struct OidDefinition {
    module_idx: usize,
    module_name: String,
    def_name: String,
    oid: HirOidAssignment,
    def_kind: DefinitionKind,
}

#[derive(Clone, Copy)]
enum DefinitionKind {
    ObjectType,
    ModuleIdentity,
    ObjectIdentity,
    Notification,
    ValueAssignment,
    ObjectGroup,
    NotificationGroup,
    ModuleCompliance,
    AgentCapabilities,
}

/// Collect all definitions that have OID assignments.
fn collect_oid_definitions(ctx: &ResolverContext) -> Vec<OidDefinition> {
    let mut defs = Vec::new();

    for (module_idx, module) in ctx.hir_modules.iter().enumerate() {
        for def in &module.definitions {
            let (name, oid, kind) = match def {
                HirDefinition::ObjectType(d) => {
                    (d.name.name.clone(), d.oid.clone(), DefinitionKind::ObjectType)
                }
                HirDefinition::ModuleIdentity(d) => {
                    (d.name.name.clone(), d.oid.clone(), DefinitionKind::ModuleIdentity)
                }
                HirDefinition::ObjectIdentity(d) => {
                    (d.name.name.clone(), d.oid.clone(), DefinitionKind::ObjectIdentity)
                }
                HirDefinition::Notification(d) => {
                    if let Some(ref oid) = d.oid {
                        (d.name.name.clone(), oid.clone(), DefinitionKind::Notification)
                    } else {
                        continue;
                    }
                }
                HirDefinition::ValueAssignment(d) => {
                    (d.name.name.clone(), d.oid.clone(), DefinitionKind::ValueAssignment)
                }
                HirDefinition::ObjectGroup(d) => {
                    (d.name.name.clone(), d.oid.clone(), DefinitionKind::ObjectGroup)
                }
                HirDefinition::NotificationGroup(d) => {
                    (d.name.name.clone(), d.oid.clone(), DefinitionKind::NotificationGroup)
                }
                HirDefinition::ModuleCompliance(d) => {
                    (d.name.name.clone(), d.oid.clone(), DefinitionKind::ModuleCompliance)
                }
                HirDefinition::AgentCapabilities(d) => {
                    (d.name.name.clone(), d.oid.clone(), DefinitionKind::AgentCapabilities)
                }
                HirDefinition::TypeDef(_) => continue,
            };

            defs.push(OidDefinition {
                module_idx,
                module_name: module.name.name.clone(),
                def_name: name,
                oid,
                def_kind: kind,
            });
        }
    }

    defs
}

/// Check if an OID starts with a built-in root.
fn is_builtin_rooted(oid: &HirOidAssignment) -> bool {
    if oid.components.is_empty() {
        return false;
    }

    match &oid.components[0] {
        HirOidComponent::Name(sym) => {
            matches!(
                sym.name.as_str(),
                "iso" | "org" | "dod" | "internet" | "mgmt" | "mib-2" | "transmission"
                    | "experimental" | "private" | "enterprises" | "security" | "snmpV2"
                    | "snmpDomains" | "snmpProxys" | "snmpModules" | "zeroDotZero" | "directory"
            )
        }
        HirOidComponent::NamedNumber { name, .. } => {
            matches!(
                name.name.as_str(),
                "iso" | "org" | "dod" | "internet" | "mgmt" | "mib-2"
            )
        }
        HirOidComponent::Number(1) => true, // iso
        HirOidComponent::Number(_) => false,
    }
}

/// Resolve a single OID definition.
fn resolve_oid_definition(ctx: &mut ResolverContext, def: &OidDefinition) {
    let module_id = match ctx.module_index.get(&def.module_name) {
        Some(&id) => id,
        None => return,
    };

    // Walk the OID components and build the path
    let mut current_node: Option<NodeId> = None;
    let mut current_oid = Oid::new(Vec::new());

    for (comp_idx, component) in def.oid.components.iter().enumerate() {
        let is_last = comp_idx == def.oid.components.len() - 1;

        match component {
            HirOidComponent::Name(sym) => {
                // Look up by name
                if let Some(node_id) = ctx.lookup_node(&sym.name) {
                    current_node = Some(node_id);
                    if let Some(node) = ctx.model.get_node(node_id) {
                        current_oid = ctx.model.get_oid(node);
                    }
                } else {
                    // Unresolved name reference
                    ctx.record_unresolved_oid(module_id, &def.def_name, &sym.name);
                    return;
                }
            }
            HirOidComponent::Number(arc) => {
                // Extend from current node
                current_oid = current_oid.child(*arc);

                if let Some(existing) = ctx.model.get_node_id_by_oid(&current_oid) {
                    current_node = Some(existing);
                } else {
                    // Create new node
                    let new_node = OidNode::new(*arc, current_node);
                    let new_id = ctx.model.add_node(new_node);

                    // Add as child of parent
                    if let Some(parent_id) = current_node {
                        if let Some(parent) = ctx.model.get_node_mut(parent_id) {
                            parent.add_child(new_id);
                        }
                    }

                    ctx.model.register_oid(current_oid.clone(), new_id);
                    current_node = Some(new_id);
                }
            }
            HirOidComponent::NamedNumber { name, number } => {
                // This creates an implicit node with the given name
                current_oid = current_oid.child(*number);

                if let Some(existing) = ctx.model.get_node_id_by_oid(&current_oid) {
                    current_node = Some(existing);
                } else {
                    // Create new node
                    let new_node = OidNode::new(*number, current_node);
                    let new_id = ctx.model.add_node(new_node);

                    // Add as child of parent
                    if let Some(parent_id) = current_node {
                        if let Some(parent) = ctx.model.get_node_mut(parent_id) {
                            parent.add_child(new_id);
                        }
                    }

                    ctx.model.register_oid(current_oid.clone(), new_id);
                    ctx.register_node_symbol(name.name.clone(), new_id);
                    current_node = Some(new_id);
                }

                // Also register the name
                if let Some(node_id) = current_node {
                    ctx.register_node_symbol(name.name.clone(), node_id);
                }
            }
        }

        // If this is the last component, add the definition
        if is_last {
            if let Some(node_id) = current_node {
                let label = ctx.intern(&def.def_name);
                let node_def = NodeDefinition::new(module_id, label);

                if let Some(node) = ctx.model.get_node_mut(node_id) {
                    node.add_definition(node_def);

                    // Set node kind based on definition type
                    let kind = match def.def_kind {
                        DefinitionKind::ObjectType => NodeKind::Scalar, // Will be refined later
                        DefinitionKind::ModuleIdentity | DefinitionKind::ObjectIdentity | DefinitionKind::ValueAssignment => {
                            NodeKind::Node
                        }
                        DefinitionKind::Notification => NodeKind::Notification,
                        DefinitionKind::ObjectGroup | DefinitionKind::NotificationGroup => NodeKind::Group,
                        DefinitionKind::ModuleCompliance => NodeKind::Compliance,
                        DefinitionKind::AgentCapabilities => NodeKind::Capabilities,
                    };
                    node.kind = kind;
                }

                // Register the name -> node mapping
                ctx.register_node_symbol(def.def_name.clone(), node_id);

                // Add to module
                if let Some(module) = ctx.model.get_module_mut(module_id) {
                    module.add_node(node_id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{
        HirModule, HirObjectType, HirOidAssignment, HirOidComponent, HirTypeSyntax,
        HirAccess, HirDefinition, HirStatus, Symbol,
    };
    use crate::lexer::Span;
    use crate::resolver::phases::registration::register_modules;
    use alloc::vec;

    fn make_object_type(name: &str, oid_components: Vec<HirOidComponent>) -> HirDefinition {
        HirDefinition::ObjectType(HirObjectType {
            name: Symbol::from_str(name),
            syntax: HirTypeSyntax::TypeRef(Symbol::from_str("Integer32")),
            units: None,
            access: HirAccess::ReadOnly,
            status: HirStatus::Current,
            description: None,
            reference: None,
            index: None,
            augments: None,
            oid: HirOidAssignment::new(oid_components, Span::new(0, 0)),
            span: Span::new(0, 0),
        })
    }

    fn make_test_module(name: &str, defs: Vec<HirDefinition>) -> HirModule {
        let mut module = HirModule::new(Symbol::from_str(name), Span::new(0, 0));
        module.definitions = defs;
        module
    }

    #[test]
    fn test_resolve_simple_oid() {
        let obj = make_object_type(
            "testObject",
            vec![
                HirOidComponent::Name(Symbol::from_str("enterprises")),
                HirOidComponent::Number(1),
            ],
        );

        let modules = vec![make_test_module("TEST-MIB", vec![obj])];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_oids(&mut ctx);

        // Check node exists
        assert!(ctx.lookup_node("testObject").is_some());

        // Check OID is correct (1.3.6.1.4.1.1)
        if let Some(node_id) = ctx.lookup_node("testObject") {
            if let Some(node) = ctx.model.get_node(node_id) {
                let oid = ctx.model.get_oid(node);
                assert_eq!(oid.arcs(), &[1, 3, 6, 1, 4, 1, 1]);
            }
        }
    }

    #[test]
    fn test_resolve_named_number_oid() {
        let obj = make_object_type(
            "testObject",
            vec![
                HirOidComponent::NamedNumber {
                    name: Symbol::from_str("iso"),
                    number: 1,
                },
                HirOidComponent::NamedNumber {
                    name: Symbol::from_str("org"),
                    number: 3,
                },
                HirOidComponent::Number(999),
            ],
        );

        let modules = vec![make_test_module("TEST-MIB", vec![obj])];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_oids(&mut ctx);

        // Check node exists
        assert!(ctx.lookup_node("testObject").is_some());

        // Check OID is correct (1.3.999)
        if let Some(node_id) = ctx.lookup_node("testObject") {
            if let Some(node) = ctx.model.get_node(node_id) {
                let oid = ctx.model.get_oid(node);
                assert_eq!(oid.arcs(), &[1, 3, 999]);
            }
        }
    }

    #[test]
    fn test_unresolved_oid_component() {
        let obj = make_object_type(
            "testObject",
            vec![
                HirOidComponent::Name(Symbol::from_str("unknownNode")),
                HirOidComponent::Number(1),
            ],
        );

        let modules = vec![make_test_module("TEST-MIB", vec![obj])];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_oids(&mut ctx);

        // Check unresolved OID was recorded
        assert_eq!(ctx.model.unresolved().oids.len(), 1);
    }

    #[test]
    fn test_is_builtin_rooted() {
        let builtin = HirOidAssignment::new(
            vec![HirOidComponent::Name(Symbol::from_str("enterprises"))],
            Span::new(0, 0),
        );
        assert!(is_builtin_rooted(&builtin));

        let user = HirOidAssignment::new(
            vec![HirOidComponent::Name(Symbol::from_str("userDefined"))],
            Span::new(0, 0),
        );
        assert!(!is_builtin_rooted(&user));

        let iso = HirOidAssignment::new(
            vec![HirOidComponent::Number(1)],
            Span::new(0, 0),
        );
        assert!(is_builtin_rooted(&iso));
    }
}
