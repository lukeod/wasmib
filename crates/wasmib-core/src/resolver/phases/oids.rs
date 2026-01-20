//! Phase 4: OID resolution.
//!
//! Build the complete OID tree, extracting implicit nodes from inline OID assignments.

use crate::hir::{HirDefinition, HirOidAssignment, HirOidComponent};
use crate::model::{ModuleId, NodeDefinition, NodeId, NodeKind, Oid, OidNode};
use crate::resolver::context::ResolverContext;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "tracing")]
use crate::resolver::tracing::{TraceEvent, TraceLevel, Tracer};

/// Look up a node by symbol name in module scope (by ModuleId).
fn lookup_node_scoped(ctx: &ResolverContext, module_id: ModuleId, symbol: &str) -> Option<NodeId> {
    ctx.lookup_node_for_module(module_id, symbol)
}

/// Resolve all OIDs across all modules.
pub fn resolve_oids(ctx: &mut ResolverContext) {
    // Multi-pass resolution to handle forward references.
    // Keep iterating until no more definitions can be resolved.
    // Final: Derive OIDs for TRAP-TYPE definitions from enterprise + trap_number

    // First pass: collect all definitions with OIDs
    let CollectedDefinitions { oid_defs, trap_defs } = collect_oid_definitions(ctx);

    // Process all definitions with multiple passes to handle forward references.
    let mut pending = oid_defs;
    let max_iterations = 20; // Safety limit to prevent infinite loops

    for _iteration in 0..max_iterations {
        if pending.is_empty() {
            break;
        }

        let initial_count = pending.len();
        let mut still_pending = Vec::new();

        for def in pending {
            // Try to resolve - check if the first component is now resolvable
            let first_resolvable = match &def.oid.components.first() {
                Some(HirOidComponent::Name(sym)) => {
                    lookup_node_scoped(ctx, def.module_id, &sym.name).is_some()
                }
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
                    ctx.record_unresolved_oid(def.module_id, &def.def_name, &sym.name);
                }
            }
            break;
        }

        pending = still_pending;
    }

    // Final pass: Derive OIDs for TRAP-TYPE definitions.
    // OID = enterprise_oid.0.trap_number (per RFC 1215)
    resolve_trap_type_definitions(ctx, trap_defs);
}

/// Resolve TRAP-TYPE definitions by deriving OIDs from enterprise + trap_number.
/// Per RFC 1215, TRAP-TYPE OID = enterprise_oid.0.trap_number
fn resolve_trap_type_definitions(ctx: &mut ResolverContext, trap_defs: Vec<TrapTypeDefinition>) {
    for def in trap_defs {
        // Look up the enterprise OID
        let enterprise_node_id = match lookup_node_scoped(ctx, def.module_id, &def.enterprise) {
            Some(id) => id,
            None => {
                // Enterprise reference not found
                ctx.record_unresolved_oid(def.module_id, &def.def_name, &def.enterprise);
                continue;
            }
        };

        // Get enterprise OID
        let enterprise_oid = match ctx.model.get_node(enterprise_node_id) {
            Some(node) => ctx.model.get_oid(node),
            None => continue,
        };

        // Build trap OID: enterprise.0.trap_number
        let trap_zero_oid = enterprise_oid.child(0);
        let trap_oid = trap_zero_oid.child(def.trap_number);

        // Find or create the intermediate .0 node
        let trap_zero_node_id = if let Some(existing) = ctx.model.get_node_id_by_oid(&trap_zero_oid)
        {
            existing
        } else {
            let new_node = OidNode::new(0, Some(enterprise_node_id));
            let new_id = ctx.model.add_node(new_node);

            // Add as child of enterprise
            if let Some(parent) = ctx.model.get_node_mut(enterprise_node_id) {
                parent.add_child(new_id);
            }

            ctx.model.register_oid(trap_zero_oid, new_id);
            new_id
        };

        // Find or create the trap node
        let trap_node_id = if let Some(existing) = ctx.model.get_node_id_by_oid(&trap_oid) {
            existing
        } else {
            let new_node = OidNode::new(def.trap_number, Some(trap_zero_node_id));
            let new_id = ctx.model.add_node(new_node);

            // Add as child of .0 node
            if let Some(parent) = ctx.model.get_node_mut(trap_zero_node_id) {
                parent.add_child(new_id);
            }

            ctx.model.register_oid(trap_oid.clone(), new_id);
            new_id
        };

        // Add the definition to the node
        let label = ctx.intern(&def.def_name);
        let node_def = NodeDefinition::new(def.module_id, label);

        if let Some(node) = ctx.model.get_node_mut(trap_node_id) {
            node.add_definition(node_def);
            node.kind = NodeKind::Notification;
        }

        // Register the name -> node mapping for this module
        ctx.register_module_node_symbol(def.module_id, def.def_name.clone(), trap_node_id);

        // Add to module
        if let Some(module) = ctx.model.get_module_mut(def.module_id) {
            module.add_node(trap_node_id);
        }
    }
}

/// Resolve all OIDs across all modules with tracing support.
#[cfg(feature = "tracing")]
pub fn resolve_oids_traced<T: Tracer>(ctx: &mut ResolverContext, tracer: &mut T) {
    // First pass: collect all definitions with OIDs
    let CollectedDefinitions { oid_defs, trap_defs } = collect_oid_definitions(ctx);

    // Process all definitions with multiple passes to handle forward references
    let mut pending = oid_defs;
    let max_iterations = 20;

    for iteration in 0..max_iterations {
        if pending.is_empty() {
            break;
        }

        crate::trace_event!(
            tracer,
            TraceLevel::Info,
            TraceEvent::OidPassStart {
                pass: iteration,
                pending: pending.len(),
            }
        );

        let initial_count = pending.len();
        let mut still_pending = Vec::new();
        let mut pass_resolved = 0;

        for def in pending {
            let first_resolvable = match &def.oid.components.first() {
                Some(HirOidComponent::Name(sym)) => {
                    let found = lookup_node_scoped(ctx, def.module_id, &sym.name).is_some();
                    crate::trace_event!(
                        tracer,
                        TraceLevel::Trace,
                        TraceEvent::OidLookup {
                            module_id: def.module_id,
                            def_name: &def.def_name,
                            component: &sym.name,
                            found,
                        }
                    );
                    found
                }
                Some(HirOidComponent::NamedNumber { .. }) => true,
                Some(HirOidComponent::Number(_)) => true,
                None => false,
            };

            if first_resolvable {
                if resolve_oid_definition_traced(ctx, &def, tracer) {
                    pass_resolved += 1;
                }
            } else {
                still_pending.push(def);
            }
        }

        crate::trace_event!(
            tracer,
            TraceLevel::Info,
            TraceEvent::OidPassEnd {
                pass: iteration,
                resolved: pass_resolved,
                remaining: still_pending.len(),
            }
        );

        // No progress made - remaining definitions have unresolvable references
        if still_pending.len() == initial_count {
            for def in still_pending {
                if let Some(HirOidComponent::Name(sym)) = def.oid.components.first() {
                    crate::trace_event!(
                        tracer,
                        TraceLevel::Debug,
                        TraceEvent::OidUnresolved {
                            def_name: &def.def_name,
                            component: &sym.name,
                        }
                    );
                    ctx.record_unresolved_oid(def.module_id, &def.def_name, &sym.name);
                }
            }
            break;
        }

        pending = still_pending;
    }

    // Final pass: Derive OIDs for TRAP-TYPE definitions.
    // OID = enterprise_oid.0.trap_number (per RFC 1215)
    resolve_trap_type_definitions(ctx, trap_defs);
}

/// An OID definition pending resolution.
struct OidDefinition {
    module_id: ModuleId,
    def_name: String,
    oid: HirOidAssignment,
    def_kind: DefinitionKind,
}

/// A TRAP-TYPE definition pending OID derivation.
/// OID is derived as: enterprise_oid.0.trap_number
struct TrapTypeDefinition {
    module_id: ModuleId,
    def_name: String,
    enterprise: String,
    trap_number: u32,
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

/// Collected OID and TRAP-TYPE definitions.
struct CollectedDefinitions {
    oid_defs: Vec<OidDefinition>,
    trap_defs: Vec<TrapTypeDefinition>,
}

/// Collect all definitions that have OID assignments, and TRAP-TYPE definitions.
fn collect_oid_definitions(ctx: &ResolverContext) -> CollectedDefinitions {
    let mut oid_defs = Vec::new();
    let mut trap_defs = Vec::new();

    // Iterate via module_id_to_hir_index to get ModuleId for each module
    for (&module_id, &hir_idx) in ctx.module_id_to_hir_index.iter() {
        let module = &ctx.hir_modules[hir_idx];
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
                        // NOTIFICATION-TYPE with explicit OID
                        (d.name.name.clone(), oid.clone(), DefinitionKind::Notification)
                    } else if let Some(ref trap_info) = d.trap_info {
                        // TRAP-TYPE: OID derived from enterprise + trap_number
                        trap_defs.push(TrapTypeDefinition {
                            module_id,
                            def_name: d.name.name.clone(),
                            enterprise: trap_info.enterprise.name.clone(),
                            trap_number: trap_info.trap_number,
                        });
                        continue;
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

            oid_defs.push(OidDefinition {
                module_id,
                def_name: name,
                oid,
                def_kind: kind,
            });
        }
    }

    CollectedDefinitions { oid_defs, trap_defs }
}

/// Resolve a single OID definition.
fn resolve_oid_definition(ctx: &mut ResolverContext, def: &OidDefinition) {
    let module_id = def.module_id;

    // Walk the OID components and build the path
    let mut current_node: Option<NodeId> = None;
    let mut current_oid = Oid::new(Vec::new());

    for (comp_idx, component) in def.oid.components.iter().enumerate() {
        let is_last = comp_idx == def.oid.components.len() - 1;

        match component {
            HirOidComponent::Name(sym) => {
                // Look up by name using module-scoped lookup
                if let Some(node_id) = lookup_node_scoped(ctx, module_id, &sym.name) {
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

                    // Add as child of parent, or register as root
                    if let Some(parent_id) = current_node {
                        if let Some(parent) = ctx.model.get_node_mut(parent_id) {
                            parent.add_child(new_id);
                        }
                    } else {
                        ctx.model.add_root(new_id);
                    }

                    ctx.model.register_oid(current_oid.clone(), new_id);
                    current_node = Some(new_id);
                }
            }
            HirOidComponent::NamedNumber { name, number } => {
                // First try to look up the name
                if let Some(node_id) = lookup_node_scoped(ctx, module_id, &name.name) {
                    current_node = Some(node_id);
                    if let Some(node) = ctx.model.get_node(node_id) {
                        current_oid = ctx.model.get_oid(node);
                    }
                } else {
                    // Create node at the given number
                    current_oid = current_oid.child(*number);

                    if let Some(existing) = ctx.model.get_node_id_by_oid(&current_oid) {
                        current_node = Some(existing);
                        // Register the name mapping
                        ctx.register_module_node_symbol(module_id, name.name.clone(), existing);
                    } else {
                        let new_node = OidNode::new(*number, current_node);
                        let new_id = ctx.model.add_node(new_node);

                        // Add as child of parent, or register as root
                        if let Some(parent_id) = current_node {
                            if let Some(parent) = ctx.model.get_node_mut(parent_id) {
                                parent.add_child(new_id);
                            }
                        } else {
                            ctx.model.add_root(new_id);
                        }

                        ctx.model.register_oid(current_oid.clone(), new_id);
                        ctx.register_module_node_symbol(module_id, name.name.clone(), new_id);
                        current_node = Some(new_id);
                    }
                }

                // Also register the name
                if let Some(node_id) = current_node {
                    ctx.register_module_node_symbol(module_id, name.name.clone(), node_id);
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

                    // Set the node kind based on definition type
                    let kind = match def.def_kind {
                        DefinitionKind::ObjectType => {
                            // Will be refined in semantics phase
                            NodeKind::Scalar
                        }
                        DefinitionKind::ModuleIdentity
                        | DefinitionKind::ObjectIdentity
                        | DefinitionKind::ValueAssignment => NodeKind::Node,
                        DefinitionKind::Notification => NodeKind::Notification,
                        DefinitionKind::ObjectGroup | DefinitionKind::NotificationGroup => NodeKind::Group,
                        DefinitionKind::ModuleCompliance => NodeKind::Compliance,
                        DefinitionKind::AgentCapabilities => NodeKind::Capabilities,
                    };
                    node.kind = kind;
                }

                // Register the name -> node mapping for this module
                ctx.register_module_node_symbol(module_id, def.def_name.clone(), node_id);

                // Add to module
                if let Some(module) = ctx.model.get_module_mut(module_id) {
                    module.add_node(node_id);
                }
            }
        }
    }
}

/// Resolve a single OID definition with tracing. Returns true if resolved successfully.
#[cfg(feature = "tracing")]
fn resolve_oid_definition_traced<T: Tracer>(
    ctx: &mut ResolverContext,
    def: &OidDefinition,
    tracer: &mut T,
) -> bool {
    let module_id = def.module_id;

    // Walk the OID components and build the path
    let mut current_node: Option<NodeId> = None;
    let mut current_oid = Oid::new(Vec::new());

    for (comp_idx, component) in def.oid.components.iter().enumerate() {
        let is_last = comp_idx == def.oid.components.len() - 1;

        match component {
            HirOidComponent::Name(sym) => {
                let found = lookup_node_scoped(ctx, module_id, &sym.name);

                crate::trace_event!(
                    tracer,
                    TraceLevel::Trace,
                    TraceEvent::OidLookup {
                        module_id,
                        def_name: &def.def_name,
                        component: &sym.name,
                        found: found.is_some(),
                    }
                );

                if let Some(node_id) = found {
                    current_node = Some(node_id);
                    if let Some(node) = ctx.model.get_node(node_id) {
                        current_oid = ctx.model.get_oid(node);
                    }
                } else {
                    crate::trace_event!(
                        tracer,
                        TraceLevel::Debug,
                        TraceEvent::OidUnresolved {
                            def_name: &def.def_name,
                            component: &sym.name,
                        }
                    );
                    ctx.record_unresolved_oid(module_id, &def.def_name, &sym.name);
                    return false;
                }
            }
            HirOidComponent::Number(arc) => {
                current_oid = current_oid.child(*arc);

                if let Some(existing) = ctx.model.get_node_id_by_oid(&current_oid) {
                    current_node = Some(existing);
                } else {
                    let new_node = OidNode::new(*arc, current_node);
                    let new_id = ctx.model.add_node(new_node);

                    if let Some(parent_id) = current_node {
                        if let Some(parent) = ctx.model.get_node_mut(parent_id) {
                            parent.add_child(new_id);
                        }
                    } else {
                        ctx.model.add_root(new_id);
                    }

                    ctx.model.register_oid(current_oid.clone(), new_id);
                    current_node = Some(new_id);
                }
            }
            HirOidComponent::NamedNumber { name, number } => {
                if let Some(node_id) = lookup_node_scoped(ctx, module_id, &name.name) {
                    current_node = Some(node_id);
                    if let Some(node) = ctx.model.get_node(node_id) {
                        current_oid = ctx.model.get_oid(node);
                    }
                } else {
                    current_oid = current_oid.child(*number);

                    if let Some(existing) = ctx.model.get_node_id_by_oid(&current_oid) {
                        current_node = Some(existing);
                        ctx.register_module_node_symbol(module_id, name.name.clone(), existing);
                    } else {
                        let new_node = OidNode::new(*number, current_node);
                        let new_id = ctx.model.add_node(new_node);

                        if let Some(parent_id) = current_node {
                            if let Some(parent) = ctx.model.get_node_mut(parent_id) {
                                parent.add_child(new_id);
                            }
                        } else {
                            ctx.model.add_root(new_id);
                        }

                        ctx.model.register_oid(current_oid.clone(), new_id);
                        ctx.register_module_node_symbol(module_id, name.name.clone(), new_id);
                        current_node = Some(new_id);
                    }
                }

                if let Some(node_id) = current_node {
                    ctx.register_module_node_symbol(module_id, name.name.clone(), node_id);
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

                    let kind = match def.def_kind {
                        DefinitionKind::ObjectType => NodeKind::Scalar,
                        DefinitionKind::ModuleIdentity
                        | DefinitionKind::ObjectIdentity
                        | DefinitionKind::ValueAssignment => NodeKind::Node,
                        DefinitionKind::Notification => NodeKind::Notification,
                        DefinitionKind::ObjectGroup | DefinitionKind::NotificationGroup => NodeKind::Group,
                        DefinitionKind::ModuleCompliance => NodeKind::Compliance,
                        DefinitionKind::AgentCapabilities => NodeKind::Capabilities,
                    };
                    node.kind = kind;
                }

                ctx.register_module_node_symbol(module_id, def.def_name.clone(), node_id);

                if let Some(module) = ctx.model.get_module_mut(module_id) {
                    module.add_node(node_id);
                }

                // Trace successful resolution
                let oid_str = current_oid.to_dotted();
                crate::trace_event!(
                    tracer,
                    TraceLevel::Trace,
                    TraceEvent::OidResolved {
                        def_name: &def.def_name,
                        oid: &oid_str,
                        node_id,
                    }
                );
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{
        HirModule, HirObjectType, HirOidAssignment, HirOidComponent, HirTypeSyntax,
        HirAccess, HirDefinition, HirStatus, Symbol, HirImport,
    };
    use crate::lexer::Span;
    use crate::resolver::phases::registration::register_modules;
    use crate::resolver::phases::imports::resolve_imports;
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
    fn test_resolve_simple_oid() {
        let obj = make_object_type(
            "testObject",
            vec![
                HirOidComponent::Name(Symbol::from_str("enterprises")),
                HirOidComponent::Number(1),
            ],
        );

        // Module imports "enterprises" from SNMPv2-SMI
        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![obj],
            vec![("enterprises", "SNMPv2-SMI")],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_oids(&mut ctx);

        // Check node exists via module lookup
        let module_id = *ctx.module_index.get("TEST-MIB").unwrap().first().unwrap();
        assert!(ctx.lookup_node_for_module(module_id, "testObject").is_some());

        // Check OID is correct (1.3.6.1.4.1.1)
        if let Some(node_id) = ctx.lookup_node_for_module(module_id, "testObject") {
            if let Some(node) = ctx.model.get_node(node_id) {
                let oid = ctx.model.get_oid(node);
                assert_eq!(oid.arcs(), &[1, 3, 6, 1, 4, 1, 1]);
            }
        }
    }

    #[test]
    fn test_resolve_named_number_oid() {
        // Using named numbers like iso(1) org(3) doesn't require imports
        // because the numbers create the OID path directly
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

        let mut module = HirModule::new(Symbol::from_str("TEST-MIB"), Span::new(0, 0));
        module.definitions = vec![obj];
        let modules = vec![module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_oids(&mut ctx);

        // Check node exists
        let module_id = *ctx.module_index.get("TEST-MIB").unwrap().first().unwrap();
        assert!(ctx.lookup_node_for_module(module_id, "testObject").is_some());

        // Check OID is correct (1.3.999)
        if let Some(node_id) = ctx.lookup_node_for_module(module_id, "testObject") {
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

        // Module doesn't import unknownNode, so it should be unresolved
        let mut module = HirModule::new(Symbol::from_str("TEST-MIB"), Span::new(0, 0));
        module.definitions = vec![obj];
        let modules = vec![module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_oids(&mut ctx);

        // Check unresolved OID was recorded
        assert_eq!(ctx.model.unresolved().oids.len(), 1);
    }
}
