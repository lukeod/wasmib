//! Phase 4: OID resolution.
//!
//! Build the complete OID tree, extracting implicit nodes from inline OID assignments.

use crate::hir::{HirDefinition, HirOidAssignment, HirOidComponent};
use crate::model::{ModuleId, NodeDefinition, NodeId, NodeKind, Oid, OidNode};
use crate::resolver::context::ResolverContext;
use alloc::vec::Vec;

#[cfg(feature = "tracing")]
use crate::resolver::tracing::{TraceEvent, TraceLevel, Tracer};

// ============================================================================
// OidTracer trait - abstracts over tracing to eliminate code duplication
// ============================================================================

/// Trait for optional OID resolution tracing.
///
/// Methods default to no-ops, enabling zero-cost abstraction when tracing is disabled.
/// This allows a single implementation of OID resolution logic to serve both
/// traced and non-traced code paths.
trait OidTracer {
    /// Called at the start of each resolution pass.
    fn trace_pass_start(&mut self, _pass: usize, _pending: usize) {}

    /// Called at the end of each resolution pass.
    fn trace_pass_end(&mut self, _pass: usize, _resolved: usize, _remaining: usize) {}

    /// Called when looking up a symbol during OID resolution.
    fn trace_lookup(
        &mut self,
        _module_id: ModuleId,
        _def_name: &str,
        _component: &str,
        _found: bool,
    ) {
    }

    /// Called when an OID is successfully resolved.
    fn trace_resolved(&mut self, _def_name: &str, _oid: &str, _node_id: NodeId) {}

    /// Called when an OID component cannot be resolved.
    fn trace_unresolved(&mut self, _def_name: &str, _component: &str) {}
}

/// No-op tracer for non-traced resolution.
struct NoopOidTracer;

impl OidTracer for NoopOidTracer {}

/// Wrapper that adapts a `Tracer` to the `OidTracer` trait.
#[cfg(feature = "tracing")]
struct TracingWrapper<'a, T: Tracer>(&'a mut T);

#[cfg(feature = "tracing")]
impl<T: Tracer> OidTracer for TracingWrapper<'_, T> {
    fn trace_pass_start(&mut self, pass: usize, pending: usize) {
        crate::trace_event!(
            self.0,
            TraceLevel::Info,
            TraceEvent::OidPassStart { pass, pending }
        );
    }

    fn trace_pass_end(&mut self, pass: usize, resolved: usize, remaining: usize) {
        crate::trace_event!(
            self.0,
            TraceLevel::Info,
            TraceEvent::OidPassEnd {
                pass,
                resolved,
                remaining,
            }
        );
    }

    fn trace_lookup(&mut self, module_id: ModuleId, def_name: &str, component: &str, found: bool) {
        crate::trace_event!(
            self.0,
            TraceLevel::Trace,
            TraceEvent::OidLookup {
                module_id,
                def_name,
                component,
                found,
            }
        );
    }

    fn trace_resolved(&mut self, def_name: &str, oid: &str, node_id: NodeId) {
        crate::trace_event!(
            self.0,
            TraceLevel::Trace,
            TraceEvent::OidResolved {
                def_name,
                oid,
                node_id,
            }
        );
    }

    fn trace_unresolved(&mut self, def_name: &str, component: &str) {
        crate::trace_event!(
            self.0,
            TraceLevel::Debug,
            TraceEvent::OidUnresolved {
                def_name,
                component
            }
        );
    }
}

/// Look up a node by symbol name in module scope (by `ModuleId`).
fn lookup_node_scoped(ctx: &ResolverContext, module_id: ModuleId, symbol: &str) -> Option<NodeId> {
    ctx.lookup_node_for_module(module_id, symbol)
}

/// Check if the first component of an OID definition is resolvable.
fn is_first_component_resolvable<TR: OidTracer>(
    ctx: &ResolverContext,
    def: &OidDefinition,
    tracer: &mut TR,
) -> bool {
    let oid = def.oid(ctx);
    match oid.components.first() {
        Some(HirOidComponent::Name(sym)) => {
            let found = lookup_node_scoped(ctx, def.module_id, &sym.name).is_some();
            tracer.trace_lookup(def.module_id, def.def_name(ctx), &sym.name, found);
            found
        }
        Some(
            HirOidComponent::NamedNumber { .. } | HirOidComponent::QualifiedNamedNumber { .. },
        ) => true, // Named numbers create nodes
        Some(HirOidComponent::Number(_)) => true, // Bare numbers extend from current
        Some(HirOidComponent::QualifiedName { module, name }) => {
            // Qualified name: use cross-module lookup
            ctx.lookup_node_in_module(&module.name, &name.name)
                .is_some()
        }
        None => false,
    }
}

/// Resolve all OIDs across all modules.
pub fn resolve_oids(ctx: &mut ResolverContext) {
    resolve_oids_inner(ctx, &mut NoopOidTracer);
}

/// Resolve all OIDs across all modules with tracing support.
#[cfg(feature = "tracing")]
pub fn resolve_oids_traced<T: Tracer>(ctx: &mut ResolverContext, tracer: &mut T) {
    resolve_oids_inner(ctx, &mut TracingWrapper(tracer));
}

/// Core OID resolution logic, parameterized over tracing.
fn resolve_oids_inner<TR: OidTracer>(ctx: &mut ResolverContext, tracer: &mut TR) {
    // Multi-pass resolution to handle forward references.
    // Keep iterating until no more definitions can be resolved.
    // Final: Derive OIDs for TRAP-TYPE definitions from enterprise + trap_number

    // First pass: collect all definitions with OIDs
    let CollectedDefinitions {
        oid_defs,
        trap_defs,
    } = collect_oid_definitions(ctx);

    // Process all definitions with multiple passes to handle forward references.
    let mut pending = oid_defs;
    let max_iterations = 20; // Safety limit to prevent infinite loops

    for iteration in 0..max_iterations {
        if pending.is_empty() {
            break;
        }

        tracer.trace_pass_start(iteration, pending.len());

        let initial_count = pending.len();
        let mut still_pending = Vec::new();
        let mut pass_resolved = 0;

        for def in pending {
            // Try to resolve - check if the first component is now resolvable
            let first_resolvable = is_first_component_resolvable(ctx, &def, tracer);

            if first_resolvable {
                if resolve_oid_definition_inner(ctx, &def, tracer) {
                    pass_resolved += 1;
                }
            } else {
                still_pending.push(def);
            }
        }

        tracer.trace_pass_end(iteration, pass_resolved, still_pending.len());

        // No progress made - remaining definitions have unresolvable references
        if still_pending.len() == initial_count {
            // Record unresolved for remaining definitions
            for def in still_pending {
                // Extract data to owned to avoid borrow conflicts
                let oid = def.oid(ctx);
                let def_name = def.def_name(ctx).to_string();
                let oid_span = oid.span;
                let first_component = oid.components.first().cloned();

                match first_component {
                    Some(HirOidComponent::Name(sym)) => {
                        tracer.trace_unresolved(&def_name, &sym.name);
                        ctx.record_unresolved_oid(def.module_id, &def_name, &sym.name, oid_span);
                    }
                    Some(HirOidComponent::QualifiedName { module, name }) => {
                        let qualified_name = alloc::format!("{}.{}", module.name, name.name);
                        tracer.trace_unresolved(&def_name, &qualified_name);
                        ctx.record_unresolved_oid(
                            def.module_id,
                            &def_name,
                            &qualified_name,
                            oid_span,
                        );
                    }
                    _ => {}
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

/// Resolve TRAP-TYPE definitions by deriving OIDs from enterprise + `trap_number`.
/// Per RFC 1215, TRAP-TYPE OID = `enterprise_oid.0.trap_number`
fn resolve_trap_type_definitions(ctx: &mut ResolverContext, trap_defs: Vec<TrapTypeDefinition>) {
    for def in trap_defs {
        // Get trap info from HIR - extract to owned values to avoid borrow conflicts
        let (enterprise_ref, trap_number, span) = def.trap_info(ctx);
        let enterprise = enterprise_ref.to_string();
        let def_name = def.def_name(ctx).to_string();

        // Look up the enterprise OID
        let enterprise_node_id =
            if let Some(id) = lookup_node_scoped(ctx, def.module_id, &enterprise) {
                id
            } else {
                // Enterprise reference not found
                ctx.record_unresolved_oid(def.module_id, &def_name, &enterprise, span);
                continue;
            };

        // Get enterprise OID
        let enterprise_oid = match ctx.model.get_node(enterprise_node_id) {
            Some(node) => ctx.model.get_oid(node),
            None => continue,
        };

        // Build trap OID: enterprise.0.trap_number
        let trap_zero_oid = enterprise_oid.child(0);
        let trap_oid = trap_zero_oid.child(trap_number);

        // Find or create the intermediate .0 node
        let trap_zero_node_id = if let Some(existing) = ctx.model.get_node_id_by_oid(&trap_zero_oid)
        {
            existing
        } else {
            let new_node = OidNode::new(0, Some(enterprise_node_id));
            let new_id = ctx.model.add_node(new_node).unwrap();

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
            let new_node = OidNode::new(trap_number, Some(trap_zero_node_id));
            let new_id = ctx.model.add_node(new_node).unwrap();

            // Add as child of .0 node
            if let Some(parent) = ctx.model.get_node_mut(trap_zero_node_id) {
                parent.add_child(new_id);
            }

            ctx.model.register_oid(trap_oid.clone(), new_id);
            new_id
        };

        // Add the definition to the node
        let label = ctx.intern(&def_name);
        let node_def = NodeDefinition::new(def.module_id, label);

        if let Some(node) = ctx.model.get_node_mut(trap_node_id) {
            node.add_definition(node_def);
            node.kind = NodeKind::Notification;
        }

        // Register the name -> node mapping for this module
        let def_name_id = ctx.intern(&def_name);
        ctx.register_module_node_symbol(def.module_id, def_name_id, trap_node_id);

        // Add to module
        if let Some(module) = ctx.model.get_module_mut(def.module_id) {
            module.add_node(trap_node_id);
        }
    }
}

/// An OID definition pending resolution.
/// Uses indices to reference HIR data instead of cloning.
struct OidDefinition {
    module_id: ModuleId,
    hir_idx: usize,
    def_idx: usize,
    def_kind: DefinitionKind,
}

impl OidDefinition {
    /// Get the definition name from HIR.
    fn def_name<'a>(&self, ctx: &'a ResolverContext) -> &'a str {
        let def = &ctx.hir_modules[self.hir_idx].definitions[self.def_idx];
        def.name().map_or("", |n| n.name.as_str())
    }

    /// Get the OID assignment from HIR.
    fn oid<'a>(&self, ctx: &'a ResolverContext) -> &'a HirOidAssignment {
        let def = &ctx.hir_modules[self.hir_idx].definitions[self.def_idx];
        match def {
            HirDefinition::ObjectType(d) => &d.oid,
            HirDefinition::ModuleIdentity(d) => &d.oid,
            HirDefinition::ObjectIdentity(d) => &d.oid,
            HirDefinition::Notification(d) => d.oid.as_ref().expect("notification has OID"),
            HirDefinition::ValueAssignment(d) => &d.oid,
            HirDefinition::ObjectGroup(d) => &d.oid,
            HirDefinition::NotificationGroup(d) => &d.oid,
            HirDefinition::ModuleCompliance(d) => &d.oid,
            HirDefinition::AgentCapabilities(d) => &d.oid,
            HirDefinition::TypeDef(_) => panic!("TypeDef has no OID"),
        }
    }
}

/// A TRAP-TYPE definition pending OID derivation.
/// OID is derived as: `enterprise_oid.0.trap_number`
/// Uses indices to reference HIR data instead of cloning.
struct TrapTypeDefinition {
    module_id: ModuleId,
    hir_idx: usize,
    def_idx: usize,
}

impl TrapTypeDefinition {
    /// Get the definition name from HIR.
    fn def_name<'a>(&self, ctx: &'a ResolverContext) -> &'a str {
        let def = &ctx.hir_modules[self.hir_idx].definitions[self.def_idx];
        def.name().map_or("", |n| n.name.as_str())
    }

    /// Get the trap info from HIR (enterprise name and trap number).
    fn trap_info<'a>(&self, ctx: &'a ResolverContext) -> (&'a str, u32, crate::lexer::Span) {
        let def = &ctx.hir_modules[self.hir_idx].definitions[self.def_idx];
        if let HirDefinition::Notification(d) = def
            && let Some(ref trap_info) = d.trap_info
        {
            return (&trap_info.enterprise.name, trap_info.trap_number, d.span);
        }
        panic!("TrapTypeDefinition must reference a TRAP-TYPE");
    }
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
    for (&module_id, &hir_idx) in &ctx.module_id_to_hir_index {
        let module = &ctx.hir_modules[hir_idx];
        for (def_idx, def) in module.definitions.iter().enumerate() {
            let kind = match def {
                HirDefinition::ObjectType(_) => DefinitionKind::ObjectType,
                HirDefinition::ModuleIdentity(_) => DefinitionKind::ModuleIdentity,
                HirDefinition::ObjectIdentity(_) => DefinitionKind::ObjectIdentity,
                HirDefinition::Notification(d) => {
                    if d.oid.is_some() {
                        // NOTIFICATION-TYPE with explicit OID
                        DefinitionKind::Notification
                    } else if d.trap_info.is_some() {
                        // TRAP-TYPE: OID derived from enterprise + trap_number
                        trap_defs.push(TrapTypeDefinition {
                            module_id,
                            hir_idx,
                            def_idx,
                        });
                        continue;
                    } else {
                        continue;
                    }
                }
                HirDefinition::ValueAssignment(_) => DefinitionKind::ValueAssignment,
                HirDefinition::ObjectGroup(_) => DefinitionKind::ObjectGroup,
                HirDefinition::NotificationGroup(_) => DefinitionKind::NotificationGroup,
                HirDefinition::ModuleCompliance(_) => DefinitionKind::ModuleCompliance,
                HirDefinition::AgentCapabilities(_) => DefinitionKind::AgentCapabilities,
                HirDefinition::TypeDef(_) => continue,
            };

            oid_defs.push(OidDefinition {
                module_id,
                hir_idx,
                def_idx,
                def_kind: kind,
            });
        }
    }

    CollectedDefinitions {
        oid_defs,
        trap_defs,
    }
}

/// Resolve a single OID definition. Returns true if resolved successfully.
fn resolve_oid_definition_inner<TR: OidTracer>(
    ctx: &mut ResolverContext,
    def: &OidDefinition,
    tracer: &mut TR,
) -> bool {
    let module_id = def.module_id;

    // Extract data from HIR upfront to avoid borrow conflicts during mutation
    let oid = def.oid(ctx);
    let def_name = def.def_name(ctx).to_string();
    let oid_span = oid.span;
    let components: Vec<_> = oid.components.clone();
    let num_components = components.len();

    // Walk the OID components and build the path
    let mut current_node: Option<NodeId> = None;
    let mut current_oid = Oid::new(Vec::new());

    for (comp_idx, component) in components.iter().enumerate() {
        let is_last = comp_idx == num_components - 1;

        match component {
            HirOidComponent::Name(sym) => {
                // Look up by name using module-scoped lookup
                let found = lookup_node_scoped(ctx, module_id, &sym.name);
                tracer.trace_lookup(module_id, &def_name, &sym.name, found.is_some());

                if let Some(node_id) = found {
                    current_node = Some(node_id);
                    if let Some(node) = ctx.model.get_node(node_id) {
                        current_oid = ctx.model.get_oid(node);
                    }
                } else {
                    // Unresolved name reference
                    tracer.trace_unresolved(&def_name, &sym.name);
                    ctx.record_unresolved_oid(module_id, &def_name, &sym.name, oid_span);
                    return false;
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
                    let new_id = ctx.model.add_node(new_node).unwrap();

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

                    let name_id = ctx.intern(&name.name);
                    if let Some(existing) = ctx.model.get_node_id_by_oid(&current_oid) {
                        current_node = Some(existing);
                        // Register the name mapping
                        ctx.register_module_node_symbol(module_id, name_id, existing);
                    } else {
                        let new_node = OidNode::new(*number, current_node);
                        let new_id = ctx.model.add_node(new_node).unwrap();

                        // Add as child of parent, or register as root
                        if let Some(parent_id) = current_node {
                            if let Some(parent) = ctx.model.get_node_mut(parent_id) {
                                parent.add_child(new_id);
                            }
                        } else {
                            ctx.model.add_root(new_id);
                        }

                        ctx.model.register_oid(current_oid.clone(), new_id);
                        ctx.register_module_node_symbol(module_id, name_id, new_id);
                        current_node = Some(new_id);
                    }
                }

                // Also register the name
                if let Some(node_id) = current_node {
                    let name_id = ctx.intern(&name.name);
                    ctx.register_module_node_symbol(module_id, name_id, node_id);
                }
            }
            HirOidComponent::QualifiedName {
                module: qual_module,
                name,
            } => {
                // Look up in the specified module using cross-module lookup
                if let Some(node_id) = ctx.lookup_node_in_module(&qual_module.name, &name.name) {
                    current_node = Some(node_id);
                    if let Some(node) = ctx.model.get_node(node_id) {
                        current_oid = ctx.model.get_oid(node);
                    }
                } else {
                    // Unresolved qualified reference
                    let qualified_name = alloc::format!("{}.{}", qual_module.name, name.name);
                    tracer.trace_unresolved(&def_name, &qualified_name);
                    ctx.record_unresolved_oid(module_id, &def_name, &qualified_name, oid_span);
                    return false;
                }
            }
            HirOidComponent::QualifiedNamedNumber {
                module: qual_module,
                name,
                number,
            } => {
                // First try to look up in the specified module
                if let Some(node_id) = ctx.lookup_node_in_module(&qual_module.name, &name.name) {
                    current_node = Some(node_id);
                    if let Some(node) = ctx.model.get_node(node_id) {
                        current_oid = ctx.model.get_oid(node);
                    }
                } else {
                    // Create node at the given number (like NamedNumber behavior)
                    current_oid = current_oid.child(*number);

                    let name_id = ctx.intern(&name.name);
                    if let Some(existing) = ctx.model.get_node_id_by_oid(&current_oid) {
                        current_node = Some(existing);
                        // Register the name mapping for this module
                        ctx.register_module_node_symbol(module_id, name_id, existing);
                    } else {
                        let new_node = OidNode::new(*number, current_node);
                        let new_id = ctx.model.add_node(new_node).unwrap();

                        // Add as child of parent, or register as root
                        if let Some(parent_id) = current_node {
                            if let Some(parent) = ctx.model.get_node_mut(parent_id) {
                                parent.add_child(new_id);
                            }
                        } else {
                            ctx.model.add_root(new_id);
                        }

                        ctx.model.register_oid(current_oid.clone(), new_id);
                        ctx.register_module_node_symbol(module_id, name_id, new_id);
                        current_node = Some(new_id);
                    }
                }

                // Also register the name for this module's scope
                if let Some(node_id) = current_node {
                    let name_id = ctx.intern(&name.name);
                    ctx.register_module_node_symbol(module_id, name_id, node_id);
                }
            }
        }

        // If this is the last component, add the definition
        if is_last && let Some(node_id) = current_node {
            let label = ctx.intern(&def_name);
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
                    DefinitionKind::ObjectGroup | DefinitionKind::NotificationGroup => {
                        NodeKind::Group
                    }
                    DefinitionKind::ModuleCompliance => NodeKind::Compliance,
                    DefinitionKind::AgentCapabilities => NodeKind::Capabilities,
                };
                node.kind = kind;
            }

            // Register the name -> node mapping for this module
            let def_name_id = ctx.intern(&def_name);
            ctx.register_module_node_symbol(module_id, def_name_id, node_id);

            // Add to module
            if let Some(module) = ctx.model.get_module_mut(module_id) {
                module.add_node(node_id);
            }

            // Trace successful resolution
            let oid_str = current_oid.to_dotted();
            tracer.trace_resolved(&def_name, &oid_str, node_id);
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{
        HirAccess, HirDefinition, HirImport, HirModule, HirObjectType, HirOidAssignment,
        HirOidComponent, HirStatus, HirTypeSyntax, Symbol,
    };
    use crate::lexer::Span;
    use crate::resolver::phases::imports::resolve_imports;
    use crate::resolver::phases::registration::register_modules;
    use alloc::vec;

    fn make_object_type(name: &str, oid_components: Vec<HirOidComponent>) -> HirDefinition {
        HirDefinition::ObjectType(HirObjectType {
            name: Symbol::from_name(name),
            syntax: HirTypeSyntax::TypeRef(Symbol::from_name("Integer32")),
            units: None,
            access: HirAccess::ReadOnly,
            status: HirStatus::Current,
            description: None,
            reference: None,
            index: None,
            augments: None,
            defval: None,
            oid: HirOidAssignment::new(oid_components, Span::new(0, 0)),
            span: Span::new(0, 0),
        })
    }

    /// Create a test module with imports.
    /// imports is a list of (symbol, `from_module`) pairs.
    fn make_test_module_with_imports(
        name: &str,
        defs: Vec<HirDefinition>,
        imports: Vec<(&str, &str)>,
    ) -> HirModule {
        let mut module = HirModule::new(Symbol::from_name(name), Span::new(0, 0));
        module.definitions = defs;
        // HirImport::new takes (module, symbol, span)
        module.imports = imports
            .into_iter()
            .map(|(sym, from)| {
                HirImport::new(
                    Symbol::from_name(from),
                    Symbol::from_name(sym),
                    Span::new(0, 0),
                )
            })
            .collect();
        module
    }

    #[test]
    fn test_resolve_simple_oid() {
        let obj = make_object_type(
            "testObject",
            vec![
                HirOidComponent::Name(Symbol::from_name("enterprises")),
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
        let module_id = ctx.get_module_id_by_name("TEST-MIB").unwrap();
        assert!(
            ctx.lookup_node_for_module(module_id, "testObject")
                .is_some()
        );

        // Check OID is correct (1.3.6.1.4.1.1)
        if let Some(node_id) = ctx.lookup_node_for_module(module_id, "testObject")
            && let Some(node) = ctx.model.get_node(node_id)
        {
            let oid = ctx.model.get_oid(node);
            assert_eq!(oid.arcs(), &[1, 3, 6, 1, 4, 1, 1]);
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
                    name: Symbol::from_name("iso"),
                    number: 1,
                },
                HirOidComponent::NamedNumber {
                    name: Symbol::from_name("org"),
                    number: 3,
                },
                HirOidComponent::Number(999),
            ],
        );

        let mut module = HirModule::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
        module.definitions = vec![obj];
        let modules = vec![module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_oids(&mut ctx);

        // Check node exists
        let module_id = ctx.get_module_id_by_name("TEST-MIB").unwrap();
        assert!(
            ctx.lookup_node_for_module(module_id, "testObject")
                .is_some()
        );

        // Check OID is correct (1.3.999)
        if let Some(node_id) = ctx.lookup_node_for_module(module_id, "testObject")
            && let Some(node) = ctx.model.get_node(node_id)
        {
            let oid = ctx.model.get_oid(node);
            assert_eq!(oid.arcs(), &[1, 3, 999]);
        }
    }

    #[test]
    fn test_unresolved_oid_component() {
        let obj = make_object_type(
            "testObject",
            vec![
                HirOidComponent::Name(Symbol::from_name("unknownNode")),
                HirOidComponent::Number(1),
            ],
        );

        // Module doesn't import unknownNode, so it should be unresolved
        let mut module = HirModule::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
        module.definitions = vec![obj];
        let modules = vec![module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_oids(&mut ctx);

        // Check unresolved OID was recorded
        assert_eq!(ctx.model.unresolved().oids.len(), 1);
    }

    #[test]
    fn test_resolve_qualified_name_oid() {
        // Test qualified name: SNMPv2-SMI.enterprises without import
        let obj = make_object_type(
            "testObject",
            vec![
                HirOidComponent::QualifiedName {
                    module: Symbol::from_name("SNMPv2-SMI"),
                    name: Symbol::from_name("enterprises"),
                },
                HirOidComponent::Number(1),
            ],
        );

        // Module does NOT import enterprises, but uses qualified syntax
        let mut module = HirModule::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
        module.definitions = vec![obj];
        let modules = vec![module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_oids(&mut ctx);

        // Check node exists via module lookup
        let module_id = ctx.get_module_id_by_name("TEST-MIB").unwrap();
        assert!(
            ctx.lookup_node_for_module(module_id, "testObject")
                .is_some()
        );

        // Check OID is correct (1.3.6.1.4.1.1) - enterprises is 1.3.6.1.4.1
        if let Some(node_id) = ctx.lookup_node_for_module(module_id, "testObject")
            && let Some(node) = ctx.model.get_node(node_id)
        {
            let oid = ctx.model.get_oid(node);
            assert_eq!(oid.arcs(), &[1, 3, 6, 1, 4, 1, 1]);
        }
    }

    #[test]
    fn test_resolve_qualified_named_number_oid() {
        // Test qualified named number: SNMPv2-SMI.enterprises(1) without import
        let obj = make_object_type(
            "testObject",
            vec![
                HirOidComponent::QualifiedNamedNumber {
                    module: Symbol::from_name("SNMPv2-SMI"),
                    name: Symbol::from_name("enterprises"),
                    number: 1, // enterprises is at 1.3.6.1.4.1
                },
                HirOidComponent::Number(42),
            ],
        );

        // Module does NOT import enterprises, but uses qualified syntax
        let mut module = HirModule::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
        module.definitions = vec![obj];
        let modules = vec![module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_oids(&mut ctx);

        // Check node exists via module lookup
        let module_id = ctx.get_module_id_by_name("TEST-MIB").unwrap();
        assert!(
            ctx.lookup_node_for_module(module_id, "testObject")
                .is_some()
        );

        // Check OID is correct - should use the existing enterprises node
        if let Some(node_id) = ctx.lookup_node_for_module(module_id, "testObject")
            && let Some(node) = ctx.model.get_node(node_id)
        {
            let oid = ctx.model.get_oid(node);
            assert_eq!(oid.arcs(), &[1, 3, 6, 1, 4, 1, 42]);
        }
    }

    #[test]
    fn test_unresolved_qualified_oid() {
        // Test that unresolved qualified reference is recorded correctly
        let obj = make_object_type(
            "testObject",
            vec![
                HirOidComponent::QualifiedName {
                    module: Symbol::from_name("NONEXISTENT-MIB"),
                    name: Symbol::from_name("unknownNode"),
                },
                HirOidComponent::Number(1),
            ],
        );

        let mut module = HirModule::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
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
