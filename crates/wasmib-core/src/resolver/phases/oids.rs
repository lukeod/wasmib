//! Phase 4: OID resolution.
//!
//! Build the complete OID tree, extracting implicit nodes from inline OID assignments.

use crate::model::{ModuleId, NodeDefinition, NodeId, NodeKind, Oid, OidNode};
use crate::module::{Definition, OidAssignment, OidComponent};
use crate::resolver::context::ResolverContext;
use alloc::boxed::Box;
use alloc::string::ToString;
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

// ============================================================================
// Well-known ASN.1 root OIDs
// ============================================================================

/// Check if a symbol name is a well-known ASN.1 root.
/// Returns the OID arc value if it is (ccitt=0, iso=1, joint-iso-ccitt=2).
fn well_known_root_arc(name: &str) -> Option<u32> {
    match name {
        "ccitt" => Some(0),
        "iso" => Some(1),
        "joint-iso-ccitt" => Some(2),
        _ => None,
    }
}

/// Look up a well-known root in the model, or create it if it doesn't exist.
/// Returns the `NodeId` for the root node.
fn lookup_or_create_well_known_root(ctx: &mut ResolverContext, name: &str) -> Option<NodeId> {
    let arc = well_known_root_arc(name)?;
    let oid = Oid::new(alloc::vec![arc]);

    // Check if node already exists
    if let Some(node_id) = ctx.model.get_node_id_by_oid(&oid) {
        return Some(node_id);
    }

    // Create the root node
    let new_node = OidNode::new(arc, None);
    let new_id = ctx.model.add_node(new_node).ok()?;
    ctx.model.add_root(new_id);
    ctx.model.register_oid(oid, new_id);

    Some(new_id)
}

// ============================================================================
// Global SMI OID root fallback
// ============================================================================

/// Common SMI OID roots that should be accessible globally without explicit import.
/// These are defined in SNMPv2-SMI and RFC1155-SMI base modules.
const SMI_GLOBAL_OID_ROOTS: &[&str] = &[
    // From both SNMPv2-SMI and RFC1155-SMI
    "internet",
    "directory",
    "mgmt",
    "mib-2",
    "transmission",
    "experimental",
    "private",
    "enterprises",
    // SNMPv2-SMI only
    "security",
    "snmpV2",
    "snmpDomains",
    "snmpProxys",
    "snmpModules",
    "zeroDotZero",
    // RFC1213-MIB / SNMPv2-MIB (commonly used without import)
    "snmp",
];

/// Check if a symbol name is a common SMI OID root that should be globally accessible.
fn is_smi_global_oid_root(name: &str) -> bool {
    SMI_GLOBAL_OID_ROOTS.contains(&name)
}

/// Look up a common SMI OID root globally (in SNMPv2-SMI or RFC1155-SMI).
/// This provides leniency for MIBs that use roots like `enterprises` without importing them.
fn lookup_smi_global_oid_root(ctx: &ResolverContext, name: &str) -> Option<NodeId> {
    if !is_smi_global_oid_root(name) {
        return None;
    }

    // Try SNMPv2-SMI first (preferred for SMIv2 modules)
    if let Some(node_id) = ctx.lookup_node_in_module("SNMPv2-SMI", name) {
        return Some(node_id);
    }

    // Fall back to RFC1155-SMI (for SMIv1 modules)
    ctx.lookup_node_in_module("RFC1155-SMI", name)
}

/// Check if the first component of an OID definition is resolvable.
fn is_first_component_resolvable<TR: OidTracer>(
    ctx: &ResolverContext,
    def: &OidDefinition,
    tracer: &mut TR,
) -> bool {
    let Some(oid) = def.oid(ctx) else {
        // Definition has no OID (e.g., TypeDef) - skip
        return false;
    };
    match oid.components.first() {
        Some(OidComponent::Name(sym)) => {
            // First check module-scoped lookup
            let found = lookup_node_scoped(ctx, def.module_id, &sym.name).is_some()
                // Fall back to well-known ASN.1 roots (iso, ccitt, joint-iso-ccitt)
                || well_known_root_arc(&sym.name).is_some()
                // Fall back to global SMI OID roots (enterprises, mib-2, etc.)
                || lookup_smi_global_oid_root(ctx, &sym.name).is_some();
            tracer.trace_lookup(def.module_id, def.def_name(ctx), &sym.name, found);
            found
        }
        Some(
            OidComponent::NamedNumber { .. }
            | OidComponent::QualifiedNamedNumber { .. }
            | OidComponent::Number(_),
        ) => true, // Named/bare numbers create or extend nodes
        Some(OidComponent::QualifiedName { module, name }) => {
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
                let Some(oid) = def.oid(ctx) else {
                    // Definition has no OID (shouldn't happen, but skip gracefully)
                    continue;
                };
                let def_name = def.def_name(ctx).to_string();
                let oid_span = oid.span;
                let first_component = oid.components.first().cloned();

                match first_component {
                    Some(OidComponent::Name(sym)) => {
                        tracer.trace_unresolved(&def_name, &sym.name);
                        ctx.record_unresolved_oid(def.module_id, &def_name, &sym.name, oid_span);
                    }
                    Some(OidComponent::QualifiedName { module, name }) => {
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
        let Some((enterprise_ref, trap_number, span)) = def.trap_info(ctx) else {
            // Not a valid TRAP-TYPE definition (shouldn't happen, but skip gracefully)
            continue;
        };
        let enterprise = enterprise_ref.to_string();
        let def_name = def.def_name(ctx).to_string();

        // Look up the enterprise OID (try module scope, then global SMI roots)
        let enterprise_node_id = lookup_node_scoped(ctx, def.module_id, &enterprise)
            .or_else(|| lookup_smi_global_oid_root(ctx, &enterprise));

        let Some(enterprise_node_id) = enterprise_node_id else {
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
        let label = def_name.as_str().into();
        let node_def = NodeDefinition::new(def.module_id, label);

        if let Some(node) = ctx.model.get_node_mut(trap_node_id) {
            node.add_definition(node_def);
            node.kind = NodeKind::Notification;
        }

        // Register the name -> node mapping for this module
        let def_name_id = def_name.as_str().into();
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
    /// Returns None for TypeDef (which has no OID) or Notification without OID.
    fn oid<'a>(&self, ctx: &'a ResolverContext) -> Option<&'a OidAssignment> {
        let def = &ctx.hir_modules[self.hir_idx].definitions[self.def_idx];
        match def {
            Definition::ObjectType(d) => Some(&d.oid),
            Definition::ModuleIdentity(d) => Some(&d.oid),
            Definition::ObjectIdentity(d) => Some(&d.oid),
            Definition::Notification(d) => d.oid.as_ref(),
            Definition::ValueAssignment(d) => Some(&d.oid),
            Definition::ObjectGroup(d) => Some(&d.oid),
            Definition::NotificationGroup(d) => Some(&d.oid),
            Definition::ModuleCompliance(d) => Some(&d.oid),
            Definition::AgentCapabilities(d) => Some(&d.oid),
            Definition::TypeDef(_) => None,
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
    /// Returns None if this isn't a valid TRAP-TYPE definition (shouldn't happen).
    fn trap_info<'a>(
        &self,
        ctx: &'a ResolverContext,
    ) -> Option<(&'a str, u32, crate::lexer::Span)> {
        let def = &ctx.hir_modules[self.hir_idx].definitions[self.def_idx];
        if let Definition::Notification(d) = def
            && let Some(ref trap_info) = d.trap_info
        {
            return Some((&trap_info.enterprise.name, trap_info.trap_number, d.span));
        }
        None
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
                Definition::ObjectType(_) => DefinitionKind::ObjectType,
                Definition::ModuleIdentity(_) => DefinitionKind::ModuleIdentity,
                Definition::ObjectIdentity(_) => DefinitionKind::ObjectIdentity,
                Definition::Notification(d) => {
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
                Definition::ValueAssignment(_) => DefinitionKind::ValueAssignment,
                Definition::ObjectGroup(_) => DefinitionKind::ObjectGroup,
                Definition::NotificationGroup(_) => DefinitionKind::NotificationGroup,
                Definition::ModuleCompliance(_) => DefinitionKind::ModuleCompliance,
                Definition::AgentCapabilities(_) => DefinitionKind::AgentCapabilities,
                Definition::TypeDef(_) => continue,
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
#[allow(clippy::too_many_lines)] // OID resolution involves many steps
fn resolve_oid_definition_inner<TR: OidTracer>(
    ctx: &mut ResolverContext,
    def: &OidDefinition,
    tracer: &mut TR,
) -> bool {
    let module_id = def.module_id;

    // Extract data from HIR upfront to avoid borrow conflicts during mutation
    let Some(oid) = def.oid(ctx) else {
        // Definition has no OID (shouldn't happen, but skip gracefully)
        return false;
    };
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
            OidComponent::Name(sym) => {
                // Look up by name using module-scoped lookup
                let found = lookup_node_scoped(ctx, module_id, &sym.name);
                tracer.trace_lookup(module_id, &def_name, &sym.name, found.is_some());

                if let Some(node_id) = found {
                    current_node = Some(node_id);
                    if let Some(node) = ctx.model.get_node(node_id) {
                        current_oid = ctx.model.get_oid(node);
                    }
                } else if let Some(node_id) = lookup_or_create_well_known_root(ctx, &sym.name) {
                    // Fall back to well-known ASN.1 roots (iso, ccitt, joint-iso-ccitt)
                    current_node = Some(node_id);
                    if let Some(node) = ctx.model.get_node(node_id) {
                        current_oid = ctx.model.get_oid(node);
                    }
                } else if let Some(node_id) = lookup_smi_global_oid_root(ctx, &sym.name) {
                    // Fall back to global SMI OID roots (enterprises, mib-2, etc.)
                    // This provides leniency for MIBs that use these roots without importing them
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
            OidComponent::Number(arc) => {
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
            OidComponent::NamedNumber { name, number } => {
                // First try to look up the name
                if let Some(node_id) = lookup_node_scoped(ctx, module_id, &name.name) {
                    current_node = Some(node_id);
                    if let Some(node) = ctx.model.get_node(node_id) {
                        current_oid = ctx.model.get_oid(node);
                    }
                } else {
                    // Create node at the given number
                    current_oid = current_oid.child(*number);

                    let name_id: Box<str> = name.name.as_str().into();
                    if let Some(existing) = ctx.model.get_node_id_by_oid(&current_oid) {
                        current_node = Some(existing);
                        // Register the name mapping
                        ctx.register_module_node_symbol(module_id, name_id.clone(), existing);
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
                        ctx.register_module_node_symbol(module_id, name_id.clone(), new_id);
                        current_node = Some(new_id);
                    }

                    // Add definition for intermediate named components (matches libsmi behavior)
                    if !is_last && let Some(node_id) = current_node {
                        let node_def = NodeDefinition::new(module_id, name_id);
                        if let Some(node) = ctx.model.get_node_mut(node_id) {
                            node.add_definition(node_def);
                            if node.kind == NodeKind::Internal {
                                node.kind = NodeKind::Node;
                            }
                        }
                    }
                }

                // Also register the name
                if let Some(node_id) = current_node {
                    let name_id = name.name.as_str().into();
                    ctx.register_module_node_symbol(module_id, name_id, node_id);
                }
            }
            OidComponent::QualifiedName {
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
            OidComponent::QualifiedNamedNumber {
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

                    let name_id: Box<str> = name.name.as_str().into();
                    if let Some(existing) = ctx.model.get_node_id_by_oid(&current_oid) {
                        current_node = Some(existing);
                        // Register the name mapping for this module
                        ctx.register_module_node_symbol(module_id, name_id.clone(), existing);
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
                        ctx.register_module_node_symbol(module_id, name_id.clone(), new_id);
                        current_node = Some(new_id);
                    }

                    // Add definition for intermediate named components (matches libsmi behavior)
                    if !is_last && let Some(node_id) = current_node {
                        let node_def = NodeDefinition::new(module_id, name_id);
                        if let Some(node) = ctx.model.get_node_mut(node_id) {
                            node.add_definition(node_def);
                            if node.kind == NodeKind::Internal {
                                node.kind = NodeKind::Node;
                            }
                        }
                    }
                }

                // Also register the name for this module's scope
                if let Some(node_id) = current_node {
                    let name_id = name.name.as_str().into();
                    ctx.register_module_node_symbol(module_id, name_id, node_id);
                }
            }
        }

        // If this is the last component, add the definition
        if is_last && let Some(node_id) = current_node {
            let label = def_name.as_str().into();
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
            let def_name_id = def_name.as_str().into();
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
    use crate::lexer::Span;
    use crate::module::{
        Access, Definition, Import, Module, ObjectType, OidAssignment, OidComponent, Status,
        Symbol, TypeSyntax,
    };
    use crate::resolver::phases::imports::resolve_imports;
    use crate::resolver::phases::registration::register_modules;
    use alloc::vec;

    fn make_object_type(name: &str, oid_components: Vec<OidComponent>) -> Definition {
        Definition::ObjectType(ObjectType {
            name: Symbol::from_name(name),
            syntax: TypeSyntax::TypeRef(Symbol::from_name("Integer32")),
            units: None,
            access: Access::ReadOnly,
            status: Status::Current,
            description: None,
            reference: None,
            index: None,
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
    fn test_resolve_simple_oid() {
        let obj = make_object_type(
            "testObject",
            vec![
                OidComponent::Name(Symbol::from_name("enterprises")),
                OidComponent::Number(1),
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
                OidComponent::NamedNumber {
                    name: Symbol::from_name("iso"),
                    number: 1,
                },
                OidComponent::NamedNumber {
                    name: Symbol::from_name("org"),
                    number: 3,
                },
                OidComponent::Number(999),
            ],
        );

        let mut module = Module::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
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
                OidComponent::Name(Symbol::from_name("unknownNode")),
                OidComponent::Number(1),
            ],
        );

        // Module doesn't import unknownNode, so it should be unresolved
        let mut module = Module::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
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
                OidComponent::QualifiedName {
                    module: Symbol::from_name("SNMPv2-SMI"),
                    name: Symbol::from_name("enterprises"),
                },
                OidComponent::Number(1),
            ],
        );

        // Module does NOT import enterprises, but uses qualified syntax
        let mut module = Module::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
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
                OidComponent::QualifiedNamedNumber {
                    module: Symbol::from_name("SNMPv2-SMI"),
                    name: Symbol::from_name("enterprises"),
                    number: 1, // enterprises is at 1.3.6.1.4.1
                },
                OidComponent::Number(42),
            ],
        );

        // Module does NOT import enterprises, but uses qualified syntax
        let mut module = Module::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
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
                OidComponent::QualifiedName {
                    module: Symbol::from_name("NONEXISTENT-MIB"),
                    name: Symbol::from_name("unknownNode"),
                },
                OidComponent::Number(1),
            ],
        );

        let mut module = Module::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
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
    fn test_intermediate_named_number_creates_definition() {
        // Test that intermediate NamedNumber components create definitions
        // This matches libsmi behavior where `{ standard jsr163(163) 1 }` creates
        // a definition for `jsr163` at OID .163, not just the final node.
        let obj = make_object_type(
            "testObject",
            vec![
                OidComponent::NamedNumber {
                    name: Symbol::from_name("intermediate"),
                    number: 99,
                },
                OidComponent::Number(1),
            ],
        );

        let mut module = Module::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
        module.definitions = vec![obj];
        let modules = vec![module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_oids(&mut ctx);

        let module_id = ctx.get_module_id_by_name("TEST-MIB").unwrap();

        // Check that intermediate node has a definition
        let intermediate_node_id = ctx
            .lookup_node_for_module(module_id, "intermediate")
            .unwrap();
        let intermediate_node = ctx.model.get_node(intermediate_node_id).unwrap();

        // Should have exactly one definition
        assert_eq!(
            intermediate_node.definitions.len(),
            1,
            "intermediate node should have a definition"
        );

        // Check the definition's label matches
        let def = &intermediate_node.definitions[0];
        assert_eq!(def.module, module_id);
        assert_eq!(def.label.as_ref(), "intermediate");

        // Check node kind is Node (not Internal)
        assert_eq!(intermediate_node.kind, NodeKind::Node);

        // Check OID is correct (99)
        let oid = ctx.model.get_oid(intermediate_node);
        assert_eq!(oid.arcs(), &[99]);

        // Also verify the final node exists with its own definition
        let final_node_id = ctx.lookup_node_for_module(module_id, "testObject").unwrap();
        let final_node = ctx.model.get_node(final_node_id).unwrap();
        assert!(final_node.has_definition());
        let final_oid = ctx.model.get_oid(final_node);
        assert_eq!(final_oid.arcs(), &[99, 1]);
    }

    #[test]
    fn test_well_known_root_iso_without_import() {
        // Test that `iso` resolves globally without import.
        // This is needed for corpus MIBs like SNMPv2-SMI-v1 that use:
        //   org OBJECT IDENTIFIER ::= { iso 3 }
        // without importing iso.
        let obj = make_object_type(
            "org",
            vec![
                OidComponent::Name(Symbol::from_name("iso")),
                OidComponent::Number(3),
            ],
        );

        // Module does NOT import iso - should still resolve via well-known roots
        let mut module = Module::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
        module.definitions = vec![obj];
        let modules = vec![module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_oids(&mut ctx);

        // No unresolved OIDs
        assert_eq!(
            ctx.model.unresolved().oids.len(),
            0,
            "iso should resolve as well-known root"
        );

        // Check node exists
        let module_id = ctx.get_module_id_by_name("TEST-MIB").unwrap();
        assert!(ctx.lookup_node_for_module(module_id, "org").is_some());

        // Check OID is correct (1.3 = iso.3)
        if let Some(node_id) = ctx.lookup_node_for_module(module_id, "org")
            && let Some(node) = ctx.model.get_node(node_id)
        {
            let oid = ctx.model.get_oid(node);
            assert_eq!(oid.arcs(), &[1, 3]);
        }
    }

    #[test]
    fn test_well_known_root_ccitt_without_import() {
        // Test that `ccitt` resolves globally without import (OID 0).
        let obj = make_object_type(
            "testObject",
            vec![
                OidComponent::Name(Symbol::from_name("ccitt")),
                OidComponent::Number(5),
            ],
        );

        let mut module = Module::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
        module.definitions = vec![obj];
        let modules = vec![module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_oids(&mut ctx);

        // No unresolved OIDs
        assert_eq!(
            ctx.model.unresolved().oids.len(),
            0,
            "ccitt should resolve as well-known root"
        );

        // Check OID is correct (0.5 = ccitt.5)
        let module_id = ctx.get_module_id_by_name("TEST-MIB").unwrap();
        if let Some(node_id) = ctx.lookup_node_for_module(module_id, "testObject")
            && let Some(node) = ctx.model.get_node(node_id)
        {
            let oid = ctx.model.get_oid(node);
            assert_eq!(oid.arcs(), &[0, 5]);
        }
    }

    #[test]
    fn test_well_known_root_joint_iso_ccitt_without_import() {
        // Test that `joint-iso-ccitt` resolves globally without import (OID 2).
        let obj = make_object_type(
            "testObject",
            vec![
                OidComponent::Name(Symbol::from_name("joint-iso-ccitt")),
                OidComponent::Number(1),
            ],
        );

        let mut module = Module::new(Symbol::from_name("TEST-MIB"), Span::new(0, 0));
        module.definitions = vec![obj];
        let modules = vec![module];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_oids(&mut ctx);

        // No unresolved OIDs
        assert_eq!(
            ctx.model.unresolved().oids.len(),
            0,
            "joint-iso-ccitt should resolve as well-known root"
        );

        // Check OID is correct (2.1 = joint-iso-ccitt.1)
        let module_id = ctx.get_module_id_by_name("TEST-MIB").unwrap();
        if let Some(node_id) = ctx.lookup_node_for_module(module_id, "testObject")
            && let Some(node) = ctx.model.get_node(node_id)
        {
            let oid = ctx.model.get_oid(node);
            assert_eq!(oid.arcs(), &[2, 1]);
        }
    }
}
