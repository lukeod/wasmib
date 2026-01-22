//! Resolution context (indices and working state during resolution).
//!
//! # Memory Optimization
//!
//! This module uses `Box<str>` keys instead of `String` keys in `BTreeMaps`.
//! `Box<str>` is 16 bytes vs ~24+ bytes for String, reducing memory when
//! processing large MIB corpora with hundreds of thousands of symbols.

use crate::module::Module;

/// Check if a type name is an ASN.1 primitive that doesn't require explicit import.
///
/// These are the fundamental ASN.1 types that MIBs use directly without importing.
fn is_asn1_primitive(name: &str) -> bool {
    matches!(
        name,
        "INTEGER" | "OCTET STRING" | "OBJECT IDENTIFIER" | "BITS"
    )
}

/// Check if a type name is a common SMI base type that should be globally accessible.
///
/// Many MIBs use these types without explicitly importing them from SNMPv2-SMI.
/// For leniency, we allow these to be resolved globally.
fn is_smi_global_type(name: &str) -> bool {
    matches!(
        name,
        "Integer32"
            | "Counter32"
            | "Counter64"
            | "Gauge32"
            | "Unsigned32"
            | "TimeTicks"
            | "IpAddress"
            | "Opaque"
    )
}
use crate::lexer::Span;
use crate::model::{
    Model, ModuleId, NodeId, TypeId, UnresolvedImport, UnresolvedImportReason,
    UnresolvedNotificationObject, UnresolvedOid, UnresolvedType,
};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

/// Resolution context holding indices and state during resolution.
pub struct ResolverContext {
    /// The model being built.
    pub model: Model,
    /// HIR modules being resolved.
    pub hir_modules: Vec<Module>,
    /// Module name -> list of `ModuleIds` (handles duplicate module names).
    /// Multiple files may declare the same MODULE-IDENTITY name.
    /// Uses `Box<str>` keys for memory efficiency.
    pub module_index: BTreeMap<Box<str>, Vec<ModuleId>>,
    /// `ModuleId` -> index in `hir_modules` for reverse lookup.
    pub module_id_to_hir_index: BTreeMap<ModuleId, usize>,
    /// Index in `hir_modules` -> `ModuleId` (reverse of `module_id_to_hir_index`).
    pub hir_index_to_module_id: BTreeMap<usize, ModuleId>,
    /// Per-module symbol -> `NodeId` mapping for module-local definitions.
    /// Key: (`ModuleId`, `symbol_name`) -> `NodeId` (uses `ModuleId` for uniqueness)
    /// Uses `Box<str>` for symbol names for memory efficiency.
    pub module_symbol_to_node: BTreeMap<(ModuleId, Box<str>), NodeId>,
    /// Import declarations: (`ModuleId`, symbol) -> source `ModuleId`
    /// Used for dynamic lookup during OID resolution.
    /// Tracks which specific module was chosen for each import.
    /// Uses `Box<str>` for symbol names for memory efficiency.
    pub module_imports: BTreeMap<(ModuleId, Box<str>), ModuleId>,
    /// Per-module symbol -> `TypeId` mapping for module-local type definitions.
    /// Key: (`ModuleId`, `type_name`) -> `TypeId`
    /// Uses `Box<str>` for type names for memory efficiency.
    pub module_symbol_to_type: BTreeMap<(ModuleId, Box<str>), TypeId>,
    /// The `ModuleId` for SNMPv2-SMI, used for ASN.1 primitive lookup.
    /// Set during registration phase when synthetic modules are registered.
    pub snmpv2_smi_module_id: Option<ModuleId>,
}

impl ResolverContext {
    /// Create a new resolver context.
    pub fn new(hir_modules: Vec<Module>) -> Self {
        Self {
            model: Model::new(),
            hir_modules,
            module_index: BTreeMap::new(),
            module_id_to_hir_index: BTreeMap::new(),
            hir_index_to_module_id: BTreeMap::new(),
            module_symbol_to_node: BTreeMap::new(),
            module_imports: BTreeMap::new(),
            module_symbol_to_type: BTreeMap::new(),
            snmpv2_smi_module_id: None,
        }
    }

    /// Get the `ModuleId` for an HIR module index.
    /// Returns None if the index is not registered (shouldn't happen after registration phase).
    pub fn get_module_id_for_hir_index(&self, hir_index: usize) -> Option<ModuleId> {
        self.hir_index_to_module_id.get(&hir_index).copied()
    }

    /// Get the first `ModuleId` for a module name.
    /// Convenience method for tests and simple cases where only one module has the name.
    #[allow(dead_code)]
    pub fn get_module_id_by_name(&self, name: &str) -> Option<ModuleId> {
        self.module_index.get(name)?.first().copied()
    }

    /// Look up a node by symbol name in a specific module's scope (by `ModuleId`).
    /// Order: 1) module-local definitions, 2) imports (iteratively following import chain).
    /// Cycle-safe: returns None if a cyclic import chain is detected.
    pub fn lookup_node_for_module(&self, module_id: ModuleId, name: &str) -> Option<NodeId> {
        let mut visited = BTreeSet::new();
        let mut current = module_id;
        // Box the name once for repeated lookups in the loop
        let name_key: Box<str> = name.into();

        loop {
            // Cycle detection: if we've seen this module before, stop
            if !visited.insert(current) {
                return None;
            }

            // Check module-local definitions
            if let Some(&node_id) = self.module_symbol_to_node.get(&(current, name_key.clone())) {
                return Some(node_id);
            }

            // Check imports - continue to source module
            if let Some(&source_module_id) = self.module_imports.get(&(current, name_key.clone())) {
                current = source_module_id;
                continue;
            }

            // No more imports to follow
            return None;
        }
    }

    /// Look up a node by symbol name in a module identified by name.
    /// If multiple modules have the same name, tries all candidates.
    /// Order: 1) module-local definitions, 2) imports (following import chain).
    /// Cycle-safe: cyclic imports are detected and handled gracefully.
    pub fn lookup_node_in_module(&self, module_name: &str, name: &str) -> Option<NodeId> {
        // Get all modules with this name
        if let Some(candidates) = self.module_index.get(module_name) {
            // Try each candidate
            for &module_id in candidates {
                if let Some(node_id) = self.lookup_node_for_module(module_id, name) {
                    return Some(node_id);
                }
            }
        }

        // No fallback to builtins - they must be explicitly imported
        None
    }

    /// Register an import declaration for later dynamic lookup.
    pub fn register_import(
        &mut self,
        importing_module: ModuleId,
        symbol: Box<str>,
        source_module: ModuleId,
    ) {
        self.module_imports
            .insert((importing_module, symbol), source_module);
    }

    /// Get the HIR module for a `ModuleId`.
    pub fn get_hir_module(&self, module_id: ModuleId) -> Option<&Module> {
        self.module_id_to_hir_index
            .get(&module_id)
            .and_then(|&idx| self.hir_modules.get(idx))
    }

    /// Look up a node by symbol name from the SNMPv2-SMI module (used in tests).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn lookup_node(&self, name: &str) -> Option<NodeId> {
        self.lookup_node_in_module("SNMPv2-SMI", name)
    }

    /// Look up a type by symbol name in the SNMPv2-SMI module.
    /// Used for primitive type lookup (INTEGER, OCTET STRING, etc.)
    pub fn lookup_type(&self, name: &str) -> Option<TypeId> {
        // First try SNMPv2-SMI for primitives
        if let Some(snmpv2_smi_id) = self.snmpv2_smi_module_id
            && let Some(type_id) = self.lookup_type_for_module(snmpv2_smi_id, name)
        {
            return Some(type_id);
        }

        // For non-primitives, search all modules
        // This is used for convenience (tests, simple lookups)
        for &type_id in self.module_symbol_to_type.values() {
            if let Some(typ) = self.model.get_type(type_id)
                && typ.name.as_ref() == name
            {
                return Some(type_id);
            }
        }

        None
    }

    /// Look up a type by symbol name in a specific module's scope.
    /// Order: 1) module-local types, 2) imports (following import chain), 3) global fallback.
    /// Cycle-safe: returns None if a cyclic import chain is detected.
    pub fn lookup_type_for_module(&self, module_id: ModuleId, name: &str) -> Option<TypeId> {
        let mut visited = BTreeSet::new();
        let mut current = module_id;
        // Box the name once for repeated lookups in the loop
        let name_key: Box<str> = name.into();

        loop {
            // Cycle detection: if we've seen this module before, stop
            if !visited.insert(current) {
                break;
            }

            // Check module-local type definitions
            if let Some(&type_id) = self.module_symbol_to_type.get(&(current, name_key.clone())) {
                return Some(type_id);
            }

            // Check imports - continue to source module
            if let Some(&source_module_id) = self.module_imports.get(&(current, name_key.clone())) {
                current = source_module_id;
                continue;
            }

            // No more imports to follow
            break;
        }

        // ASN.1 primitives: implicit access without explicit import
        // Check if this is a primitive (INTEGER, OCTET STRING, OBJECT IDENTIFIER, BITS)
        // and look it up in SNMPv2-SMI
        if let Some(snmpv2_smi_id) = self.snmpv2_smi_module_id {
            if is_asn1_primitive(name) {
                return self
                    .module_symbol_to_type
                    .get(&(snmpv2_smi_id, name_key.clone()))
                    .copied();
            }

            // SMI global types: implicit access for common base types
            // Many MIBs use Integer32, Counter32, etc. without explicit import.
            // For leniency, we fall back to SNMPv2-SMI for these types.
            if is_smi_global_type(name) {
                return self
                    .module_symbol_to_type
                    .get(&(snmpv2_smi_id, name_key))
                    .copied();
            }
        }

        None
    }

    /// Register a module-scoped symbol -> node mapping.
    pub fn register_module_node_symbol(
        &mut self,
        module_id: ModuleId,
        symbol_name: Box<str>,
        node_id: NodeId,
    ) {
        self.module_symbol_to_node
            .insert((module_id, symbol_name), node_id);
    }

    /// Register a module-scoped symbol -> type mapping.
    pub fn register_module_type_symbol(
        &mut self,
        module_id: ModuleId,
        name: Box<str>,
        type_id: TypeId,
    ) {
        self.module_symbol_to_type
            .insert((module_id, name), type_id);
    }

    /// Record an unresolved import with its failure reason.
    pub fn record_unresolved_import(
        &mut self,
        importing_module: ModuleId,
        from_module: &str,
        symbol: &str,
        reason: UnresolvedImportReason,
        span: Span,
    ) {
        self.model.unresolved_mut().imports.push(UnresolvedImport {
            importing_module,
            from_module: from_module.into(),
            symbol: symbol.into(),
            reason,
            span,
        });
    }

    /// Record an unresolved type.
    pub fn record_unresolved_type(
        &mut self,
        module: ModuleId,
        referrer: &str,
        referenced: &str,
        span: Span,
    ) {
        self.model.unresolved_mut().types.push(UnresolvedType {
            module,
            referrer: referrer.into(),
            referenced: referenced.into(),
            span,
        });
    }

    /// Record an unresolved OID component.
    pub fn record_unresolved_oid(
        &mut self,
        module: ModuleId,
        definition: &str,
        component: &str,
        span: Span,
    ) {
        self.model.unresolved_mut().oids.push(UnresolvedOid {
            module,
            definition: definition.into(),
            component: component.into(),
            span,
        });
    }

    /// Record an unresolved notification object reference.
    pub fn record_unresolved_notification_object(
        &mut self,
        module: ModuleId,
        notification: &str,
        object: &str,
        span: Span,
    ) {
        self.model
            .unresolved_mut()
            .notification_objects
            .push(UnresolvedNotificationObject {
                module,
                notification: notification.into(),
                object: object.into(),
                span,
            });
    }

    /// Drop HIR modules to free memory.
    ///
    /// After semantic analysis completes, the HIR modules are no longer needed.
    /// Calling this method frees the HIR data, reducing peak memory by
    /// preventing HIR and Model from coexisting at full size.
    ///
    /// The associated index maps are also cleared since they reference
    /// indices into the now-empty `hir_modules` vector.
    pub fn drop_hir(&mut self) {
        // Replace with empty vec to deallocate
        self.hir_modules = alloc::vec::Vec::new();
        // Clear associated indices that reference hir_modules
        self.module_id_to_hir_index.clear();
        self.hir_index_to_module_id.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Span;
    use crate::model::{OidNode, ResolvedModule};
    use crate::module::{Module, Symbol};

    fn make_test_module(name: &str) -> Module {
        Module::new(Symbol::from_name(name), Span::SYNTHETIC)
    }

    #[test]
    fn test_lookup_node_for_module_detects_cycle() {
        // Create a context with modules that have cyclic imports:
        // Module A imports "foo" from Module B
        // Module B imports "foo" from Module A
        let hir_modules = vec![make_test_module("ModuleA"), make_test_module("ModuleB")];
        let mut ctx = ResolverContext::new(hir_modules);

        // Register modules (IDs assigned by add_module)
        let module_a = ctx
            .model
            .add_module(ResolvedModule::new("ModuleA".into()))
            .expect("add_module should succeed");
        let module_b = ctx
            .model
            .add_module(ResolvedModule::new("ModuleB".into()))
            .expect("add_module should succeed");

        // Set up cyclic imports: A imports "foo" from B, B imports "foo" from A
        ctx.register_import(module_a, "foo".into(), module_b);
        ctx.register_import(module_b, "foo".into(), module_a);

        // This should return None (cycle detected) instead of infinite recursion
        let result = ctx.lookup_node_for_module(module_a, "foo");
        assert!(
            result.is_none(),
            "Should return None on cyclic import, not infinite loop"
        );
    }

    #[test]
    fn test_lookup_node_for_module_follows_valid_chain() {
        // Create a context where A imports "foo" from B, and B defines "foo"
        let hir_modules = vec![make_test_module("ModuleA"), make_test_module("ModuleB")];
        let mut ctx = ResolverContext::new(hir_modules);

        // Register modules (IDs assigned by add_module)
        let module_a = ctx
            .model
            .add_module(ResolvedModule::new("ModuleA".into()))
            .expect("add_module should succeed");
        let module_b = ctx
            .model
            .add_module(ResolvedModule::new("ModuleB".into()))
            .expect("add_module should succeed");

        // Create a node in module B - OidNode::new takes (subid, parent)
        let node = OidNode::new(1, None);
        let node_id = ctx.model.add_node(node).expect("add_node should succeed");
        ctx.register_module_node_symbol(module_b, "foo".into(), node_id);

        // A imports "foo" from B
        ctx.register_import(module_a, "foo".into(), module_b);

        // Looking up "foo" in module A should find it via the import chain
        let result = ctx.lookup_node_for_module(module_a, "foo");
        assert_eq!(result, Some(node_id));
    }

    #[test]
    #[allow(clippy::similar_names)] // node_a_id/node_b_id are intentionally similar
    fn test_lookup_node_for_module_local_takes_precedence() {
        // Create a context where A has local "foo" and also imports "foo" from B
        // Local should take precedence
        let hir_modules = vec![make_test_module("ModuleA"), make_test_module("ModuleB")];
        let mut ctx = ResolverContext::new(hir_modules);

        // Register modules (IDs assigned by add_module)
        let module_a = ctx
            .model
            .add_module(ResolvedModule::new("ModuleA".into()))
            .expect("add_module should succeed");
        let module_b = ctx
            .model
            .add_module(ResolvedModule::new("ModuleB".into()))
            .expect("add_module should succeed");

        // Create nodes in both modules
        let node_a = OidNode::new(1, None);
        let node_a_id = ctx.model.add_node(node_a).expect("add_node should succeed");
        ctx.register_module_node_symbol(module_a, "foo".into(), node_a_id);

        let node_b = OidNode::new(2, None);
        let node_b_id = ctx.model.add_node(node_b).expect("add_node should succeed");
        ctx.register_module_node_symbol(module_b, "foo".into(), node_b_id);

        // A also imports "foo" from B (should be ignored since local exists)
        ctx.register_import(module_a, "foo".into(), module_b);

        // Looking up "foo" in module A should find the local one
        let result = ctx.lookup_node_for_module(module_a, "foo");
        assert_eq!(result, Some(node_a_id));
    }

    #[test]
    fn test_lookup_node_for_module_longer_chain() {
        // A imports from B, B imports from C, C defines "foo"
        let hir_modules = vec![
            make_test_module("ModuleA"),
            make_test_module("ModuleB"),
            make_test_module("ModuleC"),
        ];
        let mut ctx = ResolverContext::new(hir_modules);

        let module_a = ctx
            .model
            .add_module(ResolvedModule::new("ModuleA".into()))
            .expect("add_module should succeed");
        let module_b = ctx
            .model
            .add_module(ResolvedModule::new("ModuleB".into()))
            .expect("add_module should succeed");
        let module_c = ctx
            .model
            .add_module(ResolvedModule::new("ModuleC".into()))
            .expect("add_module should succeed");

        // Create node in C
        let node = OidNode::new(1, None);
        let node_id = ctx.model.add_node(node).expect("add_node should succeed");
        ctx.register_module_node_symbol(module_c, "foo".into(), node_id);

        // A -> B -> C import chain
        ctx.register_import(module_a, "foo".into(), module_b);
        ctx.register_import(module_b, "foo".into(), module_c);

        // Looking up "foo" in A should follow the chain to C
        let result = ctx.lookup_node_for_module(module_a, "foo");
        assert_eq!(result, Some(node_id));
    }
}
