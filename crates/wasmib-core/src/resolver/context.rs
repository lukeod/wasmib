//! Resolution context (indices and working state during resolution).

use crate::hir::HirModule;
use crate::lexer::Span;
use crate::model::{
    Model, ModuleId, NodeId, StrId, TypeId, UnresolvedImport, UnresolvedOid, UnresolvedType,
};
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::string::String;

/// Resolution context holding indices and state during resolution.
pub struct ResolverContext {
    /// The model being built.
    pub model: Model,
    /// HIR modules being resolved.
    pub hir_modules: Vec<HirModule>,
    /// Module name -> list of ModuleIds (handles duplicate module names).
    /// Multiple files may declare the same MODULE-IDENTITY name.
    pub module_index: BTreeMap<String, Vec<ModuleId>>,
    /// ModuleId -> index in hir_modules for reverse lookup.
    pub module_id_to_hir_index: BTreeMap<ModuleId, usize>,
    /// Per-module symbol -> NodeId mapping for module-local definitions.
    /// Key: (ModuleId, symbol_name) -> NodeId (uses ModuleId for uniqueness)
    pub module_symbol_to_node: BTreeMap<(ModuleId, String), NodeId>,
    /// Import declarations: (ModuleId, symbol) -> source ModuleId
    /// Used for dynamic lookup during OID resolution.
    /// Tracks which specific module was chosen for each import.
    pub module_imports: BTreeMap<(ModuleId, String), ModuleId>,
    /// Symbol name -> TypeId mapping for type resolution.
    pub symbol_to_type: BTreeMap<String, TypeId>,
}

impl ResolverContext {
    /// Create a new resolver context.
    pub fn new(hir_modules: Vec<HirModule>) -> Self {
        Self {
            model: Model::new(),
            hir_modules,
            module_index: BTreeMap::new(),
            module_id_to_hir_index: BTreeMap::new(),
            module_symbol_to_node: BTreeMap::new(),
            module_imports: BTreeMap::new(),
            symbol_to_type: BTreeMap::new(),
        }
    }

    /// Intern a string in the model.
    pub fn intern(&mut self, s: &str) -> StrId {
        self.model.intern(s)
    }

    /// Look up a node by symbol name in a specific module's scope (by ModuleId).
    /// Order: 1) module-local definitions, 2) imports (iteratively following import chain).
    /// Cycle-safe: returns None if a cyclic import chain is detected.
    pub fn lookup_node_for_module(&self, module_id: ModuleId, name: &str) -> Option<NodeId> {
        let mut visited = BTreeSet::new();
        let mut current = module_id;
        // Convert name to String once, clone per iteration (avoids 2 allocations per iteration)
        let name_owned = name.to_string();

        loop {
            // Cycle detection: if we've seen this module before, stop
            if !visited.insert(current) {
                return None;
            }

            // Create key once per iteration for both lookups
            let key = (current, name_owned.clone());

            // Check module-local definitions
            if let Some(&node_id) = self.module_symbol_to_node.get(&key) {
                return Some(node_id);
            }

            // Check imports - continue to source module
            if let Some(&source_module_id) = self.module_imports.get(&key) {
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
    pub fn register_import(&mut self, importing_module: ModuleId, symbol: String, source_module: ModuleId) {
        self.module_imports.insert((importing_module, symbol), source_module);
    }

    /// Get the HIR module for a ModuleId.
    pub fn get_hir_module(&self, module_id: ModuleId) -> Option<&HirModule> {
        self.module_id_to_hir_index.get(&module_id)
            .and_then(|&idx| self.hir_modules.get(idx))
    }

    /// Look up a node by symbol name from the SNMPv2-SMI module (used in tests).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn lookup_node(&self, name: &str) -> Option<NodeId> {
        self.lookup_node_in_module("SNMPv2-SMI", name)
    }

    /// Look up a type by symbol name.
    pub fn lookup_type(&self, name: &str) -> Option<TypeId> {
        self.symbol_to_type.get(name).copied()
    }

    /// Register a module-scoped symbol -> node mapping.
    pub fn register_module_node_symbol(&mut self, module_id: ModuleId, symbol_name: String, node_id: NodeId) {
        self.module_symbol_to_node.insert((module_id, symbol_name), node_id);
    }

    /// Register a symbol -> type mapping.
    pub fn register_type_symbol(&mut self, name: String, type_id: TypeId) {
        self.symbol_to_type.insert(name, type_id);
    }

    /// Record an unresolved import.
    pub fn record_unresolved_import(
        &mut self,
        importing_module: ModuleId,
        from_module: &str,
        symbol: &str,
        span: Span,
    ) {
        let from_module_str = self.intern(from_module);
        let symbol_str = self.intern(symbol);
        self.model.unresolved_mut().imports.push(UnresolvedImport {
            importing_module,
            from_module: from_module_str,
            symbol: symbol_str,
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
        let referrer_str = self.intern(referrer);
        let referenced_str = self.intern(referenced);
        self.model.unresolved_mut().types.push(UnresolvedType {
            module,
            referrer: referrer_str,
            referenced: referenced_str,
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
        let def_str = self.intern(definition);
        let comp_str = self.intern(component);
        self.model.unresolved_mut().oids.push(UnresolvedOid {
            module,
            definition: def_str,
            component: comp_str,
            span,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{HirModule, Symbol};
    use crate::lexer::Span;
    use crate::model::{OidNode, ResolvedModule};

    fn make_test_module(name: &str) -> HirModule {
        HirModule::new(Symbol::from_str(name), Span::SYNTHETIC)
    }

    #[test]
    fn test_lookup_node_for_module_detects_cycle() {
        // Create a context with modules that have cyclic imports:
        // Module A imports "foo" from Module B
        // Module B imports "foo" from Module A
        let hir_modules = vec![
            make_test_module("ModuleA"),
            make_test_module("ModuleB"),
        ];
        let mut ctx = ResolverContext::new(hir_modules);

        // Register modules (IDs assigned by add_module)
        let name_a = ctx.intern("ModuleA");
        let name_b = ctx.intern("ModuleB");
        let module_a = ctx.model.add_module(ResolvedModule::new(name_a)).unwrap();
        let module_b = ctx.model.add_module(ResolvedModule::new(name_b)).unwrap();

        // Set up cyclic imports: A imports "foo" from B, B imports "foo" from A
        ctx.register_import(module_a, "foo".into(), module_b);
        ctx.register_import(module_b, "foo".into(), module_a);

        // This should return None (cycle detected) instead of infinite recursion
        let result = ctx.lookup_node_for_module(module_a, "foo");
        assert!(result.is_none(), "Should return None on cyclic import, not infinite loop");
    }

    #[test]
    fn test_lookup_node_for_module_follows_valid_chain() {
        // Create a context where A imports "foo" from B, and B defines "foo"
        let hir_modules = vec![
            make_test_module("ModuleA"),
            make_test_module("ModuleB"),
        ];
        let mut ctx = ResolverContext::new(hir_modules);

        // Register modules (IDs assigned by add_module)
        let name_a = ctx.intern("ModuleA");
        let name_b = ctx.intern("ModuleB");
        let module_a = ctx.model.add_module(ResolvedModule::new(name_a)).unwrap();
        let module_b = ctx.model.add_module(ResolvedModule::new(name_b)).unwrap();

        // Create a node in module B - OidNode::new takes (subid, parent)
        let node = OidNode::new(1, None);
        let node_id = ctx.model.add_node(node).unwrap();
        ctx.register_module_node_symbol(module_b, "foo".into(), node_id);

        // A imports "foo" from B
        ctx.register_import(module_a, "foo".into(), module_b);

        // Looking up "foo" in module A should find it via the import chain
        let result = ctx.lookup_node_for_module(module_a, "foo");
        assert_eq!(result, Some(node_id));
    }

    #[test]
    fn test_lookup_node_for_module_local_takes_precedence() {
        // Create a context where A has local "foo" and also imports "foo" from B
        // Local should take precedence
        let hir_modules = vec![
            make_test_module("ModuleA"),
            make_test_module("ModuleB"),
        ];
        let mut ctx = ResolverContext::new(hir_modules);

        // Register modules (IDs assigned by add_module)
        let name_a = ctx.intern("ModuleA");
        let name_b = ctx.intern("ModuleB");
        let module_a = ctx.model.add_module(ResolvedModule::new(name_a)).unwrap();
        let module_b = ctx.model.add_module(ResolvedModule::new(name_b)).unwrap();

        // Create nodes in both modules
        let node_a = OidNode::new(1, None);
        let node_a_id = ctx.model.add_node(node_a).unwrap();
        ctx.register_module_node_symbol(module_a, "foo".into(), node_a_id);

        let node_b = OidNode::new(2, None);
        let node_b_id = ctx.model.add_node(node_b).unwrap();
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

        let name_a = ctx.intern("ModuleA");
        let name_b = ctx.intern("ModuleB");
        let name_c = ctx.intern("ModuleC");
        let module_a = ctx.model.add_module(ResolvedModule::new(name_a)).unwrap();
        let module_b = ctx.model.add_module(ResolvedModule::new(name_b)).unwrap();
        let module_c = ctx.model.add_module(ResolvedModule::new(name_c)).unwrap();

        // Create node in C
        let node = OidNode::new(1, None);
        let node_id = ctx.model.add_node(node).unwrap();
        ctx.register_module_node_symbol(module_c, "foo".into(), node_id);

        // A -> B -> C import chain
        ctx.register_import(module_a, "foo".into(), module_b);
        ctx.register_import(module_b, "foo".into(), module_c);

        // Looking up "foo" in A should follow the chain to C
        let result = ctx.lookup_node_for_module(module_a, "foo");
        assert_eq!(result, Some(node_id));
    }
}
