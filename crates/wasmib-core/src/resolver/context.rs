//! Resolution context (indices and working state during resolution).

use crate::hir::{HirModule, Symbol};
use crate::model::{
    Model, ModuleId, NodeId, StrId, TypeId, UnresolvedImport, UnresolvedOid, UnresolvedType,
};
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::string::String;

/// Reference to a definition (user-defined).
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct DefinitionRef {
    /// Module containing the definition.
    pub module: ModuleId,
    /// Index of the definition in the module.
    pub def_index: usize,
}

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
    /// (module_name, symbol_name) -> DefinitionRef mapping.
    pub definition_index: BTreeMap<(String, String), DefinitionRef>,
    /// Per-module symbol -> NodeId mapping for module-local definitions.
    /// Key: (ModuleId, symbol_name) -> NodeId (uses ModuleId for uniqueness)
    pub module_symbol_to_node: BTreeMap<(ModuleId, String), NodeId>,
    /// Import declarations: (ModuleId, symbol) -> source ModuleId
    /// Used for dynamic lookup during OID resolution.
    /// Tracks which specific module was chosen for each import.
    pub module_imports: BTreeMap<(ModuleId, String), ModuleId>,
    /// Symbol name -> TypeId mapping for type resolution.
    pub symbol_to_type: BTreeMap<String, TypeId>,
    /// Global OID roots (iso, zeroDotZero) - nodes without parents.
    /// Used for anchoring the OID tree.
    #[allow(dead_code)]
    pub global_roots: BTreeSet<NodeId>,
}

impl ResolverContext {
    /// Create a new resolver context.
    pub fn new(hir_modules: Vec<HirModule>) -> Self {
        Self {
            model: Model::new(),
            hir_modules,
            module_index: BTreeMap::new(),
            module_id_to_hir_index: BTreeMap::new(),
            definition_index: BTreeMap::new(),
            module_symbol_to_node: BTreeMap::new(),
            module_imports: BTreeMap::new(),
            symbol_to_type: BTreeMap::new(),
            global_roots: BTreeSet::new(),
        }
    }

    /// Intern a string in the model.
    pub fn intern(&mut self, s: &str) -> StrId {
        self.model.intern(s)
    }

    /// Intern a Symbol.
    #[allow(dead_code)]
    pub fn intern_symbol(&mut self, sym: &Symbol) -> StrId {
        self.model.intern(&sym.name)
    }

    /// Look up a definition by module and symbol name.
    #[allow(dead_code)]
    pub fn lookup_definition(&self, module: &str, symbol: &str) -> Option<DefinitionRef> {
        self.definition_index
            .get(&(module.into(), symbol.into()))
            .copied()
    }

    /// Look up a node by symbol name in a specific module's scope (by ModuleId).
    /// Order: 1) module-local definitions, 2) imports (recursive), 3) built-ins.
    pub fn lookup_node_for_module(&self, module_id: ModuleId, name: &str) -> Option<NodeId> {
        // Check module-local definitions
        if let Some(node_id) = self.module_symbol_to_node
            .get(&(module_id, name.to_string()))
            .copied()
        {
            return Some(node_id);
        }

        // Check imports - look up in the source module
        if let Some(&source_module_id) = self.module_imports
            .get(&(module_id, name.to_string()))
        {
            // Recursively look up in the source module
            return self.lookup_node_for_module(source_module_id, name);
        }

        // No fallback to builtins - they must be explicitly imported
        None
    }

    /// Look up a node by symbol name in a module identified by name.
    /// If multiple modules have the same name, tries all candidates.
    /// Order: 1) module-local definitions, 2) imports (recursive).
    /// Built-ins must be explicitly imported.
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

    /// Add a global root node.
    #[allow(dead_code)]
    pub fn add_global_root(&mut self, node_id: NodeId) {
        self.global_roots.insert(node_id);
        self.model.add_root(node_id);
    }

    /// Record an unresolved import.
    pub fn record_unresolved_import(
        &mut self,
        importing_module: ModuleId,
        from_module: &str,
        symbol: &str,
    ) {
        let from_module_str = self.intern(from_module);
        let symbol_str = self.intern(symbol);
        self.model.unresolved_mut().imports.push(UnresolvedImport {
            importing_module,
            from_module: from_module_str,
            symbol: symbol_str,
        });
    }

    /// Record an unresolved type.
    pub fn record_unresolved_type(
        &mut self,
        module: ModuleId,
        referrer: &str,
        referenced: &str,
    ) {
        let referrer_str = self.intern(referrer);
        let referenced_str = self.intern(referenced);
        self.model.unresolved_mut().types.push(UnresolvedType {
            module,
            referrer: referrer_str,
            referenced: referenced_str,
        });
    }

    /// Record an unresolved OID component.
    pub fn record_unresolved_oid(
        &mut self,
        module: ModuleId,
        definition: &str,
        component: &str,
    ) {
        let def_str = self.intern(definition);
        let comp_str = self.intern(component);
        self.model.unresolved_mut().oids.push(UnresolvedOid {
            module,
            definition: def_str,
            component: comp_str,
        });
    }
}
