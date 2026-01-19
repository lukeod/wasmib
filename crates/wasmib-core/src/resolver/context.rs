//! Resolution context (indices and working state during resolution).

use crate::hir::{HirModule, Symbol};
use crate::model::{
    Model, ModuleId, NodeId, Oid, OidNode, StrId, TypeId, UnresolvedImport, UnresolvedOid,
    UnresolvedType,
};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::builtins::{self, BuiltinSymbol, BUILTIN_OID_NODES};

/// Reference to a definition (either built-in or user-defined).
#[derive(Clone, Copy, Debug)]
pub enum DefinitionRef {
    /// A built-in symbol.
    Builtin(BuiltinRef),
    /// A user-defined definition.
    User {
        /// Module containing the definition.
        module: ModuleId,
        /// Index of the definition in the module.
        def_index: usize,
    },
}

/// Reference to a built-in symbol.
#[derive(Clone, Copy, Debug)]
pub enum BuiltinRef {
    /// Built-in base type.
    BaseType(super::builtins::BuiltinBaseType),
    /// Built-in textual convention (index into BUILTIN_TEXTUAL_CONVENTIONS).
    TextualConvention(usize),
    /// Built-in OID node (index into BUILTIN_OID_NODES).
    OidNode(usize),
    /// Built-in MACRO.
    Macro(super::builtins::BuiltinMacro),
}

/// Resolution context holding indices and state during resolution.
pub struct ResolverContext {
    /// The model being built.
    pub model: Model,
    /// HIR modules being resolved.
    pub hir_modules: Vec<HirModule>,
    /// Module name -> ModuleId mapping.
    pub module_index: BTreeMap<String, ModuleId>,
    /// (module_name, symbol_name) -> DefinitionRef mapping.
    pub definition_index: BTreeMap<(String, String), DefinitionRef>,
    /// Symbol name -> NodeId mapping for OID resolution.
    pub symbol_to_node: BTreeMap<String, NodeId>,
    /// Symbol name -> TypeId mapping for type resolution.
    pub symbol_to_type: BTreeMap<String, TypeId>,
    /// Built-in OID node index -> NodeId mapping.
    pub builtin_oid_to_node: BTreeMap<usize, NodeId>,
}

impl ResolverContext {
    /// Create a new resolver context.
    pub fn new(hir_modules: Vec<HirModule>) -> Self {
        Self {
            model: Model::new(),
            hir_modules,
            module_index: BTreeMap::new(),
            definition_index: BTreeMap::new(),
            symbol_to_node: BTreeMap::new(),
            symbol_to_type: BTreeMap::new(),
            builtin_oid_to_node: BTreeMap::new(),
        }
    }

    /// Intern a string in the model.
    pub fn intern(&mut self, s: &str) -> StrId {
        self.model.intern(s)
    }

    /// Intern a Symbol.
    pub fn intern_symbol(&mut self, sym: &Symbol) -> StrId {
        self.model.intern(&sym.name)
    }

    /// Look up a definition by module and symbol name.
    pub fn lookup_definition(&self, module: &str, symbol: &str) -> Option<DefinitionRef> {
        // Check user-defined first
        if let Some(def_ref) = self
            .definition_index
            .get(&(module.into(), symbol.into()))
        {
            return Some(*def_ref);
        }

        // Check built-ins
        if let Some(builtin) = builtins::resolve_builtin_symbol(module, symbol) {
            let builtin_ref = match builtin {
                BuiltinSymbol::BaseType(bt) => BuiltinRef::BaseType(bt),
                BuiltinSymbol::TextualConvention(tc) => {
                    // Find index of this TC
                    let idx = builtins::BUILTIN_TEXTUAL_CONVENTIONS
                        .iter()
                        .position(|t| t.name == tc.name)
                        .expect("TC not found");
                    BuiltinRef::TextualConvention(idx)
                }
                BuiltinSymbol::OidNode(idx) => BuiltinRef::OidNode(idx),
                BuiltinSymbol::Macro(m) => BuiltinRef::Macro(m),
            };
            return Some(DefinitionRef::Builtin(builtin_ref));
        }

        None
    }

    /// Look up a node by symbol name.
    pub fn lookup_node(&self, name: &str) -> Option<NodeId> {
        self.symbol_to_node.get(name).copied()
    }

    /// Look up a type by symbol name.
    pub fn lookup_type(&self, name: &str) -> Option<TypeId> {
        self.symbol_to_type.get(name).copied()
    }

    /// Register a symbol -> node mapping.
    pub fn register_node_symbol(&mut self, name: String, node_id: NodeId) {
        self.symbol_to_node.insert(name, node_id);
    }

    /// Register a symbol -> type mapping.
    pub fn register_type_symbol(&mut self, name: String, type_id: TypeId) {
        self.symbol_to_type.insert(name, type_id);
    }

    /// Seed the model with built-in OID nodes.
    pub fn seed_builtin_oids(&mut self) {
        // First pass: create all nodes
        let mut node_ids = Vec::with_capacity(BUILTIN_OID_NODES.len());

        for builtin in BUILTIN_OID_NODES.iter() {
            let node = OidNode::new(builtin.arc, None);
            let node_id = self.model.add_node(node);
            node_ids.push(node_id);
        }

        // Second pass: set up parent/child relationships and register
        for (idx, builtin) in BUILTIN_OID_NODES.iter().enumerate() {
            let node_id = node_ids[idx];

            // Set parent
            if let Some(parent_idx) = builtin.parent {
                let parent_id = node_ids[parent_idx];

                // Update child's parent
                if let Some(node) = self.model.get_node_mut(node_id) {
                    node.parent = Some(parent_id);
                }

                // Add to parent's children
                if let Some(parent) = self.model.get_node_mut(parent_id) {
                    parent.add_child(node_id);
                }
            } else {
                // This is a root node
                self.model.add_root(node_id);
            }

            // Register symbol -> node mapping
            self.symbol_to_node.insert(builtin.name.into(), node_id);
            self.builtin_oid_to_node.insert(idx, node_id);

            // Register OID -> node mapping
            let oid = Oid::new(builtin.numeric_oid(BUILTIN_OID_NODES));
            self.model.register_oid(oid, node_id);
        }
    }

    /// Get a built-in OID node's NodeId.
    pub fn get_builtin_oid_node(&self, idx: usize) -> Option<NodeId> {
        self.builtin_oid_to_node.get(&idx).copied()
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
