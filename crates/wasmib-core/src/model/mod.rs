//! Resolved MIB model.
//!
//! The Model is the final resolved representation of MIB data. It sits at the
//! end of the pipeline:
//!
//! ```text
//! Source → Lexer → Parser → AST → HIR → Resolver → [Model]
//! ```
//!
//! # Features
//!
//! - Arena-based storage with stable index IDs
//! - Global string interner for identifiers, descriptions, etc.
//! - OID tree with multiple definitions per OID
//! - Fast lookups by OID, name, Module::Name
//! - Resolved type chains and inheritance
//!
//! # Usage
//!
//! ```ignore
//! let result = resolver.resolve(hir_modules);
//! let model = result.model;
//!
//! // Look up by OID
//! if let Some(node) = model.get_node_by_oid_str("1.3.6.1.2.1.1.1") {
//!     println!("Found: {:?}", node.label());
//! }
//!
//! // Walk the tree
//! for root in model.roots() {
//!     model.walk(root.id, &mut |node| {
//!         println!("{}", model.get_oid(node));
//!         true // continue
//!     });
//! }
//! ```

mod ids;
mod interner;
mod module;
mod node;
mod object;
mod oid;
mod types;

pub use ids::{ModuleId, NodeId, NotificationId, ObjectId, StrId, TypeId};
pub use interner::StringInterner;
pub use module::{ResolvedModule, Revision};
pub use node::{NodeDefinition, NodeKind, OidNode};
pub use object::{DefVal, IndexItem, IndexSpec, ResolvedNotification, ResolvedObject};
pub use oid::Oid;
pub use types::{
    Access, BaseType, BitDefinitions, EnumValues, RangeBound, ResolvedType, SizeConstraint, Status,
    ValueConstraint,
};

use crate::lexer::Span;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Unresolved reference tracking.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnresolvedReferences {
    /// Unresolved imports.
    pub imports: Vec<UnresolvedImport>,
    /// Unresolved type references.
    pub types: Vec<UnresolvedType>,
    /// Unresolved OID components.
    pub oids: Vec<UnresolvedOid>,
    /// Unresolved index objects.
    pub indexes: Vec<UnresolvedIndex>,
}

impl UnresolvedReferences {
    /// Check if there are no unresolved references.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.imports.is_empty()
            && self.types.is_empty()
            && self.oids.is_empty()
            && self.indexes.is_empty()
    }

    /// Get the total count of unresolved references.
    #[must_use]
    pub fn count(&self) -> usize {
        self.imports.len() + self.types.len() + self.oids.len() + self.indexes.len()
    }
}

/// An unresolved import.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnresolvedImport {
    /// Module requesting the import.
    pub importing_module: ModuleId,
    /// Module being imported from.
    pub from_module: StrId,
    /// Symbol being imported.
    pub symbol: StrId,
    /// Source location of the import.
    pub span: Span,
}

/// An unresolved type reference.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnresolvedType {
    /// Module containing the reference.
    pub module: ModuleId,
    /// Definition referencing the type.
    pub referrer: StrId,
    /// Type being referenced.
    pub referenced: StrId,
    /// Source location of the type reference.
    pub span: Span,
}

/// An unresolved OID component.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnresolvedOid {
    /// Module containing the definition.
    pub module: ModuleId,
    /// Definition with the OID.
    pub definition: StrId,
    /// Unresolved component name.
    pub component: StrId,
    /// Source location of the OID reference.
    pub span: Span,
}

/// An unresolved index object.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnresolvedIndex {
    /// Module containing the row.
    pub module: ModuleId,
    /// Row definition name.
    pub row: StrId,
    /// Unresolved index object name.
    pub index_object: StrId,
    /// Source location of the index reference.
    pub span: Span,
}

/// Error returned when model storage capacity is exceeded.
///
/// The model uses `NonZeroU32` IDs, limiting each collection to `u32::MAX - 1` items.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityError {
    /// The kind of storage that exceeded capacity.
    pub kind: CapacityErrorKind,
}

/// The kind of storage that exceeded capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityErrorKind {
    /// Too many modules (limit: u32::MAX - 1).
    Modules,
    /// Too many OID nodes (limit: u32::MAX - 1).
    Nodes,
    /// Too many types (limit: u32::MAX - 1).
    Types,
    /// Too many objects (limit: u32::MAX - 1).
    Objects,
    /// Too many notifications (limit: u32::MAX - 1).
    Notifications,
}

impl core::fmt::Display for CapacityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = match self.kind {
            CapacityErrorKind::Modules => "modules",
            CapacityErrorKind::Nodes => "nodes",
            CapacityErrorKind::Types => "types",
            CapacityErrorKind::Objects => "objects",
            CapacityErrorKind::Notifications => "notifications",
        };
        write!(f, "model capacity exceeded: too many {} (limit: {})", kind, u32::MAX - 1)
    }
}

/// Decomposed model for serialization.
///
/// This struct contains all data needed to reconstruct a Model.
/// It exposes internal storage directly for efficient serialization.
/// Lookup indices are rebuilt on load from `from_parts()`.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ModelParts {
    /// String interner data (concatenated strings).
    pub strings_data: String,
    /// String interner offsets.
    pub strings_offsets: Vec<u32>,
    /// All resolved modules.
    pub modules: Vec<ResolvedModule>,
    /// All OID tree nodes.
    pub nodes: Vec<OidNode>,
    /// All resolved types.
    pub types: Vec<ResolvedType>,
    /// All resolved objects.
    pub objects: Vec<ResolvedObject>,
    /// All resolved notifications.
    pub notifications: Vec<ResolvedNotification>,
    /// Root node IDs.
    pub roots: Vec<NodeId>,
    /// Unresolved references.
    pub unresolved: UnresolvedReferences,
}

/// The resolved MIB model.
#[derive(Clone, Debug)]
pub struct Model {
    // Storage
    strings: StringInterner,
    modules: Vec<ResolvedModule>,
    nodes: Vec<OidNode>,
    types: Vec<ResolvedType>,
    objects: Vec<ResolvedObject>,
    notifications: Vec<ResolvedNotification>,

    // Lookup indices (rebuilt on load)
    oid_to_node: BTreeMap<Oid, NodeId>,
    module_name_to_id: BTreeMap<StrId, ModuleId>,
    name_to_nodes: BTreeMap<StrId, Vec<NodeId>>,

    // Tree roots
    roots: Vec<NodeId>,

    // Partial resolution tracking
    unresolved: UnresolvedReferences,
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}

impl Model {
    /// Create a new empty model.
    #[must_use]
    pub fn new() -> Self {
        Self {
            strings: StringInterner::new(),
            modules: Vec::new(),
            nodes: Vec::new(),
            types: Vec::new(),
            objects: Vec::new(),
            notifications: Vec::new(),
            oid_to_node: BTreeMap::new(),
            module_name_to_id: BTreeMap::new(),
            name_to_nodes: BTreeMap::new(),
            roots: Vec::new(),
            unresolved: UnresolvedReferences::default(),
        }
    }

    // === String Operations ===

    /// Intern a string and return its ID.
    pub fn intern(&mut self, s: &str) -> StrId {
        self.strings.intern(s)
    }

    /// Get a string by its ID.
    #[must_use]
    pub fn get_str(&self, id: StrId) -> &str {
        self.strings.get(id)
    }

    /// Get the string interner.
    #[must_use]
    pub fn strings(&self) -> &StringInterner {
        &self.strings
    }

    // === Module Operations ===

    /// Add a module and return its ID.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityError`] if the model already contains `u32::MAX - 1` modules.
    /// 
    pub fn add_module(&mut self, mut module: ResolvedModule) -> Result<ModuleId, CapacityError> {
        let id = ModuleId::from_index(self.modules.len())
            .ok_or(CapacityError { kind: CapacityErrorKind::Modules })?;
        module.id = id;
        self.module_name_to_id.insert(module.name, id);
        self.modules.push(module);
        Ok(id)
    }

    /// Get a module by ID.
    #[must_use]
    pub fn get_module(&self, id: ModuleId) -> Option<&ResolvedModule> {
        self.modules.get(id.to_index())
    }

    /// Get a mutable reference to a module by ID.
    pub fn get_module_mut(&mut self, id: ModuleId) -> Option<&mut ResolvedModule> {
        self.modules.get_mut(id.to_index())
    }

    /// Get a module by name.
    ///
    /// Uses the module name index for O(log n) lookup.
    #[must_use]
    pub fn get_module_by_name(&self, name: &str) -> Option<&ResolvedModule> {
        let str_id = self.strings.find(name)?;
        let module_id = self.module_name_to_id.get(&str_id)?;
        self.get_module(*module_id)
    }

    /// Iterate over all modules.
    pub fn modules(&self) -> impl Iterator<Item = &ResolvedModule> {
        self.modules.iter()
    }

    /// Get the number of modules.
    #[must_use]
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    // === Node Operations ===

    /// Add a node and return its ID.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityError`] if the model already contains `u32::MAX - 1` nodes.
    /// 
    pub fn add_node(&mut self, node: OidNode) -> Result<NodeId, CapacityError> {
        let id = NodeId::from_index(self.nodes.len())
            .ok_or(CapacityError { kind: CapacityErrorKind::Nodes })?;
        self.nodes.push(node);
        Ok(id)
    }

    /// Get a node by ID.
    #[must_use]
    pub fn get_node(&self, id: NodeId) -> Option<&OidNode> {
        self.nodes.get(id.to_index())
    }

    /// Get a mutable reference to a node by ID.
    pub fn get_node_mut(&mut self, id: NodeId) -> Option<&mut OidNode> {
        self.nodes.get_mut(id.to_index())
    }

    /// Get a node by OID.
    #[must_use]
    pub fn get_node_by_oid(&self, oid: &Oid) -> Option<&OidNode> {
        self.oid_to_node.get(oid).and_then(|id| self.get_node(*id))
    }

    /// Get a node ID by OID.
    #[must_use]
    pub fn get_node_id_by_oid(&self, oid: &Oid) -> Option<NodeId> {
        self.oid_to_node.get(oid).copied()
    }

    /// Get a node by dotted OID string.
    #[must_use]
    pub fn get_node_by_oid_str(&self, oid: &str) -> Option<&OidNode> {
        Oid::from_dotted(oid).and_then(|o| self.get_node_by_oid(&o))
    }

    /// Get all nodes with a given name.
    /// Uses the name index for O(1) lookup after finding the StrId.
    pub fn get_nodes_by_name(&self, name: &str) -> Vec<&OidNode> {
        let Some(str_id) = self.strings.find(name) else {
            return Vec::new();
        };
        self.name_to_nodes
            .get(&str_id)
            .map(|ids| ids.iter().filter_map(|id| self.get_node(*id)).collect())
            .unwrap_or_default()
    }

    /// Get a node by module-qualified name.
    /// Uses the name index for faster lookup.
    #[must_use]
    pub fn get_node_by_qualified_name(&self, module: &str, name: &str) -> Option<&OidNode> {
        let module_id = self.get_module_by_name(module)?.id;
        let str_id = self.strings.find(name)?;

        if let Some(node_ids) = self.name_to_nodes.get(&str_id) {
            for &node_id in node_ids {
                if let Some(node) = self.get_node(node_id) {
                    for def in &node.definitions {
                        if def.module == module_id {
                            return Some(node);
                        }
                    }
                }
            }
        }
        None
    }

    /// Add a root node.
    pub fn add_root(&mut self, node_id: NodeId) {
        self.roots.push(node_id);
    }

    /// Iterate over root nodes.
    pub fn roots(&self) -> impl Iterator<Item = &OidNode> {
        self.roots.iter().filter_map(|id| self.get_node(*id))
    }

    /// Get root node IDs.
    #[must_use]
    pub fn root_ids(&self) -> &[NodeId] {
        &self.roots
    }

    /// Get children of a node.
    pub fn children(&self, node: &OidNode) -> Vec<&OidNode> {
        node.children
            .iter()
            .filter_map(|id| self.get_node(*id))
            .collect()
    }

    /// Get parent of a node.
    #[must_use]
    pub fn parent(&self, node: &OidNode) -> Option<&OidNode> {
        node.parent.and_then(|id| self.get_node(id))
    }

    /// Walk the tree starting from a node, calling visitor for each node.
    /// Returns false if visitor returned false (early termination).
    pub fn walk<F>(&self, start: NodeId, visitor: &mut F) -> bool
    where
        F: FnMut(&OidNode) -> bool,
    {
        let Some(node) = self.get_node(start) else {
            return true;
        };
        if !visitor(node) {
            return false;
        }
        for child_id in &node.children {
            if !self.walk(*child_id, visitor) {
                return false;
            }
        }
        true
    }

    /// Compute the full OID for a node.
    #[must_use]
    pub fn get_oid(&self, node: &OidNode) -> Oid {
        let mut arcs = Vec::new();
        self.collect_arcs(node, &mut arcs);
        arcs.reverse();
        Oid::new(arcs)
    }

    fn collect_arcs(&self, node: &OidNode, arcs: &mut Vec<u32>) {
        arcs.push(node.subid);
        if let Some(parent) = node.parent.and_then(|id| self.get_node(id)) {
            self.collect_arcs(parent, arcs);
        }
    }

    /// Register an OID-to-node mapping.
    pub fn register_oid(&mut self, oid: Oid, node_id: NodeId) {
        self.oid_to_node.insert(oid, node_id);
    }

    /// Get the number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    // === Type Operations ===

    /// Add a type and return its ID.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityError`] if the model already contains `u32::MAX - 1` types.
    /// 
    pub fn add_type(&mut self, mut typ: ResolvedType) -> Result<TypeId, CapacityError> {
        let id = TypeId::from_index(self.types.len())
            .ok_or(CapacityError { kind: CapacityErrorKind::Types })?;
        typ.id = id;
        self.types.push(typ);
        Ok(id)
    }

    /// Get a type by ID.
    #[must_use]
    pub fn get_type(&self, id: TypeId) -> Option<&ResolvedType> {
        self.types.get(id.to_index())
    }

    /// Get a mutable reference to a type by ID.
    pub fn get_type_mut(&mut self, id: TypeId) -> Option<&mut ResolvedType> {
        self.types.get_mut(id.to_index())
    }

    /// Get the type inheritance chain.
    pub fn get_type_chain(&self, id: TypeId) -> Vec<&ResolvedType> {
        let mut chain = Vec::new();
        let mut current = Some(id);
        while let Some(type_id) = current {
            if let Some(typ) = self.get_type(type_id) {
                chain.push(typ);
                current = typ.parent_type;
            } else {
                break;
            }
        }
        chain
    }

    /// Get the effective display hint by walking the type chain.
    #[must_use]
    pub fn get_effective_hint(&self, id: TypeId) -> Option<StrId> {
        for typ in self.get_type_chain(id) {
            if typ.hint.is_some() {
                return typ.hint;
            }
        }
        None
    }

    /// Get the number of types.
    #[must_use]
    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    // === Object Operations ===

    /// Add an object and return its ID.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityError`] if the model already contains `u32::MAX - 1` objects.
    /// 
    pub fn add_object(&mut self, mut obj: ResolvedObject) -> Result<ObjectId, CapacityError> {
        let id = ObjectId::from_index(self.objects.len())
            .ok_or(CapacityError { kind: CapacityErrorKind::Objects })?;
        obj.id = id;
        self.objects.push(obj);
        Ok(id)
    }

    /// Get an object by ID.
    #[must_use]
    pub fn get_object(&self, id: ObjectId) -> Option<&ResolvedObject> {
        self.objects.get(id.to_index())
    }

    /// Get the number of objects.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    // === Notification Operations ===

    /// Add a notification and return its ID.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityError`] if the model already contains `u32::MAX - 1` notifications.
    /// 
    pub fn add_notification(&mut self, mut notif: ResolvedNotification) -> Result<NotificationId, CapacityError> {
        let id = NotificationId::from_index(self.notifications.len())
            .ok_or(CapacityError { kind: CapacityErrorKind::Notifications })?;
        notif.id = id;
        self.notifications.push(notif);
        Ok(id)
    }

    /// Get a notification by ID.
    #[must_use]
    pub fn get_notification(&self, id: NotificationId) -> Option<&ResolvedNotification> {
        self.notifications.get(id.to_index())
    }

    /// Get the number of notifications.
    #[must_use]
    pub fn notification_count(&self) -> usize {
        self.notifications.len()
    }

    // === Status ===

    /// Check if resolution is complete (no unresolved references).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unresolved.is_empty()
    }

    /// Get unresolved references.
    #[must_use]
    pub fn unresolved(&self) -> &UnresolvedReferences {
        &self.unresolved
    }

    /// Get mutable unresolved references.
    pub fn unresolved_mut(&mut self) -> &mut UnresolvedReferences {
        &mut self.unresolved
    }

    // === Serialization ===

    /// Decompose the model into parts for serialization.
    /// Indices are not serialized; they are rebuilt on load.
    #[must_use]
    pub fn into_parts(self) -> ModelParts {
        let (strings_data, strings_offsets) = self.strings.into_parts();
        ModelParts {
            strings_data,
            strings_offsets,
            modules: self.modules,
            nodes: self.nodes,
            types: self.types,
            objects: self.objects,
            notifications: self.notifications,
            roots: self.roots,
            unresolved: self.unresolved,
        }
    }

    /// Reconstruct a model from serialized parts.
    /// Rebuilds all lookup indices from raw data.
    #[must_use]
    pub fn from_parts(parts: ModelParts) -> Self {
        let mut model = Self {
            strings: StringInterner::from_parts(parts.strings_data, parts.strings_offsets),
            modules: parts.modules,
            nodes: parts.nodes,
            types: parts.types,
            objects: parts.objects,
            notifications: parts.notifications,
            oid_to_node: BTreeMap::new(),
            module_name_to_id: BTreeMap::new(),
            name_to_nodes: BTreeMap::new(),
            roots: parts.roots,
            unresolved: parts.unresolved,
        };
        model.rebuild_indices();
        model
    }

    /// Rebuild all lookup indices from raw data.
    /// Called after deserialization.
    fn rebuild_indices(&mut self) {
        self.oid_to_node.clear();
        self.module_name_to_id.clear();
        self.name_to_nodes.clear();

        // Module name index
        for (idx, module) in self.modules.iter().enumerate() {
            if let Some(id) = ModuleId::from_index(idx) {
                self.module_name_to_id.insert(module.name, id);
            }
        }

        // Name-to-nodes index and OID-to-node index
        for idx in 0..self.nodes.len() {
            let Some(node_id) = NodeId::from_index(idx) else {
                continue;
            };
            let Some(node) = self.nodes.get(idx) else {
                continue;
            };

            // Add to name index
            for def in &node.definitions {
                self.name_to_nodes
                    .entry(def.label)
                    .or_default()
                    .push(node_id);
            }

            // Compute and register OID
            let oid = self.compute_oid_for_index(idx);
            self.oid_to_node.insert(oid, node_id);
        }
    }

    /// Compute OID for a node by index (avoids borrow issues during rebuild).
    fn compute_oid_for_index(&self, idx: usize) -> Oid {
        let mut arcs = Vec::new();
        let mut current_idx = Some(idx);

        while let Some(i) = current_idx {
            if let Some(node) = self.nodes.get(i) {
                arcs.push(node.subid);
                current_idx = node.parent.map(|id| id.to_index());
            } else {
                break;
            }
        }

        arcs.reverse();
        Oid::new(arcs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_new() {
        let model = Model::new();
        assert_eq!(model.module_count(), 0);
        assert_eq!(model.node_count(), 0);
        assert!(model.is_complete());
    }

    #[test]
    fn test_intern_and_get_str() {
        let mut model = Model::new();
        let id = model.intern("hello");
        assert_eq!(model.get_str(id), "hello");
    }

    #[test]
    fn test_add_module() {
        let mut model = Model::new();
        let name = model.intern("IF-MIB");
        let module = ResolvedModule::new(name);

        let id = model.add_module(module).unwrap();
        assert_eq!(model.module_count(), 1);
        assert!(model.get_module(id).is_some());
    }

    #[test]
    fn test_get_module_by_name() {
        let mut model = Model::new();
        let name = model.intern("IF-MIB");
        let module = ResolvedModule::new(name);

        model.add_module(module).unwrap();
        assert!(model.get_module_by_name("IF-MIB").is_some());
        assert!(model.get_module_by_name("NOT-EXIST").is_none());
    }

    #[test]
    fn test_add_node() {
        let mut model = Model::new();
        let node = OidNode::new(1, None);

        let id = model.add_node(node).unwrap();
        assert_eq!(model.node_count(), 1);
        assert!(model.get_node(id).is_some());
    }

    #[test]
    fn test_register_and_get_oid() {
        let mut model = Model::new();
        let node = OidNode::new(1, None);
        let id = model.add_node(node).unwrap();

        let oid = Oid::new(vec![1]);
        model.register_oid(oid.clone(), id);

        assert!(model.get_node_by_oid(&oid).is_some());
        assert!(model.get_node_by_oid_str("1").is_some());
    }

    #[test]
    fn test_unresolved_empty() {
        let unresolved = UnresolvedReferences::default();
        assert!(unresolved.is_empty());
        assert_eq!(unresolved.count(), 0);
    }
}
