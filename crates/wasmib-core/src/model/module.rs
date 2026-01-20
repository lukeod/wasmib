//! Module definition types for the resolved model.

use super::ids::{ModuleId, NodeId, NotificationId, ObjectId, StrId, TypeId};
use alloc::vec::Vec;

/// A revision entry in a module.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Revision {
    /// Revision date string.
    pub date: StrId,
    /// Revision description.
    pub description: StrId,
}

impl Revision {
    /// Create a new revision.
    #[must_use]
    pub fn new(date: StrId, description: StrId) -> Self {
        Self { date, description }
    }
}

/// A resolved MIB module.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResolvedModule {
    /// Module identifier.
    pub id: ModuleId,
    /// Module name.
    pub name: StrId,
    /// LAST-UPDATED value.
    pub last_updated: Option<StrId>,
    /// ORGANIZATION value.
    pub organization: Option<StrId>,
    /// CONTACT-INFO value.
    pub contact_info: Option<StrId>,
    /// Description text.
    pub description: Option<StrId>,
    /// Revision history.
    pub revisions: Vec<Revision>,
    /// MODULE-IDENTITY node.
    pub identity_node: Option<NodeId>,
    /// All OID nodes from this module.
    pub nodes: Vec<NodeId>,
    /// All type definitions from this module.
    pub types: Vec<TypeId>,
    /// All object definitions from this module.
    pub objects: Vec<ObjectId>,
    /// All notification definitions from this module.
    pub notifications: Vec<NotificationId>,
}

impl ResolvedModule {
    /// Create a new resolved module.
    ///
    /// The `id` field is initialized to a placeholder and will be assigned
    /// by `Model::add_module()` when the module is added to the model.
    #[must_use]
    pub fn new(name: StrId) -> Self {
        Self {
            id: ModuleId::placeholder(),
            name,
            last_updated: None,
            organization: None,
            contact_info: None,
            description: None,
            revisions: Vec::new(),
            identity_node: None,
            nodes: Vec::new(),
            types: Vec::new(),
            objects: Vec::new(),
            notifications: Vec::new(),
        }
    }

    /// Add a node to this module.
    pub fn add_node(&mut self, node: NodeId) {
        self.nodes.push(node);
    }

    /// Add a type to this module.
    pub fn add_type(&mut self, type_id: TypeId) {
        self.types.push(type_id);
    }

    /// Add an object to this module.
    pub fn add_object(&mut self, object: ObjectId) {
        self.objects.push(object);
    }

    /// Add a notification to this module.
    pub fn add_notification(&mut self, notification: NotificationId) {
        self.notifications.push(notification);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolved_module_new() {
        let name = StrId::from_raw(1).unwrap();
        let module = ResolvedModule::new(name);

        // ID is a placeholder until added to model
        assert_eq!(module.id, ModuleId::placeholder());
        assert_eq!(module.name, name);
        assert!(module.nodes.is_empty());
        assert!(module.types.is_empty());
        assert!(module.objects.is_empty());
    }

    #[test]
    fn test_add_nodes() {
        let name = StrId::from_raw(1).unwrap();
        let mut module = ResolvedModule::new(name);

        let node1 = NodeId::from_raw(1).unwrap();
        let node2 = NodeId::from_raw(2).unwrap();

        module.add_node(node1);
        module.add_node(node2);

        assert_eq!(module.nodes.len(), 2);
    }
}
