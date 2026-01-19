//! OID tree node types.

use super::ids::{ModuleId, NodeId, NotificationId, ObjectId, StrId};
use alloc::vec::Vec;

/// Node kind inferred from definition context.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum NodeKind {
    /// Internal node (no definition, just OID path).
    #[default]
    Internal,
    /// OBJECT-IDENTITY, MODULE-IDENTITY, or value assignment.
    Node,
    /// OBJECT-TYPE not in a table.
    Scalar,
    /// SYNTAX is SEQUENCE OF.
    Table,
    /// Has INDEX or AUGMENTS clause.
    Row,
    /// Parent is Row (column object).
    Column,
    /// NOTIFICATION-TYPE or TRAP-TYPE.
    Notification,
    /// OBJECT-GROUP or NOTIFICATION-GROUP.
    Group,
    /// MODULE-COMPLIANCE.
    Compliance,
    /// AGENT-CAPABILITIES.
    Capabilities,
}

impl NodeKind {
    /// Check if this is an OBJECT-TYPE kind.
    #[must_use]
    pub fn is_object_type(&self) -> bool {
        matches!(self, Self::Scalar | Self::Table | Self::Row | Self::Column)
    }

    /// Check if this is a conformance kind.
    #[must_use]
    pub fn is_conformance(&self) -> bool {
        matches!(self, Self::Group | Self::Compliance | Self::Capabilities)
    }
}

/// A node in the OID tree.
#[derive(Clone, Debug)]
pub struct OidNode {
    /// The arc (subidentifier) at this position.
    pub subid: u32,
    /// Parent node, if any.
    pub parent: Option<NodeId>,
    /// Child nodes.
    pub children: Vec<NodeId>,
    /// Inferred node kind.
    pub kind: NodeKind,
    /// Definitions at this OID (may be from multiple modules).
    pub definitions: Vec<NodeDefinition>,
}

impl OidNode {
    /// Create a new internal node.
    #[must_use]
    pub fn new(subid: u32, parent: Option<NodeId>) -> Self {
        Self {
            subid,
            parent,
            children: Vec::new(),
            kind: NodeKind::Internal,
            definitions: Vec::new(),
        }
    }

    /// Get the primary definition (first one).
    #[must_use]
    pub fn primary_definition(&self) -> Option<&NodeDefinition> {
        self.definitions.first()
    }

    /// Get the label from the primary definition.
    #[must_use]
    pub fn label(&self) -> Option<StrId> {
        self.primary_definition().map(|d| d.label)
    }

    /// Check if this node has any definitions.
    #[must_use]
    pub fn has_definition(&self) -> bool {
        !self.definitions.is_empty()
    }

    /// Check if this is a leaf node.
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Add a child node.
    pub fn add_child(&mut self, child: NodeId) {
        self.children.push(child);
    }

    /// Add a definition.
    pub fn add_definition(&mut self, def: NodeDefinition) {
        self.definitions.push(def);
    }
}

/// A single definition at an OID.
#[derive(Clone, Debug)]
pub struct NodeDefinition {
    /// Module where this definition appears.
    pub module: ModuleId,
    /// Object name/label.
    pub label: StrId,
    /// Associated object (for OBJECT-TYPE).
    pub object: Option<ObjectId>,
    /// Associated notification (for NOTIFICATION-TYPE/TRAP-TYPE).
    pub notification: Option<NotificationId>,
}

impl NodeDefinition {
    /// Create a new node definition.
    #[must_use]
    pub fn new(module: ModuleId, label: StrId) -> Self {
        Self {
            module,
            label,
            object: None,
            notification: None,
        }
    }

    /// Create a node definition with an object.
    #[must_use]
    pub fn with_object(module: ModuleId, label: StrId, object: ObjectId) -> Self {
        Self {
            module,
            label,
            object: Some(object),
            notification: None,
        }
    }

    /// Create a node definition with a notification.
    #[must_use]
    pub fn with_notification(module: ModuleId, label: StrId, notification: NotificationId) -> Self {
        Self {
            module,
            label,
            object: None,
            notification: Some(notification),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_kind_is_object_type() {
        assert!(NodeKind::Scalar.is_object_type());
        assert!(NodeKind::Table.is_object_type());
        assert!(NodeKind::Row.is_object_type());
        assert!(NodeKind::Column.is_object_type());
        assert!(!NodeKind::Node.is_object_type());
        assert!(!NodeKind::Notification.is_object_type());
    }

    #[test]
    fn test_node_kind_is_conformance() {
        assert!(NodeKind::Group.is_conformance());
        assert!(NodeKind::Compliance.is_conformance());
        assert!(NodeKind::Capabilities.is_conformance());
        assert!(!NodeKind::Scalar.is_conformance());
    }

    #[test]
    fn test_oid_node_new() {
        let parent = NodeId::from_raw(1).unwrap();
        let node = OidNode::new(42, Some(parent));

        assert_eq!(node.subid, 42);
        assert_eq!(node.parent, Some(parent));
        assert!(node.children.is_empty());
        assert_eq!(node.kind, NodeKind::Internal);
        assert!(node.definitions.is_empty());
    }

    #[test]
    fn test_node_add_child() {
        let mut node = OidNode::new(1, None);
        let child = NodeId::from_raw(2).unwrap();

        node.add_child(child);
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.children[0], child);
    }
}
