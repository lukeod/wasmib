//! Object definition types for the resolved model.

use super::ids::{ModuleId, NodeId, ObjectId, StrId, TypeId};
use super::types::{Access, BitDefinitions, EnumValues, Status};
use alloc::vec::Vec;

/// An item in an INDEX clause.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IndexItem {
    /// The index object node.
    pub object: NodeId,
    /// Whether this index is IMPLIED.
    pub implied: bool,
}

impl IndexItem {
    /// Create a new index item.
    #[must_use]
    pub fn new(object: NodeId, implied: bool) -> Self {
        Self { object, implied }
    }
}

/// Index specification for a row object.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IndexSpec {
    /// Index items.
    pub items: Vec<IndexItem>,
}

impl IndexSpec {
    /// Create a new index specification.
    #[must_use]
    pub fn new(items: Vec<IndexItem>) -> Self {
        Self { items }
    }

    /// Check if any index is implied.
    #[must_use]
    pub fn has_implied(&self) -> bool {
        self.items.iter().any(|i| i.implied)
    }
}

/// A resolved OBJECT-TYPE definition.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResolvedObject {
    /// Object identifier.
    pub id: ObjectId,
    /// Node in OID tree.
    pub node: NodeId,
    /// Defining module.
    pub module: ModuleId,
    /// Object name.
    pub name: StrId,
    /// Resolved type (None if type reference couldn't be resolved).
    pub type_id: Option<TypeId>,
    /// Inline enumeration values (not from type).
    pub inline_enum: Option<EnumValues>,
    /// Inline BITS values (not from type).
    pub inline_bits: Option<BitDefinitions>,
    /// Access level.
    pub access: Access,
    /// Definition status.
    pub status: Status,
    /// Description text.
    pub description: Option<StrId>,
    /// Units string.
    pub units: Option<StrId>,
    /// Index specification (for row objects).
    pub index: Option<IndexSpec>,
    /// AUGMENTS target (for row objects).
    pub augments: Option<NodeId>,
    /// Reference text.
    pub reference: Option<StrId>,
}

/// Placeholder ID used before entity is added to the model.
/// This value is always overwritten by Model::add_object().
const UNASSIGNED_OBJECT_ID: ObjectId = match ObjectId::from_raw(1) {
    Some(id) => id,
    None => unreachable!(),
};

impl ResolvedObject {
    /// Create a new resolved object.
    ///
    /// The `id` field is initialized to a placeholder and will be assigned
    /// by `Model::add_object()` when the object is added to the model.
    #[must_use]
    pub fn new(
        node: NodeId,
        module: ModuleId,
        name: StrId,
        type_id: Option<TypeId>,
        access: Access,
    ) -> Self {
        Self {
            id: UNASSIGNED_OBJECT_ID,
            node,
            module,
            name,
            type_id,
            inline_enum: None,
            inline_bits: None,
            access,
            status: Status::Current,
            description: None,
            units: None,
            index: None,
            augments: None,
            reference: None,
        }
    }

    /// Check if this object has an INDEX clause.
    #[must_use]
    pub fn has_index(&self) -> bool {
        self.index.is_some()
    }

    /// Check if this object has an AUGMENTS clause.
    #[must_use]
    pub fn has_augments(&self) -> bool {
        self.augments.is_some()
    }
}

/// A resolved NOTIFICATION-TYPE or TRAP-TYPE definition.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResolvedNotification {
    /// Notification identifier.
    pub id: super::ids::NotificationId,
    /// Node in OID tree.
    pub node: NodeId,
    /// Defining module.
    pub module: ModuleId,
    /// Notification name.
    pub name: StrId,
    /// Objects included in the notification.
    pub objects: Vec<NodeId>,
    /// Definition status.
    pub status: Status,
    /// Description text.
    pub description: Option<StrId>,
    /// Reference text.
    pub reference: Option<StrId>,
}

/// Placeholder ID used before entity is added to the model.
/// This value is always overwritten by Model::add_notification().
const UNASSIGNED_NOTIFICATION_ID: super::ids::NotificationId =
    match super::ids::NotificationId::from_raw(1) {
        Some(id) => id,
        None => unreachable!(),
    };

impl ResolvedNotification {
    /// Create a new resolved notification.
    ///
    /// The `id` field is initialized to a placeholder and will be assigned
    /// by `Model::add_notification()` when the notification is added to the model.
    #[must_use]
    pub fn new(node: NodeId, module: ModuleId, name: StrId) -> Self {
        Self {
            id: UNASSIGNED_NOTIFICATION_ID,
            node,
            module,
            name,
            objects: Vec::new(),
            status: Status::Current,
            description: None,
            reference: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_item() {
        let node = NodeId::from_raw(1).unwrap();
        let item = IndexItem::new(node, true);

        assert_eq!(item.object, node);
        assert!(item.implied);
    }

    #[test]
    fn test_index_spec_has_implied() {
        let node1 = NodeId::from_raw(1).unwrap();
        let node2 = NodeId::from_raw(2).unwrap();

        let spec1 = IndexSpec::new(vec![IndexItem::new(node1, false)]);
        assert!(!spec1.has_implied());

        let spec2 = IndexSpec::new(vec![IndexItem::new(node1, false), IndexItem::new(node2, true)]);
        assert!(spec2.has_implied());
    }
}
