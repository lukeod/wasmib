//! FFI serialization layer for cross-language model export.
//!
//! This module provides serialization types that map the internal `Model` to a format
//! suitable for cross-language deserialization via postcard.
//!
//! # Design Principles
//!
//! 1. **Flat structures** - No nested references, use indices instead
//! 2. **Compact enums** - Use u8 representation for enums
//! 3. **String table** - All strings are interned, referenced by u32 ID
//! 4. **Versioned** - Schema version in envelope for forward compatibility
//! 5. **Self-contained** - Indices can be rebuilt from serialized data

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use wasmib_core::model::{
    DefVal, IndexItem, Model, OidNode, ResolvedModule, ResolvedNotification, ResolvedObject,
    ResolvedType, Revision, StringInterner,
};

/// Current schema version. Bump on any breaking change to serialized format.
pub const SCHEMA_VERSION: u32 = 1;

/// Root serialization envelope for FFI export.
///
/// This is the format exported to host languages (Go, etc.) for native querying.
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedModel {
    /// Schema version for forward compatibility.
    pub version: u32,

    /// Optional fingerprint of source MIB files (for cache validation).
    pub fingerprint: Option<[u8; 32]>,

    /// Concatenated string data.
    pub strings_data: String,

    /// Offsets into strings_data for each StrId (1-indexed in Model).
    /// `strings_offsets[i]` = `(start, end)` for `StrId(i+1)`.
    pub strings_offsets: Vec<(u32, u32)>,

    /// Resolved modules.
    pub modules: Vec<SerializedModule>,

    /// OID tree nodes.
    pub nodes: Vec<SerializedNode>,

    /// Type definitions.
    pub types: Vec<SerializedType>,

    /// Object definitions.
    pub objects: Vec<SerializedObject>,

    /// Notification definitions.
    pub notifications: Vec<SerializedNotification>,

    /// Root node IDs (typically iso=1).
    pub roots: Vec<u32>,

    /// Unresolved reference counts (for diagnostics).
    pub unresolved_imports: u32,
    pub unresolved_types: u32,
    pub unresolved_oids: u32,
    pub unresolved_indexes: u32,
    pub unresolved_notification_objects: u32,
}

/// Serialized module definition.
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedModule {
    /// Module name (StrId).
    pub name: u32,
    /// LAST-UPDATED value (StrId, 0 = none).
    pub last_updated: u32,
    /// CONTACT-INFO value (StrId, 0 = none).
    pub contact_info: u32,
    /// ORGANIZATION value (StrId, 0 = none).
    pub organization: u32,
    /// Description text (StrId, 0 = none).
    pub description: u32,
    /// Revision history.
    pub revisions: Vec<SerializedRevision>,
}

/// Serialized revision entry.
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedRevision {
    /// Revision date (StrId).
    pub date: u32,
    /// Revision description (StrId).
    pub description: u32,
}

/// Serialized OID tree node.
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedNode {
    /// The arc (subidentifier) at this position.
    pub subid: u32,
    /// Parent node (NodeId, 0 = none/root).
    pub parent: u32,
    /// Child nodes (Vec<NodeId>).
    pub children: Vec<u32>,
    /// Node kind as u8.
    pub kind: u8,
    /// Definitions at this OID.
    pub definitions: Vec<SerializedNodeDef>,
}

/// Serialized node definition.
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedNodeDef {
    /// Module where this definition appears (ModuleId).
    pub module: u32,
    /// Object name/label (StrId).
    pub label: u32,
    /// Associated object (ObjectId, 0 = none).
    pub object: u32,
    /// Associated notification (NotificationId, 0 = none).
    pub notification: u32,
}

/// Serialized object definition.
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedObject {
    /// Node in OID tree (NodeId).
    pub node: u32,
    /// Defining module (ModuleId).
    pub module: u32,
    /// Object name (StrId).
    pub name: u32,
    /// Resolved type (TypeId, 0 = unresolved).
    pub type_id: u32,
    /// Access level as u8.
    pub access: u8,
    /// Definition status as u8.
    pub status: u8,
    /// Description text (StrId, 0 = none).
    pub description: u32,
    /// Units string (StrId, 0 = none).
    pub units: u32,
    /// Reference text (StrId, 0 = none).
    pub reference: u32,
    /// Index specification (for row objects).
    pub index: Option<SerializedIndex>,
    /// AUGMENTS target (NodeId, 0 = none).
    pub augments: u32,
    /// Default value.
    pub defval: Option<SerializedDefVal>,
    /// Inline enumeration values (not from type).
    pub inline_enum: Option<Vec<(i64, u32)>>,
    /// Inline BITS values (not from type).
    pub inline_bits: Option<Vec<(u32, u32)>>,
}

/// Serialized index specification.
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedIndex {
    /// Index items.
    pub items: Vec<SerializedIndexItem>,
}

/// Serialized index item.
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedIndexItem {
    /// The index object node (NodeId).
    pub object: u32,
    /// Whether this index is IMPLIED.
    pub implied: bool,
}

/// Serialized default value.
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedDefVal {
    /// Kind: 0=Integer, 1=Unsigned, 2=String, 3=HexString, 4=BinaryString, 5=Enum, 6=Bits, 7=OidRef.
    pub kind: u8,
    /// Integer value (for kind 0).
    pub int_val: Option<i64>,
    /// Unsigned value (for kind 1).
    pub uint_val: Option<u64>,
    /// String ID (for kinds 2, 5, or unresolved OID symbol).
    pub str_val: Option<u32>,
    /// Raw string (for kinds 3, 4 - hex/binary strings).
    pub raw_str: Option<String>,
    /// Node ID (for kind 7 - resolved OID ref).
    pub node_val: Option<u32>,
    /// Bit names as StrIds (for kind 6).
    pub bits_val: Option<Vec<u32>>,
}

/// Serialized type definition.
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedType {
    /// Defining module (ModuleId).
    pub module: u32,
    /// Type name (StrId).
    pub name: u32,
    /// Base type as u8.
    pub base: u8,
    /// Parent type (TypeId, 0 = none, for TC inheritance).
    pub parent: u32,
    /// Definition status as u8.
    pub status: u8,
    /// Is this a textual convention?
    pub is_tc: bool,
    /// Display hint (StrId, 0 = none).
    pub hint: u32,
    /// Description text (StrId, 0 = none).
    pub description: u32,
    /// Size constraint.
    pub size: Option<SerializedConstraint>,
    /// Value range constraint.
    pub range: Option<SerializedConstraint>,
    /// Enumeration values: (value, StrId).
    pub enum_values: Option<Vec<(i64, u32)>>,
    /// Bit definitions: (position, StrId).
    pub bit_defs: Option<Vec<(u32, u32)>>,
}

/// Serialized constraint (for size or value ranges).
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedConstraint {
    /// (min, max) pairs for allowed values/sizes.
    /// For signed ranges, values are cast to i64.
    pub ranges: Vec<(i64, i64)>,
}

/// Serialized notification definition.
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedNotification {
    /// Node in OID tree (NodeId).
    pub node: u32,
    /// Defining module (ModuleId).
    pub module: u32,
    /// Notification name (StrId).
    pub name: u32,
    /// Definition status as u8.
    pub status: u8,
    /// Description text (StrId, 0 = none).
    pub description: u32,
    /// Reference text (StrId, 0 = none).
    pub reference: u32,
    /// Objects included in the notification (Vec<NodeId>).
    pub objects: Vec<u32>,
}

// === Conversion Functions ===

impl SerializedModel {
    /// Create a serialized model from a resolved Model.
    #[must_use]
    pub fn from_model(model: &Model, fingerprint: Option<[u8; 32]>) -> Self {
        // 1. Serialize string interner
        let (strings_data, strings_offsets) = serialize_strings(model.strings());

        // 2. Serialize modules
        let modules: Vec<_> = model.modules().map(serialize_module).collect();

        // 3. Serialize nodes
        let nodes: Vec<_> = (0..model.node_count())
            .filter_map(|i| {
                wasmib_core::model::NodeId::from_index(i)
                    .and_then(|id| model.get_node(id))
                    .map(serialize_node)
            })
            .collect();

        // 4. Serialize types
        let types: Vec<_> = (0..model.type_count())
            .filter_map(|i| {
                wasmib_core::model::TypeId::from_index(i)
                    .and_then(|id| model.get_type(id))
                    .map(serialize_type)
            })
            .collect();

        // 5. Serialize objects
        let objects: Vec<_> = (0..model.object_count())
            .filter_map(|i| {
                wasmib_core::model::ObjectId::from_index(i)
                    .and_then(|id| model.get_object(id))
                    .map(|obj| serialize_object(obj, model))
            })
            .collect();

        // 6. Serialize notifications
        let notifications: Vec<_> = (0..model.notification_count())
            .filter_map(|i| {
                wasmib_core::model::NotificationId::from_index(i)
                    .and_then(|id| model.get_notification(id))
                    .map(serialize_notification)
            })
            .collect();

        // 7. Get roots
        let roots: Vec<_> = model.root_ids().iter().map(|id| id.to_raw()).collect();

        // 8. Get unresolved counts
        let unresolved = model.unresolved();

        Self {
            version: SCHEMA_VERSION,
            fingerprint,
            strings_data,
            strings_offsets,
            modules,
            nodes,
            types,
            objects,
            notifications,
            roots,
            unresolved_imports: unresolved.imports.len() as u32,
            unresolved_types: unresolved.types.len() as u32,
            unresolved_oids: unresolved.oids.len() as u32,
            unresolved_indexes: unresolved.indexes.len() as u32,
            unresolved_notification_objects: unresolved.notification_objects.len() as u32,
        }
    }

    /// Serialize to postcard bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("serialization should not fail")
    }

    /// Deserialize from postcard bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

/// Serialize the string interner to (data, offsets).
fn serialize_strings(interner: &StringInterner) -> (String, Vec<(u32, u32)>) {
    let (data, offsets) = interner.export_parts();

    // Convert offsets to (start, end) pairs
    let offset_pairs: Vec<(u32, u32)> = if offsets.is_empty() {
        Vec::new()
    } else {
        offsets
            .windows(2)
            .map(|w| (w[0], w[1]))
            .chain(core::iter::once((
                *offsets.last().unwrap_or(&0),
                data.len() as u32,
            )))
            .collect()
    };

    (data, offset_pairs)
}

fn serialize_module(module: &ResolvedModule) -> SerializedModule {
    SerializedModule {
        name: module.name.to_raw(),
        last_updated: module.last_updated.map_or(0, |id| id.to_raw()),
        contact_info: module.contact_info.map_or(0, |id| id.to_raw()),
        organization: module.organization.map_or(0, |id| id.to_raw()),
        description: module.description.map_or(0, |id| id.to_raw()),
        revisions: module.revisions.iter().map(serialize_revision).collect(),
    }
}

fn serialize_revision(rev: &Revision) -> SerializedRevision {
    SerializedRevision {
        date: rev.date.to_raw(),
        description: rev.description.to_raw(),
    }
}

fn serialize_node(node: &OidNode) -> SerializedNode {
    SerializedNode {
        subid: node.subid,
        parent: node.parent.map_or(0, |id| id.to_raw()),
        children: node.children.iter().map(|id| id.to_raw()).collect(),
        kind: node.kind.as_u8(),
        definitions: node.definitions.iter().map(serialize_node_def).collect(),
    }
}

fn serialize_node_def(def: &wasmib_core::model::NodeDefinition) -> SerializedNodeDef {
    SerializedNodeDef {
        module: def.module.to_raw(),
        label: def.label.to_raw(),
        object: def.object.map_or(0, |id| id.to_raw()),
        notification: def.notification.map_or(0, |id| id.to_raw()),
    }
}

fn serialize_object(obj: &ResolvedObject, model: &Model) -> SerializedObject {
    SerializedObject {
        node: obj.node.to_raw(),
        module: obj.module.to_raw(),
        name: obj.name.to_raw(),
        type_id: obj.type_id.map_or(0, |id| id.to_raw()),
        access: obj.access.as_u8(),
        status: obj.status.as_u8(),
        description: obj.description.map_or(0, |id| id.to_raw()),
        units: obj.units.map_or(0, |id| id.to_raw()),
        reference: obj.reference.map_or(0, |id| id.to_raw()),
        index: obj.index.as_ref().map(serialize_index),
        augments: obj.augments.map_or(0, |id| id.to_raw()),
        defval: obj.defval.as_ref().map(|d| serialize_defval(d, model)),
        inline_enum: obj.inline_enum.as_ref().map(|e| {
            e.values
                .iter()
                .map(|(v, id)| (*v, id.to_raw()))
                .collect()
        }),
        inline_bits: obj.inline_bits.as_ref().map(|b| {
            b.bits
                .iter()
                .map(|(pos, id)| (*pos, id.to_raw()))
                .collect()
        }),
    }
}

fn serialize_index(index: &wasmib_core::model::IndexSpec) -> SerializedIndex {
    SerializedIndex {
        items: index.items.iter().map(serialize_index_item).collect(),
    }
}

fn serialize_index_item(item: &IndexItem) -> SerializedIndexItem {
    SerializedIndexItem {
        object: item.object.to_raw(),
        implied: item.implied,
    }
}

fn serialize_defval(defval: &DefVal, _model: &Model) -> SerializedDefVal {
    match defval {
        DefVal::Integer(v) => SerializedDefVal {
            kind: 0,
            int_val: Some(*v),
            uint_val: None,
            str_val: None,
            raw_str: None,
            node_val: None,
            bits_val: None,
        },
        DefVal::Unsigned(v) => SerializedDefVal {
            kind: 1,
            int_val: None,
            uint_val: Some(*v),
            str_val: None,
            raw_str: None,
            node_val: None,
            bits_val: None,
        },
        DefVal::String(id) => SerializedDefVal {
            kind: 2,
            int_val: None,
            uint_val: None,
            str_val: Some(id.to_raw()),
            raw_str: None,
            node_val: None,
            bits_val: None,
        },
        DefVal::HexString(s) => SerializedDefVal {
            kind: 3,
            int_val: None,
            uint_val: None,
            str_val: None,
            raw_str: Some(s.clone()),
            node_val: None,
            bits_val: None,
        },
        DefVal::BinaryString(s) => SerializedDefVal {
            kind: 4,
            int_val: None,
            uint_val: None,
            str_val: None,
            raw_str: Some(s.clone()),
            node_val: None,
            bits_val: None,
        },
        DefVal::Enum(id) => SerializedDefVal {
            kind: 5,
            int_val: None,
            uint_val: None,
            str_val: Some(id.to_raw()),
            raw_str: None,
            node_val: None,
            bits_val: None,
        },
        DefVal::Bits(ids) => SerializedDefVal {
            kind: 6,
            int_val: None,
            uint_val: None,
            str_val: None,
            raw_str: None,
            node_val: None,
            bits_val: Some(ids.iter().map(|id| id.to_raw()).collect()),
        },
        DefVal::OidRef { node, symbol } => SerializedDefVal {
            kind: 7,
            int_val: None,
            uint_val: None,
            str_val: symbol.map(|id| id.to_raw()),
            raw_str: None,
            node_val: node.map(|id| id.to_raw()),
            bits_val: None,
        },
    }
}

fn serialize_type(typ: &ResolvedType) -> SerializedType {
    SerializedType {
        module: typ.module.to_raw(),
        name: typ.name.to_raw(),
        base: typ.base.as_u8(),
        parent: typ.parent_type.map_or(0, |id| id.to_raw()),
        status: typ.status.as_u8(),
        is_tc: typ.is_textual_convention,
        hint: typ.hint.map_or(0, |id| id.to_raw()),
        description: typ.description.map_or(0, |id| id.to_raw()),
        size: typ.size.as_ref().map(serialize_size_constraint),
        range: typ.value_range.as_ref().map(serialize_value_constraint),
        enum_values: typ.enum_values.as_ref().map(|e| {
            e.values
                .iter()
                .map(|(v, id)| (*v, id.to_raw()))
                .collect()
        }),
        bit_defs: typ.bit_defs.as_ref().map(|b| {
            b.bits
                .iter()
                .map(|(pos, id)| (*pos, id.to_raw()))
                .collect()
        }),
    }
}

fn serialize_size_constraint(constraint: &wasmib_core::model::SizeConstraint) -> SerializedConstraint {
    SerializedConstraint {
        ranges: constraint
            .ranges
            .iter()
            .map(|(min, max)| (i64::from(*min), i64::from(*max)))
            .collect(),
    }
}

fn serialize_value_constraint(
    constraint: &wasmib_core::model::ValueConstraint,
) -> SerializedConstraint {
    SerializedConstraint {
        ranges: constraint
            .ranges
            .iter()
            .map(|(min, max)| (range_bound_to_i64(min), range_bound_to_i64(max)))
            .collect(),
    }
}

fn range_bound_to_i64(bound: &wasmib_core::model::RangeBound) -> i64 {
    match bound {
        wasmib_core::model::RangeBound::Signed(v) => *v,
        wasmib_core::model::RangeBound::Unsigned(v) => *v as i64,
    }
}

fn serialize_notification(notif: &ResolvedNotification) -> SerializedNotification {
    SerializedNotification {
        node: notif.node.to_raw(),
        module: notif.module.to_raw(),
        name: notif.name.to_raw(),
        status: notif.status.as_u8(),
        description: notif.description.map_or(0, |id| id.to_raw()),
        reference: notif.reference.map_or(0, |id| id.to_raw()),
        objects: notif.objects.iter().map(|id| id.to_raw()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmib_core::model::{Access, BaseType, Model, NodeKind, Status};

    #[test]
    fn test_serialize_empty_model() {
        let model = Model::new();
        let serialized = SerializedModel::from_model(&model, None);

        assert_eq!(serialized.version, SCHEMA_VERSION);
        assert!(serialized.fingerprint.is_none());
        assert!(serialized.modules.is_empty());
        assert!(serialized.nodes.is_empty());
        assert!(serialized.types.is_empty());
        assert!(serialized.objects.is_empty());
        assert!(serialized.notifications.is_empty());
        assert!(serialized.roots.is_empty());
    }

    #[test]
    fn test_serialize_with_fingerprint() {
        let model = Model::new();
        let fp = [42u8; 32];
        let serialized = SerializedModel::from_model(&model, Some(fp));

        assert_eq!(serialized.fingerprint, Some(fp));
    }

    #[test]
    fn test_round_trip_empty_model() {
        let model = Model::new();
        let serialized = SerializedModel::from_model(&model, None);
        let bytes = serialized.to_bytes();
        let restored = SerializedModel::from_bytes(&bytes).unwrap();

        assert_eq!(restored.version, SCHEMA_VERSION);
        assert!(restored.modules.is_empty());
        assert!(restored.nodes.is_empty());
    }

    #[test]
    fn test_node_kind_round_trip() {
        for i in 0..10u8 {
            let kind = NodeKind::from_u8(i).unwrap();
            assert_eq!(kind.as_u8(), i);
        }
        assert!(NodeKind::from_u8(10).is_none());
    }

    #[test]
    fn test_access_round_trip() {
        for i in 0..6u8 {
            let access = Access::from_u8(i).unwrap();
            assert_eq!(access.as_u8(), i);
        }
        assert!(Access::from_u8(6).is_none());
    }

    #[test]
    fn test_status_round_trip() {
        for i in 0..3u8 {
            let status = Status::from_u8(i).unwrap();
            assert_eq!(status.as_u8(), i);
        }
        assert!(Status::from_u8(3).is_none());
    }

    #[test]
    fn test_base_type_round_trip() {
        for i in 0..12u8 {
            let base = BaseType::from_u8(i).unwrap();
            assert_eq!(base.as_u8(), i);
        }
        assert!(BaseType::from_u8(12).is_none());
    }
}
