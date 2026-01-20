//! Phase 6: Definition deduplication.
//!
//! After full resolution, deduplicate definitions from duplicate module files.
//! This handles the case where the same MIB file is copied to multiple vendor
//! directories (e.g., RFC1213-MIB in /std, /cisco, /juniper).
//!
//! Deduplication criteria:
//! - Same module name (not ModuleId - different files have different IDs)
//! - Same label (symbol name)
//! - Same OID (implied by being on the same node)
//! - Semantically identical definition (type, access, enums, etc.)
//!
//! Definitions that share module name and label but differ semantically
//! are kept as separate definitions (e.g., vendor extension adds enum value).

use crate::model::{Model, NodeDefinition, NodeId, ResolvedObject, StrId};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Deduplicate definitions across all nodes in the model.
///
/// Returns the number of duplicate definitions removed.
pub fn deduplicate_definitions(model: &mut Model) -> usize {
    let mut total_removed = 0;

    // We need to iterate by index since we'll modify the nodes
    let node_count = model.node_count();

    for idx in 0..node_count {
        let node_id = match crate::model::NodeId::from_index(idx) {
            Some(id) => id,
            None => continue,
        };

        let removed = deduplicate_node_definitions(model, node_id);
        total_removed += removed;
    }

    #[cfg(feature = "std")]
    if total_removed > 0 {
        eprintln!("[dedup] Removed {} duplicate definitions", total_removed);
    }

    total_removed
}

/// Deduplicate definitions on a single node.
fn deduplicate_node_definitions(model: &mut Model, node_id: NodeId) -> usize {
    // Get the definitions for this node
    let definitions = match model.get_node(node_id) {
        Some(node) => node.definitions.clone(),
        None => return 0,
    };

    if definitions.len() <= 1 {
        return 0;
    }

    // Group definitions by module name
    let mut by_module_name: BTreeMap<StrId, Vec<(usize, &NodeDefinition)>> = BTreeMap::new();

    for (idx, def) in definitions.iter().enumerate() {
        if let Some(module) = model.get_module(def.module) {
            by_module_name
                .entry(module.name)
                .or_default()
                .push((idx, def));
        }
    }

    // Find indices to remove (duplicates within same module name)
    let mut indices_to_remove: Vec<usize> = Vec::new();

    for (_module_name, defs) in &by_module_name {
        if defs.len() <= 1 {
            continue;
        }

        // Compare each pair - keep the first unique one, remove duplicates
        let mut kept_indices: Vec<usize> = Vec::new();

        for (idx, def) in defs {
            let is_duplicate = kept_indices.iter().any(|&kept_idx| {
                let kept_def = &definitions[kept_idx];
                definitions_are_equivalent(model, def, kept_def)
            });

            if is_duplicate {
                indices_to_remove.push(*idx);
            } else {
                kept_indices.push(*idx);
            }
        }
    }

    if indices_to_remove.is_empty() {
        return 0;
    }

    // Sort in reverse order so we can remove from the end first
    indices_to_remove.sort_by(|a, b| b.cmp(a));

    // Remove the duplicates
    if let Some(node) = model.get_node_mut(node_id) {
        for idx in &indices_to_remove {
            node.definitions.remove(*idx);
        }
    }

    indices_to_remove.len()
}

/// Check if two definitions are semantically equivalent.
///
/// This compares the resolved content, not just the identifiers.
fn definitions_are_equivalent(
    model: &Model,
    def_a: &NodeDefinition,
    def_b: &NodeDefinition,
) -> bool {
    // Labels must match (should always be true on same node, but check anyway)
    if def_a.label != def_b.label {
        return false;
    }

    // Compare objects if both have them
    match (def_a.object, def_b.object) {
        (Some(obj_a), Some(obj_b)) => {
            let obj_a = model.get_object(obj_a);
            let obj_b = model.get_object(obj_b);

            match (obj_a, obj_b) {
                (Some(a), Some(b)) => objects_are_equivalent(model, a, b),
                (None, None) => true,
                _ => false,
            }
        }
        (None, None) => {
            // Neither has an object - compare notifications
            match (def_a.notification, def_b.notification) {
                (Some(notif_a), Some(notif_b)) => {
                    let notif_a = model.get_notification(notif_a);
                    let notif_b = model.get_notification(notif_b);

                    match (notif_a, notif_b) {
                        (Some(a), Some(b)) => notifications_are_equivalent(a, b),
                        (None, None) => true,
                        _ => false,
                    }
                }
                (None, None) => true, // Both are simple nodes (OBJECT-IDENTITY, etc.)
                _ => false,
            }
        }
        _ => false, // One has object, other doesn't
    }
}

/// Check if two ResolvedObjects are semantically equivalent.
fn objects_are_equivalent(model: &Model, a: &ResolvedObject, b: &ResolvedObject) -> bool {
    // Compare type structure (not just TypeId, as duplicates have different IDs)
    if !types_are_equivalent(model, a.type_id, b.type_id) {
        return false;
    }

    // Compare inline enums
    if a.inline_enum != b.inline_enum {
        return false;
    }

    // Compare inline bits
    if a.inline_bits != b.inline_bits {
        return false;
    }

    // Compare access
    if a.access != b.access {
        return false;
    }

    // Compare status
    if a.status != b.status {
        return false;
    }

    // Compare units
    if a.units != b.units {
        return false;
    }

    // Compare index specification
    if a.index != b.index {
        return false;
    }

    // Compare augments
    if a.augments != b.augments {
        return false;
    }

    // Note: We intentionally don't compare description/reference
    // as these may have whitespace differences

    true
}

/// Check if two types are structurally equivalent.
fn types_are_equivalent(model: &Model, type_a: crate::model::TypeId, type_b: crate::model::TypeId) -> bool {
    let a = model.get_type(type_a);
    let b = model.get_type(type_b);

    match (a, b) {
        (Some(a), Some(b)) => {
            // Compare base type
            if a.base != b.base {
                return false;
            }

            // Compare size constraints
            if a.size != b.size {
                return false;
            }

            // Compare value constraints
            if a.value_range != b.value_range {
                return false;
            }

            // Compare enum values
            if a.enum_values != b.enum_values {
                return false;
            }

            // Compare bit definitions
            if a.bit_defs != b.bit_defs {
                return false;
            }

            // Compare display hint
            if a.hint != b.hint {
                return false;
            }

            // Recursively compare parent types
            match (a.parent_type, b.parent_type) {
                (Some(pa), Some(pb)) => types_are_equivalent(model, pa, pb),
                (None, None) => true,
                _ => false,
            }
        }
        (None, None) => true,
        _ => false,
    }
}

/// Check if two notifications are semantically equivalent.
fn notifications_are_equivalent(
    a: &crate::model::ResolvedNotification,
    b: &crate::model::ResolvedNotification,
) -> bool {
    // Compare objects list
    if a.objects != b.objects {
        return false;
    }

    // Compare status
    if a.status != b.status {
        return false;
    }

    // Note: We intentionally don't compare description/reference

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deduplicate_empty_model() {
        let mut model = Model::new();
        let removed = deduplicate_definitions(&mut model);
        assert_eq!(removed, 0);
    }
}
