//! Phase 6: Definition deduplication.
//!
//! After full resolution, deduplicate definitions from duplicate module files.
//! This handles the case where the same MIB file is copied to multiple vendor
//! directories (e.g., RFC1213-MIB in /std, /cisco, /juniper).
//!
//! Deduplication criteria:
//! - Same module name (not `ModuleId` - different files have different IDs)
//! - Same label (symbol name)
//! - Same OID (implied by being on the same node)
//! - Semantically identical definition (type, access, enums, etc.)
//!
//! Definitions that share module name and label but differ semantically
//! are kept as separate definitions (e.g., vendor extension adds enum value).

use crate::model::{Model, NodeDefinition, NodeId, ResolvedObject, TypeId};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// Deduplicate definitions across all nodes in the model.
///
/// Returns the number of duplicate definitions removed.
pub fn deduplicate_definitions(model: &mut Model) -> usize {
    let mut total_removed = 0;

    // We need to iterate by index since we'll modify the nodes
    let node_count = model.node_count();

    for idx in 0..node_count {
        let Some(node_id) = crate::model::NodeId::from_index(idx) else {
            continue;
        };

        let removed = deduplicate_node_definitions(model, node_id);
        total_removed += removed;
    }

    #[cfg(feature = "std")]
    if total_removed > 0 {
        eprintln!("[dedup] Removed {total_removed} duplicate definitions");
    }

    total_removed
}

/// Deduplicate definitions on a single node.
///
/// Uses a two-phase approach to avoid cloning the definitions vector:
/// 1. First pass (read-only): group indices by module name
/// 2. Second pass (read-only): identify duplicates within each group
/// 3. Third pass (mutable): remove duplicates
fn deduplicate_node_definitions(model: &mut Model, node_id: NodeId) -> usize {
    // Phase 1: Early check and group definition indices by module name (read-only)
    let module_groups: BTreeMap<Box<str>, Vec<usize>> = {
        let node = match model.get_node(node_id) {
            Some(node) if node.definitions.len() > 1 => node,
            _ => return 0,
        };

        let mut groups: BTreeMap<Box<str>, Vec<usize>> = BTreeMap::new();
        for (idx, def) in node.definitions.iter().enumerate() {
            if let Some(module) = model.get_module(def.module) {
                groups.entry(module.name.clone()).or_default().push(idx);
            }
        }
        groups
    };

    // Phase 2: Find indices to remove (duplicates within same module name)
    let mut indices_to_remove: Vec<usize> = Vec::new();

    for indices in module_groups.values() {
        if indices.len() <= 1 {
            continue;
        }

        // Compare each pair - keep the first unique one, remove duplicates
        let mut kept_indices: Vec<usize> = Vec::new();

        for &idx in indices {
            let is_duplicate = kept_indices.iter().any(|&kept_idx| {
                // Re-access definitions through model for each comparison
                // This avoids holding a long-lived reference to definitions
                let node = model.get_node(node_id).unwrap();
                let def = &node.definitions[idx];
                let kept_def = &node.definitions[kept_idx];
                definitions_are_equivalent(model, def, kept_def)
            });

            if is_duplicate {
                indices_to_remove.push(idx);
            } else {
                kept_indices.push(idx);
            }
        }
    }

    if indices_to_remove.is_empty() {
        return 0;
    }

    let removed_count = indices_to_remove.len();

    // Phase 3: Apply removals (mutable)
    // Convert to set for O(1) lookup during filter
    let remove_set: BTreeSet<usize> = indices_to_remove.into_iter().collect();

    // Rebuild definitions vector, filtering out duplicates - O(n) vs O(n²) for repeated remove()
    if let Some(node) = model.get_node_mut(node_id) {
        let mut idx = 0;
        node.definitions.retain(|_| {
            let keep = !remove_set.contains(&idx);
            idx += 1;
            keep
        });
    }

    removed_count
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

/// Check if two `ResolvedObjects` are semantically equivalent.
fn objects_are_equivalent(model: &Model, a: &ResolvedObject, b: &ResolvedObject) -> bool {
    // Compare type structure (not just TypeId, as duplicates have different IDs)
    // Both None = equivalent, both Some = compare structurally, mixed = not equivalent
    match (a.type_id, b.type_id) {
        (Some(type_a), Some(type_b)) => {
            if !types_are_equivalent(model, type_a, type_b) {
                return false;
            }
        }
        (None, None) => {
            // Both unresolved - consider equivalent for dedup purposes
        }
        _ => {
            // One resolved, one not - not equivalent
            return false;
        }
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
/// Uses a visited set to prevent infinite recursion if the type graph has cycles.
fn types_are_equivalent(model: &Model, type_a: TypeId, type_b: TypeId) -> bool {
    let mut visited = BTreeSet::new();
    types_are_equivalent_inner(model, type_a, type_b, &mut visited)
}

/// Inner recursive helper for `types_are_equivalent` with cycle detection.
fn types_are_equivalent_inner(
    model: &Model,
    type_a: TypeId,
    type_b: TypeId,
    visited: &mut BTreeSet<(TypeId, TypeId)>,
) -> bool {
    // Cycle detection: if we've already compared this pair, assume equivalent
    // (if they weren't, we would have returned false earlier in the comparison)
    if !visited.insert((type_a, type_b)) {
        return true;
    }

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
                (Some(pa), Some(pb)) => types_are_equivalent_inner(model, pa, pb, visited),
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
