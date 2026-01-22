//! Phase 3: Type resolution.
//!
//! Build the type graph with inheritance chains and resolve all type references.

use crate::model::{
    BaseType, BitDefinitions, EnumValues, RangeBound, ResolvedType, SizeConstraint, Status, TypeId,
    ValueConstraint,
};
use crate::module::{
    Constraint, Definition, Range, RangeValue, Status as ModuleStatus, TypeSyntax,
};
use crate::resolver::context::ResolverContext;
use alloc::string::ToString;
use alloc::vec::Vec;

/// Resolve all types across all modules.
pub fn resolve_types(ctx: &mut ResolverContext) {
    // First: seed primitive ASN.1 types
    seed_primitive_types(ctx);

    // Second: create type nodes for all types (from synthetic base modules and user modules)
    create_user_types(ctx);

    // Third: resolve base types and parent pointers
    resolve_type_bases(ctx);
}

/// Seed the model with primitive ASN.1 types.
///
/// These are the fundamental types that other types reference.
/// Primitives are registered in the SNMPv2-SMI module scope.
fn seed_primitive_types(ctx: &mut ResolverContext) {
    // Get the SNMPv2-SMI module ID (first synthetic module, index 0)
    let Some(module_id) = ctx.snmpv2_smi_module_id else {
        // SNMPv2-SMI not registered yet - should not happen after registration phase
        return;
    };

    // INTEGER - base integer type
    let name = ctx.intern("INTEGER");
    let typ = ResolvedType::new(name, module_id, BaseType::Integer32);
    let type_id = ctx.model.add_type(typ).unwrap();
    ctx.register_module_type_symbol(module_id, name, type_id);

    // OCTET STRING - base octet string type
    let name = ctx.intern("OCTET STRING");
    let typ = ResolvedType::new(name, module_id, BaseType::OctetString);
    let type_id = ctx.model.add_type(typ).unwrap();
    ctx.register_module_type_symbol(module_id, name, type_id);

    // OBJECT IDENTIFIER - base OID type
    let name = ctx.intern("OBJECT IDENTIFIER");
    let typ = ResolvedType::new(name, module_id, BaseType::ObjectIdentifier);
    let type_id = ctx.model.add_type(typ).unwrap();
    ctx.register_module_type_symbol(module_id, name, type_id);

    // BITS - bit string type
    let name = ctx.intern("BITS");
    let typ = ResolvedType::new(name, module_id, BaseType::Bits);
    let type_id = ctx.model.add_type(typ).unwrap();
    ctx.register_module_type_symbol(module_id, name, type_id);
}

/// Create type nodes for all user-defined types.
///
/// Uses split borrows to intern strings directly from `hir_modules` without
/// intermediate cloning, reducing peak memory usage for large MIB corpora.
fn create_user_types(ctx: &mut ResolverContext) {
    // Split borrows: immutable access to hir data, mutable access to model/indices.
    // This allows us to intern strings directly without cloning into intermediate structs.
    let hir_modules = &ctx.hir_modules;
    let hir_index_to_module_id = &ctx.hir_index_to_module_id;
    let model = &mut ctx.model;
    let module_symbol_to_type = &mut ctx.module_symbol_to_type;

    for (module_idx, module) in hir_modules.iter().enumerate() {
        let Some(&module_id) = hir_index_to_module_id.get(&module_idx) else {
            continue; // Skip if module not registered (shouldn't happen)
        };

        for def in &module.definitions {
            let Definition::TypeDef(td) = def else {
                continue;
            };

            // Intern name directly - no clone needed
            let name = model.intern(&td.name.name);

            // Determine base type
            let base_from_syntax = td.base_type.or_else(|| syntax_to_base_type(&td.syntax));
            let base = base_from_syntax.unwrap_or(BaseType::Integer32);

            let mut typ = ResolvedType::new(name, module_id, base);

            // Track if base type needs resolution from parent
            typ.needs_base_resolution = base_from_syntax.is_none();
            typ.is_textual_convention = td.is_textual_convention;
            typ.status = hir_status_to_status(td.status);

            // Intern hint directly if present
            if let Some(ref hint) = td.display_hint {
                typ.hint = Some(model.intern(hint));
            }

            // Intern description directly if present
            if let Some(ref desc) = td.description {
                typ.description = Some(model.intern(desc));
            }

            // Handle enum values - intern names directly
            if let TypeSyntax::IntegerEnum(e) = &td.syntax {
                let values: Vec<_> = e
                    .iter()
                    .map(|nn| (nn.value, model.intern(&nn.name.name)))
                    .collect();
                typ.enum_values = Some(EnumValues::new(values));
            }

            // Handle BITS - intern names directly
            if let TypeSyntax::Bits(b) = &td.syntax {
                let defs: Vec<_> = b
                    .iter()
                    .map(|nb| (nb.position, model.intern(&nb.name.name)))
                    .collect();
                typ.bit_defs = Some(BitDefinitions::new(defs));
            }

            // Handle constraints
            if let TypeSyntax::Constrained { constraint, .. } = &td.syntax {
                match constraint {
                    Constraint::Size(r) => typ.size = Some(hir_ranges_to_size_constraint(r)),
                    Constraint::Range(r) => {
                        typ.value_range = Some(hir_ranges_to_value_constraint(r));
                    }
                }
            }

            let type_id = model.add_type(typ).unwrap();

            // Register module-scoped type for import-aware lookup
            module_symbol_to_type.insert((module_id, name), type_id);

            // Add to module
            if let Some(resolved_module) = model.get_module_mut(module_id) {
                resolved_module.add_type(type_id);
            }
        }
    }
}

/// Resolve base types and set parent pointers using multi-pass resolution.
///
/// This uses an iterative approach similar to OID resolution to handle forward
/// references. Types that reference other types defined later in the same module
/// will be resolved in subsequent passes.
fn resolve_type_bases(ctx: &mut ResolverContext) {
    // Multi-pass parent linking for TypeRef-based types
    resolve_typeref_parents_multipass(ctx);

    // Link primitive-syntax types to their primitive parents
    // This handles types like `DisplayString SYNTAX OCTET STRING (SIZE ...)` which
    // should have parent_type pointing to "OCTET STRING".
    // Primitives are always available after seed_primitive_types, so no multi-pass needed.
    link_primitive_syntax_parents(ctx);

    // Link RFC1213-MIB's legacy types (DisplayString, PhysAddress) to their
    // SNMPv2-TC textual convention equivalents. This ensures that objects using
    // RFC1213-MIB's types inherit display hints from the TC versions.
    link_rfc1213_types_to_tcs(ctx);

    // After all parents are linked, inherit base types from parent chains (single pass)
    inherit_base_types(ctx);
}

/// Index-based reference to a type that needs parent resolution.
/// Stores indices into `hir_modules` to avoid cloning strings.
struct TypeResolutionIndex {
    module_idx: usize,
    def_idx: usize,
}

/// Resolve `TypeRef` parent pointers using multi-pass iteration.
///
/// Collects all types with `TypeRef` syntax and iteratively attempts to link
/// their parent pointers. Types that reference forward-declared types will
/// be resolved in subsequent passes.
fn resolve_typeref_parents_multipass(ctx: &mut ResolverContext) {
    // Collect indices of types with TypeRef syntax (no string cloning).
    let mut pending: Vec<TypeResolutionIndex> = ctx
        .hir_modules
        .iter()
        .enumerate()
        .flat_map(|(module_idx, module)| {
            module
                .definitions
                .iter()
                .enumerate()
                .filter_map(move |(def_idx, def)| {
                    if let Definition::TypeDef(td) = def {
                        // Check if this typedef has a TypeRef that needs resolution
                        let has_typeref = matches!(td.syntax, TypeSyntax::TypeRef(_))
                            || matches!(
                                &td.syntax,
                                TypeSyntax::Constrained { base, .. }
                                    if matches!(**base, TypeSyntax::TypeRef(_))
                            );
                        if has_typeref {
                            return Some(TypeResolutionIndex {
                                module_idx,
                                def_idx,
                            });
                        }
                    }
                    None
                })
        })
        .collect();

    // Multi-pass resolution
    let max_iterations = 20; // Safety limit (matches OID resolution)

    for _iteration in 0..max_iterations {
        if pending.is_empty() {
            break;
        }

        let initial_count = pending.len();
        let mut still_pending = Vec::new();

        for idx in pending {
            if !try_resolve_type_parent(ctx, &idx) {
                still_pending.push(idx);
            }
        }

        // No progress - record remaining as unresolved
        if still_pending.len() == initial_count {
            for idx in still_pending {
                // Extract needed data, then drop borrow on hir_modules
                let (type_name, base_name, span) = {
                    let Definition::TypeDef(td) =
                        &ctx.hir_modules[idx.module_idx].definitions[idx.def_idx]
                    else {
                        continue;
                    };
                    let base = get_typeref_base_name(&td.syntax).map(ToString::to_string);
                    (td.name.name.clone(), base, td.span)
                };

                let Some(module_id) = ctx.get_module_id_for_hir_index(idx.module_idx) else {
                    continue;
                };
                if let Some(ref base) = base_name {
                    ctx.record_unresolved_type(module_id, &type_name, base, span);
                }
            }
            break;
        }

        pending = still_pending;
    }
}

/// Extract the base type name from a TypeRef syntax.
fn get_typeref_base_name(syntax: &TypeSyntax) -> Option<&str> {
    match syntax {
        TypeSyntax::TypeRef(base) => Some(&base.name),
        TypeSyntax::Constrained { base, .. } => {
            if let TypeSyntax::TypeRef(base_name) = &**base {
                Some(&base_name.name)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Attempt to resolve a type's parent pointer. Returns true if successful.
fn try_resolve_type_parent(ctx: &mut ResolverContext, idx: &TypeResolutionIndex) -> bool {
    // Extract the names we need, then drop the borrow on hir_modules
    // so we can call methods on ctx afterwards.
    let (type_name, base_name) = {
        let Definition::TypeDef(td) = &ctx.hir_modules[idx.module_idx].definitions[idx.def_idx]
        else {
            return false;
        };
        let Some(base) = get_typeref_base_name(&td.syntax) else {
            return false;
        };
        // Clone just the short type names to release the borrow
        (td.name.name.clone(), base.to_string())
    };

    let Some(module_id) = ctx.get_module_id_for_hir_index(idx.module_idx) else {
        return false;
    };

    // Look up the type being resolved (must be module-scoped to find THIS module's type)
    let type_id = ctx.lookup_type_for_module(module_id, &type_name);
    // Look up the parent type (respects imports)
    let parent_id = ctx.lookup_type_for_module(module_id, &base_name);

    if let (Some(type_id), Some(parent_id)) = (type_id, parent_id) {
        // Check if parent already has its parent resolved (if it needs one)
        // This ensures we don't link to a type that's still pending resolution
        let parent_ready = if let Some(parent_type) = ctx.model.get_type(parent_id) {
            // Parent is ready if it doesn't need base resolution, or if it has a parent set
            !parent_type.needs_base_resolution || parent_type.parent_type.is_some()
        } else {
            false
        };

        if parent_ready {
            if let Some(typ) = ctx.model.get_type_mut(type_id) {
                typ.parent_type = Some(parent_id);
            }
            return true;
        }
    }

    false
}

/// Get the primitive type name for a syntax that uses primitive syntax directly.
///
/// Returns the primitive type name to link as parent for:
/// - `TypeSyntax::OctetString` -> "OCTET STRING"
/// - `TypeSyntax::ObjectIdentifier` -> "OBJECT IDENTIFIER"
/// - `TypeSyntax::IntegerEnum` -> "INTEGER"
/// - `TypeSyntax::Bits` -> "BITS"
/// - `TypeSyntax::Constrained { base: OctetString/ObjectIdentifier, .. }` -> respective primitive
fn get_primitive_parent_name(syntax: &TypeSyntax) -> Option<&'static str> {
    match syntax {
        TypeSyntax::OctetString => Some("OCTET STRING"),
        TypeSyntax::ObjectIdentifier => Some("OBJECT IDENTIFIER"),
        TypeSyntax::IntegerEnum(_) => Some("INTEGER"),
        TypeSyntax::Bits(_) => Some("BITS"),
        TypeSyntax::Constrained { base, .. } => {
            match **base {
                TypeSyntax::OctetString => Some("OCTET STRING"),
                TypeSyntax::ObjectIdentifier => Some("OBJECT IDENTIFIER"),
                // TypeRef cases are handled in link_typeref_parents
                _ => None,
            }
        }
        // TypeRef, SequenceOf, Sequence are handled elsewhere or don't need primitive linking
        _ => None,
    }
}

/// Link types that use primitive syntax directly to their primitive parent types.
///
/// This handles textual conventions and types that are defined using:
/// - `SYNTAX OCTET STRING (SIZE ...)`
/// - `SYNTAX OBJECT IDENTIFIER`
/// - `SYNTAX INTEGER { enum values }`
/// - `SYNTAX BITS { bit values }`
fn link_primitive_syntax_parents(ctx: &mut ResolverContext) {
    // Collect indices of types that need primitive parent linking.
    // Stores (module_idx, def_idx, primitive_name) - no string cloning needed.
    let primitive_links: Vec<_> = ctx
        .hir_modules
        .iter()
        .enumerate()
        .flat_map(|(module_idx, module)| {
            module
                .definitions
                .iter()
                .enumerate()
                .filter_map(move |(def_idx, def)| {
                    if let Definition::TypeDef(td) = def {
                        get_primitive_parent_name(&td.syntax)
                            .map(|primitive_name| (module_idx, def_idx, primitive_name))
                    } else {
                        None
                    }
                })
        })
        .collect();

    // Link each type to its primitive parent
    for (module_idx, def_idx, primitive_name) in primitive_links {
        // Access the typedef by index to get the type name (no clone)
        let Definition::TypeDef(td) = &ctx.hir_modules[module_idx].definitions[def_idx] else {
            continue;
        };
        let type_name = &td.name.name;

        let Some(module_id) = ctx.get_module_id_for_hir_index(module_idx) else {
            continue;
        };

        // Use module-scoped lookup for type_name to find THIS module's type
        // Primitive names are global (INTEGER, OCTET STRING, etc.)
        if let (Some(type_id), Some(parent_id)) = (
            ctx.lookup_type_for_module(module_id, type_name),
            ctx.lookup_type(primitive_name),
        ) && let Some(typ) = ctx.model.get_type_mut(type_id)
        {
            // Only set if not already set (TypeRef linking takes precedence)
            if typ.parent_type.is_none() {
                typ.parent_type = Some(parent_id);
            }
        }
    }
}

/// Link RFC1213-MIB's legacy type definitions to their SNMPv2-TC equivalents.
///
/// RFC1213-MIB (MIB-II, SMIv1) defines `DisplayString` and `PhysAddress` as plain
/// type aliases without textual convention metadata. SNMPv2-TC defines the same
/// types as TCs with display hints ("255a" and "1x:" respectively).
///
/// When both modules are loaded, objects defined in RFC1213-MIB use the local
/// (hintless) type definitions. By linking RFC1213-MIB's types as children of
/// their SNMPv2-TC counterparts, `get_effective_hint()` can walk the parent chain
/// to find the display hints.
///
/// This preserves module scoping (RFC1213-MIB's types remain distinct TypeIds)
/// while providing practical utility (hints are available via parent chain).
fn link_rfc1213_types_to_tcs(ctx: &mut ResolverContext) {
    // Types to link: (type_name, source_module, target_module)
    const LEGACY_TYPE_MAPPINGS: &[(&str, &str, &str)] = &[
        ("DisplayString", "RFC1213-MIB", "SNMPv2-TC"),
        ("PhysAddress", "RFC1213-MIB", "SNMPv2-TC"),
    ];

    for &(type_name, source_module, target_module) in LEGACY_TYPE_MAPPINGS {
        // Find source module (RFC1213-MIB) - may not be present
        let Some(source_module_id) = ctx.get_module_id_by_name(source_module) else {
            continue;
        };

        // Find target module (SNMPv2-TC) - should always be present (synthetic)
        let Some(target_module_id) = ctx.get_module_id_by_name(target_module) else {
            continue;
        };

        // Look up the source type (RFC1213-MIB's version)
        let Some(source_type_id) = ctx.lookup_type_for_module(source_module_id, type_name) else {
            continue;
        };

        // Look up the target type (SNMPv2-TC's TC version)
        let Some(target_type_id) = ctx.lookup_type_for_module(target_module_id, type_name) else {
            continue;
        };

        // Don't link if they're the same type (shouldn't happen, but be safe)
        if source_type_id == target_type_id {
            continue;
        }

        // Link the source type to the target TC
        // We intentionally overwrite any existing parent (typically a primitive like OCTET STRING)
        // because the TC parent provides more useful metadata (display hints, etc.)
        if let Some(typ) = ctx.model.get_type_mut(source_type_id) {
            typ.parent_type = Some(target_type_id);
        }
    }
}

/// Inherit base types from parent types.
/// This handles cases like `MyString ::= DisplayString` where `MyString` needs
/// to inherit `OctetString` as its base type from `DisplayString`.
fn inherit_base_types(ctx: &mut ResolverContext) {
    // Collect types that need base resolution
    let types_needing_resolution: Vec<TypeId> = (0..ctx.model.type_count())
        .filter_map(|idx| {
            let type_id = TypeId::from_index(idx)?;
            let typ = ctx.model.get_type(type_id)?;
            if typ.needs_base_resolution && typ.parent_type.is_some() {
                Some(type_id)
            } else {
                None
            }
        })
        .collect();

    // Resolve each type's base from its parent chain
    for type_id in types_needing_resolution {
        if let Some(base) = resolve_base_from_chain(ctx, type_id)
            && let Some(typ) = ctx.model.get_type_mut(type_id)
        {
            typ.base = base;
            typ.needs_base_resolution = false;
        }
    }
}

/// Walk the parent chain to find the ultimate base type.
fn resolve_base_from_chain(ctx: &ResolverContext, type_id: TypeId) -> Option<BaseType> {
    let mut current = Some(type_id);
    let mut visited = alloc::collections::BTreeSet::new();

    while let Some(tid) = current {
        // Cycle detection
        if !visited.insert(tid) {
            return None;
        }

        if let Some(typ) = ctx.model.get_type(tid) {
            // If this type doesn't need resolution, use its base
            if !typ.needs_base_resolution {
                return Some(typ.base);
            }
            // Otherwise, continue to parent
            current = typ.parent_type;
        } else {
            break;
        }
    }

    None
}

/// Convert `TypeSyntax` to `BaseType`.
/// Returns None for `TypeRef` that cannot be immediately resolved (will be inherited from parent).
fn syntax_to_base_type(syntax: &TypeSyntax) -> Option<BaseType> {
    match syntax {
        TypeSyntax::TypeRef(name) => {
            // Only map primitive/built-in type names; others need parent resolution
            match name.name.as_str() {
                "Integer32" | "INTEGER" => Some(BaseType::Integer32),
                "Counter32" => Some(BaseType::Counter32),
                "Counter64" => Some(BaseType::Counter64),
                "Gauge32" => Some(BaseType::Gauge32),
                "Unsigned32" => Some(BaseType::Unsigned32),
                "TimeTicks" => Some(BaseType::TimeTicks),
                "IpAddress" => Some(BaseType::IpAddress),
                "Opaque" => Some(BaseType::Opaque),
                "OCTET STRING" => Some(BaseType::OctetString),
                "OBJECT IDENTIFIER" => Some(BaseType::ObjectIdentifier),
                "BITS" => Some(BaseType::Bits),
                _ => None, // Unknown TypeRef - will inherit from parent
            }
        }
        TypeSyntax::IntegerEnum(_) => Some(BaseType::Integer32),
        TypeSyntax::Bits(_) => Some(BaseType::Bits),
        TypeSyntax::OctetString => Some(BaseType::OctetString),
        TypeSyntax::ObjectIdentifier => Some(BaseType::ObjectIdentifier),
        TypeSyntax::Constrained { base, .. } => syntax_to_base_type(base),
        TypeSyntax::SequenceOf(_) | TypeSyntax::Sequence(_) => Some(BaseType::Sequence),
    }
}

/// Convert `Status` to Status.
fn hir_status_to_status(status: ModuleStatus) -> Status {
    match status {
        ModuleStatus::Current => Status::Current,
        ModuleStatus::Deprecated => Status::Deprecated,
        ModuleStatus::Obsolete => Status::Obsolete,
    }
}

/// Convert HIR ranges to `SizeConstraint`.
fn hir_ranges_to_size_constraint(ranges: &[Range]) -> SizeConstraint {
    let size_ranges: Vec<_> = ranges
        .iter()
        .map(|r| {
            let min = range_value_to_u32(&r.min);
            let max = r.max.as_ref().map_or(min, range_value_to_u32);
            (min, max)
        })
        .collect();
    SizeConstraint {
        ranges: size_ranges,
    }
}

/// Convert HIR ranges to `ValueConstraint`.
fn hir_ranges_to_value_constraint(ranges: &[Range]) -> ValueConstraint {
    let value_ranges: Vec<_> = ranges
        .iter()
        .map(|r| {
            let min = range_value_to_bound(&r.min);
            let max = r.max.as_ref().map_or(min, range_value_to_bound);
            (min, max)
        })
        .collect();
    ValueConstraint {
        ranges: value_ranges,
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn range_value_to_u32(v: &RangeValue) -> u32 {
    // Intentional conversion: size constraints in MIBs are typically small values
    match v {
        RangeValue::Signed(n) => *n as u32,
        RangeValue::Unsigned(n) => *n as u32,
        RangeValue::Min => 0,
        RangeValue::Max => u32::MAX,
    }
}

fn range_value_to_bound(v: &RangeValue) -> RangeBound {
    match v {
        RangeValue::Signed(n) => RangeBound::Signed(*n),
        RangeValue::Unsigned(n) => RangeBound::Unsigned(*n),
        // For MIN/MAX, we use signed variants as they're typically used in signed integer contexts
        // The actual interpretation depends on the type (Integer32 vs Counter64)
        RangeValue::Min => RangeBound::Signed(i64::MIN),
        RangeValue::Max => RangeBound::Unsigned(u64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Span;
    use crate::module::{
        Import, Module, NamedBit, NamedNumber, Status as ModuleStatus, Symbol, TypeDef,
    };
    use crate::resolver::phases::imports::resolve_imports;
    use crate::resolver::phases::registration::register_modules;
    use alloc::vec;

    fn make_test_module(name: &str, defs: Vec<Definition>) -> Module {
        let mut module = Module::new(Symbol::from_name(name), Span::new(0, 0));
        module.definitions = defs;
        module
    }

    fn make_test_module_with_imports(
        name: &str,
        imports: Vec<(&str, &str)>,
        defs: Vec<Definition>,
    ) -> Module {
        let mut module = Module::new(Symbol::from_name(name), Span::new(0, 0));
        module.imports = imports
            .into_iter()
            .map(|(from_mod, sym)| {
                Import::new(
                    Symbol::from_name(from_mod),
                    Symbol::from_name(sym),
                    Span::SYNTHETIC,
                )
            })
            .collect();
        module.definitions = defs;
        module
    }

    #[test]
    fn test_builtin_types_seeded() {
        let modules = vec![make_test_module("TEST-MIB", vec![])];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        // Check built-in types exist
        assert!(ctx.lookup_type("Integer32").is_some());
        assert!(ctx.lookup_type("Counter32").is_some());
        assert!(ctx.lookup_type("DisplayString").is_some());
        assert!(ctx.lookup_type("TruthValue").is_some());
    }

    #[test]
    fn test_user_type_creation() {
        let typedef = TypeDef {
            name: Symbol::from_name("MyString"),
            syntax: TypeSyntax::TypeRef(Symbol::from_name("DisplayString")),
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: Some("Test type".into()),
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![("SNMPv2-TC", "DisplayString")],
            vec![Definition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);

        assert!(ctx.lookup_type("MyString").is_some());
    }

    #[test]
    fn test_type_inheritance_parent_pointer() {
        // MyString ::= DisplayString
        // DisplayString is a built-in TC based on OCTET STRING
        let typedef = TypeDef {
            name: Symbol::from_name("MyString"),
            syntax: TypeSyntax::TypeRef(Symbol::from_name("DisplayString")),
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: Some("Test type".into()),
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![("SNMPv2-TC", "DisplayString")],
            vec![Definition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);

        // Check parent pointer is set
        let my_string_id = ctx.lookup_type("MyString").expect("MyString should exist");
        let my_string = ctx.model.get_type(my_string_id).expect("type should exist");
        assert!(my_string.parent_type.is_some(), "parent_type should be set");

        let display_string_id = ctx
            .lookup_type("DisplayString")
            .expect("DisplayString should exist");
        assert_eq!(my_string.parent_type, Some(display_string_id));
    }

    #[test]
    fn test_type_inheritance_base_type() {
        // MyString ::= DisplayString
        // DisplayString is based on OCTET STRING, so MyString should have OctetString base
        let typedef = TypeDef {
            name: Symbol::from_name("MyString"),
            syntax: TypeSyntax::TypeRef(Symbol::from_name("DisplayString")),
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: Some("Test type".into()),
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![("SNMPv2-TC", "DisplayString")],
            vec![Definition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);

        let my_string_id = ctx.lookup_type("MyString").expect("MyString should exist");
        let my_string = ctx.model.get_type(my_string_id).expect("type should exist");

        // Base type should be inherited from DisplayString -> OCTET STRING
        assert_eq!(
            my_string.base,
            BaseType::OctetString,
            "MyString should inherit OctetString base from DisplayString"
        );
    }

    #[test]
    fn test_type_chain() {
        // MyString ::= DisplayString (which is based on OCTET STRING)
        let typedef = TypeDef {
            name: Symbol::from_name("MyString"),
            syntax: TypeSyntax::TypeRef(Symbol::from_name("DisplayString")),
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![("SNMPv2-TC", "DisplayString")],
            vec![Definition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);

        let my_string_id = ctx.lookup_type("MyString").expect("MyString should exist");

        // Get the type chain
        let chain = ctx.model.get_type_chain(my_string_id);
        assert!(
            chain.len() >= 2,
            "chain should have at least MyString and DisplayString"
        );

        // First should be MyString
        assert_eq!(ctx.model.get_str(chain[0].name), "MyString");
        // Second should be DisplayString
        assert_eq!(ctx.model.get_str(chain[1].name), "DisplayString");
    }

    #[test]
    fn test_multi_level_inheritance() {
        // Create: MyString2 ::= MyString ::= DisplayString
        let typedef1 = TypeDef {
            name: Symbol::from_name("MyString"),
            syntax: TypeSyntax::TypeRef(Symbol::from_name("DisplayString")),
            base_type: None,
            display_hint: Some("255a".into()),
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let typedef2 = TypeDef {
            name: Symbol::from_name("MyString2"),
            syntax: TypeSyntax::TypeRef(Symbol::from_name("MyString")),
            base_type: None,
            display_hint: None, // No hint - should inherit from MyString
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![("SNMPv2-TC", "DisplayString")],
            vec![Definition::TypeDef(typedef1), Definition::TypeDef(typedef2)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);

        let my_string2_id = ctx
            .lookup_type("MyString2")
            .expect("MyString2 should exist");
        let my_string2 = ctx
            .model
            .get_type(my_string2_id)
            .expect("type should exist");

        // Base type should propagate through the chain
        assert_eq!(
            my_string2.base,
            BaseType::OctetString,
            "MyString2 should inherit OctetString base through MyString -> DisplayString"
        );

        // Type chain should have 3 levels
        let chain = ctx.model.get_type_chain(my_string2_id);
        assert!(
            chain.len() >= 3,
            "chain should have at least MyString2, MyString, DisplayString"
        );

        // get_effective_hint should find MyString's hint
        let effective_hint = ctx.model.get_effective_hint(my_string2_id);
        assert!(
            effective_hint.is_some(),
            "should find hint from parent chain"
        );
        assert_eq!(ctx.model.get_str(effective_hint.unwrap()), "255a");
    }

    #[test]
    fn test_sequence_base_type() {
        // SEQUENCE types should have BaseType::Sequence
        let typedef = TypeDef {
            name: Symbol::from_name("IfEntry"),
            syntax: TypeSyntax::Sequence(vec![]),
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: false,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![Definition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let if_entry_id = ctx.lookup_type("IfEntry").expect("IfEntry should exist");
        let if_entry = ctx.model.get_type(if_entry_id).expect("type should exist");

        assert_eq!(
            if_entry.base,
            BaseType::Sequence,
            "SEQUENCE types should have BaseType::Sequence"
        );
    }

    // ============================================================
    // Tests for primitive syntax parent linking
    // ============================================================

    #[test]
    fn test_octet_string_syntax_parent_linking() {
        // PhysAddress-like TC: SYNTAX OCTET STRING (no constraint)
        let typedef = TypeDef {
            name: Symbol::from_name("TestPhysAddress"),
            syntax: TypeSyntax::OctetString,
            base_type: None,
            display_hint: Some("1x:".into()),
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![Definition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let type_id = ctx
            .lookup_type("TestPhysAddress")
            .expect("type should exist");
        let typ = ctx.model.get_type(type_id).expect("type should exist");

        // Should have parent_type pointing to OCTET STRING primitive
        assert!(
            typ.parent_type.is_some(),
            "parent_type should be set for OctetString syntax"
        );

        let parent_id = typ.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "OCTET STRING");
    }

    #[test]
    fn test_constrained_octet_string_parent_linking() {
        use alloc::boxed::Box;
        // DisplayString-like TC: SYNTAX OCTET STRING (SIZE (0..255))
        let typedef = TypeDef {
            name: Symbol::from_name("TestDisplayString"),
            syntax: TypeSyntax::Constrained {
                base: Box::new(TypeSyntax::OctetString),
                constraint: Constraint::Size(vec![Range {
                    min: RangeValue::Unsigned(0),
                    max: Some(RangeValue::Unsigned(255)),
                }]),
            },
            base_type: None,
            display_hint: Some("255a".into()),
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![Definition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let type_id = ctx
            .lookup_type("TestDisplayString")
            .expect("type should exist");
        let typ = ctx.model.get_type(type_id).expect("type should exist");

        // Should have parent_type pointing to OCTET STRING primitive
        assert!(
            typ.parent_type.is_some(),
            "parent_type should be set for constrained OctetString"
        );

        let parent_id = typ.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "OCTET STRING");
    }

    #[test]
    fn test_object_identifier_syntax_parent_linking() {
        // AutonomousType-like TC: SYNTAX OBJECT IDENTIFIER
        let typedef = TypeDef {
            name: Symbol::from_name("TestAutonomousType"),
            syntax: TypeSyntax::ObjectIdentifier,
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![Definition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let type_id = ctx
            .lookup_type("TestAutonomousType")
            .expect("type should exist");
        let typ = ctx.model.get_type(type_id).expect("type should exist");

        // Should have parent_type pointing to OBJECT IDENTIFIER primitive
        assert!(
            typ.parent_type.is_some(),
            "parent_type should be set for ObjectIdentifier syntax"
        );

        let parent_id = typ.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "OBJECT IDENTIFIER");
    }

    #[test]
    fn test_integer_enum_syntax_parent_linking() {
        // TruthValue-like TC: SYNTAX INTEGER { true(1), false(2) }
        let typedef = TypeDef {
            name: Symbol::from_name("TestTruthValue"),
            syntax: TypeSyntax::IntegerEnum(vec![
                NamedNumber::new(Symbol::from_name("true"), 1),
                NamedNumber::new(Symbol::from_name("false"), 2),
            ]),
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![Definition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let type_id = ctx
            .lookup_type("TestTruthValue")
            .expect("type should exist");
        let typ = ctx.model.get_type(type_id).expect("type should exist");

        // Should have parent_type pointing to INTEGER primitive
        assert!(
            typ.parent_type.is_some(),
            "parent_type should be set for IntegerEnum syntax"
        );

        let parent_id = typ.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "INTEGER");
    }

    #[test]
    fn test_bits_syntax_parent_linking() {
        // BITS-based type: SYNTAX BITS { flag1(0), flag2(1) }
        let typedef = TypeDef {
            name: Symbol::from_name("TestBitsType"),
            syntax: TypeSyntax::Bits(vec![
                NamedBit::new(Symbol::from_name("flag1"), 0),
                NamedBit::new(Symbol::from_name("flag2"), 1),
            ]),
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![Definition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let type_id = ctx.lookup_type("TestBitsType").expect("type should exist");
        let typ = ctx.model.get_type(type_id).expect("type should exist");

        // Should have parent_type pointing to BITS primitive
        assert!(
            typ.parent_type.is_some(),
            "parent_type should be set for Bits syntax"
        );

        let parent_id = typ.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "BITS");
    }

    #[test]
    fn test_builtin_tc_has_primitive_parent() {
        // Verify that built-in TCs like DisplayString have parent linking to primitives
        let modules = vec![make_test_module("TEST-MIB", vec![])];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        // DisplayString should have OCTET STRING as parent
        let display_string_id = ctx
            .lookup_type("DisplayString")
            .expect("DisplayString should exist");
        let display_string = ctx
            .model
            .get_type(display_string_id)
            .expect("type should exist");

        assert!(
            display_string.parent_type.is_some(),
            "DisplayString should have parent_type"
        );
        let parent_id = display_string.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "OCTET STRING");

        // TruthValue should have INTEGER as parent
        let truth_value_id = ctx
            .lookup_type("TruthValue")
            .expect("TruthValue should exist");
        let truth_value = ctx
            .model
            .get_type(truth_value_id)
            .expect("type should exist");

        assert!(
            truth_value.parent_type.is_some(),
            "TruthValue should have parent_type"
        );
        let parent_id = truth_value.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "INTEGER");

        // AutonomousType should have OBJECT IDENTIFIER as parent
        let autonomous_type_id = ctx
            .lookup_type("AutonomousType")
            .expect("AutonomousType should exist");
        let autonomous_type = ctx
            .model
            .get_type(autonomous_type_id)
            .expect("type should exist");

        assert!(
            autonomous_type.parent_type.is_some(),
            "AutonomousType should have parent_type"
        );
        let parent_id = autonomous_type.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "OBJECT IDENTIFIER");
    }

    #[test]
    fn test_full_type_chain_includes_primitive() {
        // MyString -> DisplayString -> OCTET STRING
        let typedef = TypeDef {
            name: Symbol::from_name("MyString"),
            syntax: TypeSyntax::TypeRef(Symbol::from_name("DisplayString")),
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![("SNMPv2-TC", "DisplayString")],
            vec![Definition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);

        let my_string_id = ctx.lookup_type("MyString").expect("MyString should exist");
        let chain = ctx.model.get_type_chain(my_string_id);

        // Chain should be: MyString -> DisplayString -> OCTET STRING
        assert!(
            chain.len() >= 3,
            "chain should have at least 3 types, got {}",
            chain.len()
        );

        let names: Vec<_> = chain.iter().map(|t| ctx.model.get_str(t.name)).collect();

        assert_eq!(names[0], "MyString");
        assert_eq!(names[1], "DisplayString");
        assert_eq!(names[2], "OCTET STRING");
    }

    // ============================================================
    // Tests for forward reference resolution (multi-pass)
    // ============================================================

    #[test]
    fn test_forward_reference_type_resolution() {
        // DerivedString references BaseString, but DerivedString is defined first.
        // This tests that forward references within a module are handled correctly.
        //
        // DerivedString ::= TEXTUAL-CONVENTION SYNTAX BaseString (SIZE (0..64))
        // BaseString ::= TEXTUAL-CONVENTION SYNTAX OCTET STRING (SIZE (0..255))
        use alloc::boxed::Box;

        let derived = TypeDef {
            name: Symbol::from_name("DerivedString"),
            syntax: TypeSyntax::Constrained {
                base: Box::new(TypeSyntax::TypeRef(Symbol::from_name("BaseString"))),
                constraint: Constraint::Size(vec![Range {
                    min: RangeValue::Unsigned(0),
                    max: Some(RangeValue::Unsigned(64)),
                }]),
            },
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let base = TypeDef {
            name: Symbol::from_name("BaseString"),
            syntax: TypeSyntax::Constrained {
                base: Box::new(TypeSyntax::OctetString),
                constraint: Constraint::Size(vec![Range {
                    min: RangeValue::Unsigned(0),
                    max: Some(RangeValue::Unsigned(255)),
                }]),
            },
            base_type: None,
            display_hint: Some("255a".into()),
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        // Note: DerivedString is defined BEFORE BaseString (forward reference)
        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![Definition::TypeDef(derived), Definition::TypeDef(base)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        // Both types should exist
        let derived_id = ctx
            .lookup_type("DerivedString")
            .expect("DerivedString should exist");
        let base_id = ctx
            .lookup_type("BaseString")
            .expect("BaseString should exist");

        // Check parent pointer: DerivedString -> BaseString
        let derived_type = ctx.model.get_type(derived_id).expect("type should exist");
        assert_eq!(
            derived_type.parent_type,
            Some(base_id),
            "DerivedString should have BaseString as parent"
        );

        // Check base type inheritance: DerivedString should inherit OctetString
        assert_eq!(
            derived_type.base,
            BaseType::OctetString,
            "DerivedString should inherit OctetString base from BaseString"
        );

        // Verify the chain: DerivedString -> BaseString -> OCTET STRING
        let chain = ctx.model.get_type_chain(derived_id);
        assert!(
            chain.len() >= 3,
            "chain should have at least DerivedString, BaseString, OCTET STRING"
        );
        let names: Vec<_> = chain.iter().map(|t| ctx.model.get_str(t.name)).collect();
        assert_eq!(names[0], "DerivedString");
        assert_eq!(names[1], "BaseString");
        assert_eq!(names[2], "OCTET STRING");
    }

    #[test]
    fn test_forward_reference_chain_three_levels() {
        // Tests a chain of three user types with forward references:
        // Level1 references Level2, Level2 references Level3, Level3 references DisplayString
        // All defined in reverse order (Level1 first, Level3 last before DisplayString)

        let level1 = TypeDef {
            name: Symbol::from_name("Level1"),
            syntax: TypeSyntax::TypeRef(Symbol::from_name("Level2")),
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let level2 = TypeDef {
            name: Symbol::from_name("Level2"),
            syntax: TypeSyntax::TypeRef(Symbol::from_name("Level3")),
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let level3 = TypeDef {
            name: Symbol::from_name("Level3"),
            syntax: TypeSyntax::TypeRef(Symbol::from_name("DisplayString")),
            base_type: None,
            display_hint: None,
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        // Defined in reverse order (forward references)
        let modules = vec![make_test_module_with_imports(
            "TEST-MIB",
            vec![("SNMPv2-TC", "DisplayString")],
            vec![
                Definition::TypeDef(level1),
                Definition::TypeDef(level2),
                Definition::TypeDef(level3),
            ],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);

        // All types should exist
        let level1_id = ctx.lookup_type("Level1").expect("Level1 should exist");

        // Check base type inheritance: Level1 should ultimately resolve to OctetString
        let level1_type = ctx.model.get_type(level1_id).expect("type should exist");
        assert_eq!(
            level1_type.base,
            BaseType::OctetString,
            "Level1 should inherit OctetString base through the chain"
        );

        // Verify the full chain
        let chain = ctx.model.get_type_chain(level1_id);
        assert!(
            chain.len() >= 4,
            "chain should have at least Level1, Level2, Level3, DisplayString"
        );
        let names: Vec<_> = chain.iter().map(|t| ctx.model.get_str(t.name)).collect();
        assert_eq!(names[0], "Level1");
        assert_eq!(names[1], "Level2");
        assert_eq!(names[2], "Level3");
        assert_eq!(names[3], "DisplayString");
    }

    // ============================================================
    // Tests for RFC1213-MIB legacy type linking
    // ============================================================

    #[test]
    fn test_rfc1213_displaystring_links_to_snmpv2_tc() {
        // RFC1213-MIB defines DisplayString as a plain type alias without TC metadata.
        // This test verifies that it gets linked to SNMPv2-TC's DisplayString,
        // allowing get_effective_hint() to find the "255a" hint.
        use alloc::boxed::Box;

        // Simulate RFC1213-MIB's DisplayString definition:
        // DisplayString ::= OCTET STRING (SIZE (0..255))
        let rfc1213_displaystring = TypeDef {
            name: Symbol::from_name("DisplayString"),
            syntax: TypeSyntax::Constrained {
                base: Box::new(TypeSyntax::OctetString),
                constraint: Constraint::Size(vec![Range {
                    min: RangeValue::Unsigned(0),
                    max: Some(RangeValue::Unsigned(255)),
                }]),
            },
            base_type: None,
            display_hint: None, // RFC1213-MIB has no hint
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: false, // Not a TC in SMIv1
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "RFC1213-MIB",
            vec![Definition::TypeDef(rfc1213_displaystring)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);

        // Find RFC1213-MIB's module ID
        let rfc1213_module_id = ctx
            .get_module_id_by_name("RFC1213-MIB")
            .expect("RFC1213-MIB should exist");

        // Find SNMPv2-TC's module ID
        let snmpv2_tc_module_id = ctx
            .get_module_id_by_name("SNMPv2-TC")
            .expect("SNMPv2-TC should exist");

        // Look up RFC1213-MIB's DisplayString
        let rfc1213_ds_id = ctx
            .lookup_type_for_module(rfc1213_module_id, "DisplayString")
            .expect("RFC1213-MIB DisplayString should exist");

        // Look up SNMPv2-TC's DisplayString
        let snmpv2_tc_ds_id = ctx
            .lookup_type_for_module(snmpv2_tc_module_id, "DisplayString")
            .expect("SNMPv2-TC DisplayString should exist");

        // They should be different TypeIds (module scoping preserved)
        assert_ne!(
            rfc1213_ds_id, snmpv2_tc_ds_id,
            "RFC1213-MIB and SNMPv2-TC should have separate DisplayString TypeIds"
        );

        // RFC1213-MIB's DisplayString should have SNMPv2-TC's as parent
        let rfc1213_ds = ctx
            .model
            .get_type(rfc1213_ds_id)
            .expect("type should exist");
        assert_eq!(
            rfc1213_ds.parent_type,
            Some(snmpv2_tc_ds_id),
            "RFC1213-MIB DisplayString should have SNMPv2-TC DisplayString as parent"
        );

        // get_effective_hint should find SNMPv2-TC's "255a" hint
        let effective_hint = ctx.model.get_effective_hint(rfc1213_ds_id);
        assert!(
            effective_hint.is_some(),
            "should find hint from SNMPv2-TC via parent chain"
        );
        assert_eq!(
            ctx.model.get_str(effective_hint.unwrap()),
            "255a",
            "effective hint should be '255a' from SNMPv2-TC"
        );
    }

    #[test]
    fn test_rfc1213_physaddress_links_to_snmpv2_tc() {
        // Similar test for PhysAddress
        let rfc1213_physaddress = TypeDef {
            name: Symbol::from_name("PhysAddress"),
            syntax: TypeSyntax::OctetString,
            base_type: None,
            display_hint: None, // RFC1213-MIB has no hint
            status: ModuleStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: false,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "RFC1213-MIB",
            vec![Definition::TypeDef(rfc1213_physaddress)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_imports(&mut ctx);
        resolve_types(&mut ctx);

        let rfc1213_module_id = ctx
            .get_module_id_by_name("RFC1213-MIB")
            .expect("RFC1213-MIB should exist");
        let snmpv2_tc_module_id = ctx
            .get_module_id_by_name("SNMPv2-TC")
            .expect("SNMPv2-TC should exist");

        let rfc1213_pa_id = ctx
            .lookup_type_for_module(rfc1213_module_id, "PhysAddress")
            .expect("RFC1213-MIB PhysAddress should exist");
        let snmpv2_tc_pa_id = ctx
            .lookup_type_for_module(snmpv2_tc_module_id, "PhysAddress")
            .expect("SNMPv2-TC PhysAddress should exist");

        // They should be different TypeIds
        assert_ne!(rfc1213_pa_id, snmpv2_tc_pa_id);

        // RFC1213-MIB's PhysAddress should have SNMPv2-TC's as parent
        let rfc1213_pa = ctx
            .model
            .get_type(rfc1213_pa_id)
            .expect("type should exist");
        assert_eq!(rfc1213_pa.parent_type, Some(snmpv2_tc_pa_id));

        // get_effective_hint should find SNMPv2-TC's "1x:" hint
        let effective_hint = ctx.model.get_effective_hint(rfc1213_pa_id);
        assert!(effective_hint.is_some());
        assert_eq!(ctx.model.get_str(effective_hint.unwrap()), "1x:");
    }
}
