//! Phase 3: Type resolution.
//!
//! Build the type graph with inheritance chains and resolve all type references.

use crate::hir::{HirConstraint, HirDefinition, HirRange, HirRangeValue, HirStatus, HirTypeSyntax};
use crate::model::{
    BaseType, BitDefinitions, EnumValues, RangeBound, ResolvedType, SizeConstraint, Status, TypeId,
    ValueConstraint,
};
use crate::resolver::context::ResolverContext;
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
fn seed_primitive_types(ctx: &mut ResolverContext) {
    // Use a pseudo-module for primitives (module_id=1 which is SNMPv2-SMI)
    let module_id = crate::model::ModuleId::from_raw(1).unwrap();

    // INTEGER - base integer type
    let name = ctx.intern("INTEGER");
    let typ = ResolvedType::new(name, module_id, BaseType::Integer32);
    let type_id = ctx.model.add_type(typ).unwrap();
    ctx.register_type_symbol(name, type_id);

    // OCTET STRING - base octet string type
    let name = ctx.intern("OCTET STRING");
    let typ = ResolvedType::new(name, module_id, BaseType::OctetString);
    let type_id = ctx.model.add_type(typ).unwrap();
    ctx.register_type_symbol(name, type_id);

    // OBJECT IDENTIFIER - base OID type
    let name = ctx.intern("OBJECT IDENTIFIER");
    let typ = ResolvedType::new(name, module_id, BaseType::ObjectIdentifier);
    let type_id = ctx.model.add_type(typ).unwrap();
    ctx.register_type_symbol(name, type_id);

    // BITS - bit string type
    let name = ctx.intern("BITS");
    let typ = ResolvedType::new(name, module_id, BaseType::Bits);
    let type_id = ctx.model.add_type(typ).unwrap();
    ctx.register_type_symbol(name, type_id);
}

/// Create type nodes for all user-defined types.
fn create_user_types(ctx: &mut ResolverContext) {
    // Collect type definitions
    let type_defs: Vec<_> = ctx
        .hir_modules
        .iter()
        .enumerate()
        .flat_map(|(module_idx, module)| {
            module
                .definitions
                .iter()
                .enumerate()
                .filter_map(move |(def_idx, def)| {
                    if let HirDefinition::TypeDef(td) = def {
                        Some((module_idx, def_idx, td.clone()))
                    } else {
                        None
                    }
                })
        })
        .collect();

    for (module_idx, _def_idx, td) in type_defs {
        let module_id = match ctx.get_module_id_for_hir_index(module_idx) {
            Some(id) => id,
            None => continue, // Skip if module not registered (shouldn't happen)
        };

        let name = ctx.intern(&td.name.name);

        // Determine base type from syntax (None means it needs parent resolution)
        let base = syntax_to_base_type(&td.syntax).unwrap_or(BaseType::Integer32);

        let mut typ = ResolvedType::new(name, module_id, base);

        // Track if base type needs resolution from parent
        typ.needs_base_resolution = syntax_to_base_type(&td.syntax).is_none();

        typ.is_textual_convention = td.is_textual_convention;
        typ.status = hir_status_to_status(td.status);

        if let Some(ref hint) = td.display_hint {
            typ.hint = Some(ctx.intern(hint));
        }

        if let Some(ref desc) = td.description {
            typ.description = Some(ctx.intern(desc));
        }

        // Handle enum values from syntax
        if let HirTypeSyntax::IntegerEnum(enums) = &td.syntax {
            let values: Vec<_> = enums
                .iter()
                .map(|(sym, val)| (*val, ctx.intern(&sym.name)))
                .collect();
            typ.enum_values = Some(EnumValues::new(values));
        }

        // Handle BITS from syntax
        if let HirTypeSyntax::Bits(bits) = &td.syntax {
            let defs: Vec<_> = bits
                .iter()
                .map(|(sym, pos)| (*pos, ctx.intern(&sym.name)))
                .collect();
            typ.bit_defs = Some(BitDefinitions::new(defs));
        }

        // Handle constraints
        if let HirTypeSyntax::Constrained { constraint, .. } = &td.syntax {
            match constraint {
                HirConstraint::Size(ranges) => {
                    typ.size = Some(hir_ranges_to_size_constraint(ranges));
                }
                HirConstraint::Range(ranges) => {
                    typ.value_range = Some(hir_ranges_to_value_constraint(ranges));
                }
            }
        }

        let type_id = ctx.model.add_type(typ).unwrap();
        ctx.register_type_symbol(name, type_id);

        // Add to module
        if let Some(module) = ctx.model.get_module_mut(module_id) {
            module.add_type(type_id);
        }
    }
}

/// Resolve base types and set parent pointers.
fn resolve_type_bases(ctx: &mut ResolverContext) {
    // First pass: link TypeRef-based types to their parent
    link_typeref_parents(ctx);

    // Second pass: link primitive-syntax types to their primitive parents
    // This handles types like `DisplayString SYNTAX OCTET STRING (SIZE ...)` which
    // should have parent_type pointing to "OCTET STRING".
    link_primitive_syntax_parents(ctx);

    // Third pass: inherit base types from parents for types that need it
    inherit_base_types(ctx);
}

/// Link types that use TypeRef syntax to their parent types.
fn link_typeref_parents(ctx: &mut ResolverContext) {
    // For each type with a TypeRef syntax, try to resolve the parent
    let type_refs: Vec<_> = ctx
        .hir_modules
        .iter()
        .enumerate()
        .flat_map(|(module_idx, module)| {
            module
                .definitions
                .iter()
                .filter_map(move |def| {
                    if let HirDefinition::TypeDef(td) = def {
                        if let HirTypeSyntax::TypeRef(ref base_name) = td.syntax {
                            return Some((module_idx, td.name.name.clone(), base_name.name.clone(), td.span));
                        }
                        if let HirTypeSyntax::Constrained { ref base, .. } = td.syntax {
                            if let HirTypeSyntax::TypeRef(ref base_name) = **base {
                                return Some((module_idx, td.name.name.clone(), base_name.name.clone(), td.span));
                            }
                        }
                    }
                    None
                })
        })
        .collect();

    for (module_idx, type_name, base_name, span) in type_refs {
        let module_id = match ctx.get_module_id_for_hir_index(module_idx) {
            Some(id) => id,
            None => continue, // Skip if module not registered (shouldn't happen)
        };

        // Look up the type and its base
        if let (Some(type_id), Some(parent_id)) = (
            ctx.lookup_type(&type_name),
            ctx.lookup_type(&base_name),
        ) {
            // Set parent pointer
            if let Some(typ) = ctx.model.get_type_mut(type_id) {
                typ.parent_type = Some(parent_id);
            }
        } else if ctx.lookup_type(&base_name).is_none() {
            ctx.record_unresolved_type(module_id, &type_name, &base_name, span);
        }
    }
}

/// Get the primitive type name for a syntax that uses primitive syntax directly.
///
/// Returns the primitive type name to link as parent for:
/// - `HirTypeSyntax::OctetString` -> "OCTET STRING"
/// - `HirTypeSyntax::ObjectIdentifier` -> "OBJECT IDENTIFIER"
/// - `HirTypeSyntax::IntegerEnum` -> "INTEGER"
/// - `HirTypeSyntax::Bits` -> "BITS"
/// - `HirTypeSyntax::Constrained { base: OctetString/ObjectIdentifier, .. }` -> respective primitive
fn get_primitive_parent_name(syntax: &HirTypeSyntax) -> Option<&'static str> {
    match syntax {
        HirTypeSyntax::OctetString => Some("OCTET STRING"),
        HirTypeSyntax::ObjectIdentifier => Some("OBJECT IDENTIFIER"),
        HirTypeSyntax::IntegerEnum(_) => Some("INTEGER"),
        HirTypeSyntax::Bits(_) => Some("BITS"),
        HirTypeSyntax::Constrained { base, .. } => {
            match **base {
                HirTypeSyntax::OctetString => Some("OCTET STRING"),
                HirTypeSyntax::ObjectIdentifier => Some("OBJECT IDENTIFIER"),
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
    // Collect types that need primitive parent linking
    let primitive_links: Vec<_> = ctx
        .hir_modules
        .iter()
        .flat_map(|module| {
            module
                .definitions
                .iter()
                .filter_map(|def| {
                    if let HirDefinition::TypeDef(td) = def {
                        get_primitive_parent_name(&td.syntax)
                            .map(|primitive_name| (td.name.name.clone(), primitive_name))
                    } else {
                        None
                    }
                })
        })
        .collect();

    // Link each type to its primitive parent
    for (type_name, primitive_name) in primitive_links {
        if let (Some(type_id), Some(parent_id)) = (
            ctx.lookup_type(&type_name),
            ctx.lookup_type(primitive_name),
        ) {
            if let Some(typ) = ctx.model.get_type_mut(type_id) {
                // Only set if not already set (TypeRef linking takes precedence)
                if typ.parent_type.is_none() {
                    typ.parent_type = Some(parent_id);
                }
            }
        }
    }
}

/// Inherit base types from parent types.
/// This handles cases like `MyString ::= DisplayString` where MyString needs
/// to inherit OctetString as its base type from DisplayString.
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
        if let Some(base) = resolve_base_from_chain(ctx, type_id) {
            if let Some(typ) = ctx.model.get_type_mut(type_id) {
                typ.base = base;
                typ.needs_base_resolution = false;
            }
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

/// Convert HirTypeSyntax to BaseType.
/// Returns None for TypeRef that cannot be immediately resolved (will be inherited from parent).
fn syntax_to_base_type(syntax: &HirTypeSyntax) -> Option<BaseType> {
    match syntax {
        HirTypeSyntax::TypeRef(name) => {
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
        HirTypeSyntax::IntegerEnum(_) => Some(BaseType::Integer32),
        HirTypeSyntax::Bits(_) => Some(BaseType::Bits),
        HirTypeSyntax::OctetString => Some(BaseType::OctetString),
        HirTypeSyntax::ObjectIdentifier => Some(BaseType::ObjectIdentifier),
        HirTypeSyntax::Constrained { base, .. } => syntax_to_base_type(base),
        HirTypeSyntax::SequenceOf(_) | HirTypeSyntax::Sequence(_) => Some(BaseType::Sequence),
    }
}

/// Convert HirStatus to Status.
fn hir_status_to_status(status: HirStatus) -> Status {
    match status {
        HirStatus::Current => Status::Current,
        HirStatus::Deprecated => Status::Deprecated,
        HirStatus::Obsolete => Status::Obsolete,
    }
}

/// Convert HIR ranges to SizeConstraint.
fn hir_ranges_to_size_constraint(ranges: &[HirRange]) -> SizeConstraint {
    let size_ranges: Vec<_> = ranges
        .iter()
        .map(|r| {
            let min = range_value_to_u32(&r.min);
            let max = r.max.as_ref().map_or(min, |m| range_value_to_u32(m));
            (min, max)
        })
        .collect();
    SizeConstraint { ranges: size_ranges }
}

/// Convert HIR ranges to ValueConstraint.
fn hir_ranges_to_value_constraint(ranges: &[HirRange]) -> ValueConstraint {
    let value_ranges: Vec<_> = ranges
        .iter()
        .map(|r| {
            let min = range_value_to_bound(&r.min);
            let max = r.max.as_ref().map_or(min, |m| range_value_to_bound(m));
            (min, max)
        })
        .collect();
    ValueConstraint { ranges: value_ranges }
}

fn range_value_to_u32(v: &HirRangeValue) -> u32 {
    match v {
        HirRangeValue::Signed(n) => *n as u32,
        HirRangeValue::Unsigned(n) => *n as u32,
        HirRangeValue::Min => 0,
        HirRangeValue::Max => u32::MAX,
    }
}

fn range_value_to_bound(v: &HirRangeValue) -> RangeBound {
    match v {
        HirRangeValue::Signed(n) => RangeBound::Signed(*n),
        HirRangeValue::Unsigned(n) => RangeBound::Unsigned(*n),
        // For MIN/MAX, we use signed variants as they're typically used in signed integer contexts
        // The actual interpretation depends on the type (Integer32 vs Counter64)
        HirRangeValue::Min => RangeBound::Signed(i64::MIN),
        HirRangeValue::Max => RangeBound::Unsigned(u64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{HirModule, HirTypeDef, Symbol};
    use crate::lexer::Span;
    use crate::resolver::phases::registration::register_modules;
    use alloc::vec;

    fn make_test_module(name: &str, defs: Vec<HirDefinition>) -> HirModule {
        let mut module = HirModule::new(Symbol::from_str(name), Span::new(0, 0));
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
        let typedef = HirTypeDef {
            name: Symbol::from_str("MyString"),
            syntax: HirTypeSyntax::TypeRef(Symbol::from_str("DisplayString")),
            display_hint: None,
            status: HirStatus::Current,
            description: Some("Test type".into()),
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        assert!(ctx.lookup_type("MyString").is_some());
    }

    #[test]
    fn test_type_inheritance_parent_pointer() {
        // MyString ::= DisplayString
        // DisplayString is a built-in TC based on OCTET STRING
        let typedef = HirTypeDef {
            name: Symbol::from_str("MyString"),
            syntax: HirTypeSyntax::TypeRef(Symbol::from_str("DisplayString")),
            display_hint: None,
            status: HirStatus::Current,
            description: Some("Test type".into()),
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        // Check parent pointer is set
        let my_string_id = ctx.lookup_type("MyString").expect("MyString should exist");
        let my_string = ctx.model.get_type(my_string_id).expect("type should exist");
        assert!(my_string.parent_type.is_some(), "parent_type should be set");

        let display_string_id = ctx.lookup_type("DisplayString").expect("DisplayString should exist");
        assert_eq!(my_string.parent_type, Some(display_string_id));
    }

    #[test]
    fn test_type_inheritance_base_type() {
        // MyString ::= DisplayString
        // DisplayString is based on OCTET STRING, so MyString should have OctetString base
        let typedef = HirTypeDef {
            name: Symbol::from_str("MyString"),
            syntax: HirTypeSyntax::TypeRef(Symbol::from_str("DisplayString")),
            display_hint: None,
            status: HirStatus::Current,
            description: Some("Test type".into()),
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let my_string_id = ctx.lookup_type("MyString").expect("MyString should exist");
        let my_string = ctx.model.get_type(my_string_id).expect("type should exist");

        // Base type should be inherited from DisplayString -> OCTET STRING
        assert_eq!(my_string.base, BaseType::OctetString,
            "MyString should inherit OctetString base from DisplayString");
    }

    #[test]
    fn test_type_chain() {
        // MyString ::= DisplayString (which is based on OCTET STRING)
        let typedef = HirTypeDef {
            name: Symbol::from_str("MyString"),
            syntax: HirTypeSyntax::TypeRef(Symbol::from_str("DisplayString")),
            display_hint: None,
            status: HirStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let my_string_id = ctx.lookup_type("MyString").expect("MyString should exist");

        // Get the type chain
        let chain = ctx.model.get_type_chain(my_string_id);
        assert!(chain.len() >= 2, "chain should have at least MyString and DisplayString");

        // First should be MyString
        assert_eq!(ctx.model.get_str(chain[0].name), "MyString");
        // Second should be DisplayString
        assert_eq!(ctx.model.get_str(chain[1].name), "DisplayString");
    }

    #[test]
    fn test_multi_level_inheritance() {
        // Create: MyString2 ::= MyString ::= DisplayString
        let typedef1 = HirTypeDef {
            name: Symbol::from_str("MyString"),
            syntax: HirTypeSyntax::TypeRef(Symbol::from_str("DisplayString")),
            display_hint: Some("255a".into()),
            status: HirStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let typedef2 = HirTypeDef {
            name: Symbol::from_str("MyString2"),
            syntax: HirTypeSyntax::TypeRef(Symbol::from_str("MyString")),
            display_hint: None, // No hint - should inherit from MyString
            status: HirStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::TypeDef(typedef1), HirDefinition::TypeDef(typedef2)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let my_string2_id = ctx.lookup_type("MyString2").expect("MyString2 should exist");
        let my_string2 = ctx.model.get_type(my_string2_id).expect("type should exist");

        // Base type should propagate through the chain
        assert_eq!(my_string2.base, BaseType::OctetString,
            "MyString2 should inherit OctetString base through MyString -> DisplayString");

        // Type chain should have 3 levels
        let chain = ctx.model.get_type_chain(my_string2_id);
        assert!(chain.len() >= 3, "chain should have at least MyString2, MyString, DisplayString");

        // get_effective_hint should find MyString's hint
        let effective_hint = ctx.model.get_effective_hint(my_string2_id);
        assert!(effective_hint.is_some(), "should find hint from parent chain");
        assert_eq!(ctx.model.get_str(effective_hint.unwrap()), "255a");
    }

    #[test]
    fn test_sequence_base_type() {
        // SEQUENCE types should have BaseType::Sequence
        let typedef = HirTypeDef {
            name: Symbol::from_str("IfEntry"),
            syntax: HirTypeSyntax::Sequence(vec![]),
            display_hint: None,
            status: HirStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: false,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let if_entry_id = ctx.lookup_type("IfEntry").expect("IfEntry should exist");
        let if_entry = ctx.model.get_type(if_entry_id).expect("type should exist");

        assert_eq!(if_entry.base, BaseType::Sequence,
            "SEQUENCE types should have BaseType::Sequence");
    }

    // ============================================================
    // Tests for primitive syntax parent linking (Issue #3 fix)
    // ============================================================

    #[test]
    fn test_octet_string_syntax_parent_linking() {
        // PhysAddress-like TC: SYNTAX OCTET STRING (no constraint)
        let typedef = HirTypeDef {
            name: Symbol::from_str("TestPhysAddress"),
            syntax: HirTypeSyntax::OctetString,
            display_hint: Some("1x:".into()),
            status: HirStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let type_id = ctx.lookup_type("TestPhysAddress").expect("type should exist");
        let typ = ctx.model.get_type(type_id).expect("type should exist");

        // Should have parent_type pointing to OCTET STRING primitive
        assert!(typ.parent_type.is_some(), "parent_type should be set for OctetString syntax");

        let parent_id = typ.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "OCTET STRING");
    }

    #[test]
    fn test_constrained_octet_string_parent_linking() {
        use alloc::boxed::Box;
        // DisplayString-like TC: SYNTAX OCTET STRING (SIZE (0..255))
        let typedef = HirTypeDef {
            name: Symbol::from_str("TestDisplayString"),
            syntax: HirTypeSyntax::Constrained {
                base: Box::new(HirTypeSyntax::OctetString),
                constraint: HirConstraint::Size(vec![HirRange {
                    min: HirRangeValue::Unsigned(0),
                    max: Some(HirRangeValue::Unsigned(255)),
                }]),
            },
            display_hint: Some("255a".into()),
            status: HirStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let type_id = ctx.lookup_type("TestDisplayString").expect("type should exist");
        let typ = ctx.model.get_type(type_id).expect("type should exist");

        // Should have parent_type pointing to OCTET STRING primitive
        assert!(typ.parent_type.is_some(), "parent_type should be set for constrained OctetString");

        let parent_id = typ.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "OCTET STRING");
    }

    #[test]
    fn test_object_identifier_syntax_parent_linking() {
        // AutonomousType-like TC: SYNTAX OBJECT IDENTIFIER
        let typedef = HirTypeDef {
            name: Symbol::from_str("TestAutonomousType"),
            syntax: HirTypeSyntax::ObjectIdentifier,
            display_hint: None,
            status: HirStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let type_id = ctx.lookup_type("TestAutonomousType").expect("type should exist");
        let typ = ctx.model.get_type(type_id).expect("type should exist");

        // Should have parent_type pointing to OBJECT IDENTIFIER primitive
        assert!(typ.parent_type.is_some(), "parent_type should be set for ObjectIdentifier syntax");

        let parent_id = typ.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "OBJECT IDENTIFIER");
    }

    #[test]
    fn test_integer_enum_syntax_parent_linking() {
        // TruthValue-like TC: SYNTAX INTEGER { true(1), false(2) }
        let typedef = HirTypeDef {
            name: Symbol::from_str("TestTruthValue"),
            syntax: HirTypeSyntax::IntegerEnum(vec![
                (Symbol::from_str("true"), 1),
                (Symbol::from_str("false"), 2),
            ]),
            display_hint: None,
            status: HirStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let type_id = ctx.lookup_type("TestTruthValue").expect("type should exist");
        let typ = ctx.model.get_type(type_id).expect("type should exist");

        // Should have parent_type pointing to INTEGER primitive
        assert!(typ.parent_type.is_some(), "parent_type should be set for IntegerEnum syntax");

        let parent_id = typ.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "INTEGER");
    }

    #[test]
    fn test_bits_syntax_parent_linking() {
        // BITS-based type: SYNTAX BITS { flag1(0), flag2(1) }
        let typedef = HirTypeDef {
            name: Symbol::from_str("TestBitsType"),
            syntax: HirTypeSyntax::Bits(vec![
                (Symbol::from_str("flag1"), 0),
                (Symbol::from_str("flag2"), 1),
            ]),
            display_hint: None,
            status: HirStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let type_id = ctx.lookup_type("TestBitsType").expect("type should exist");
        let typ = ctx.model.get_type(type_id).expect("type should exist");

        // Should have parent_type pointing to BITS primitive
        assert!(typ.parent_type.is_some(), "parent_type should be set for Bits syntax");

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
        let display_string_id = ctx.lookup_type("DisplayString").expect("DisplayString should exist");
        let display_string = ctx.model.get_type(display_string_id).expect("type should exist");

        assert!(display_string.parent_type.is_some(), "DisplayString should have parent_type");
        let parent_id = display_string.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "OCTET STRING");

        // TruthValue should have INTEGER as parent
        let truth_value_id = ctx.lookup_type("TruthValue").expect("TruthValue should exist");
        let truth_value = ctx.model.get_type(truth_value_id).expect("type should exist");

        assert!(truth_value.parent_type.is_some(), "TruthValue should have parent_type");
        let parent_id = truth_value.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "INTEGER");

        // AutonomousType should have OBJECT IDENTIFIER as parent
        let autonomous_type_id = ctx.lookup_type("AutonomousType").expect("AutonomousType should exist");
        let autonomous_type = ctx.model.get_type(autonomous_type_id).expect("type should exist");

        assert!(autonomous_type.parent_type.is_some(), "AutonomousType should have parent_type");
        let parent_id = autonomous_type.parent_type.unwrap();
        let parent = ctx.model.get_type(parent_id).expect("parent should exist");
        assert_eq!(ctx.model.get_str(parent.name), "OBJECT IDENTIFIER");
    }

    #[test]
    fn test_full_type_chain_includes_primitive() {
        // MyString -> DisplayString -> OCTET STRING
        let typedef = HirTypeDef {
            name: Symbol::from_str("MyString"),
            syntax: HirTypeSyntax::TypeRef(Symbol::from_str("DisplayString")),
            display_hint: None,
            status: HirStatus::Current,
            description: None,
            reference: None,
            is_textual_convention: true,
            span: Span::new(0, 0),
        };

        let modules = vec![make_test_module(
            "TEST-MIB",
            vec![HirDefinition::TypeDef(typedef)],
        )];
        let mut ctx = ResolverContext::new(modules);

        register_modules(&mut ctx);
        resolve_types(&mut ctx);

        let my_string_id = ctx.lookup_type("MyString").expect("MyString should exist");
        let chain = ctx.model.get_type_chain(my_string_id);

        // Chain should be: MyString -> DisplayString -> OCTET STRING
        assert!(chain.len() >= 3, "chain should have at least 3 types, got {}", chain.len());

        let names: Vec<_> = chain.iter()
            .map(|t| ctx.model.get_str(t.name))
            .collect();

        assert_eq!(names[0], "MyString");
        assert_eq!(names[1], "DisplayString");
        assert_eq!(names[2], "OCTET STRING");
    }
}
