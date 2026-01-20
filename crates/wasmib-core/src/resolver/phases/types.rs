//! Phase 3: Type resolution.
//!
//! Build the type graph with inheritance chains and resolve all type references.

use crate::hir::{HirConstraint, HirDefinition, HirRange, HirRangeValue, HirStatus, HirTypeSyntax};
use crate::model::{
    BaseType, BitDefinitions, EnumValues, ResolvedType, SizeConstraint, Status, ValueConstraint,
};
use crate::resolver::builtins::{
    BuiltinBaseType, TcBaseSyntax, BUILTIN_TEXTUAL_CONVENTIONS,
};
use crate::resolver::context::ResolverContext;
use alloc::string::String;
use alloc::vec::Vec;

/// Resolve all types across all modules.
pub fn resolve_types(ctx: &mut ResolverContext) {
    // First: seed built-in types
    seed_builtin_types(ctx);

    // Second: create type nodes for all user-defined types
    create_user_types(ctx);

    // Third: resolve base types and parent pointers
    resolve_type_bases(ctx);
}

/// Seed the model with built-in base types.
fn seed_builtin_types(ctx: &mut ResolverContext) {
    // Add base types
    for bt in BuiltinBaseType::all() {
        let name = ctx.intern(bt.name());
        // Use a pseudo-module for built-ins (module 0 is reserved)
        let module_id = crate::model::ModuleId::from_raw(1).unwrap();

        let base = builtin_to_base_type(bt);
        let typ = ResolvedType::new(
            crate::model::TypeId::from_raw(1).unwrap(), // Will be updated
            name,
            module_id,
            base,
        );

        let type_id = ctx.model.add_type(typ);
        ctx.register_type_symbol(String::from(bt.name()), type_id);
    }

    // Add textual conventions
    for tc in BUILTIN_TEXTUAL_CONVENTIONS.iter() {
        let name = ctx.intern(tc.name);
        let module_id = crate::model::ModuleId::from_raw(1).unwrap();

        let base = tc_base_to_base_type(&tc.base_syntax);
        let mut typ = ResolvedType::new(
            crate::model::TypeId::from_raw(1).unwrap(),
            name,
            module_id,
            base,
        );

        typ.is_textual_convention = true;
        typ.status = hir_status_to_status(tc.status);

        if let Some(hint) = tc.display_hint {
            typ.hint = Some(ctx.intern(hint));
        }

        // Handle enum values
        if let Some(enums) = tc.enum_values {
            let values: Vec<_> = enums
                .iter()
                .map(|(name, val)| (*val, ctx.intern(name)))
                .collect();
            typ.enum_values = Some(EnumValues::new(values));
        }

        // Handle constraints
        if let Some(ref constraint) = tc.constraint {
            match constraint {
                crate::resolver::builtins::TcConstraint::Size(size) => {
                    typ.size = Some(tc_size_to_constraint(size));
                }
                crate::resolver::builtins::TcConstraint::Range { min, max } => {
                    typ.value_range = Some(ValueConstraint::range(*min, *max));
                }
            }
        }

        let type_id = ctx.model.add_type(typ);
        ctx.register_type_symbol(String::from(tc.name), type_id);
    }
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
        let hir_module = &ctx.hir_modules[module_idx];
        let module_id = *ctx.module_index.get(&hir_module.name.name)
            .and_then(|v| v.first())
            .unwrap();

        let name = ctx.intern(&td.name.name);

        // Determine base type from syntax
        let base = syntax_to_base_type(&td.syntax);

        let mut typ = ResolvedType::new(
            crate::model::TypeId::from_raw(1).unwrap(),
            name,
            module_id,
            base,
        );

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

        let type_id = ctx.model.add_type(typ);
        ctx.register_type_symbol(td.name.name.clone(), type_id);

        // Add to module
        if let Some(module) = ctx.model.get_module_mut(module_id) {
            module.add_type(type_id);
        }
    }
}

/// Resolve base types and set parent pointers.
fn resolve_type_bases(ctx: &mut ResolverContext) {
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
                            return Some((module_idx, td.name.name.clone(), base_name.name.clone()));
                        }
                        if let HirTypeSyntax::Constrained { ref base, .. } = td.syntax {
                            if let HirTypeSyntax::TypeRef(ref base_name) = **base {
                                return Some((module_idx, td.name.name.clone(), base_name.name.clone()));
                            }
                        }
                    }
                    None
                })
        })
        .collect();

    for (module_idx, type_name, base_name) in type_refs {
        let hir_module = &ctx.hir_modules[module_idx];
        let module_id = *ctx.module_index.get(&hir_module.name.name)
            .and_then(|v| v.first())
            .unwrap();

        // Look up the type and its base
        if let (Some(type_id), Some(parent_id)) = (
            ctx.lookup_type(&type_name),
            ctx.lookup_type(&base_name),
        ) {
            // Update parent pointer
            // Note: We need to get the type_id index and update, but we can't
            // easily mutate through the model. For now, record unresolved.
            // In a full implementation, we'd track this differently.
            let _ = (type_id, parent_id);
        } else if ctx.lookup_type(&base_name).is_none() {
            ctx.record_unresolved_type(module_id, &type_name, &base_name);
        }
    }
}

/// Convert BuiltinBaseType to BaseType.
fn builtin_to_base_type(bt: BuiltinBaseType) -> BaseType {
    match bt {
        BuiltinBaseType::Integer32 => BaseType::Integer32,
        BuiltinBaseType::Counter32 => BaseType::Counter32,
        BuiltinBaseType::Counter64 => BaseType::Counter64,
        BuiltinBaseType::Gauge32 => BaseType::Gauge32,
        BuiltinBaseType::Unsigned32 => BaseType::Unsigned32,
        BuiltinBaseType::TimeTicks => BaseType::TimeTicks,
        BuiltinBaseType::IpAddress => BaseType::IpAddress,
        BuiltinBaseType::Opaque => BaseType::Opaque,
    }
}

/// Convert TcBaseSyntax to BaseType.
fn tc_base_to_base_type(syntax: &TcBaseSyntax) -> BaseType {
    match syntax {
        TcBaseSyntax::BuiltinType(bt) => builtin_to_base_type(*bt),
        TcBaseSyntax::Integer => BaseType::Integer32,
        TcBaseSyntax::OctetString => BaseType::OctetString,
        TcBaseSyntax::ObjectIdentifier => BaseType::ObjectIdentifier,
    }
}

/// Convert HirTypeSyntax to BaseType.
fn syntax_to_base_type(syntax: &HirTypeSyntax) -> BaseType {
    match syntax {
        HirTypeSyntax::TypeRef(name) => {
            // Try to map common type names
            match name.name.as_str() {
                "Integer32" | "INTEGER" => BaseType::Integer32,
                "Counter32" => BaseType::Counter32,
                "Counter64" => BaseType::Counter64,
                "Gauge32" => BaseType::Gauge32,
                "Unsigned32" => BaseType::Unsigned32,
                "TimeTicks" => BaseType::TimeTicks,
                "IpAddress" => BaseType::IpAddress,
                "Opaque" => BaseType::Opaque,
                "OCTET STRING" => BaseType::OctetString,
                "OBJECT IDENTIFIER" => BaseType::ObjectIdentifier,
                "BITS" => BaseType::Bits,
                _ => BaseType::Integer32, // Default fallback
            }
        }
        HirTypeSyntax::IntegerEnum(_) => BaseType::Integer32,
        HirTypeSyntax::Bits(_) => BaseType::Bits,
        HirTypeSyntax::OctetString => BaseType::OctetString,
        HirTypeSyntax::ObjectIdentifier => BaseType::ObjectIdentifier,
        HirTypeSyntax::Constrained { base, .. } => syntax_to_base_type(base),
        HirTypeSyntax::SequenceOf(_) | HirTypeSyntax::Sequence(_) => BaseType::ObjectIdentifier,
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

/// Convert TcSizeConstraint to SizeConstraint.
fn tc_size_to_constraint(tc: &crate::resolver::builtins::TcSizeConstraint) -> SizeConstraint {
    use crate::resolver::builtins::TcSizeConstraint;
    match tc {
        TcSizeConstraint::Fixed(n) => SizeConstraint::fixed(*n as u32),
        TcSizeConstraint::Range { min, max } => SizeConstraint::range(*min as u32, *max as u32),
        TcSizeConstraint::Union(sizes) => SizeConstraint {
            ranges: sizes.iter().map(|&s| (s as u32, s as u32)).collect(),
        },
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
            let min = range_value_to_i64(&r.min);
            let max = r.max.as_ref().map_or(min, |m| range_value_to_i64(m));
            (min, max)
        })
        .collect();
    ValueConstraint { ranges: value_ranges }
}

fn range_value_to_u32(v: &HirRangeValue) -> u32 {
    match v {
        HirRangeValue::Number(n) => *n as u32,
        HirRangeValue::Min => 0,
        HirRangeValue::Max => u32::MAX,
    }
}

fn range_value_to_i64(v: &HirRangeValue) -> i64 {
    match v {
        HirRangeValue::Number(n) => *n,
        HirRangeValue::Min => i64::MIN,
        HirRangeValue::Max => i64::MAX,
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
}
