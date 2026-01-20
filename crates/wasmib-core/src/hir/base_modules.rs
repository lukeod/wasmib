//! Synthetic base modules for SMI definitions.
//!
//! This module generates synthetic [`HirModule`]s for the SMI base modules
//! (SNMPv2-SMI, SNMPv2-TC, SNMPv2-CONF). These contain the built-in types,
//! OID roots, and textual conventions that the resolver needs.
//!
//! # Design
//!
//! Rather than hard-coding built-in recognition throughout the resolver,
//! we generate actual HIR modules that get processed like any user module.
//! This simplifies the resolver by eliminating special-case handling.
//!
//! # Usage
//!
//! ```ignore
//! use wasmib_core::hir::base_modules::create_base_modules;
//!
//! let base_modules = create_base_modules();
//! let mut all_modules = base_modules;
//! all_modules.extend(user_modules);
//! let result = resolver.resolve(all_modules);
//! ```

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::lexer::Span;

use alloc::boxed::Box;

use super::{
    HirConstraint, HirDefinition, HirModule, HirOidAssignment, HirOidComponent, HirRange,
    HirRangeValue, HirStatus, HirTypeDef, HirTypeSyntax, HirValueAssignment, NamedNumber,
    SmiLanguage, Symbol,
};

/// SMI base modules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BaseModule {
    /// SNMPv2-SMI (RFC 2578) - `SMIv2` base types, OIDs, MACROs.
    SnmpV2Smi,
    /// SNMPv2-TC (RFC 2579) - Textual conventions.
    SnmpV2Tc,
    /// SNMPv2-CONF (RFC 2580) - Conformance MACROs.
    SnmpV2Conf,
    /// RFC1155-SMI - `SMIv1` base types, OIDs.
    Rfc1155Smi,
    /// RFC1065-SMI - Original `SMIv1` base (predates RFC 1155).
    Rfc1065Smi,
    /// RFC-1212 - `SMIv1` OBJECT-TYPE MACRO.
    Rfc1212,
    /// RFC-1215 - `SMIv1` TRAP-TYPE MACRO.
    Rfc1215,
    /// RFC1213-MIB - Legacy module (mib-2, `DisplayString`).
    Rfc1213Mib,
}

impl BaseModule {
    /// Get the canonical module name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SnmpV2Smi => "SNMPv2-SMI",
            Self::SnmpV2Tc => "SNMPv2-TC",
            Self::SnmpV2Conf => "SNMPv2-CONF",
            Self::Rfc1155Smi => "RFC1155-SMI",
            Self::Rfc1065Smi => "RFC1065-SMI",
            Self::Rfc1212 => "RFC-1212",
            Self::Rfc1215 => "RFC-1215",
            Self::Rfc1213Mib => "RFC1213-MIB",
        }
    }

    /// Check if this is an `SMIv2` module.
    #[must_use]
    pub const fn is_smiv2(self) -> bool {
        matches!(self, Self::SnmpV2Smi | Self::SnmpV2Tc | Self::SnmpV2Conf)
    }

    /// Check if this is an `SMIv1` module.
    #[must_use]
    pub const fn is_smiv1(self) -> bool {
        matches!(
            self,
            Self::Rfc1155Smi | Self::Rfc1065Smi | Self::Rfc1212 | Self::Rfc1215
        )
    }

    /// Look up a base module by name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SNMPv2-SMI" => Some(Self::SnmpV2Smi),
            "SNMPv2-TC" => Some(Self::SnmpV2Tc),
            "SNMPv2-CONF" => Some(Self::SnmpV2Conf),
            "RFC1155-SMI" => Some(Self::Rfc1155Smi),
            "RFC1065-SMI" => Some(Self::Rfc1065Smi),
            "RFC-1212" => Some(Self::Rfc1212),
            "RFC-1215" => Some(Self::Rfc1215),
            "RFC1213-MIB" => Some(Self::Rfc1213Mib),
            _ => None,
        }
    }

    /// Iterate over all base modules.
    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::SnmpV2Smi,
            Self::SnmpV2Tc,
            Self::SnmpV2Conf,
            Self::Rfc1155Smi,
            Self::Rfc1065Smi,
            Self::Rfc1212,
            Self::Rfc1215,
            Self::Rfc1213Mib,
        ]
        .into_iter()
    }
}

/// Check if a module name is a recognized base module.
#[must_use]
pub fn is_base_module(name: &str) -> bool {
    BaseModule::from_name(name).is_some()
}

/// Create synthetic HIR modules for all base modules.
///
/// Returns modules in order: SNMPv2-SMI, SNMPv2-TC.
/// These should be prepended to the user module list before resolution.
#[must_use]
pub fn create_base_modules() -> Vec<HirModule> {
    vec![create_snmpv2_smi(), create_snmpv2_tc()]
}

/// Create the synthetic SNMPv2-SMI module.
///
/// Contains:
/// - OID root definitions (iso, internet, enterprises, etc.)
/// - Base type definitions (Integer32, Counter32, etc.)
fn create_snmpv2_smi() -> HirModule {
    let mut module = HirModule::new(Symbol::from_name("SNMPv2-SMI"), Span::SYNTHETIC);
    module.language = SmiLanguage::Smiv2;

    // Add OID root definitions
    module.definitions.extend(create_oid_definitions());

    // Add base type definitions
    module.definitions.extend(create_base_type_definitions());

    module
}

/// Create the synthetic SNMPv2-TC module.
///
/// Contains textual convention definitions (`DisplayString`, `TruthValue`, etc.)
fn create_snmpv2_tc() -> HirModule {
    let mut module = HirModule::new(Symbol::from_name("SNMPv2-TC"), Span::SYNTHETIC);
    module.language = SmiLanguage::Smiv2;

    // Add imports from SNMPv2-SMI (for base types used by TCs)
    // Note: The resolver will handle these through the normal import path

    // Add textual convention definitions
    module.definitions.extend(create_tc_definitions());

    module
}

/// Create OID root definitions as `ValueAssignments`.
#[allow(clippy::too_many_lines)] // Data-driven definition list
fn create_oid_definitions() -> Vec<HirDefinition> {
    vec![
        // ccitt OBJECT IDENTIFIER ::= { 0 }
        // ITU-T (formerly CCITT) administered subtree
        make_oid_value("ccitt", vec![HirOidComponent::Number(0)]),
        // iso OBJECT IDENTIFIER ::= { 1 }
        make_oid_value("iso", vec![HirOidComponent::Number(1)]),
        // joint-iso-ccitt OBJECT IDENTIFIER ::= { 2 }
        // Jointly administered by ISO and ITU-T
        make_oid_value("joint-iso-ccitt", vec![HirOidComponent::Number(2)]),
        // org OBJECT IDENTIFIER ::= { iso 3 }
        make_oid_value(
            "org",
            vec![
                HirOidComponent::Name(Symbol::from_name("iso")),
                HirOidComponent::Number(3),
            ],
        ),
        // dod OBJECT IDENTIFIER ::= { org 6 }
        make_oid_value(
            "dod",
            vec![
                HirOidComponent::Name(Symbol::from_name("org")),
                HirOidComponent::Number(6),
            ],
        ),
        // internet OBJECT IDENTIFIER ::= { dod 1 }
        make_oid_value(
            "internet",
            vec![
                HirOidComponent::Name(Symbol::from_name("dod")),
                HirOidComponent::Number(1),
            ],
        ),
        // directory OBJECT IDENTIFIER ::= { internet 1 }
        make_oid_value(
            "directory",
            vec![
                HirOidComponent::Name(Symbol::from_name("internet")),
                HirOidComponent::Number(1),
            ],
        ),
        // mgmt OBJECT IDENTIFIER ::= { internet 2 }
        make_oid_value(
            "mgmt",
            vec![
                HirOidComponent::Name(Symbol::from_name("internet")),
                HirOidComponent::Number(2),
            ],
        ),
        // mib-2 OBJECT IDENTIFIER ::= { mgmt 1 }
        make_oid_value(
            "mib-2",
            vec![
                HirOidComponent::Name(Symbol::from_name("mgmt")),
                HirOidComponent::Number(1),
            ],
        ),
        // transmission OBJECT IDENTIFIER ::= { mib-2 10 }
        make_oid_value(
            "transmission",
            vec![
                HirOidComponent::Name(Symbol::from_name("mib-2")),
                HirOidComponent::Number(10),
            ],
        ),
        // experimental OBJECT IDENTIFIER ::= { internet 3 }
        make_oid_value(
            "experimental",
            vec![
                HirOidComponent::Name(Symbol::from_name("internet")),
                HirOidComponent::Number(3),
            ],
        ),
        // private OBJECT IDENTIFIER ::= { internet 4 }
        make_oid_value(
            "private",
            vec![
                HirOidComponent::Name(Symbol::from_name("internet")),
                HirOidComponent::Number(4),
            ],
        ),
        // enterprises OBJECT IDENTIFIER ::= { private 1 }
        make_oid_value(
            "enterprises",
            vec![
                HirOidComponent::Name(Symbol::from_name("private")),
                HirOidComponent::Number(1),
            ],
        ),
        // security OBJECT IDENTIFIER ::= { internet 5 }
        make_oid_value(
            "security",
            vec![
                HirOidComponent::Name(Symbol::from_name("internet")),
                HirOidComponent::Number(5),
            ],
        ),
        // snmpV2 OBJECT IDENTIFIER ::= { internet 6 }
        make_oid_value(
            "snmpV2",
            vec![
                HirOidComponent::Name(Symbol::from_name("internet")),
                HirOidComponent::Number(6),
            ],
        ),
        // snmpDomains OBJECT IDENTIFIER ::= { snmpV2 1 }
        make_oid_value(
            "snmpDomains",
            vec![
                HirOidComponent::Name(Symbol::from_name("snmpV2")),
                HirOidComponent::Number(1),
            ],
        ),
        // snmpProxys OBJECT IDENTIFIER ::= { snmpV2 2 }
        make_oid_value(
            "snmpProxys",
            vec![
                HirOidComponent::Name(Symbol::from_name("snmpV2")),
                HirOidComponent::Number(2),
            ],
        ),
        // snmpModules OBJECT IDENTIFIER ::= { snmpV2 3 }
        make_oid_value(
            "snmpModules",
            vec![
                HirOidComponent::Name(Symbol::from_name("snmpV2")),
                HirOidComponent::Number(3),
            ],
        ),
        // zeroDotZero OBJECT IDENTIFIER ::= { 0 0 }
        make_oid_value(
            "zeroDotZero",
            vec![HirOidComponent::Number(0), HirOidComponent::Number(0)],
        ),
    ]
}

/// Create a `ValueAssignment` for an OID definition.
fn make_oid_value(name: &str, components: Vec<HirOidComponent>) -> HirDefinition {
    HirDefinition::ValueAssignment(HirValueAssignment {
        name: Symbol::from_name(name),
        oid: HirOidAssignment::new(components, Span::SYNTHETIC),
        span: Span::SYNTHETIC,
    })
}

// ============================================================================
// Helper functions for constrained type syntax
// ============================================================================

/// Create a constrained INTEGER type with a value range.
fn constrained_int_range(min: HirRangeValue, max: Option<HirRangeValue>) -> HirTypeSyntax {
    HirTypeSyntax::Constrained {
        base: Box::new(HirTypeSyntax::TypeRef(Symbol::from_name("INTEGER"))),
        constraint: HirConstraint::Range(vec![HirRange { min, max }]),
    }
}

/// Create a constrained OCTET STRING type with size constraints.
fn constrained_octet_size(ranges: Vec<HirRange>) -> HirTypeSyntax {
    HirTypeSyntax::Constrained {
        base: Box::new(HirTypeSyntax::OctetString),
        constraint: HirConstraint::Size(ranges),
    }
}

/// Create a constrained OCTET STRING with a single fixed size.
fn constrained_octet_fixed(size: u64) -> HirTypeSyntax {
    constrained_octet_size(vec![HirRange {
        min: HirRangeValue::Unsigned(size),
        max: None,
    }])
}

/// Create a constrained OCTET STRING with a size range.
fn constrained_octet_range(min: u64, max: u64) -> HirTypeSyntax {
    constrained_octet_size(vec![HirRange {
        min: HirRangeValue::Unsigned(min),
        max: Some(HirRangeValue::Unsigned(max)),
    }])
}

/// Create a constrained INTEGER with unsigned range (0..max).
fn constrained_uint_range(max: u64) -> HirTypeSyntax {
    constrained_int_range(
        HirRangeValue::Unsigned(0),
        Some(HirRangeValue::Unsigned(max)),
    )
}

/// Create base type definitions as `TypeDefs`.
///
/// These are the `SMIv2` base types from RFC 2578.
fn create_base_type_definitions() -> Vec<HirDefinition> {
    vec![
        // Integer32 ::= INTEGER (-2147483648..2147483647)
        make_typedef(
            "Integer32",
            constrained_int_range(
                HirRangeValue::Signed(i64::from(i32::MIN)),
                Some(HirRangeValue::Signed(i64::from(i32::MAX))),
            ),
        ),
        // Counter32 ::= [APPLICATION 1] IMPLICIT INTEGER (0..4294967295)
        make_typedef("Counter32", constrained_uint_range(u64::from(u32::MAX))),
        // Counter64 ::= [APPLICATION 6] IMPLICIT INTEGER (0..18446744073709551615)
        make_typedef("Counter64", constrained_uint_range(u64::MAX)),
        // Gauge32 ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295)
        make_typedef("Gauge32", constrained_uint_range(u64::from(u32::MAX))),
        // Unsigned32 ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295)
        make_typedef("Unsigned32", constrained_uint_range(u64::from(u32::MAX))),
        // TimeTicks ::= [APPLICATION 3] IMPLICIT INTEGER (0..4294967295)
        make_typedef("TimeTicks", constrained_uint_range(u64::from(u32::MAX))),
        // IpAddress ::= [APPLICATION 0] IMPLICIT OCTET STRING (SIZE (4))
        make_typedef("IpAddress", constrained_octet_fixed(4)),
        // Opaque ::= [APPLICATION 4] IMPLICIT OCTET STRING
        make_typedef("Opaque", HirTypeSyntax::OctetString),
    ]
}

/// Create a `TypeDef` for a base type definition.
fn make_typedef(name: &str, syntax: HirTypeSyntax) -> HirDefinition {
    HirDefinition::TypeDef(HirTypeDef {
        name: Symbol::from_name(name),
        syntax,
        display_hint: None,
        status: HirStatus::Current,
        description: None,
        reference: None,
        is_textual_convention: false,
        span: Span::SYNTHETIC,
    })
}

/// Create textual convention definitions as `TypeDefs`.
///
/// These are from SNMPv2-TC (RFC 2579).
fn create_tc_definitions() -> Vec<HirDefinition> {
    vec![
        // DisplayString ::= TEXTUAL-CONVENTION
        //     DISPLAY-HINT "255a"
        //     SYNTAX OCTET STRING (SIZE (0..255))
        make_tc(
            "DisplayString",
            Some("255a"),
            constrained_octet_range(0, 255),
        ),
        // PhysAddress ::= TEXTUAL-CONVENTION
        //     DISPLAY-HINT "1x:"
        //     SYNTAX OCTET STRING
        make_tc("PhysAddress", Some("1x:"), HirTypeSyntax::OctetString),
        // MacAddress ::= TEXTUAL-CONVENTION
        //     DISPLAY-HINT "1x:"
        //     SYNTAX OCTET STRING (SIZE (6))
        make_tc("MacAddress", Some("1x:"), constrained_octet_fixed(6)),
        // TruthValue ::= TEXTUAL-CONVENTION
        //     SYNTAX INTEGER { true(1), false(2) }
        make_tc_with_enum("TruthValue", &[("true", 1), ("false", 2)]),
        // RowStatus ::= TEXTUAL-CONVENTION
        //     SYNTAX INTEGER { active(1), notInService(2), notReady(3),
        //                      createAndGo(4), createAndWait(5), destroy(6) }
        make_tc_with_enum(
            "RowStatus",
            &[
                ("active", 1),
                ("notInService", 2),
                ("notReady", 3),
                ("createAndGo", 4),
                ("createAndWait", 5),
                ("destroy", 6),
            ],
        ),
        // StorageType ::= TEXTUAL-CONVENTION
        //     SYNTAX INTEGER { other(1), volatile(2), nonVolatile(3),
        //                      permanent(4), readOnly(5) }
        make_tc_with_enum(
            "StorageType",
            &[
                ("other", 1),
                ("volatile", 2),
                ("nonVolatile", 3),
                ("permanent", 4),
                ("readOnly", 5),
            ],
        ),
        // TimeStamp ::= TEXTUAL-CONVENTION
        //     SYNTAX TimeTicks
        make_tc(
            "TimeStamp",
            None,
            HirTypeSyntax::TypeRef(Symbol::from_name("TimeTicks")),
        ),
        // TimeInterval ::= TEXTUAL-CONVENTION
        //     SYNTAX INTEGER (0..2147483647)
        make_tc(
            "TimeInterval",
            None,
            constrained_int_range(
                HirRangeValue::Unsigned(0),
                Some(HirRangeValue::Signed(i64::from(i32::MAX))),
            ),
        ),
        // DateAndTime ::= TEXTUAL-CONVENTION
        //     DISPLAY-HINT "2d-1d-1d,1d:1d:1d.1d,1a1d:1d"
        //     SYNTAX OCTET STRING (SIZE (8 | 11))
        make_tc(
            "DateAndTime",
            Some("2d-1d-1d,1d:1d:1d.1d,1a1d:1d"),
            constrained_octet_size(vec![
                HirRange {
                    min: HirRangeValue::Unsigned(8),
                    max: None,
                },
                HirRange {
                    min: HirRangeValue::Unsigned(11),
                    max: None,
                },
            ]),
        ),
        // TestAndIncr ::= TEXTUAL-CONVENTION
        //     SYNTAX INTEGER (0..2147483647)
        make_tc(
            "TestAndIncr",
            None,
            constrained_int_range(
                HirRangeValue::Unsigned(0),
                Some(HirRangeValue::Signed(i64::from(i32::MAX))),
            ),
        ),
        // AutonomousType ::= TEXTUAL-CONVENTION
        //     SYNTAX OBJECT IDENTIFIER
        make_tc("AutonomousType", None, HirTypeSyntax::ObjectIdentifier),
        // InstancePointer ::= TEXTUAL-CONVENTION (obsolete)
        //     SYNTAX OBJECT IDENTIFIER
        make_tc_obsolete("InstancePointer", None, HirTypeSyntax::ObjectIdentifier),
        // VariablePointer ::= TEXTUAL-CONVENTION
        //     SYNTAX OBJECT IDENTIFIER
        make_tc("VariablePointer", None, HirTypeSyntax::ObjectIdentifier),
        // RowPointer ::= TEXTUAL-CONVENTION
        //     SYNTAX OBJECT IDENTIFIER
        make_tc("RowPointer", None, HirTypeSyntax::ObjectIdentifier),
        // TDomain ::= TEXTUAL-CONVENTION
        //     SYNTAX OBJECT IDENTIFIER
        make_tc("TDomain", None, HirTypeSyntax::ObjectIdentifier),
        // TAddress ::= TEXTUAL-CONVENTION
        //     SYNTAX OCTET STRING (SIZE (1..255))
        make_tc("TAddress", None, constrained_octet_range(1, 255)),
    ]
}

/// Create a `TypeDef` for a textual convention.
fn make_tc(name: &str, display_hint: Option<&str>, syntax: HirTypeSyntax) -> HirDefinition {
    HirDefinition::TypeDef(HirTypeDef {
        name: Symbol::from_name(name),
        syntax,
        display_hint: display_hint.map(String::from),
        status: HirStatus::Current,
        description: None,
        reference: None,
        is_textual_convention: true,
        span: Span::SYNTHETIC,
    })
}

/// Create a `TypeDef` for an obsolete textual convention.
fn make_tc_obsolete(
    name: &str,
    display_hint: Option<&str>,
    syntax: HirTypeSyntax,
) -> HirDefinition {
    HirDefinition::TypeDef(HirTypeDef {
        name: Symbol::from_name(name),
        syntax,
        display_hint: display_hint.map(String::from),
        status: HirStatus::Obsolete,
        description: None,
        reference: None,
        is_textual_convention: true,
        span: Span::SYNTHETIC,
    })
}

/// Create a `TypeDef` for a textual convention with enumerated values.
fn make_tc_with_enum(name: &str, values: &[(&str, i64)]) -> HirDefinition {
    let enum_values: Vec<NamedNumber> = values
        .iter()
        .map(|(n, v)| NamedNumber::new(Symbol::from_name(n), *v))
        .collect();

    HirDefinition::TypeDef(HirTypeDef {
        name: Symbol::from_name(name),
        syntax: HirTypeSyntax::IntegerEnum(enum_values),
        display_hint: None,
        status: HirStatus::Current,
        description: None,
        reference: None,
        is_textual_convention: true,
        span: Span::SYNTHETIC,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_module_count() {
        assert_eq!(BaseModule::all().count(), 8);
    }

    #[test]
    fn test_base_module_roundtrip() {
        for m in BaseModule::all() {
            let name = m.name();
            let parsed = BaseModule::from_name(name);
            assert_eq!(parsed, Some(m), "roundtrip failed for {name}");
        }
    }

    #[test]
    fn test_is_base_module() {
        assert!(is_base_module("SNMPv2-SMI"));
        assert!(is_base_module("SNMPv2-TC"));
        assert!(is_base_module("RFC1155-SMI"));
        assert!(!is_base_module("IF-MIB"));
    }

    #[test]
    fn test_create_base_modules() {
        let modules = create_base_modules();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name.name, "SNMPv2-SMI");
        assert_eq!(modules[1].name.name, "SNMPv2-TC");
    }

    #[test]
    fn test_snmpv2_smi_has_oid_definitions() {
        let module = create_snmpv2_smi();

        // Check that key OIDs are defined
        let def_names: Vec<_> = module
            .definitions
            .iter()
            .filter_map(|d| d.name().map(|n| n.name.as_str()))
            .collect();

        // All three X.208 root arcs
        assert!(def_names.contains(&"ccitt"));
        assert!(def_names.contains(&"iso"));
        assert!(def_names.contains(&"joint-iso-ccitt"));
        // Standard SNMP hierarchy
        assert!(def_names.contains(&"internet"));
        assert!(def_names.contains(&"enterprises"));
        assert!(def_names.contains(&"mib-2"));
        assert!(def_names.contains(&"zeroDotZero"));
    }

    #[test]
    fn test_snmpv2_smi_has_base_types() {
        let module = create_snmpv2_smi();

        let def_names: Vec<_> = module
            .definitions
            .iter()
            .filter_map(|d| d.name().map(|n| n.name.as_str()))
            .collect();

        assert!(def_names.contains(&"Integer32"));
        assert!(def_names.contains(&"Counter32"));
        assert!(def_names.contains(&"Counter64"));
        assert!(def_names.contains(&"Gauge32"));
        assert!(def_names.contains(&"Unsigned32"));
        assert!(def_names.contains(&"TimeTicks"));
        assert!(def_names.contains(&"IpAddress"));
        assert!(def_names.contains(&"Opaque"));
    }

    #[test]
    fn test_snmpv2_tc_has_tcs() {
        let module = create_snmpv2_tc();

        let def_names: Vec<_> = module
            .definitions
            .iter()
            .filter_map(|d| d.name().map(|n| n.name.as_str()))
            .collect();

        assert!(def_names.contains(&"DisplayString"));
        assert!(def_names.contains(&"TruthValue"));
        assert!(def_names.contains(&"RowStatus"));
        assert!(def_names.contains(&"MacAddress"));
    }

    #[test]
    fn test_root_oid_arcs() {
        let module = create_snmpv2_smi();

        // Verify all three X.208 root arcs have correct numeric values
        let find_oid_value = |name: &str| -> Option<u32> {
            module.definitions.iter().find_map(|d| {
                if let HirDefinition::ValueAssignment(va) = d
                    && va.name.name == name
                    && va.oid.components.len() == 1
                    && let HirOidComponent::Number(n) = va.oid.components[0]
                {
                    return Some(n);
                }
                None
            })
        };

        assert_eq!(find_oid_value("ccitt"), Some(0));
        assert_eq!(find_oid_value("iso"), Some(1));
        assert_eq!(find_oid_value("joint-iso-ccitt"), Some(2));
    }

    #[test]
    fn test_oid_chain() {
        let module = create_snmpv2_smi();

        // Find the enterprises definition
        let enterprises = module
            .definitions
            .iter()
            .find(|d| d.name().is_some_and(|n| n.name == "enterprises"));
        assert!(enterprises.is_some());

        // It should have OID components { private 1 }
        if let Some(HirDefinition::ValueAssignment(va)) = enterprises {
            assert_eq!(va.oid.components.len(), 2);
            if let HirOidComponent::Name(ref sym) = va.oid.components[0] {
                assert_eq!(sym.name, "private");
            } else {
                panic!("Expected Name component");
            }
            if let HirOidComponent::Number(n) = va.oid.components[1] {
                assert_eq!(n, 1);
            } else {
                panic!("Expected Number component");
            }
        }
    }
}
