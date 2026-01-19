//! Built-in textual conventions from SNMPv2-TC (RFC 2579).

use super::types::BuiltinBaseType;
use crate::hir::HirStatus;

/// Base syntax for a textual convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcBaseSyntax {
    /// A built-in SMI type (Counter32, TimeTicks, etc.).
    BuiltinType(BuiltinBaseType),
    /// ASN.1 INTEGER (with or without named values/subrange).
    Integer,
    /// ASN.1 OCTET STRING (with or without SIZE constraint).
    OctetString,
    /// ASN.1 OBJECT IDENTIFIER.
    ObjectIdentifier,
}

/// Size constraint for OCTET STRING types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcSizeConstraint {
    /// Fixed size (e.g., SIZE (6) for MacAddress).
    Fixed(usize),
    /// Range (e.g., SIZE (0..255) for DisplayString).
    Range { min: usize, max: usize },
    /// Union of specific sizes (e.g., SIZE (8 | 11) for DateAndTime).
    Union(&'static [usize]),
}

/// Constraint for a textual convention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcConstraint {
    /// SIZE constraint for OCTET STRING.
    Size(TcSizeConstraint),
    /// Value range constraint for INTEGER.
    Range { min: i64, max: i64 },
}

/// A built-in textual convention definition.
#[derive(Clone, Debug)]
pub struct BuiltinTextualConvention {
    /// The canonical name of this TC.
    pub name: &'static str,
    /// The DISPLAY-HINT string, if any.
    pub display_hint: Option<&'static str>,
    /// The base syntax (INTEGER, OCTET STRING, etc.).
    pub base_syntax: TcBaseSyntax,
    /// Constraint on the base syntax.
    pub constraint: Option<TcConstraint>,
    /// Status of this TC.
    pub status: HirStatus,
    /// Named enumeration values, if any.
    pub enum_values: Option<&'static [(&'static str, i64)]>,
}

/// All built-in textual conventions from SNMPv2-TC.
pub static BUILTIN_TEXTUAL_CONVENTIONS: &[BuiltinTextualConvention] = &[
    BuiltinTextualConvention {
        name: "DisplayString",
        display_hint: Some("255a"),
        base_syntax: TcBaseSyntax::OctetString,
        constraint: Some(TcConstraint::Size(TcSizeConstraint::Range {
            min: 0,
            max: 255,
        })),
        status: HirStatus::Current,
        enum_values: None,
    },
    BuiltinTextualConvention {
        name: "PhysAddress",
        display_hint: Some("1x:"),
        base_syntax: TcBaseSyntax::OctetString,
        constraint: None,
        status: HirStatus::Current,
        enum_values: None,
    },
    BuiltinTextualConvention {
        name: "MacAddress",
        display_hint: Some("1x:"),
        base_syntax: TcBaseSyntax::OctetString,
        constraint: Some(TcConstraint::Size(TcSizeConstraint::Fixed(6))),
        status: HirStatus::Current,
        enum_values: None,
    },
    BuiltinTextualConvention {
        name: "TruthValue",
        display_hint: None,
        base_syntax: TcBaseSyntax::Integer,
        constraint: None,
        status: HirStatus::Current,
        enum_values: Some(&[("true", 1), ("false", 2)]),
    },
    BuiltinTextualConvention {
        name: "RowStatus",
        display_hint: None,
        base_syntax: TcBaseSyntax::Integer,
        constraint: None,
        status: HirStatus::Current,
        enum_values: Some(&[
            ("active", 1),
            ("notInService", 2),
            ("notReady", 3),
            ("createAndGo", 4),
            ("createAndWait", 5),
            ("destroy", 6),
        ]),
    },
    BuiltinTextualConvention {
        name: "StorageType",
        display_hint: None,
        base_syntax: TcBaseSyntax::Integer,
        constraint: None,
        status: HirStatus::Current,
        enum_values: Some(&[
            ("other", 1),
            ("volatile", 2),
            ("nonVolatile", 3),
            ("permanent", 4),
            ("readOnly", 5),
        ]),
    },
    BuiltinTextualConvention {
        name: "TimeStamp",
        display_hint: None,
        base_syntax: TcBaseSyntax::BuiltinType(BuiltinBaseType::TimeTicks),
        constraint: None,
        status: HirStatus::Current,
        enum_values: None,
    },
    BuiltinTextualConvention {
        name: "TimeInterval",
        display_hint: None,
        base_syntax: TcBaseSyntax::Integer,
        constraint: Some(TcConstraint::Range {
            min: 0,
            max: i32::MAX as i64,
        }),
        status: HirStatus::Current,
        enum_values: None,
    },
    BuiltinTextualConvention {
        name: "DateAndTime",
        display_hint: Some("2d-1d-1d,1d:1d:1d.1d,1a1d:1d"),
        base_syntax: TcBaseSyntax::OctetString,
        constraint: Some(TcConstraint::Size(TcSizeConstraint::Union(&[8, 11]))),
        status: HirStatus::Current,
        enum_values: None,
    },
    BuiltinTextualConvention {
        name: "TestAndIncr",
        display_hint: None,
        base_syntax: TcBaseSyntax::Integer,
        constraint: Some(TcConstraint::Range {
            min: 0,
            max: i32::MAX as i64,
        }),
        status: HirStatus::Current,
        enum_values: None,
    },
    BuiltinTextualConvention {
        name: "AutonomousType",
        display_hint: None,
        base_syntax: TcBaseSyntax::ObjectIdentifier,
        constraint: None,
        status: HirStatus::Current,
        enum_values: None,
    },
    BuiltinTextualConvention {
        name: "InstancePointer",
        display_hint: None,
        base_syntax: TcBaseSyntax::ObjectIdentifier,
        constraint: None,
        status: HirStatus::Obsolete,
        enum_values: None,
    },
    BuiltinTextualConvention {
        name: "VariablePointer",
        display_hint: None,
        base_syntax: TcBaseSyntax::ObjectIdentifier,
        constraint: None,
        status: HirStatus::Current,
        enum_values: None,
    },
    BuiltinTextualConvention {
        name: "RowPointer",
        display_hint: None,
        base_syntax: TcBaseSyntax::ObjectIdentifier,
        constraint: None,
        status: HirStatus::Current,
        enum_values: None,
    },
    BuiltinTextualConvention {
        name: "TDomain",
        display_hint: None,
        base_syntax: TcBaseSyntax::ObjectIdentifier,
        constraint: None,
        status: HirStatus::Current,
        enum_values: None,
    },
    BuiltinTextualConvention {
        name: "TAddress",
        display_hint: None,
        base_syntax: TcBaseSyntax::OctetString,
        constraint: Some(TcConstraint::Size(TcSizeConstraint::Range {
            min: 1,
            max: 255,
        })),
        status: HirStatus::Current,
        enum_values: None,
    },
];

impl BuiltinTextualConvention {
    /// Look up a textual convention by name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<&'static BuiltinTextualConvention> {
        BUILTIN_TEXTUAL_CONVENTIONS.iter().find(|tc| tc.name == name)
    }

    /// Iterate over all built-in textual conventions.
    pub fn all() -> impl Iterator<Item = &'static BuiltinTextualConvention> {
        BUILTIN_TEXTUAL_CONVENTIONS.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tc_count() {
        assert_eq!(BUILTIN_TEXTUAL_CONVENTIONS.len(), 16);
    }

    #[test]
    fn test_lookup_by_name() {
        let tc = BuiltinTextualConvention::from_name("DisplayString").unwrap();
        assert_eq!(tc.name, "DisplayString");
        assert_eq!(tc.display_hint, Some("255a"));
    }

    #[test]
    fn test_unknown_tc() {
        assert!(BuiltinTextualConvention::from_name("NotATc").is_none());
    }

    #[test]
    fn test_obsolete_tc() {
        let tc = BuiltinTextualConvention::from_name("InstancePointer").unwrap();
        assert_eq!(tc.status, HirStatus::Obsolete);
    }

    #[test]
    fn test_enum_tc() {
        let tc = BuiltinTextualConvention::from_name("TruthValue").unwrap();
        let enums = tc.enum_values.unwrap();
        assert_eq!(enums.len(), 2);
        assert_eq!(enums[0], ("true", 1));
        assert_eq!(enums[1], ("false", 2));
    }

    #[test]
    fn test_rowstatus_enums() {
        let tc = BuiltinTextualConvention::from_name("RowStatus").unwrap();
        let enums = tc.enum_values.unwrap();
        assert_eq!(enums.len(), 6);
        assert!(enums.iter().any(|(n, v)| *n == "active" && *v == 1));
        assert!(enums.iter().any(|(n, v)| *n == "destroy" && *v == 6));
    }
}
