//! SMI base module recognition.
//!
//! These are the RFC-defined modules that provide the SMI framework.
//! Imports from these modules resolve against built-in definitions.

/// SMI base modules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BaseModule {
    /// SNMPv2-SMI (RFC 2578) - SMIv2 base types, OIDs, MACROs.
    SnmpV2Smi,
    /// SNMPv2-TC (RFC 2579) - Textual conventions.
    SnmpV2Tc,
    /// SNMPv2-CONF (RFC 2580) - Conformance MACROs.
    SnmpV2Conf,
    /// RFC1155-SMI - SMIv1 base types, OIDs.
    Rfc1155Smi,
    /// RFC1065-SMI - Original SMIv1 base (predates RFC 1155).
    Rfc1065Smi,
    /// RFC-1212 - SMIv1 OBJECT-TYPE MACRO.
    Rfc1212,
    /// RFC-1215 - SMIv1 TRAP-TYPE MACRO.
    Rfc1215,
    /// RFC1213-MIB - Legacy module (mib-2, DisplayString).
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

    /// Check if this is an SMIv2 module.
    #[must_use]
    pub const fn is_smiv2(self) -> bool {
        matches!(self, Self::SnmpV2Smi | Self::SnmpV2Tc | Self::SnmpV2Conf)
    }

    /// Check if this is an SMIv1 module.
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

/// Check if a symbol name is a MACRO (not a type or object).
///
/// MACROs are imported but do not resolve to runtime definitions.
#[must_use]
pub fn is_macro_symbol(name: &str) -> bool {
    matches!(
        name,
        "MODULE-IDENTITY"
            | "OBJECT-IDENTITY"
            | "OBJECT-TYPE"
            | "NOTIFICATION-TYPE"
            | "TEXTUAL-CONVENTION"
            | "OBJECT-GROUP"
            | "NOTIFICATION-GROUP"
            | "MODULE-COMPLIANCE"
            | "AGENT-CAPABILITIES"
            | "TRAP-TYPE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_count() {
        assert_eq!(BaseModule::all().count(), 8);
    }

    #[test]
    fn test_roundtrip_names() {
        for m in BaseModule::all() {
            let name = m.name();
            let parsed = BaseModule::from_name(name);
            assert_eq!(parsed, Some(m), "roundtrip failed for {name}");
        }
    }

    #[test]
    fn test_unknown_module() {
        assert!(BaseModule::from_name("IF-MIB").is_none());
        assert!(BaseModule::from_name("snmpv2-smi").is_none()); // case-sensitive
    }

    #[test]
    fn test_is_base_module() {
        assert!(is_base_module("SNMPv2-SMI"));
        assert!(is_base_module("RFC1155-SMI"));
        assert!(!is_base_module("IF-MIB"));
    }

    #[test]
    fn test_smiv2_modules() {
        let v2_mods: Vec<_> = BaseModule::all().filter(|m| m.is_smiv2()).collect();
        assert_eq!(v2_mods.len(), 3);
        assert!(v2_mods.contains(&BaseModule::SnmpV2Smi));
        assert!(v2_mods.contains(&BaseModule::SnmpV2Tc));
        assert!(v2_mods.contains(&BaseModule::SnmpV2Conf));
    }

    #[test]
    fn test_smiv1_modules() {
        let v1_mods: Vec<_> = BaseModule::all().filter(|m| m.is_smiv1()).collect();
        assert_eq!(v1_mods.len(), 4);
    }

    #[test]
    fn test_is_macro_symbol() {
        assert!(is_macro_symbol("OBJECT-TYPE"));
        assert!(is_macro_symbol("MODULE-IDENTITY"));
        assert!(is_macro_symbol("TEXTUAL-CONVENTION"));
        assert!(!is_macro_symbol("Integer32"));
        assert!(!is_macro_symbol("enterprises"));
    }
}
