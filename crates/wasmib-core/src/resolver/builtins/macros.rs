//! Built-in MACRO definitions from SMI base modules.
//!
//! MACROs define the syntax for SMI constructs like OBJECT-TYPE, NOTIFICATION-TYPE, etc.
//! wasmib has hardcoded knowledge of these; they are imported but do not resolve to
//! runtime values.

/// Built-in MACROs from SMI base modules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BuiltinMacro {
    /// MODULE-IDENTITY from SNMPv2-SMI.
    ModuleIdentity,
    /// OBJECT-IDENTITY from SNMPv2-SMI.
    ObjectIdentity,
    /// OBJECT-TYPE from SNMPv2-SMI (or RFC-1212 for SMIv1).
    ObjectType,
    /// NOTIFICATION-TYPE from SNMPv2-SMI.
    NotificationType,
    /// TEXTUAL-CONVENTION from SNMPv2-TC.
    TextualConvention,
    /// OBJECT-GROUP from SNMPv2-CONF.
    ObjectGroup,
    /// NOTIFICATION-GROUP from SNMPv2-CONF.
    NotificationGroup,
    /// MODULE-COMPLIANCE from SNMPv2-CONF.
    ModuleCompliance,
    /// AGENT-CAPABILITIES from SNMPv2-CONF.
    AgentCapabilities,
    /// TRAP-TYPE from RFC-1215 (SMIv1 only).
    TrapType,
}

impl BuiltinMacro {
    /// Get the canonical name of this MACRO.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ModuleIdentity => "MODULE-IDENTITY",
            Self::ObjectIdentity => "OBJECT-IDENTITY",
            Self::ObjectType => "OBJECT-TYPE",
            Self::NotificationType => "NOTIFICATION-TYPE",
            Self::TextualConvention => "TEXTUAL-CONVENTION",
            Self::ObjectGroup => "OBJECT-GROUP",
            Self::NotificationGroup => "NOTIFICATION-GROUP",
            Self::ModuleCompliance => "MODULE-COMPLIANCE",
            Self::AgentCapabilities => "AGENT-CAPABILITIES",
            Self::TrapType => "TRAP-TYPE",
        }
    }

    /// Get the source module where this MACRO is defined.
    #[must_use]
    pub const fn source_module(self) -> &'static str {
        match self {
            Self::ModuleIdentity
            | Self::ObjectIdentity
            | Self::ObjectType
            | Self::NotificationType => "SNMPv2-SMI",
            Self::TextualConvention => "SNMPv2-TC",
            Self::ObjectGroup
            | Self::NotificationGroup
            | Self::ModuleCompliance
            | Self::AgentCapabilities => "SNMPv2-CONF",
            Self::TrapType => "RFC-1215",
        }
    }

    /// Look up a MACRO by name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "MODULE-IDENTITY" => Some(Self::ModuleIdentity),
            "OBJECT-IDENTITY" => Some(Self::ObjectIdentity),
            "OBJECT-TYPE" => Some(Self::ObjectType),
            "NOTIFICATION-TYPE" => Some(Self::NotificationType),
            "TEXTUAL-CONVENTION" => Some(Self::TextualConvention),
            "OBJECT-GROUP" => Some(Self::ObjectGroup),
            "NOTIFICATION-GROUP" => Some(Self::NotificationGroup),
            "MODULE-COMPLIANCE" => Some(Self::ModuleCompliance),
            "AGENT-CAPABILITIES" => Some(Self::AgentCapabilities),
            "TRAP-TYPE" => Some(Self::TrapType),
            _ => None,
        }
    }

    /// Iterate over all built-in MACROs.
    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::ModuleIdentity,
            Self::ObjectIdentity,
            Self::ObjectType,
            Self::NotificationType,
            Self::TextualConvention,
            Self::ObjectGroup,
            Self::NotificationGroup,
            Self::ModuleCompliance,
            Self::AgentCapabilities,
            Self::TrapType,
        ]
        .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macro_count() {
        assert_eq!(BuiltinMacro::all().count(), 10);
    }

    #[test]
    fn test_roundtrip_names() {
        for m in BuiltinMacro::all() {
            let name = m.name();
            let parsed = BuiltinMacro::from_name(name);
            assert_eq!(parsed, Some(m), "roundtrip failed for {name}");
        }
    }

    #[test]
    fn test_unknown_macro() {
        assert!(BuiltinMacro::from_name("UNKNOWN-MACRO").is_none());
    }

    #[test]
    fn test_source_modules() {
        assert_eq!(
            BuiltinMacro::ModuleIdentity.source_module(),
            "SNMPv2-SMI"
        );
        assert_eq!(
            BuiltinMacro::TextualConvention.source_module(),
            "SNMPv2-TC"
        );
        assert_eq!(BuiltinMacro::ObjectGroup.source_module(), "SNMPv2-CONF");
        assert_eq!(BuiltinMacro::TrapType.source_module(), "RFC-1215");
    }

    #[test]
    fn test_smiv2_smi_macros() {
        let smi_macros: Vec<_> = BuiltinMacro::all()
            .filter(|m| m.source_module() == "SNMPv2-SMI")
            .collect();
        assert_eq!(smi_macros.len(), 4);
    }

    #[test]
    fn test_smiv2_conf_macros() {
        let conf_macros: Vec<_> = BuiltinMacro::all()
            .filter(|m| m.source_module() == "SNMPv2-CONF")
            .collect();
        assert_eq!(conf_macros.len(), 4);
    }
}
