//! Built-in SMI definitions.
//!
//! This module provides pre-seeded definitions that the resolver needs before
//! processing user modules. These are the RFC-defined types, textual conventions,
//! OID roots, and MACROs from the SMI base modules.
//!
//! # Built-in Categories
//!
//! - **Base Types** (8): Integer32, Counter32, Counter64, Gauge32, Unsigned32,
//!   TimeTicks, IpAddress, Opaque
//! - **Textual Conventions** (16): DisplayString, TruthValue, RowStatus, etc.
//! - **OID Roots** (17): iso, internet, enterprises, mib-2, etc.
//! - **MACROs** (10): OBJECT-TYPE, MODULE-IDENTITY, etc.
//! - **Base Modules** (8): SNMPv2-SMI, SNMPv2-TC, RFC1155-SMI, etc.
//!
//! # Usage
//!
//! The main entry point is [`resolve_builtin_symbol`], which looks up a symbol
//! imported from a base module:
//!
//! ```ignore
//! use wasmib_core::resolver::builtins::resolve_builtin_symbol;
//!
//! let sym = resolve_builtin_symbol("SNMPv2-SMI", "Counter32");
//! assert!(matches!(sym, Some(BuiltinSymbol::BaseType(_))));
//! ```

mod macros;
mod modules;
mod oid;
mod tc;
mod types;

pub use macros::BuiltinMacro;
pub use modules::BaseModule;
pub use oid::{all_builtin_oids, lookup_builtin_oid, idx as oid_idx, BuiltinOidNode, BUILTIN_OID_NODES};
pub use tc::{
    BuiltinTextualConvention, TcBaseSyntax, TcConstraint, TcSizeConstraint,
    BUILTIN_TEXTUAL_CONVENTIONS,
};
pub use types::BuiltinBaseType;

/// A resolved built-in symbol.
#[derive(Clone, Debug)]
pub enum BuiltinSymbol {
    /// A built-in SMI base type (Integer32, Counter32, etc.).
    BaseType(BuiltinBaseType),
    /// A built-in textual convention (DisplayString, TruthValue, etc.).
    TextualConvention(&'static BuiltinTextualConvention),
    /// A built-in OID node (internet, enterprises, etc.).
    /// The value is an index into [`BUILTIN_OID_NODES`].
    OidNode(usize),
    /// A built-in MACRO (OBJECT-TYPE, MODULE-IDENTITY, etc.).
    Macro(BuiltinMacro),
}

/// Resolve a symbol imported from a base module.
///
/// This is the main entry point for resolving built-in symbols. The caller should
/// perform import normalization (SMIv1→SMIv2) before calling this function.
///
/// # Arguments
///
/// * `module` - The source module name (e.g., "SNMPv2-SMI", "SNMPv2-TC")
/// * `symbol` - The symbol name to resolve (e.g., "Counter32", "DisplayString")
///
/// # Returns
///
/// `Some(BuiltinSymbol)` if the symbol is a known built-in, `None` otherwise.
///
/// # Examples
///
/// ```ignore
/// // Type from SNMPv2-SMI
/// let sym = resolve_builtin_symbol("SNMPv2-SMI", "Counter32");
/// assert!(matches!(sym, Some(BuiltinSymbol::BaseType(_))));
///
/// // OID from SNMPv2-SMI
/// let sym = resolve_builtin_symbol("SNMPv2-SMI", "enterprises");
/// assert!(matches!(sym, Some(BuiltinSymbol::OidNode(_))));
///
/// // TC from SNMPv2-TC
/// let sym = resolve_builtin_symbol("SNMPv2-TC", "DisplayString");
/// assert!(matches!(sym, Some(BuiltinSymbol::TextualConvention(_))));
///
/// // MACRO from SNMPv2-CONF
/// let sym = resolve_builtin_symbol("SNMPv2-CONF", "OBJECT-GROUP");
/// assert!(matches!(sym, Some(BuiltinSymbol::Macro(_))));
/// ```
#[must_use]
pub fn resolve_builtin_symbol(module: &str, symbol: &str) -> Option<BuiltinSymbol> {
    let base_mod = BaseModule::from_name(module)?;

    match base_mod {
        BaseModule::SnmpV2Smi => {
            // Check base types first
            if let Some(bt) = BuiltinBaseType::from_name(symbol) {
                return Some(BuiltinSymbol::BaseType(bt));
            }
            // Check OID nodes
            if let Some((idx, _)) = lookup_builtin_oid(symbol) {
                return Some(BuiltinSymbol::OidNode(idx));
            }
            // Check MACROs defined in SNMPv2-SMI
            if let Some(m) = BuiltinMacro::from_name(symbol) {
                if m.source_module() == "SNMPv2-SMI" {
                    return Some(BuiltinSymbol::Macro(m));
                }
            }
            None
        }
        BaseModule::SnmpV2Tc => {
            // Check textual conventions
            if let Some(tc) = BuiltinTextualConvention::from_name(symbol) {
                return Some(BuiltinSymbol::TextualConvention(tc));
            }
            // Check TEXTUAL-CONVENTION macro
            if symbol == "TEXTUAL-CONVENTION" {
                return Some(BuiltinSymbol::Macro(BuiltinMacro::TextualConvention));
            }
            None
        }
        BaseModule::SnmpV2Conf => {
            // Only MACROs from SNMPv2-CONF
            if let Some(m) = BuiltinMacro::from_name(symbol) {
                if m.source_module() == "SNMPv2-CONF" {
                    return Some(BuiltinSymbol::Macro(m));
                }
            }
            None
        }
        BaseModule::Rfc1155Smi | BaseModule::Rfc1065Smi => {
            // SMIv1 modules - should be normalized to SNMPv2-SMI,
            // but handle gracefully if not
            if let Some(bt) = BuiltinBaseType::from_name(symbol) {
                return Some(BuiltinSymbol::BaseType(bt));
            }
            if let Some((idx, _)) = lookup_builtin_oid(symbol) {
                return Some(BuiltinSymbol::OidNode(idx));
            }
            None
        }
        BaseModule::Rfc1212 => {
            // RFC-1212 only defines OBJECT-TYPE
            if symbol == "OBJECT-TYPE" {
                return Some(BuiltinSymbol::Macro(BuiltinMacro::ObjectType));
            }
            None
        }
        BaseModule::Rfc1215 => {
            // RFC-1215 only defines TRAP-TYPE
            if symbol == "TRAP-TYPE" {
                return Some(BuiltinSymbol::Macro(BuiltinMacro::TrapType));
            }
            None
        }
        BaseModule::Rfc1213Mib => {
            // RFC1213-MIB exports mib-2 and DisplayString
            if symbol == "mib-2" {
                return Some(BuiltinSymbol::OidNode(oid_idx::MIB_2));
            }
            if symbol == "DisplayString" {
                return Some(BuiltinSymbol::TextualConvention(
                    BuiltinTextualConvention::from_name("DisplayString").unwrap(),
                ));
            }
            None
        }
    }
}

/// Check if a module is a recognized base module.
#[must_use]
pub fn is_base_module(name: &str) -> bool {
    BaseModule::from_name(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_snmpv2_smi_type() {
        let sym = resolve_builtin_symbol("SNMPv2-SMI", "Counter32");
        assert!(matches!(sym, Some(BuiltinSymbol::BaseType(BuiltinBaseType::Counter32))));
    }

    #[test]
    fn test_resolve_snmpv2_smi_oid() {
        let sym = resolve_builtin_symbol("SNMPv2-SMI", "enterprises");
        assert!(matches!(sym, Some(BuiltinSymbol::OidNode(idx)) if idx == oid_idx::ENTERPRISES));
    }

    #[test]
    fn test_resolve_snmpv2_smi_macro() {
        let sym = resolve_builtin_symbol("SNMPv2-SMI", "OBJECT-TYPE");
        assert!(matches!(sym, Some(BuiltinSymbol::Macro(BuiltinMacro::ObjectType))));
    }

    #[test]
    fn test_resolve_snmpv2_tc_tc() {
        let sym = resolve_builtin_symbol("SNMPv2-TC", "DisplayString");
        assert!(matches!(sym, Some(BuiltinSymbol::TextualConvention(tc)) if tc.name == "DisplayString"));
    }

    #[test]
    fn test_resolve_snmpv2_tc_macro() {
        let sym = resolve_builtin_symbol("SNMPv2-TC", "TEXTUAL-CONVENTION");
        assert!(matches!(sym, Some(BuiltinSymbol::Macro(BuiltinMacro::TextualConvention))));
    }

    #[test]
    fn test_resolve_snmpv2_conf_macro() {
        let sym = resolve_builtin_symbol("SNMPv2-CONF", "OBJECT-GROUP");
        assert!(matches!(sym, Some(BuiltinSymbol::Macro(BuiltinMacro::ObjectGroup))));
    }

    #[test]
    fn test_resolve_rfc1155_smi() {
        // Counter in RFC1155-SMI should resolve (as Counter32 after normalization)
        let sym = resolve_builtin_symbol("RFC1155-SMI", "internet");
        assert!(matches!(sym, Some(BuiltinSymbol::OidNode(_))));
    }

    #[test]
    fn test_resolve_rfc1212() {
        let sym = resolve_builtin_symbol("RFC-1212", "OBJECT-TYPE");
        assert!(matches!(sym, Some(BuiltinSymbol::Macro(BuiltinMacro::ObjectType))));
    }

    #[test]
    fn test_resolve_rfc1215() {
        let sym = resolve_builtin_symbol("RFC-1215", "TRAP-TYPE");
        assert!(matches!(sym, Some(BuiltinSymbol::Macro(BuiltinMacro::TrapType))));
    }

    #[test]
    fn test_resolve_rfc1213_mib() {
        let sym = resolve_builtin_symbol("RFC1213-MIB", "mib-2");
        assert!(matches!(sym, Some(BuiltinSymbol::OidNode(idx)) if idx == oid_idx::MIB_2));

        let sym = resolve_builtin_symbol("RFC1213-MIB", "DisplayString");
        assert!(matches!(sym, Some(BuiltinSymbol::TextualConvention(_))));
    }

    #[test]
    fn test_unknown_module() {
        assert!(resolve_builtin_symbol("IF-MIB", "ifIndex").is_none());
    }

    #[test]
    fn test_unknown_symbol() {
        assert!(resolve_builtin_symbol("SNMPv2-SMI", "NotAType").is_none());
    }

    #[test]
    fn test_wrong_module_for_symbol() {
        // OBJECT-GROUP is from SNMPv2-CONF, not SNMPv2-SMI
        assert!(resolve_builtin_symbol("SNMPv2-SMI", "OBJECT-GROUP").is_none());
        // DisplayString is from SNMPv2-TC, not SNMPv2-SMI
        assert!(resolve_builtin_symbol("SNMPv2-SMI", "DisplayString").is_none());
    }

    #[test]
    fn test_is_base_module() {
        assert!(is_base_module("SNMPv2-SMI"));
        assert!(is_base_module("SNMPv2-TC"));
        assert!(is_base_module("RFC1155-SMI"));
        assert!(!is_base_module("IF-MIB"));
        assert!(!is_base_module("CISCO-MEMORY-POOL-MIB"));
    }
}
