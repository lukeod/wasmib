//! Normalization tables for imports and types.
//!
//! Based on libsmi's `convertImportv2` table and BUILTINS.md specifications.
//! These normalizations allow SMIv1 and SMIv2 MIBs to be processed uniformly.

use super::types::Symbol;

/// Result of normalizing an import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedImport {
    /// Normalized module name.
    pub module: Symbol,
    /// Normalized symbol name.
    pub symbol: Symbol,
}

/// Normalize an import from an SMIv1 module to its SMIv2 equivalent.
///
/// This implements libsmi's `convertImportv2` table plus additional mappings
/// from BUILTINS.md.
///
/// # Arguments
///
/// * `module` - The source module name
/// * `symbol` - The symbol being imported
///
/// # Returns
///
/// The normalized (module, symbol) pair. If no normalization is needed,
/// returns the original values.
#[must_use]
pub fn normalize_import(module: &str, symbol: &str) -> NormalizedImport {
    // Check for explicit mappings first
    if let Some(normalized) = lookup_import_mapping(module, symbol) {
        return normalized;
    }

    // No normalization needed
    NormalizedImport {
        module: Symbol::from_str(module),
        symbol: Symbol::from_str(symbol),
    }
}

/// Look up an import in the normalization table.
fn lookup_import_mapping(module: &str, symbol: &str) -> Option<NormalizedImport> {
    // Shared mappings for RFC1155-SMI and RFC1065-SMI → SNMPv2-SMI
    // Format: (original_symbol, normalized_symbol)
    // Both RFC1155-SMI and RFC1065-SMI use identical mappings to SNMPv2-SMI.
    const RFC1155_1065_TO_SNMPV2: &[(&str, &str)] = &[
        ("internet", "internet"),
        ("directory", "directory"),
        ("mgmt", "mgmt"),
        ("experimental", "experimental"),
        ("private", "private"),
        ("enterprises", "enterprises"),
        ("IpAddress", "IpAddress"),
        ("Counter", "Counter32"),
        ("Gauge", "Gauge32"),
        ("TimeTicks", "TimeTicks"),
        ("Opaque", "Opaque"),
        ("NetworkAddress", "IpAddress"),
    ];

    // Check RFC1155-SMI and RFC1065-SMI (share identical mappings)
    if module == "RFC1155-SMI" || module == "RFC1065-SMI" {
        for &(src_sym, dst_sym) in RFC1155_1065_TO_SNMPV2 {
            if symbol == src_sym {
                return Some(NormalizedImport {
                    module: Symbol::from_str("SNMPv2-SMI"),
                    symbol: Symbol::from_str(dst_sym),
                });
            }
        }
        return None;
    }

    // RFC1213-MIB mappings (different target modules)
    if module == "RFC1213-MIB" {
        return match symbol {
            "mib-2" => Some(NormalizedImport {
                module: Symbol::from_str("SNMPv2-SMI"),
                symbol: Symbol::from_str("mib-2"),
            }),
            "DisplayString" => Some(NormalizedImport {
                module: Symbol::from_str("SNMPv2-TC"),
                symbol: Symbol::from_str("DisplayString"),
            }),
            _ => None,
        };
    }

    // RFC-1212 and RFC-1215 MACROs stay as-is (just recognize them)
    None
}

/// Normalize a type name from SMIv1 to SMIv2.
///
/// This handles type aliases used in SYNTAX clauses:
/// - `Counter` → `Counter32`
/// - `Gauge` → `Gauge32`
/// - `NetworkAddress` → `IpAddress`
///
/// # Arguments
///
/// * `type_name` - The type name to normalize
///
/// # Returns
///
/// The normalized type name, or the original if no normalization is needed.
#[must_use]
pub fn normalize_type_name(type_name: &str) -> &str {
    match type_name {
        "Counter" => "Counter32",
        "Gauge" => "Gauge32",
        "NetworkAddress" => "IpAddress",
        _ => type_name,
    }
}

/// Check if a module name is an SMIv2 base module.
///
/// These modules indicate the MIB is using SMIv2 syntax.
#[must_use]
pub fn is_smiv2_base_module(module: &str) -> bool {
    matches!(
        module,
        "SNMPv2-SMI" | "SNMPv2-TC" | "SNMPv2-CONF" | "SNMPv2-MIB"
    )
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_rfc1155_types() {
        let result = normalize_import("RFC1155-SMI", "Counter");
        assert_eq!(result.module.name, "SNMPv2-SMI");
        assert_eq!(result.symbol.name, "Counter32");

        let result = normalize_import("RFC1155-SMI", "Gauge");
        assert_eq!(result.module.name, "SNMPv2-SMI");
        assert_eq!(result.symbol.name, "Gauge32");
    }

    #[test]
    fn test_normalize_rfc1065_types() {
        // RFC1065-SMI uses identical mappings to RFC1155-SMI
        let result = normalize_import("RFC1065-SMI", "Counter");
        assert_eq!(result.module.name, "SNMPv2-SMI");
        assert_eq!(result.symbol.name, "Counter32");

        let result = normalize_import("RFC1065-SMI", "enterprises");
        assert_eq!(result.module.name, "SNMPv2-SMI");
        assert_eq!(result.symbol.name, "enterprises");

        let result = normalize_import("RFC1065-SMI", "NetworkAddress");
        assert_eq!(result.module.name, "SNMPv2-SMI");
        assert_eq!(result.symbol.name, "IpAddress");

        // Unknown symbol in RFC1065-SMI returns as-is
        let result = normalize_import("RFC1065-SMI", "UnknownSymbol");
        assert_eq!(result.module.name, "RFC1065-SMI");
        assert_eq!(result.symbol.name, "UnknownSymbol");
    }

    #[test]
    fn test_normalize_rfc1213_displaystring() {
        let result = normalize_import("RFC1213-MIB", "DisplayString");
        assert_eq!(result.module.name, "SNMPv2-TC");
        assert_eq!(result.symbol.name, "DisplayString");
    }

    #[test]
    fn test_normalize_network_address() {
        let result = normalize_import("RFC1155-SMI", "NetworkAddress");
        assert_eq!(result.module.name, "SNMPv2-SMI");
        assert_eq!(result.symbol.name, "IpAddress");
    }

    #[test]
    fn test_no_normalization_needed() {
        let result = normalize_import("SNMPv2-SMI", "Integer32");
        assert_eq!(result.module.name, "SNMPv2-SMI");
        assert_eq!(result.symbol.name, "Integer32");
    }

    #[test]
    fn test_type_name_normalization() {
        assert_eq!(normalize_type_name("Counter"), "Counter32");
        assert_eq!(normalize_type_name("Gauge"), "Gauge32");
        assert_eq!(normalize_type_name("NetworkAddress"), "IpAddress");
        assert_eq!(normalize_type_name("Integer32"), "Integer32");
    }

    #[test]
    fn test_is_smiv2_base_module() {
        assert!(is_smiv2_base_module("SNMPv2-SMI"));
        assert!(is_smiv2_base_module("SNMPv2-TC"));
        assert!(is_smiv2_base_module("SNMPv2-CONF"));
        assert!(!is_smiv2_base_module("RFC1155-SMI"));
        assert!(!is_smiv2_base_module("IF-MIB"));
    }

}
