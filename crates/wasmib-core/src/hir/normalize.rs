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
    // Import normalization table from libsmi's convertImportv2 and BUILTINS.md
    //
    // Format: (original_module, original_symbol, normalized_module, normalized_symbol)
    const IMPORT_MAPPINGS: &[(&str, &str, &str, &str)] = &[
        // RFC1155-SMI → SNMPv2-SMI
        ("RFC1155-SMI", "internet", "SNMPv2-SMI", "internet"),
        ("RFC1155-SMI", "directory", "SNMPv2-SMI", "directory"),
        ("RFC1155-SMI", "mgmt", "SNMPv2-SMI", "mgmt"),
        ("RFC1155-SMI", "experimental", "SNMPv2-SMI", "experimental"),
        ("RFC1155-SMI", "private", "SNMPv2-SMI", "private"),
        ("RFC1155-SMI", "enterprises", "SNMPv2-SMI", "enterprises"),
        ("RFC1155-SMI", "IpAddress", "SNMPv2-SMI", "IpAddress"),
        ("RFC1155-SMI", "Counter", "SNMPv2-SMI", "Counter32"),
        ("RFC1155-SMI", "Gauge", "SNMPv2-SMI", "Gauge32"),
        ("RFC1155-SMI", "TimeTicks", "SNMPv2-SMI", "TimeTicks"),
        ("RFC1155-SMI", "Opaque", "SNMPv2-SMI", "Opaque"),
        (
            "RFC1155-SMI",
            "NetworkAddress",
            "SNMPv2-SMI",
            "IpAddress",
        ),
        // RFC1065-SMI → SNMPv2-SMI (same as RFC1155-SMI)
        ("RFC1065-SMI", "internet", "SNMPv2-SMI", "internet"),
        ("RFC1065-SMI", "directory", "SNMPv2-SMI", "directory"),
        ("RFC1065-SMI", "mgmt", "SNMPv2-SMI", "mgmt"),
        ("RFC1065-SMI", "experimental", "SNMPv2-SMI", "experimental"),
        ("RFC1065-SMI", "private", "SNMPv2-SMI", "private"),
        ("RFC1065-SMI", "enterprises", "SNMPv2-SMI", "enterprises"),
        ("RFC1065-SMI", "IpAddress", "SNMPv2-SMI", "IpAddress"),
        ("RFC1065-SMI", "Counter", "SNMPv2-SMI", "Counter32"),
        ("RFC1065-SMI", "Gauge", "SNMPv2-SMI", "Gauge32"),
        ("RFC1065-SMI", "TimeTicks", "SNMPv2-SMI", "TimeTicks"),
        ("RFC1065-SMI", "Opaque", "SNMPv2-SMI", "Opaque"),
        (
            "RFC1065-SMI",
            "NetworkAddress",
            "SNMPv2-SMI",
            "IpAddress",
        ),
        // RFC1213-MIB → SNMPv2-SMI/SNMPv2-TC
        ("RFC1213-MIB", "mib-2", "SNMPv2-SMI", "mib-2"),
        ("RFC1213-MIB", "DisplayString", "SNMPv2-TC", "DisplayString"),
        // RFC-1212 MACROs stay as-is (just recognize them)
        // RFC-1215 MACROs stay as-is (just recognize them)
    ];

    for &(src_mod, src_sym, dst_mod, dst_sym) in IMPORT_MAPPINGS {
        if module == src_mod && symbol == src_sym {
            return Some(NormalizedImport {
                module: Symbol::from_str(dst_mod),
                symbol: Symbol::from_str(dst_sym),
            });
        }
    }

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
