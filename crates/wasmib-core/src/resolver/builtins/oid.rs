//! Built-in OID tree roots from SNMPv2-SMI.
//!
//! These form the foundation of the OID tree that all MIB definitions
//! hang from. The resolver seeds its OID tree with these nodes.

/// Index constants for built-in OID nodes.
///
/// These indices correspond to positions in [`BUILTIN_OID_NODES`].
pub mod idx {
    /// `iso(1)` - ISO root.
    pub const ISO: usize = 0;
    /// `org(3)` - ISO organizations.
    pub const ORG: usize = 1;
    /// `dod(6)` - US Department of Defense.
    pub const DOD: usize = 2;
    /// `internet(1)` - Internet subtree (1.3.6.1).
    pub const INTERNET: usize = 3;
    /// `directory(1)` - Internet directory (1.3.6.1.1).
    pub const DIRECTORY: usize = 4;
    /// `mgmt(2)` - Internet management (1.3.6.1.2).
    pub const MGMT: usize = 5;
    /// `mib-2(1)` - MIB-2 root (1.3.6.1.2.1).
    pub const MIB_2: usize = 6;
    /// `transmission(10)` - Transmission media (1.3.6.1.2.1.10).
    pub const TRANSMISSION: usize = 7;
    /// `experimental(3)` - Experimental area (1.3.6.1.3).
    pub const EXPERIMENTAL: usize = 8;
    /// `private(4)` - Private enterprises (1.3.6.1.4).
    pub const PRIVATE: usize = 9;
    /// `enterprises(1)` - Enterprise MIBs (1.3.6.1.4.1).
    pub const ENTERPRISES: usize = 10;
    /// `security(5)` - Security area (1.3.6.1.5).
    pub const SECURITY: usize = 11;
    /// `snmpV2(6)` - SNMPv2 area (1.3.6.1.6).
    pub const SNMPV2: usize = 12;
    /// `snmpDomains(1)` - SNMP domains (1.3.6.1.6.1).
    pub const SNMP_DOMAINS: usize = 13;
    /// `snmpProxys(2)` - SNMP proxies (1.3.6.1.6.2).
    pub const SNMP_PROXYS: usize = 14;
    /// `snmpModules(3)` - SNMP modules (1.3.6.1.6.3).
    pub const SNMP_MODULES: usize = 15;
    /// `zeroDotZero(0.0)` - Special null/unknown OID value.
    pub const ZERO_DOT_ZERO: usize = 16;
}

/// A built-in OID tree node.
#[derive(Clone, Debug)]
pub struct BuiltinOidNode {
    /// The canonical name of this node (lowercase except iso).
    pub name: &'static str,
    /// The arc (subidentifier) at this position.
    pub arc: u32,
    /// Index of the parent node in [`BUILTIN_OID_NODES`], or `None` for roots.
    pub parent: Option<usize>,
}

/// All built-in OID nodes.
///
/// The order matches the index constants in [`idx`].
pub static BUILTIN_OID_NODES: &[BuiltinOidNode] = &[
    BuiltinOidNode {
        name: "iso",
        arc: 1,
        parent: None,
    },
    BuiltinOidNode {
        name: "org",
        arc: 3,
        parent: Some(idx::ISO),
    },
    BuiltinOidNode {
        name: "dod",
        arc: 6,
        parent: Some(idx::ORG),
    },
    BuiltinOidNode {
        name: "internet",
        arc: 1,
        parent: Some(idx::DOD),
    },
    BuiltinOidNode {
        name: "directory",
        arc: 1,
        parent: Some(idx::INTERNET),
    },
    BuiltinOidNode {
        name: "mgmt",
        arc: 2,
        parent: Some(idx::INTERNET),
    },
    BuiltinOidNode {
        name: "mib-2",
        arc: 1,
        parent: Some(idx::MGMT),
    },
    BuiltinOidNode {
        name: "transmission",
        arc: 10,
        parent: Some(idx::MIB_2),
    },
    BuiltinOidNode {
        name: "experimental",
        arc: 3,
        parent: Some(idx::INTERNET),
    },
    BuiltinOidNode {
        name: "private",
        arc: 4,
        parent: Some(idx::INTERNET),
    },
    BuiltinOidNode {
        name: "enterprises",
        arc: 1,
        parent: Some(idx::PRIVATE),
    },
    BuiltinOidNode {
        name: "security",
        arc: 5,
        parent: Some(idx::INTERNET),
    },
    BuiltinOidNode {
        name: "snmpV2",
        arc: 6,
        parent: Some(idx::INTERNET),
    },
    BuiltinOidNode {
        name: "snmpDomains",
        arc: 1,
        parent: Some(idx::SNMPV2),
    },
    BuiltinOidNode {
        name: "snmpProxys",
        arc: 2,
        parent: Some(idx::SNMPV2),
    },
    BuiltinOidNode {
        name: "snmpModules",
        arc: 3,
        parent: Some(idx::SNMPV2),
    },
    // zeroDotZero is special: OID 0.0, separate root (not under iso)
    BuiltinOidNode {
        name: "zeroDotZero",
        arc: 0,
        parent: None,
    },
];

impl BuiltinOidNode {
    /// Compute the full numeric OID for this node.
    #[must_use]
    pub fn numeric_oid(&self, nodes: &[BuiltinOidNode]) -> alloc::vec::Vec<u32> {
        let mut path = alloc::vec::Vec::new();
        let mut current = Some(self);
        while let Some(node) = current {
            path.push(node.arc);
            current = node.parent.map(|idx| &nodes[idx]);
        }
        path.reverse();
        path
    }
}

/// Look up a built-in OID node by name.
///
/// Returns the index and a reference to the node if found.
#[must_use]
pub fn lookup_builtin_oid(name: &str) -> Option<(usize, &'static BuiltinOidNode)> {
    BUILTIN_OID_NODES
        .iter()
        .enumerate()
        .find(|(_, node)| node.name == name)
}

/// Iterate over all built-in OID nodes.
pub fn all_builtin_oids() -> impl Iterator<Item = (usize, &'static BuiltinOidNode)> {
    BUILTIN_OID_NODES.iter().enumerate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_count() {
        assert_eq!(BUILTIN_OID_NODES.len(), 17);
    }

    #[test]
    fn test_iso_oid() {
        let node = &BUILTIN_OID_NODES[idx::ISO];
        assert_eq!(node.name, "iso");
        assert_eq!(node.arc, 1);
        assert!(node.parent.is_none());
        assert_eq!(node.numeric_oid(BUILTIN_OID_NODES), vec![1]);
    }

    #[test]
    fn test_internet_oid() {
        let node = &BUILTIN_OID_NODES[idx::INTERNET];
        assert_eq!(node.name, "internet");
        assert_eq!(node.numeric_oid(BUILTIN_OID_NODES), vec![1, 3, 6, 1]);
    }

    #[test]
    fn test_enterprises_oid() {
        let node = &BUILTIN_OID_NODES[idx::ENTERPRISES];
        assert_eq!(node.name, "enterprises");
        assert_eq!(node.numeric_oid(BUILTIN_OID_NODES), vec![1, 3, 6, 1, 4, 1]);
    }

    #[test]
    fn test_mib2_oid() {
        let node = &BUILTIN_OID_NODES[idx::MIB_2];
        assert_eq!(node.name, "mib-2");
        assert_eq!(node.numeric_oid(BUILTIN_OID_NODES), vec![1, 3, 6, 1, 2, 1]);
    }

    #[test]
    fn test_zero_dot_zero() {
        let node = &BUILTIN_OID_NODES[idx::ZERO_DOT_ZERO];
        assert_eq!(node.name, "zeroDotZero");
        assert_eq!(node.arc, 0);
        assert!(node.parent.is_none());
        // zeroDotZero is 0.0, but since it's a single-arc root with arc=0,
        // numeric_oid returns just [0]
        assert_eq!(node.numeric_oid(BUILTIN_OID_NODES), vec![0]);
    }

    #[test]
    fn test_lookup_by_name() {
        let (idx, node) = lookup_builtin_oid("internet").unwrap();
        assert_eq!(idx, idx::INTERNET);
        assert_eq!(node.name, "internet");
    }

    #[test]
    fn test_lookup_unknown() {
        assert!(lookup_builtin_oid("foobar").is_none());
    }

    #[test]
    fn test_snmp_modules_oid() {
        let node = &BUILTIN_OID_NODES[idx::SNMP_MODULES];
        assert_eq!(node.name, "snmpModules");
        assert_eq!(
            node.numeric_oid(BUILTIN_OID_NODES),
            vec![1, 3, 6, 1, 6, 3]
        );
    }
}
