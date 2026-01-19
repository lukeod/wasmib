//! Built-in SMI base types from SNMPv2-SMI.

/// Built-in SMI base types from SNMPv2-SMI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BuiltinBaseType {
    /// Signed 32-bit integer (-2147483648..2147483647).
    Integer32,
    /// 32-bit counter (0..4294967295), monotonically increasing, wraps.
    Counter32,
    /// 64-bit counter (0..18446744073709551615).
    Counter64,
    /// 32-bit gauge (0..4294967295), can increase or decrease.
    Gauge32,
    /// Unsigned 32-bit integer (0..4294967295).
    Unsigned32,
    /// Time in hundredths of a second (0..4294967295).
    TimeTicks,
    /// IPv4 address as 4 octets in network byte order.
    IpAddress,
    /// Arbitrary ASN.1 data (discouraged).
    Opaque,
}

impl BuiltinBaseType {
    /// Get the canonical name of this base type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Integer32 => "Integer32",
            Self::Counter32 => "Counter32",
            Self::Counter64 => "Counter64",
            Self::Gauge32 => "Gauge32",
            Self::Unsigned32 => "Unsigned32",
            Self::TimeTicks => "TimeTicks",
            Self::IpAddress => "IpAddress",
            Self::Opaque => "Opaque",
        }
    }

    /// Get the valid range for this base type.
    ///
    /// For size-based types (IpAddress, Opaque), returns (0, 0) as they
    /// use size constraints rather than value ranges.
    #[must_use]
    pub const fn range(self) -> (i128, i128) {
        match self {
            Self::Integer32 => (i32::MIN as i128, i32::MAX as i128),
            Self::Counter32 | Self::Gauge32 | Self::Unsigned32 | Self::TimeTicks => {
                (0, u32::MAX as i128)
            }
            Self::Counter64 => (0, u64::MAX as i128),
            Self::IpAddress | Self::Opaque => (0, 0),
        }
    }

    /// Look up a base type by name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Integer32" => Some(Self::Integer32),
            "Counter32" => Some(Self::Counter32),
            "Counter64" => Some(Self::Counter64),
            "Gauge32" => Some(Self::Gauge32),
            "Unsigned32" => Some(Self::Unsigned32),
            "TimeTicks" => Some(Self::TimeTicks),
            "IpAddress" => Some(Self::IpAddress),
            "Opaque" => Some(Self::Opaque),
            _ => None,
        }
    }

    /// Iterate over all built-in base types.
    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::Integer32,
            Self::Counter32,
            Self::Counter64,
            Self::Gauge32,
            Self::Unsigned32,
            Self::TimeTicks,
            Self::IpAddress,
            Self::Opaque,
        ]
        .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_types_count() {
        assert_eq!(BuiltinBaseType::all().count(), 8);
    }

    #[test]
    fn test_roundtrip_names() {
        for bt in BuiltinBaseType::all() {
            let name = bt.name();
            let parsed = BuiltinBaseType::from_name(name);
            assert_eq!(parsed, Some(bt), "roundtrip failed for {name}");
        }
    }

    #[test]
    fn test_unknown_name() {
        assert_eq!(BuiltinBaseType::from_name("Foo"), None);
        assert_eq!(BuiltinBaseType::from_name("integer32"), None); // case-sensitive
    }

    #[test]
    fn test_ranges() {
        assert_eq!(
            BuiltinBaseType::Integer32.range(),
            (i32::MIN as i128, i32::MAX as i128)
        );
        assert_eq!(
            BuiltinBaseType::Counter32.range(),
            (0, u32::MAX as i128)
        );
        assert_eq!(
            BuiltinBaseType::Counter64.range(),
            (0, u64::MAX as i128)
        );
    }
}
