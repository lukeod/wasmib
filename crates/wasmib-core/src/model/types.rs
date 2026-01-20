//! Type system types for the resolved model.

use super::ids::{ModuleId, StrId, TypeId};
use alloc::vec;
use alloc::vec::Vec;

/// SMI base type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BaseType {
    /// Signed 32-bit integer.
    Integer32,
    /// 32-bit counter (monotonically increasing, wraps).
    Counter32,
    /// 64-bit counter.
    Counter64,
    /// 32-bit gauge (can increase or decrease).
    Gauge32,
    /// Unsigned 32-bit integer.
    Unsigned32,
    /// Time in hundredths of a second.
    TimeTicks,
    /// IPv4 address.
    IpAddress,
    /// Arbitrary ASN.1 data.
    Opaque,
    /// OCTET STRING.
    OctetString,
    /// OBJECT IDENTIFIER.
    ObjectIdentifier,
    /// BITS (bit string with named bits).
    Bits,
    /// SEQUENCE (compound type for table rows).
    Sequence,
}

impl BaseType {
    /// Get a string representation for downstream consumers.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Integer32 => "INTEGER",
            Self::Counter32 => "COUNTER32",
            Self::Counter64 => "COUNTER64",
            Self::Gauge32 => "GAUGE32",
            Self::Unsigned32 => "UNSIGNED32",
            Self::TimeTicks => "TIMETICKS",
            Self::IpAddress => "IPADDRESS",
            Self::Opaque => "OPAQUE",
            Self::OctetString => "OCTETSTR",
            Self::ObjectIdentifier => "OBJID",
            Self::Bits => "BITS",
            Self::Sequence => "SEQUENCE",
        }
    }

    /// Convert to u8 for compact serialization.
    #[must_use]
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Integer32 => 0,
            Self::Unsigned32 => 1,
            Self::Counter32 => 2,
            Self::Counter64 => 3,
            Self::Gauge32 => 4,
            Self::TimeTicks => 5,
            Self::IpAddress => 6,
            Self::OctetString => 7,
            Self::ObjectIdentifier => 8,
            Self::Opaque => 9,
            Self::Bits => 10,
            Self::Sequence => 11,
        }
    }

    /// Convert from u8.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Integer32),
            1 => Some(Self::Unsigned32),
            2 => Some(Self::Counter32),
            3 => Some(Self::Counter64),
            4 => Some(Self::Gauge32),
            5 => Some(Self::TimeTicks),
            6 => Some(Self::IpAddress),
            7 => Some(Self::OctetString),
            8 => Some(Self::ObjectIdentifier),
            9 => Some(Self::Opaque),
            10 => Some(Self::Bits),
            11 => Some(Self::Sequence),
            _ => None,
        }
    }
}

/// Size constraint for OCTET STRING types.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SizeConstraint {
    /// (min, max) pairs for allowed sizes.
    pub ranges: Vec<(u32, u32)>,
}

impl SizeConstraint {
    /// Create a single-value size constraint.
    #[must_use]
    pub fn fixed(size: u32) -> Self {
        Self {
            ranges: vec![(size, size)],
        }
    }

    /// Create a range size constraint.
    #[must_use]
    pub fn range(min: u32, max: u32) -> Self {
        Self {
            ranges: vec![(min, max)],
        }
    }
}

/// A range bound value that can be signed or unsigned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RangeBound {
    /// Signed value (for Integer32 ranges).
    Signed(i64),
    /// Unsigned value (for Counter64 ranges).
    Unsigned(u64),
}

impl RangeBound {
    /// Get the value as i128 for comparison purposes.
    #[must_use]
    pub fn as_i128(self) -> i128 {
        match self {
            Self::Signed(v) => i128::from(v),
            Self::Unsigned(v) => i128::from(v),
        }
    }
}

/// Value range constraint for INTEGER types.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValueConstraint {
    /// (min, max) pairs for allowed values.
    pub ranges: Vec<(RangeBound, RangeBound)>,
}

impl ValueConstraint {
    /// Create a single-range value constraint with signed bounds.
    #[must_use]
    pub fn range_signed(min: i64, max: i64) -> Self {
        Self {
            ranges: vec![(RangeBound::Signed(min), RangeBound::Signed(max))],
        }
    }

    /// Create a single-range value constraint with unsigned bounds.
    #[must_use]
    pub fn range_unsigned(min: u64, max: u64) -> Self {
        Self {
            ranges: vec![(RangeBound::Unsigned(min), RangeBound::Unsigned(max))],
        }
    }
}

/// Named enumeration values for INTEGER types.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EnumValues {
    /// (value, label) pairs.
    pub values: Vec<(i64, StrId)>,
}

impl EnumValues {
    /// Create new enum values.
    #[must_use]
    pub fn new(values: Vec<(i64, StrId)>) -> Self {
        Self { values }
    }

    /// Get the label for a numeric value.
    #[must_use]
    pub fn get_label(&self, value: i64) -> Option<StrId> {
        self.values
            .iter()
            .find(|(v, _)| *v == value)
            .map(|(_, l)| *l)
    }

    /// Get the value for a label.
    #[must_use]
    pub fn get_value(&self, label: StrId) -> Option<i64> {
        self.values
            .iter()
            .find(|(_, l)| *l == label)
            .map(|(v, _)| *v)
    }
}

/// Named bit definitions for BITS types.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BitDefinitions {
    /// (bit position, label) pairs.
    pub bits: Vec<(u32, StrId)>,
}

impl BitDefinitions {
    /// Create new bit definitions.
    #[must_use]
    pub fn new(bits: Vec<(u32, StrId)>) -> Self {
        Self { bits }
    }
}

/// Status of a definition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Status {
    /// Currently in use.
    #[default]
    Current,
    /// Being phased out.
    Deprecated,
    /// No longer in use.
    Obsolete,
}

impl Status {
    /// Get a string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Deprecated => "deprecated",
            Self::Obsolete => "obsolete",
        }
    }

    /// Convert to u8 for compact serialization.
    #[must_use]
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Current => 0,
            Self::Deprecated => 1,
            Self::Obsolete => 2,
        }
    }

    /// Convert from u8.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Current),
            1 => Some(Self::Deprecated),
            2 => Some(Self::Obsolete),
            _ => None,
        }
    }
}

/// Access level of an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Access {
    /// Can only be read.
    ReadOnly,
    /// Can be read and written.
    ReadWrite,
    /// Can be read, written, or used to create rows.
    ReadCreate,
    /// Not accessible via SNMP.
    NotAccessible,
    /// Accessible only for notifications.
    AccessibleForNotify,
    /// Write-only (deprecated but seen in wild).
    WriteOnly,
}

impl Access {
    /// Get a string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::ReadWrite => "read-write",
            Self::ReadCreate => "read-create",
            Self::NotAccessible => "not-accessible",
            Self::AccessibleForNotify => "accessible-for-notify",
            Self::WriteOnly => "write-only",
        }
    }

    /// Check if the object is accessible for GET operations.
    #[must_use]
    pub fn is_readable(&self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite | Self::ReadCreate)
    }

    /// Convert to u8 for compact serialization.
    #[must_use]
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::NotAccessible => 0,
            Self::AccessibleForNotify => 1,
            Self::ReadOnly => 2,
            Self::ReadWrite => 3,
            Self::ReadCreate => 4,
            Self::WriteOnly => 5,
        }
    }

    /// Convert from u8.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NotAccessible),
            1 => Some(Self::AccessibleForNotify),
            2 => Some(Self::ReadOnly),
            3 => Some(Self::ReadWrite),
            4 => Some(Self::ReadCreate),
            5 => Some(Self::WriteOnly),
            _ => None,
        }
    }
}

/// A resolved type definition.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResolvedType {
    /// Type identifier.
    pub id: TypeId,
    /// Type name.
    pub name: StrId,
    /// Defining module.
    pub module: ModuleId,
    /// Underlying primitive type.
    pub base: BaseType,
    /// Parent type for textual conventions.
    pub parent_type: Option<TypeId>,
    /// Display hint.
    pub hint: Option<StrId>,
    /// Size constraint.
    pub size: Option<SizeConstraint>,
    /// Value range constraint.
    pub value_range: Option<ValueConstraint>,
    /// Enumeration values.
    pub enum_values: Option<EnumValues>,
    /// Bit definitions.
    pub bit_defs: Option<BitDefinitions>,
    /// Description text.
    pub description: Option<StrId>,
    /// Is this a textual convention?
    pub is_textual_convention: bool,
    /// Definition status.
    pub status: Status,
    /// Internal: needs base type resolution from parent.
    /// This is set during initial type creation when the base type couldn't
    /// be determined from syntax alone (e.g., `TypeRef` to another TC).
    #[cfg_attr(feature = "serde", serde(skip))]
    pub needs_base_resolution: bool,
}

impl ResolvedType {
    /// Create a new resolved type.
    ///
    /// The `id` field is initialized to a placeholder and will be assigned
    /// by `Model::add_type()` when the type is added to the model.
    #[must_use]
    pub fn new(name: StrId, module: ModuleId, base: BaseType) -> Self {
        Self {
            id: TypeId::placeholder(),
            name,
            module,
            base,
            parent_type: None,
            hint: None,
            size: None,
            value_range: None,
            enum_values: None,
            bit_defs: None,
            description: None,
            is_textual_convention: false,
            status: Status::Current,
            needs_base_resolution: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_type_as_str() {
        assert_eq!(BaseType::Integer32.as_str(), "INTEGER");
        assert_eq!(BaseType::Counter64.as_str(), "COUNTER64");
        assert_eq!(BaseType::OctetString.as_str(), "OCTETSTR");
    }

    #[test]
    fn test_status_as_str() {
        assert_eq!(Status::Current.as_str(), "current");
        assert_eq!(Status::Deprecated.as_str(), "deprecated");
    }

    #[test]
    fn test_access_is_readable() {
        assert!(Access::ReadOnly.is_readable());
        assert!(Access::ReadWrite.is_readable());
        assert!(Access::ReadCreate.is_readable());
        assert!(!Access::NotAccessible.is_readable());
        assert!(!Access::AccessibleForNotify.is_readable());
    }

    #[test]
    fn test_size_constraint() {
        let fixed = SizeConstraint::fixed(6);
        assert_eq!(fixed.ranges, vec![(6, 6)]);

        let range = SizeConstraint::range(0, 255);
        assert_eq!(range.ranges, vec![(0, 255)]);
    }

    #[test]
    fn test_base_type_as_u8_round_trip() {
        for i in 0..12u8 {
            let base = BaseType::from_u8(i).unwrap();
            assert_eq!(base.as_u8(), i, "Round-trip failed for value {}", i);
        }
        assert!(BaseType::from_u8(12).is_none());
        assert!(BaseType::from_u8(255).is_none());
    }

    #[test]
    fn test_status_as_u8_round_trip() {
        for i in 0..3u8 {
            let status = Status::from_u8(i).unwrap();
            assert_eq!(status.as_u8(), i, "Round-trip failed for value {}", i);
        }
        assert!(Status::from_u8(3).is_none());
        assert!(Status::from_u8(255).is_none());
    }

    #[test]
    fn test_access_as_u8_round_trip() {
        for i in 0..6u8 {
            let access = Access::from_u8(i).unwrap();
            assert_eq!(access.as_u8(), i, "Round-trip failed for value {}", i);
        }
        assert!(Access::from_u8(6).is_none());
        assert!(Access::from_u8(255).is_none());
    }
}
