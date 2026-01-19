//! Token types and spans.

use super::ByteOffset;

/// Span of source text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    /// Start byte offset (inclusive).
    pub start: ByteOffset,
    /// End byte offset (exclusive).
    pub end: ByteOffset,
}

impl Span {
    /// Create a new span.
    #[must_use]
    pub const fn new(start: ByteOffset, end: ByteOffset) -> Self {
        Self { start, end }
    }

    /// Get the length of the span in bytes.
    #[must_use]
    pub const fn len(&self) -> ByteOffset {
        self.end - self.start
    }

    /// Check if the span is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Token with kind and source span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    /// The kind of token.
    pub kind: TokenKind,
    /// Location in source text.
    pub span: Span,
}

impl Token {
    /// Create a new token.
    #[must_use]
    pub const fn new(kind: TokenKind, span: Span) -> Self {
        Self { kind, span }
    }
}

/// Token kinds.
///
/// Derived from libsmi `scanner-smi.l`. See `.local/lexer/DESIGN.md` for details.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TokenKind {
    // === Special ===
    /// Lexical error.
    Error = 0,
    /// End of input.
    Eof,
    /// Forbidden ASN.1 keyword (FALSE, TRUE, NULL, etc.).
    /// Per libsmi scanner-smi.l:699-705, these are ASN.1 reserved words
    /// that should not appear in SMI modules.
    ForbiddenKeyword,

    // === Identifiers ===
    /// Uppercase identifier (module names, type names).
    UppercaseIdent,
    /// Lowercase identifier (object names, enum labels).
    LowercaseIdent,

    // === Literals ===
    /// Unsigned decimal number.
    Number,
    /// Signed decimal number (negative).
    NegativeNumber,
    /// Quoted string literal.
    QuotedString,
    /// Hex string literal ('...'H).
    HexString,
    /// Binary string literal ('...'B).
    BinString,

    // === Single-character punctuation ===
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `:`
    Colon,
    /// `;`
    Semicolon,
    /// `,`
    Comma,
    /// `.`
    Dot,
    /// `|`
    Pipe,
    /// `-`
    Minus,

    // === Multi-character operators ===
    /// `..`
    DotDot,
    /// `::=`
    ColonColonEqual,

    // === Structural keywords ===
    /// `DEFINITIONS`
    KwDefinitions,
    /// `BEGIN`
    KwBegin,
    /// `END`
    KwEnd,
    /// `IMPORTS`
    KwImports,
    /// `EXPORTS`
    KwExports,
    /// `FROM`
    KwFrom,
    /// `OBJECT`
    KwObject,
    /// `IDENTIFIER`
    KwIdentifier,
    /// `SEQUENCE`
    KwSequence,
    /// `OF`
    KwOf,
    /// `CHOICE`
    KwChoice,
    /// `MACRO`
    KwMacro,

    // === Clause keywords ===
    /// `SYNTAX`
    KwSyntax,
    /// `MAX-ACCESS`
    KwMaxAccess,
    /// `MIN-ACCESS`
    KwMinAccess,
    /// `ACCESS`
    KwAccess,
    /// `STATUS`
    KwStatus,
    /// `DESCRIPTION`
    KwDescription,
    /// `REFERENCE`
    KwReference,
    /// `INDEX`
    KwIndex,
    /// `DEFVAL`
    KwDefval,
    /// `AUGMENTS`
    KwAugments,
    /// `UNITS`
    KwUnits,
    /// `DISPLAY-HINT`
    KwDisplayHint,
    /// `OBJECTS`
    KwObjects,
    /// `NOTIFICATIONS`
    KwNotifications,
    /// `MODULE`
    KwModule,
    /// `MANDATORY-GROUPS`
    KwMandatoryGroups,
    /// `GROUP`
    KwGroup,
    /// `WRITE-SYNTAX`
    KwWriteSyntax,
    /// `PRODUCT-RELEASE`
    KwProductRelease,
    /// `SUPPORTS`
    KwSupports,
    /// `INCLUDES`
    KwIncludes,
    /// `VARIATION`
    KwVariation,
    /// `CREATION-REQUIRES`
    KwCreationRequires,
    /// `REVISION`
    KwRevision,
    /// `LAST-UPDATED`
    KwLastUpdated,
    /// `ORGANIZATION`
    KwOrganization,
    /// `CONTACT-INFO`
    KwContactInfo,
    /// `IMPLIED`
    KwImplied,
    /// `SIZE`
    KwSize,
    /// `ENTERPRISE`
    KwEnterprise,
    /// `VARIABLES`
    KwVariables,

    // === MACRO invocation keywords ===
    /// `MODULE-IDENTITY`
    KwModuleIdentity,
    /// `MODULE-COMPLIANCE`
    KwModuleCompliance,
    /// `OBJECT-GROUP`
    KwObjectGroup,
    /// `NOTIFICATION-GROUP`
    KwNotificationGroup,
    /// `AGENT-CAPABILITIES`
    KwAgentCapabilities,
    /// `OBJECT-TYPE`
    KwObjectType,
    /// `OBJECT-IDENTITY`
    KwObjectIdentity,
    /// `NOTIFICATION-TYPE`
    KwNotificationType,
    /// `TEXTUAL-CONVENTION`
    KwTextualConvention,
    /// `TRAP-TYPE`
    KwTrapType,

    // === Type keywords ===
    /// `INTEGER`
    KwInteger,
    /// `Integer32`
    KwInteger32,
    /// `Unsigned32`
    KwUnsigned32,
    /// `Counter32`
    KwCounter32,
    /// `Counter64`
    KwCounter64,
    /// `Gauge32`
    KwGauge32,
    /// `IpAddress`
    KwIpAddress,
    /// `Opaque`
    KwOpaque,
    /// `TimeTicks`
    KwTimeTicks,
    /// `BITS`
    KwBits,
    /// `OCTET`
    KwOctet,
    /// `STRING`
    KwString,

    // === SMIv1 type aliases ===
    /// `Counter` (normalized to `Counter32`).
    KwCounter,
    /// `Gauge` (normalized to `Gauge32`).
    KwGauge,
    /// `NetworkAddress` (normalized to `IpAddress`).
    KwNetworkAddress,

    // === ASN.1 tag keywords ===
    /// `APPLICATION`
    KwApplication,
    /// `IMPLICIT`
    KwImplicit,
    /// `UNIVERSAL`
    KwUniversal,

    // === Status/Access value keywords ===
    /// `current`
    KwCurrent,
    /// `deprecated`
    KwDeprecated,
    /// `obsolete`
    KwObsolete,
    /// `mandatory` (v1 status).
    KwMandatory,
    /// `optional` (v1 status).
    KwOptional,
    /// `read-only`
    KwReadOnly,
    /// `read-write`
    KwReadWrite,
    /// `read-create`
    KwReadCreate,
    /// `write-only` (deprecated)
    KwWriteOnly,
    /// `not-accessible`
    KwNotAccessible,
    /// `accessible-for-notify`
    KwAccessibleForNotify,
    /// `not-implemented` (AGENT-CAPABILITIES)
    KwNotImplemented,
}

impl TokenKind {
    /// Check if this token is a keyword.
    #[must_use]
    pub const fn is_keyword(self) -> bool {
        matches!(
            self,
            Self::KwDefinitions
                | Self::KwBegin
                | Self::KwEnd
                | Self::KwImports
                | Self::KwExports
                | Self::KwFrom
                | Self::KwObject
                | Self::KwIdentifier
                | Self::KwSequence
                | Self::KwOf
                | Self::KwChoice
                | Self::KwMacro
                | Self::KwSyntax
                | Self::KwMaxAccess
                | Self::KwMinAccess
                | Self::KwAccess
                | Self::KwStatus
                | Self::KwDescription
                | Self::KwReference
                | Self::KwIndex
                | Self::KwDefval
                | Self::KwAugments
                | Self::KwUnits
                | Self::KwDisplayHint
                | Self::KwObjects
                | Self::KwNotifications
                | Self::KwModule
                | Self::KwMandatoryGroups
                | Self::KwGroup
                | Self::KwWriteSyntax
                | Self::KwProductRelease
                | Self::KwSupports
                | Self::KwIncludes
                | Self::KwVariation
                | Self::KwCreationRequires
                | Self::KwRevision
                | Self::KwLastUpdated
                | Self::KwOrganization
                | Self::KwContactInfo
                | Self::KwImplied
                | Self::KwSize
                | Self::KwEnterprise
                | Self::KwVariables
                | Self::KwModuleIdentity
                | Self::KwModuleCompliance
                | Self::KwObjectGroup
                | Self::KwNotificationGroup
                | Self::KwAgentCapabilities
                | Self::KwObjectType
                | Self::KwObjectIdentity
                | Self::KwNotificationType
                | Self::KwTextualConvention
                | Self::KwTrapType
                | Self::KwInteger
                | Self::KwInteger32
                | Self::KwUnsigned32
                | Self::KwCounter32
                | Self::KwCounter64
                | Self::KwGauge32
                | Self::KwIpAddress
                | Self::KwOpaque
                | Self::KwTimeTicks
                | Self::KwBits
                | Self::KwOctet
                | Self::KwString
                | Self::KwCounter
                | Self::KwGauge
                | Self::KwNetworkAddress
                | Self::KwApplication
                | Self::KwImplicit
                | Self::KwUniversal
                | Self::KwCurrent
                | Self::KwDeprecated
                | Self::KwObsolete
                | Self::KwMandatory
                | Self::KwOptional
                | Self::KwReadOnly
                | Self::KwReadWrite
                | Self::KwReadCreate
                | Self::KwWriteOnly
                | Self::KwNotAccessible
                | Self::KwAccessibleForNotify
                | Self::KwNotImplemented
        )
    }

    /// Check if this token is a type keyword.
    #[must_use]
    pub const fn is_type_keyword(self) -> bool {
        matches!(
            self,
            Self::KwInteger
                | Self::KwInteger32
                | Self::KwUnsigned32
                | Self::KwCounter32
                | Self::KwCounter64
                | Self::KwGauge32
                | Self::KwIpAddress
                | Self::KwOpaque
                | Self::KwTimeTicks
                | Self::KwBits
                | Self::KwOctet
                | Self::KwString
                | Self::KwCounter
                | Self::KwGauge
                | Self::KwNetworkAddress
        )
    }

    /// Check if this token is a macro keyword (OBJECT-TYPE, etc.).
    #[must_use]
    pub const fn is_macro_keyword(self) -> bool {
        matches!(
            self,
            Self::KwModuleIdentity
                | Self::KwModuleCompliance
                | Self::KwObjectGroup
                | Self::KwNotificationGroup
                | Self::KwAgentCapabilities
                | Self::KwObjectType
                | Self::KwObjectIdentity
                | Self::KwNotificationType
                | Self::KwTextualConvention
                | Self::KwTrapType
        )
    }
}
