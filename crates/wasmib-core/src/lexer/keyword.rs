//! Keyword lookup table.
//!
//! Uses a sorted static array with binary search for `no_std` compatibility.

use super::TokenKind;

/// Keyword entry mapping text to token kind.
struct KeywordEntry {
    text: &'static str,
    kind: TokenKind,
}

/// Sorted keyword table for binary search.
///
/// IMPORTANT: This table MUST be sorted alphabetically by text.
/// The test `test_keywords_sorted` verifies this at test time.
// Sorted by ASCII byte order: uppercase letters (A-Z: 65-90) come before
// lowercase letters (a-z: 97-122). Hyphen (45) comes before digits (48-57)
// and letters.
static KEYWORDS: &[KeywordEntry] = &[
    KeywordEntry {
        text: "ACCESS",
        kind: TokenKind::KwAccess,
    },
    KeywordEntry {
        text: "AGENT-CAPABILITIES",
        kind: TokenKind::KwAgentCapabilities,
    },
    KeywordEntry {
        text: "APPLICATION",
        kind: TokenKind::KwApplication,
    },
    KeywordEntry {
        text: "AUGMENTS",
        kind: TokenKind::KwAugments,
    },
    KeywordEntry {
        text: "BEGIN",
        kind: TokenKind::KwBegin,
    },
    KeywordEntry {
        text: "BITS",
        kind: TokenKind::KwBits,
    },
    KeywordEntry {
        text: "CHOICE",
        kind: TokenKind::KwChoice,
    },
    KeywordEntry {
        text: "CONTACT-INFO",
        kind: TokenKind::KwContactInfo,
    },
    KeywordEntry {
        text: "CREATION-REQUIRES",
        kind: TokenKind::KwCreationRequires,
    },
    KeywordEntry {
        text: "Counter",
        kind: TokenKind::KwCounter,
    },
    KeywordEntry {
        text: "Counter32",
        kind: TokenKind::KwCounter32,
    },
    KeywordEntry {
        text: "Counter64",
        kind: TokenKind::KwCounter64,
    },
    KeywordEntry {
        text: "DEFINITIONS",
        kind: TokenKind::KwDefinitions,
    },
    KeywordEntry {
        text: "DEFVAL",
        kind: TokenKind::KwDefval,
    },
    KeywordEntry {
        text: "DESCRIPTION",
        kind: TokenKind::KwDescription,
    },
    KeywordEntry {
        text: "DISPLAY-HINT",
        kind: TokenKind::KwDisplayHint,
    },
    KeywordEntry {
        text: "END",
        kind: TokenKind::KwEnd,
    },
    KeywordEntry {
        text: "ENTERPRISE",
        kind: TokenKind::KwEnterprise,
    },
    KeywordEntry {
        text: "EXPORTS",
        kind: TokenKind::KwExports,
    },
    KeywordEntry {
        text: "FROM",
        kind: TokenKind::KwFrom,
    },
    KeywordEntry {
        text: "GROUP",
        kind: TokenKind::KwGroup,
    },
    KeywordEntry {
        text: "Gauge",
        kind: TokenKind::KwGauge,
    },
    KeywordEntry {
        text: "Gauge32",
        kind: TokenKind::KwGauge32,
    },
    KeywordEntry {
        text: "IDENTIFIER",
        kind: TokenKind::KwIdentifier,
    },
    KeywordEntry {
        text: "IMPLICIT",
        kind: TokenKind::KwImplicit,
    },
    KeywordEntry {
        text: "IMPLIED",
        kind: TokenKind::KwImplied,
    },
    KeywordEntry {
        text: "IMPORTS",
        kind: TokenKind::KwImports,
    },
    KeywordEntry {
        text: "INCLUDES",
        kind: TokenKind::KwIncludes,
    },
    KeywordEntry {
        text: "INDEX",
        kind: TokenKind::KwIndex,
    },
    KeywordEntry {
        text: "INTEGER",
        kind: TokenKind::KwInteger,
    },
    KeywordEntry {
        text: "Integer32",
        kind: TokenKind::KwInteger32,
    },
    KeywordEntry {
        text: "IpAddress",
        kind: TokenKind::KwIpAddress,
    },
    KeywordEntry {
        text: "LAST-UPDATED",
        kind: TokenKind::KwLastUpdated,
    },
    KeywordEntry {
        text: "MACRO",
        kind: TokenKind::KwMacro,
    },
    KeywordEntry {
        text: "MANDATORY-GROUPS",
        kind: TokenKind::KwMandatoryGroups,
    },
    KeywordEntry {
        text: "MAX-ACCESS",
        kind: TokenKind::KwMaxAccess,
    },
    KeywordEntry {
        text: "MIN-ACCESS",
        kind: TokenKind::KwMinAccess,
    },
    KeywordEntry {
        text: "MODULE",
        kind: TokenKind::KwModule,
    },
    KeywordEntry {
        text: "MODULE-COMPLIANCE",
        kind: TokenKind::KwModuleCompliance,
    },
    KeywordEntry {
        text: "MODULE-IDENTITY",
        kind: TokenKind::KwModuleIdentity,
    },
    KeywordEntry {
        text: "NOTIFICATION-GROUP",
        kind: TokenKind::KwNotificationGroup,
    },
    KeywordEntry {
        text: "NOTIFICATION-TYPE",
        kind: TokenKind::KwNotificationType,
    },
    KeywordEntry {
        text: "NOTIFICATIONS",
        kind: TokenKind::KwNotifications,
    },
    KeywordEntry {
        text: "NetworkAddress",
        kind: TokenKind::KwNetworkAddress,
    },
    KeywordEntry {
        text: "OBJECT",
        kind: TokenKind::KwObject,
    },
    KeywordEntry {
        text: "OBJECT-GROUP",
        kind: TokenKind::KwObjectGroup,
    },
    KeywordEntry {
        text: "OBJECT-IDENTITY",
        kind: TokenKind::KwObjectIdentity,
    },
    KeywordEntry {
        text: "OBJECT-TYPE",
        kind: TokenKind::KwObjectType,
    },
    KeywordEntry {
        text: "OBJECTS",
        kind: TokenKind::KwObjects,
    },
    KeywordEntry {
        text: "OCTET",
        kind: TokenKind::KwOctet,
    },
    KeywordEntry {
        text: "OF",
        kind: TokenKind::KwOf,
    },
    KeywordEntry {
        text: "ORGANIZATION",
        kind: TokenKind::KwOrganization,
    },
    KeywordEntry {
        text: "Opaque",
        kind: TokenKind::KwOpaque,
    },
    KeywordEntry {
        text: "PRODUCT-RELEASE",
        kind: TokenKind::KwProductRelease,
    },
    KeywordEntry {
        text: "REFERENCE",
        kind: TokenKind::KwReference,
    },
    KeywordEntry {
        text: "REVISION",
        kind: TokenKind::KwRevision,
    },
    KeywordEntry {
        text: "SEQUENCE",
        kind: TokenKind::KwSequence,
    },
    KeywordEntry {
        text: "SIZE",
        kind: TokenKind::KwSize,
    },
    KeywordEntry {
        text: "STATUS",
        kind: TokenKind::KwStatus,
    },
    KeywordEntry {
        text: "STRING",
        kind: TokenKind::KwString,
    },
    KeywordEntry {
        text: "SUPPORTS",
        kind: TokenKind::KwSupports,
    },
    KeywordEntry {
        text: "SYNTAX",
        kind: TokenKind::KwSyntax,
    },
    KeywordEntry {
        text: "TEXTUAL-CONVENTION",
        kind: TokenKind::KwTextualConvention,
    },
    KeywordEntry {
        text: "TRAP-TYPE",
        kind: TokenKind::KwTrapType,
    },
    KeywordEntry {
        text: "TimeTicks",
        kind: TokenKind::KwTimeTicks,
    },
    KeywordEntry {
        text: "UNITS",
        kind: TokenKind::KwUnits,
    },
    KeywordEntry {
        text: "UNIVERSAL",
        kind: TokenKind::KwUniversal,
    },
    KeywordEntry {
        text: "Unsigned32",
        kind: TokenKind::KwUnsigned32,
    },
    KeywordEntry {
        text: "VARIABLES",
        kind: TokenKind::KwVariables,
    },
    KeywordEntry {
        text: "VARIATION",
        kind: TokenKind::KwVariation,
    },
    KeywordEntry {
        text: "WRITE-SYNTAX",
        kind: TokenKind::KwWriteSyntax,
    },
    KeywordEntry {
        text: "accessible-for-notify",
        kind: TokenKind::KwAccessibleForNotify,
    },
    KeywordEntry {
        text: "current",
        kind: TokenKind::KwCurrent,
    },
    KeywordEntry {
        text: "deprecated",
        kind: TokenKind::KwDeprecated,
    },
    KeywordEntry {
        text: "mandatory",
        kind: TokenKind::KwMandatory,
    },
    KeywordEntry {
        text: "not-accessible",
        kind: TokenKind::KwNotAccessible,
    },
    KeywordEntry {
        text: "not-implemented",
        kind: TokenKind::KwNotImplemented,
    },
    KeywordEntry {
        text: "obsolete",
        kind: TokenKind::KwObsolete,
    },
    KeywordEntry {
        text: "optional",
        kind: TokenKind::KwOptional,
    },
    KeywordEntry {
        text: "read-create",
        kind: TokenKind::KwReadCreate,
    },
    KeywordEntry {
        text: "read-only",
        kind: TokenKind::KwReadOnly,
    },
    KeywordEntry {
        text: "read-write",
        kind: TokenKind::KwReadWrite,
    },
    KeywordEntry {
        text: "write-only",
        kind: TokenKind::KwWriteOnly,
    },
];

/// Look up a keyword by text.
///
/// Returns `Some(TokenKind)` if the text is a keyword, `None` otherwise.
#[must_use]
pub fn lookup_keyword(text: &str) -> Option<TokenKind> {
    KEYWORDS
        .binary_search_by(|entry| entry.text.cmp(text))
        .ok()
        .map(|idx| KEYWORDS[idx].kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keywords_sorted() {
        // Verify the keyword table is sorted
        for window in KEYWORDS.windows(2) {
            assert!(
                window[0].text < window[1].text,
                "Keywords not sorted: {:?} should come before {:?}",
                window[0].text,
                window[1].text
            );
        }
    }

    #[test]
    fn test_keyword_lookup() {
        // Test some keywords
        assert_eq!(lookup_keyword("OBJECT-TYPE"), Some(TokenKind::KwObjectType));
        assert_eq!(
            lookup_keyword("DEFINITIONS"),
            Some(TokenKind::KwDefinitions)
        );
        assert_eq!(lookup_keyword("BEGIN"), Some(TokenKind::KwBegin));
        assert_eq!(lookup_keyword("END"), Some(TokenKind::KwEnd));
        assert_eq!(lookup_keyword("Integer32"), Some(TokenKind::KwInteger32));
        assert_eq!(lookup_keyword("Counter32"), Some(TokenKind::KwCounter32));
        assert_eq!(lookup_keyword("current"), Some(TokenKind::KwCurrent));
        assert_eq!(lookup_keyword("read-only"), Some(TokenKind::KwReadOnly));

        // Test non-keywords
        assert_eq!(lookup_keyword("ifIndex"), None);
        assert_eq!(lookup_keyword("MyModule"), None);
        assert_eq!(lookup_keyword(""), None);
    }

    #[test]
    fn test_case_sensitive() {
        // Keywords are case-sensitive
        assert_eq!(lookup_keyword("OBJECT-TYPE"), Some(TokenKind::KwObjectType));
        assert_eq!(lookup_keyword("object-type"), None);
        assert_eq!(lookup_keyword("Object-Type"), None);

        assert_eq!(lookup_keyword("Integer32"), Some(TokenKind::KwInteger32));
        assert_eq!(lookup_keyword("INTEGER32"), None);
        assert_eq!(lookup_keyword("integer32"), None);
    }
}
