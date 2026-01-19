//! Token dump utility for comparison with libsmi tokenizer.
//!
//! Usage: tokenize <file>
//!
//! Outputs tokens in the same format as `tools/libsmi-tokenizer/tokenizer`:
//!   `LINE:COL<TAB>TOKEN_NAME<TAB>text`

use std::env;
use std::fs;
use std::process;

use wasmib_core::lexer::{Lexer, TokenKind};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file>", args[0]);
        process::exit(1);
    }

    let path = &args[1];
    let source = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("{path}: {e}");
            process::exit(1);
        }
    };

    // Build line offset table for line/column computation
    let line_offsets = compute_line_offsets(&source);

    let lexer = Lexer::new(&source);
    let (tokens, _diagnostics) = lexer.tokenize();

    for token in &tokens {
        let (line, col) = offset_to_line_col(&line_offsets, token.span.start as usize);
        let text = &source[token.span.start as usize..token.span.end as usize];

        let token_name = token_kind_to_libsmi_name(token.kind);

        // Escape special characters in text for readability (lossy UTF-8 for non-ASCII)
        let escaped = escape_text(text);

        println!("{line}:{col}\t{token_name}\t{escaped}");
    }
}

/// Compute byte offsets for the start of each line.
fn compute_line_offsets(source: &[u8]) -> Vec<usize> {
    let mut offsets = vec![0];
    for (i, &b) in source.iter().enumerate() {
        if b == b'\n' {
            offsets.push(i + 1);
        }
    }
    offsets
}

/// Convert byte offset to 1-based line and column.
fn offset_to_line_col(line_offsets: &[usize], offset: usize) -> (usize, usize) {
    // Binary search for the line containing offset
    let line_idx = match line_offsets.binary_search(&offset) {
        Ok(i) => i,
        Err(i) => i.saturating_sub(1),
    };
    let line = line_idx + 1; // 1-based
    let col = offset - line_offsets[line_idx] + 1; // 1-based
    (line, col)
}

/// Escape newlines and other special chars for output.
/// Uses lossy UTF-8 conversion for non-ASCII bytes.
fn escape_text(text: &[u8]) -> String {
    // Convert to string (lossy for non-UTF-8 bytes)
    let text_str = String::from_utf8_lossy(text);
    let mut result = String::with_capacity(text.len());
    for c in text_str.chars() {
        match c {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(c),
        }
    }
    result
}

/// Map wasmib `TokenKind` to libsmi-compatible token names.
#[allow(clippy::too_many_lines)]
fn token_kind_to_libsmi_name(kind: TokenKind) -> &'static str {
    match kind {
        // Special
        TokenKind::Error => "ERROR",
        TokenKind::Eof => "EOF",
        TokenKind::ForbiddenKeyword => "FORBIDDEN_KEYWORD",

        // Identifiers
        TokenKind::UppercaseIdent => "UPPERCASE_IDENTIFIER",
        TokenKind::LowercaseIdent => "LOWERCASE_IDENTIFIER",

        // Literals
        TokenKind::Number => "NUMBER",
        TokenKind::NegativeNumber => "NEGATIVENUMBER",
        TokenKind::QuotedString => "QUOTED_STRING",
        TokenKind::HexString => "HEX_STRING",
        TokenKind::BinString => "BIN_STRING",

        // Single-char punctuation
        TokenKind::LBracket => "LBRACKET",
        TokenKind::RBracket => "RBRACKET",
        TokenKind::LBrace => "LBRACE",
        TokenKind::RBrace => "RBRACE",
        TokenKind::LParen => "LPAREN",
        TokenKind::RParen => "RPAREN",
        TokenKind::Colon => "COLON",
        TokenKind::Semicolon => "SEMICOLON",
        TokenKind::Comma => "COMMA",
        TokenKind::Dot => "DOT",
        TokenKind::Pipe => "PIPE",
        TokenKind::Minus => "MINUS",

        // Multi-char operators
        TokenKind::DotDot => "DOT_DOT",
        TokenKind::ColonColonEqual => "COLON_COLON_EQUAL",

        // Structural keywords
        TokenKind::KwDefinitions => "DEFINITIONS",
        TokenKind::KwBegin => "BEGIN",
        TokenKind::KwEnd => "END",
        TokenKind::KwImports => "IMPORTS",
        TokenKind::KwExports => "EXPORTS",
        TokenKind::KwFrom => "FROM",
        TokenKind::KwObject => "OBJECT",
        TokenKind::KwIdentifier => "IDENTIFIER",
        TokenKind::KwSequence => "SEQUENCE",
        TokenKind::KwOf => "OF",
        TokenKind::KwChoice => "CHOICE",
        TokenKind::KwMacro => "MACRO",

        // Clause keywords
        TokenKind::KwSyntax => "SYNTAX",
        TokenKind::KwMaxAccess => "MAX_ACCESS",
        TokenKind::KwMinAccess => "MIN_ACCESS",
        TokenKind::KwAccess => "ACCESS",
        TokenKind::KwStatus => "STATUS",
        TokenKind::KwDescription => "DESCRIPTION",
        TokenKind::KwReference => "REFERENCE",
        TokenKind::KwIndex => "INDEX",
        TokenKind::KwDefval => "DEFVAL",
        TokenKind::KwAugments => "AUGMENTS",
        TokenKind::KwUnits => "UNITS",
        TokenKind::KwDisplayHint => "DISPLAY_HINT",
        TokenKind::KwObjects => "OBJECTS",
        TokenKind::KwNotifications => "NOTIFICATIONS",
        TokenKind::KwModule => "MODULE",
        TokenKind::KwMandatoryGroups => "MANDATORY_GROUPS",
        TokenKind::KwGroup => "GROUP",
        TokenKind::KwWriteSyntax => "WRITE_SYNTAX",
        TokenKind::KwProductRelease => "PRODUCT_RELEASE",
        TokenKind::KwSupports => "SUPPORTS",
        TokenKind::KwIncludes => "INCLUDES",
        TokenKind::KwVariation => "VARIATION",
        TokenKind::KwCreationRequires => "CREATION_REQUIRES",
        TokenKind::KwRevision => "REVISION",
        TokenKind::KwLastUpdated => "LAST_UPDATED",
        TokenKind::KwOrganization => "ORGANIZATION",
        TokenKind::KwContactInfo => "CONTACT_INFO",
        TokenKind::KwImplied => "IMPLIED",
        TokenKind::KwSize => "SIZE",
        TokenKind::KwEnterprise => "ENTERPRISE",
        TokenKind::KwVariables => "VARIABLES",

        // MACRO invocation keywords
        TokenKind::KwModuleIdentity => "MODULE_IDENTITY",
        TokenKind::KwModuleCompliance => "MODULE_COMPLIANCE",
        TokenKind::KwObjectGroup => "OBJECT_GROUP",
        TokenKind::KwNotificationGroup => "NOTIFICATION_GROUP",
        TokenKind::KwAgentCapabilities => "AGENT_CAPABILITIES",
        TokenKind::KwObjectType => "OBJECT_TYPE",
        TokenKind::KwObjectIdentity => "OBJECT_IDENTITY",
        TokenKind::KwNotificationType => "NOTIFICATION_TYPE",
        TokenKind::KwTextualConvention => "TEXTUAL_CONVENTION",
        TokenKind::KwTrapType => "TRAP_TYPE",

        // Type keywords
        TokenKind::KwInteger => "INTEGER",
        TokenKind::KwInteger32 => "INTEGER32",
        TokenKind::KwUnsigned32 => "UNSIGNED32",
        TokenKind::KwCounter32 => "COUNTER32",
        TokenKind::KwCounter64 => "COUNTER64",
        TokenKind::KwGauge32 => "GAUGE32",
        TokenKind::KwIpAddress => "IPADDRESS",
        TokenKind::KwOpaque => "OPAQUE",
        TokenKind::KwTimeTicks => "TIMETICKS",
        TokenKind::KwBits => "BITS",
        TokenKind::KwOctet => "OCTET",
        TokenKind::KwString => "STRING",

        // SMIv1 type aliases
        TokenKind::KwCounter => "COUNTER",
        TokenKind::KwGauge => "GAUGE",
        TokenKind::KwNetworkAddress => "NETWORKADDRESS",

        // ASN.1 tag keywords
        TokenKind::KwApplication => "APPLICATION",
        TokenKind::KwImplicit => "IMPLICIT",
        TokenKind::KwUniversal => "UNIVERSAL",

        // Status/access keywords
        TokenKind::KwCurrent => "CURRENT",
        TokenKind::KwDeprecated => "DEPRECATED",
        TokenKind::KwObsolete => "OBSOLETE",
        TokenKind::KwMandatory => "MANDATORY",
        TokenKind::KwOptional => "OPTIONAL",
        TokenKind::KwReadOnly => "READ_ONLY",
        TokenKind::KwReadWrite => "READ_WRITE",
        TokenKind::KwReadCreate => "READ_CREATE",
        TokenKind::KwWriteOnly => "WRITE_ONLY",
        TokenKind::KwNotAccessible => "NOT_ACCESSIBLE",
        TokenKind::KwAccessibleForNotify => "ACCESSIBLE_FOR_NOTIFY",
        TokenKind::KwNotImplemented => "NOT_IMPLEMENTED",
    }
}
