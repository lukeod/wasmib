//! MIB lexer module.
//!
//! Tokenizes SMIv1/SMIv2 MIB source text into a token stream.

// Allow truncation casts - we limit source size to u32::MAX bytes
#![allow(clippy::cast_possible_truncation)]

mod keyword;
mod token;

pub use keyword::lookup_keyword;
pub use token::{Span, Token, TokenKind};

use alloc::string::String;
use alloc::vec::Vec;

/// Byte offset into source text.
pub type ByteOffset = u32;

/// Diagnostic severity level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Blocks progress; the input may be malformed.
    Error,
    /// Informational; parsing continues.
    Warning,
}

/// A diagnostic message from the lexer.
#[derive(Clone, Debug)]
pub struct Diagnostic {
    /// Severity level.
    pub severity: Severity,
    /// Location in source text.
    pub span: Span,
    /// Human-readable message.
    pub message: String,
}

/// Lexer state for skip modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LexerState {
    /// Normal tokenization.
    Normal,
    /// Inside a MACRO definition; skip until END.
    InMacro,
    /// Inside an EXPORTS clause; skip until semicolon.
    InExports,
    /// Inside a CHOICE definition; skip until closing brace.
    InChoice,
    /// Inside a comment.
    InComment,
}

/// MIB lexer.
///
/// Tokenizes source text into a stream of tokens. The lexer is lenient by
/// default and collects diagnostics rather than failing early.
pub struct Lexer<'src> {
    /// Source text being tokenized.
    source: &'src [u8],
    /// Current byte position.
    pos: usize,
    /// Current lexer state.
    state: LexerState,
    /// Collected diagnostics.
    diagnostics: Vec<Diagnostic>,
}

impl<'src> Lexer<'src> {
    /// Create a new lexer for the given source text.
    #[must_use]
    pub fn new(source: &'src str) -> Self {
        Self {
            source: source.as_bytes(),
            pos: 0,
            state: LexerState::Normal,
            diagnostics: Vec::new(),
        }
    }

    /// Consume the lexer and return collected diagnostics.
    #[must_use]
    pub fn into_diagnostics(self) -> Vec<Diagnostic> {
        self.diagnostics
    }

    /// Get a reference to collected diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Tokenize the entire source and return all tokens.
    #[must_use]
    pub fn tokenize(mut self) -> (Vec<Token>, Vec<Diagnostic>) {
        let mut tokens = Vec::new();
        loop {
            let token = self.next_token();
            let is_eof = token.kind == TokenKind::Eof;
            tokens.push(token);
            if is_eof {
                break;
            }
        }
        (tokens, self.diagnostics)
    }

    /// Get the next token.
    pub fn next_token(&mut self) -> Token {
        match self.state {
            LexerState::Normal => self.next_normal_token(),
            LexerState::InMacro => self.skip_macro_body(),
            LexerState::InExports => self.skip_exports_body(),
            LexerState::InChoice => self.skip_choice_body(),
            LexerState::InComment => self.skip_comment(),
        }
    }

    /// Check if we're at the end of input.
    fn is_eof(&self) -> bool {
        self.pos >= self.source.len()
    }

    /// Peek at the current byte without advancing.
    fn peek(&self) -> Option<u8> {
        self.source.get(self.pos).copied()
    }

    /// Peek at the byte at offset from current position.
    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.source.get(self.pos + offset).copied()
    }

    /// Advance by one byte and return it.
    fn advance(&mut self) -> Option<u8> {
        let b = self.source.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    /// Skip whitespace (space, tab, CR, LF).
    fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
                self.advance();
            } else {
                break;
            }
        }
    }

    /// Add an error diagnostic.
    fn error(&mut self, span: Span, message: String) {
        self.diagnostics.push(Diagnostic {
            severity: Severity::Error,
            span,
            message,
        });
    }

    /// Add a warning diagnostic.
    #[allow(dead_code)]
    fn warning(&mut self, span: Span, message: String) {
        self.diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            span,
            message,
        });
    }

    /// Make a span from start to current position.
    fn span_from(&self, start: usize) -> Span {
        Span {
            start: start as ByteOffset,
            end: self.pos as ByteOffset,
        }
    }

    /// Make a token from start position to current position.
    fn token(&self, kind: TokenKind, start: usize) -> Token {
        Token {
            kind,
            span: self.span_from(start),
        }
    }

    /// Get the next token in normal state.
    fn next_normal_token(&mut self) -> Token {
        self.skip_whitespace();

        let start = self.pos;

        // Check for EOF
        let Some(b) = self.peek() else {
            return self.token(TokenKind::Eof, start);
        };

        // Check for comment start
        if b == b'-' && self.peek_at(1) == Some(b'-') {
            self.advance(); // first -
            self.advance(); // second -
            self.state = LexerState::InComment;
            return self.skip_comment();
        }

        // Single-character tokens
        match b {
            b'[' => {
                self.advance();
                return self.token(TokenKind::LBracket, start);
            }
            b']' => {
                self.advance();
                return self.token(TokenKind::RBracket, start);
            }
            b'{' => {
                self.advance();
                return self.token(TokenKind::LBrace, start);
            }
            b'}' => {
                self.advance();
                return self.token(TokenKind::RBrace, start);
            }
            b'(' => {
                self.advance();
                return self.token(TokenKind::LParen, start);
            }
            b')' => {
                self.advance();
                return self.token(TokenKind::RParen, start);
            }
            b';' => {
                self.advance();
                return self.token(TokenKind::Semicolon, start);
            }
            b',' => {
                self.advance();
                return self.token(TokenKind::Comma, start);
            }
            b'|' => {
                self.advance();
                return self.token(TokenKind::Pipe, start);
            }
            _ => {}
        }

        // Dot or DotDot
        if b == b'.' {
            self.advance();
            if self.peek() == Some(b'.') {
                self.advance();
                return self.token(TokenKind::DotDot, start);
            }
            return self.token(TokenKind::Dot, start);
        }

        // ColonColonEqual (::=) or just colon
        if b == b':' {
            self.advance();
            if self.peek() == Some(b':') && self.peek_at(1) == Some(b'=') {
                self.advance(); // second :
                self.advance(); // =
                return self.token(TokenKind::ColonColonEqual, start);
            }
            // Lone colon is rare but valid in some contexts
            return self.token(TokenKind::Colon, start);
        }

        // Minus (could be negative number or standalone)
        if b == b'-' {
            // Check if it's a negative number (- followed by digit)
            if self.peek_at(1).is_some_and(|next| next.is_ascii_digit()) {
                return self.scan_negative_number();
            }
            self.advance();
            return self.token(TokenKind::Minus, start);
        }

        // Numbers
        if b.is_ascii_digit() {
            return self.scan_number();
        }

        // Quoted string
        if b == b'"' {
            return self.scan_quoted_string();
        }

        // Hex or binary string
        if b == b'\'' {
            return self.scan_hex_or_bin_string();
        }

        // Identifiers and keywords
        if b.is_ascii_alphabetic() {
            return self.scan_identifier_or_keyword();
        }

        // Unknown character
        self.advance();
        let span = self.span_from(start);
        self.error(
            span,
            alloc::format!("unexpected character: {:?}", b as char),
        );
        self.token(TokenKind::Error, start)
    }

    /// Skip comment body and return the next real token.
    fn skip_comment(&mut self) -> Token {
        // We're already past the initial --
        loop {
            match self.peek() {
                None => {
                    // EOF in comment is fine
                    self.state = LexerState::Normal;
                    return self.next_token();
                }
                Some(b'\n' | b'\r') => {
                    // End of line ends comment
                    self.advance();
                    // Handle \r\n
                    if self.peek() == Some(b'\n') {
                        self.advance();
                    }
                    self.state = LexerState::Normal;
                    return self.next_token();
                }
                Some(b'-') if self.peek_at(1) == Some(b'-') => {
                    // -- ends comment
                    self.advance();
                    self.advance();
                    self.state = LexerState::Normal;
                    return self.next_token();
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Skip MACRO body until END keyword.
    fn skip_macro_body(&mut self) -> Token {
        // Scan until we find END followed by a delimiter
        loop {
            self.skip_whitespace();

            if self.is_eof() {
                let start = self.pos;
                self.state = LexerState::Normal;
                return self.token(TokenKind::Eof, start);
            }

            // Check for END keyword
            if self.matches_keyword(b"END") {
                let start = self.pos;
                self.pos += 3;
                // Verify delimiter follows
                if self.is_eof() || !self.peek().unwrap_or(0).is_ascii_alphanumeric() {
                    self.state = LexerState::Normal;
                    return self.token(TokenKind::KwEnd, start);
                }
                // Not actually END keyword, continue
            }

            // Skip comments in macro body
            if self.peek() == Some(b'-') && self.peek_at(1) == Some(b'-') {
                self.skip_comment_inline();
                continue;
            }

            // Skip any other content
            self.advance();
        }
    }

    /// Skip EXPORTS body until semicolon.
    fn skip_exports_body(&mut self) -> Token {
        loop {
            match self.peek() {
                None => {
                    let start = self.pos;
                    self.state = LexerState::Normal;
                    return self.token(TokenKind::Eof, start);
                }
                Some(b';') => {
                    let start = self.pos;
                    self.advance();
                    self.state = LexerState::Normal;
                    return self.token(TokenKind::Semicolon, start);
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Skip CHOICE body until closing brace.
    fn skip_choice_body(&mut self) -> Token {
        loop {
            match self.peek() {
                None => {
                    let start = self.pos;
                    self.state = LexerState::Normal;
                    return self.token(TokenKind::Eof, start);
                }
                Some(b'}') => {
                    let start = self.pos;
                    self.advance();
                    self.state = LexerState::Normal;
                    return self.token(TokenKind::RBrace, start);
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Skip a comment inline without changing state (for use inside skip modes).
    fn skip_comment_inline(&mut self) {
        // Skip the --
        self.advance();
        self.advance();
        loop {
            match self.peek() {
                None | Some(b'\n' | b'\r') => break,
                Some(b'-') if self.peek_at(1) == Some(b'-') => {
                    self.advance();
                    self.advance();
                    break;
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Check if source matches a keyword at current position.
    fn matches_keyword(&self, keyword: &[u8]) -> bool {
        let remaining = &self.source[self.pos..];
        if remaining.len() < keyword.len() {
            return false;
        }
        remaining[..keyword.len()] == *keyword
    }

    /// Scan an identifier or keyword.
    fn scan_identifier_or_keyword(&mut self) -> Token {
        let start = self.pos;
        let first_char = self.advance().unwrap();
        let is_uppercase = first_char.is_ascii_uppercase();

        // Continue scanning identifier characters
        // Pattern: [a-zA-Z0-9_-]* but with restrictions
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                self.advance();
            } else {
                break;
            }
        }

        let text = &self.source[start..self.pos];
        let text_str = core::str::from_utf8(text).unwrap_or("");

        // Check for trailing hyphen
        if text.last() == Some(&b'-') {
            let span = self.span_from(start);
            self.error(
                span,
                alloc::format!("identifier ends in hyphen: {text_str}"),
            );
        }

        // Check for underscores (warning per leniency, but we accept it)
        if text.contains(&b'_') {
            // Per ARCHITECTURE.md leniency philosophy, silently accept underscores
        }

        // Check if it's a keyword
        if let Some(kind) = lookup_keyword(text_str) {
            // Handle state transitions for skip keywords
            match kind {
                TokenKind::KwMacro => {
                    self.state = LexerState::InMacro;
                }
                TokenKind::KwExports => {
                    self.state = LexerState::InExports;
                }
                TokenKind::KwChoice => {
                    self.state = LexerState::InChoice;
                }
                _ => {}
            }
            return self.token(kind, start);
        }

        // It's an identifier
        let kind = if is_uppercase {
            TokenKind::UppercaseIdent
        } else {
            TokenKind::LowercaseIdent
        };

        self.token(kind, start)
    }

    /// Scan a number literal.
    fn scan_number(&mut self) -> Token {
        let start = self.pos;
        let first = self.peek().unwrap();

        // Check for leading zeros
        if first == b'0' && self.peek_at(1).is_some_and(|b| b.is_ascii_digit()) {
            let span = Span {
                start: start as ByteOffset,
                end: (start + 2) as ByteOffset,
            };
            self.error(span, "leading zeros in number".into());
        }

        // Consume all digits
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.advance();
        }

        self.token(TokenKind::Number, start)
    }

    /// Scan a negative number literal.
    fn scan_negative_number(&mut self) -> Token {
        let start = self.pos;
        self.advance(); // consume -

        // Check for leading zeros
        let first = self.peek().unwrap();
        if first == b'0' && self.peek_at(1).is_some_and(|b| b.is_ascii_digit()) {
            let span = Span {
                start: (start + 1) as ByteOffset,
                end: (start + 3) as ByteOffset,
            };
            self.error(span, "leading zeros in number".into());
        }

        // Consume all digits
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.advance();
        }

        self.token(TokenKind::NegativeNumber, start)
    }

    /// Scan a quoted string literal.
    fn scan_quoted_string(&mut self) -> Token {
        let start = self.pos;
        self.advance(); // consume opening quote

        loop {
            match self.peek() {
                None => {
                    let span = self.span_from(start);
                    self.error(span, "unterminated string literal".into());
                    return self.token(TokenKind::QuotedString, start);
                }
                Some(b'"') => {
                    self.advance(); // consume closing quote
                    return self.token(TokenKind::QuotedString, start);
                }
                Some(b) => {
                    // Check for non-ASCII (per libsmi, warning but accept)
                    if b > 127 {
                        // Silently accept per leniency philosophy
                    }
                    self.advance();
                }
            }
        }
    }

    /// Scan a hex or binary string literal.
    fn scan_hex_or_bin_string(&mut self) -> Token {
        let start = self.pos;
        self.advance(); // consume opening quote

        // Collect digits
        let digit_start = self.pos;
        while let Some(b) = self.peek() {
            if b == b'\'' {
                break;
            }
            self.advance();
        }
        let digit_end = self.pos;

        // Expect closing quote
        if self.peek() != Some(b'\'') {
            let span = self.span_from(start);
            self.error(span, "unterminated hex/binary string".into());
            return self.token(TokenKind::Error, start);
        }
        self.advance(); // consume closing quote

        // Expect H/h or B/b suffix
        let kind = match self.peek() {
            Some(b'H' | b'h') => {
                self.advance();
                // Validate hex digits and even count
                let digits = &self.source[digit_start..digit_end];
                let digit_count = digits.iter().filter(|b| !b.is_ascii_whitespace()).count();
                if digit_count % 2 != 0 {
                    let span = self.span_from(start);
                    self.error(span, "hex string must have even number of digits".into());
                }
                for &b in digits {
                    if !b.is_ascii_hexdigit() && !b.is_ascii_whitespace() {
                        let span = self.span_from(start);
                        self.error(span, "invalid character in hex string".into());
                        break;
                    }
                }
                TokenKind::HexString
            }
            Some(b'B' | b'b') => {
                self.advance();
                // Validate binary digits
                let digits = &self.source[digit_start..digit_end];
                let digit_count = digits.iter().filter(|b| !b.is_ascii_whitespace()).count();
                if digit_count % 8 != 0 {
                    let span = self.span_from(start);
                    self.error(span, "binary string must have multiple of 8 bits".into());
                }
                for &b in digits {
                    if b != b'0' && b != b'1' && !b.is_ascii_whitespace() {
                        let span = self.span_from(start);
                        self.error(span, "invalid character in binary string".into());
                        break;
                    }
                }
                TokenKind::BinString
            }
            _ => {
                let span = self.span_from(start);
                self.error(
                    span,
                    "expected 'H' or 'B' suffix for hex/binary string".into(),
                );
                TokenKind::Error
            }
        };

        self.token(kind, start)
    }
}

/// Iterator implementation for convenient token iteration.
impl Iterator for Lexer<'_> {
    type Item = Token;

    fn next(&mut self) -> Option<Self::Item> {
        let token = self.next_token();
        if token.kind == TokenKind::Eof {
            None
        } else {
            Some(token)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to tokenize and get kinds only.
    fn token_kinds(source: &str) -> Vec<TokenKind> {
        let lexer = Lexer::new(source);
        let (tokens, _) = lexer.tokenize();
        tokens.into_iter().map(|t| t.kind).collect()
    }

    /// Helper to tokenize and get text slices.
    fn token_texts<'a>(source: &'a str) -> Vec<&'a str> {
        let lexer = Lexer::new(source);
        let (tokens, _) = lexer.tokenize();
        tokens
            .into_iter()
            .filter(|t| t.kind != TokenKind::Eof)
            .map(|t| &source[t.span.start as usize..t.span.end as usize])
            .collect()
    }

    #[test]
    fn test_empty_input() {
        let kinds = token_kinds("");
        assert_eq!(kinds, vec![TokenKind::Eof]);
    }

    #[test]
    fn test_whitespace_only() {
        let kinds = token_kinds("   \t\n\r\n  ");
        assert_eq!(kinds, vec![TokenKind::Eof]);
    }

    #[test]
    fn test_punctuation() {
        let kinds = token_kinds("[ ] { } ( ) ; , . |");
        assert_eq!(
            kinds,
            vec![
                TokenKind::LBracket,
                TokenKind::RBracket,
                TokenKind::LBrace,
                TokenKind::RBrace,
                TokenKind::LParen,
                TokenKind::RParen,
                TokenKind::Semicolon,
                TokenKind::Comma,
                TokenKind::Dot,
                TokenKind::Pipe,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_operators() {
        let kinds = token_kinds(".. ::= : -");
        assert_eq!(
            kinds,
            vec![
                TokenKind::DotDot,
                TokenKind::ColonColonEqual,
                TokenKind::Colon,
                TokenKind::Minus,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_numbers() {
        let texts = token_texts("0 1 42 12345");
        assert_eq!(texts, vec!["0", "1", "42", "12345"]);

        let kinds = token_kinds("0 1 42 12345");
        assert_eq!(
            kinds,
            vec![
                TokenKind::Number,
                TokenKind::Number,
                TokenKind::Number,
                TokenKind::Number,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_negative_numbers() {
        let texts = token_texts("-1 -42 -0");
        assert_eq!(texts, vec!["-1", "-42", "-0"]);

        let kinds = token_kinds("-1 -42");
        assert_eq!(
            kinds,
            vec![
                TokenKind::NegativeNumber,
                TokenKind::NegativeNumber,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_identifiers() {
        let texts = token_texts("ifIndex myObject IF-MIB MyModule");
        assert_eq!(texts, vec!["ifIndex", "myObject", "IF-MIB", "MyModule"]);

        let kinds = token_kinds("ifIndex myObject IF-MIB MyModule");
        assert_eq!(
            kinds,
            vec![
                TokenKind::LowercaseIdent,
                TokenKind::LowercaseIdent,
                TokenKind::UppercaseIdent,
                TokenKind::UppercaseIdent,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_keywords() {
        let kinds = token_kinds("DEFINITIONS BEGIN END IMPORTS FROM");
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwDefinitions,
                TokenKind::KwBegin,
                TokenKind::KwEnd,
                TokenKind::KwImports,
                TokenKind::KwFrom,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_type_keywords() {
        let kinds = token_kinds("INTEGER Integer32 Counter32 Counter64 Gauge32");
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwInteger,
                TokenKind::KwInteger32,
                TokenKind::KwCounter32,
                TokenKind::KwCounter64,
                TokenKind::KwGauge32,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_macro_keywords() {
        let kinds = token_kinds("OBJECT-TYPE OBJECT-IDENTITY MODULE-IDENTITY");
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwObjectType,
                TokenKind::KwObjectIdentity,
                TokenKind::KwModuleIdentity,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_quoted_string() {
        let texts = token_texts(r#""hello" "world" "with spaces""#);
        assert_eq!(texts, vec![r#""hello""#, r#""world""#, r#""with spaces""#]);

        let kinds = token_kinds(r#""hello""#);
        assert_eq!(kinds, vec![TokenKind::QuotedString, TokenKind::Eof]);
    }

    #[test]
    fn test_multiline_string() {
        let source = "\"line1\nline2\nline3\"";
        let kinds = token_kinds(source);
        assert_eq!(kinds, vec![TokenKind::QuotedString, TokenKind::Eof]);
    }

    #[test]
    fn test_hex_string() {
        let texts = token_texts("'0A1B'H 'ff00'h");
        assert_eq!(texts, vec!["'0A1B'H", "'ff00'h"]);

        let kinds = token_kinds("'0A1B'H");
        assert_eq!(kinds, vec![TokenKind::HexString, TokenKind::Eof]);
    }

    #[test]
    fn test_bin_string() {
        let texts = token_texts("'01010101'B '11110000'b");
        assert_eq!(texts, vec!["'01010101'B", "'11110000'b"]);

        let kinds = token_kinds("'01010101'B");
        assert_eq!(kinds, vec![TokenKind::BinString, TokenKind::Eof]);
    }

    #[test]
    fn test_comments_dash_dash() {
        // Comment ends at end of line
        let kinds = token_kinds("OBJECT -- comment\nTYPE");
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwObject,
                TokenKind::UppercaseIdent, // TYPE is not a keyword
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_comments_inline() {
        // Comment ends at --
        let kinds = token_kinds("OBJECT -- comment -- TYPE");
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwObject,
                TokenKind::UppercaseIdent, // TYPE
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_module_header() {
        let source = "IF-MIB DEFINITIONS ::= BEGIN";
        let kinds = token_kinds(source);
        assert_eq!(
            kinds,
            vec![
                TokenKind::UppercaseIdent, // IF-MIB
                TokenKind::KwDefinitions,
                TokenKind::ColonColonEqual,
                TokenKind::KwBegin,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_object_type_declaration() {
        let source = r#"
            ifIndex OBJECT-TYPE
                SYNTAX      Integer32
                MAX-ACCESS  read-only
                STATUS      current
                DESCRIPTION "The index."
                ::= { ifEntry 1 }
        "#;
        let kinds = token_kinds(source);
        assert_eq!(
            kinds,
            vec![
                TokenKind::LowercaseIdent, // ifIndex
                TokenKind::KwObjectType,
                TokenKind::KwSyntax,
                TokenKind::KwInteger32,
                TokenKind::KwMaxAccess,
                TokenKind::KwReadOnly,
                TokenKind::KwStatus,
                TokenKind::KwCurrent,
                TokenKind::KwDescription,
                TokenKind::QuotedString,
                TokenKind::ColonColonEqual,
                TokenKind::LBrace,
                TokenKind::LowercaseIdent, // ifEntry
                TokenKind::Number,         // 1
                TokenKind::RBrace,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_imports_clause() {
        let source = r#"
            IMPORTS
                MODULE-IDENTITY, OBJECT-TYPE
                    FROM SNMPv2-SMI
                DisplayString
                    FROM SNMPv2-TC;
        "#;
        let kinds = token_kinds(source);
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwImports,
                TokenKind::KwModuleIdentity,
                TokenKind::Comma,
                TokenKind::KwObjectType,
                TokenKind::KwFrom,
                TokenKind::UppercaseIdent, // SNMPv2-SMI
                TokenKind::UppercaseIdent, // DisplayString
                TokenKind::KwFrom,
                TokenKind::UppercaseIdent, // SNMPv2-TC
                TokenKind::Semicolon,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_macro_skip() {
        // MACRO body should be skipped entirely
        let source = r#"
            OBJECT-TYPE MACRO ::=
            BEGIN
                TYPE NOTATION ::= ...lots of content...
                VALUE NOTATION ::= value
            END

            ifIndex OBJECT-TYPE
        "#;
        let kinds = token_kinds(source);
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwObjectType,
                TokenKind::KwMacro,
                TokenKind::KwEnd,          // From the MACRO END
                TokenKind::LowercaseIdent, // ifIndex
                TokenKind::KwObjectType,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_exports_skip() {
        // EXPORTS clause should be skipped
        let source = "EXPORTS foo, bar, baz;OBJECT-TYPE";
        let kinds = token_kinds(source);
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwExports,
                TokenKind::Semicolon,
                TokenKind::KwObjectType,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_choice_skip() {
        // CHOICE body should be skipped
        let source = "NetworkAddress ::= CHOICE { internet IpAddress }Counter";
        let kinds = token_kinds(source);
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwNetworkAddress,
                TokenKind::ColonColonEqual,
                TokenKind::KwChoice,
                TokenKind::RBrace, // End of choice
                TokenKind::KwCounter,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_oid_value() {
        let source = "{ iso org(3) dod(6) internet(1) }";
        let kinds = token_kinds(source);
        assert_eq!(
            kinds,
            vec![
                TokenKind::LBrace,
                TokenKind::LowercaseIdent, // iso
                TokenKind::LowercaseIdent, // org
                TokenKind::LParen,
                TokenKind::Number, // 3
                TokenKind::RParen,
                TokenKind::LowercaseIdent, // dod
                TokenKind::LParen,
                TokenKind::Number, // 6
                TokenKind::RParen,
                TokenKind::LowercaseIdent, // internet
                TokenKind::LParen,
                TokenKind::Number, // 1
                TokenKind::RParen,
                TokenKind::RBrace,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_range_constraint() {
        let source = "INTEGER (0..255)";
        let kinds = token_kinds(source);
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwInteger,
                TokenKind::LParen,
                TokenKind::Number, // 0
                TokenKind::DotDot,
                TokenKind::Number, // 255
                TokenKind::RParen,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_size_constraint() {
        let source = "OCTET STRING (SIZE (0..255))";
        let kinds = token_kinds(source);
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwOctet,
                TokenKind::KwString,
                TokenKind::LParen,
                TokenKind::KwSize,
                TokenKind::LParen,
                TokenKind::Number, // 0
                TokenKind::DotDot,
                TokenKind::Number, // 255
                TokenKind::RParen,
                TokenKind::RParen,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_enum_values() {
        let source = "INTEGER { up(1), down(2), testing(3) }";
        let kinds = token_kinds(source);
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwInteger,
                TokenKind::LBrace,
                TokenKind::LowercaseIdent, // up
                TokenKind::LParen,
                TokenKind::Number, // 1
                TokenKind::RParen,
                TokenKind::Comma,
                TokenKind::LowercaseIdent, // down
                TokenKind::LParen,
                TokenKind::Number, // 2
                TokenKind::RParen,
                TokenKind::Comma,
                TokenKind::LowercaseIdent, // testing
                TokenKind::LParen,
                TokenKind::Number, // 3
                TokenKind::RParen,
                TokenKind::RBrace,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_identifier_with_underscore() {
        // Per leniency philosophy, underscores should be accepted
        let texts = token_texts("my_identifier SOME_TYPE");
        assert_eq!(texts, vec!["my_identifier", "SOME_TYPE"]);
    }

    #[test]
    fn test_trailing_hyphen_error() {
        let lexer = Lexer::new("bad-");
        let (tokens, diagnostics) = lexer.tokenize();

        // Should still produce a token
        assert_eq!(tokens[0].kind, TokenKind::LowercaseIdent);

        // Should have an error diagnostic
        assert!(!diagnostics.is_empty());
        assert_eq!(diagnostics[0].severity, Severity::Error);
        assert!(diagnostics[0].message.contains("hyphen"));
    }

    #[test]
    fn test_leading_zeros_error() {
        let lexer = Lexer::new("007");
        let (tokens, diagnostics) = lexer.tokenize();

        // Should still produce a number token
        assert_eq!(tokens[0].kind, TokenKind::Number);

        // Should have an error diagnostic
        assert!(!diagnostics.is_empty());
        assert_eq!(diagnostics[0].severity, Severity::Error);
        assert!(diagnostics[0].message.contains("leading zeros"));
    }

    #[test]
    fn test_span_tracking() {
        let source = "BEGIN END";
        let lexer = Lexer::new(source);
        let (tokens, _) = lexer.tokenize();

        assert_eq!(tokens[0].kind, TokenKind::KwBegin);
        assert_eq!(tokens[0].span.start, 0);
        assert_eq!(tokens[0].span.end, 5);

        assert_eq!(tokens[1].kind, TokenKind::KwEnd);
        assert_eq!(tokens[1].span.start, 6);
        assert_eq!(tokens[1].span.end, 9);
    }

    #[test]
    fn test_status_keywords() {
        let kinds = token_kinds("current deprecated obsolete mandatory optional");
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwCurrent,
                TokenKind::KwDeprecated,
                TokenKind::KwObsolete,
                TokenKind::KwMandatory,
                TokenKind::KwOptional,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn test_access_keywords() {
        let kinds = token_kinds("read-only read-write read-create not-accessible");
        assert_eq!(
            kinds,
            vec![
                TokenKind::KwReadOnly,
                TokenKind::KwReadWrite,
                TokenKind::KwReadCreate,
                TokenKind::KwNotAccessible,
                TokenKind::Eof,
            ]
        );
    }
}
