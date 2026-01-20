//! MIB parser module.
//!
//! Parses SMIv1/SMIv2 MIB source text into an AST.

use crate::ast::{
    AccessClause, AccessKeyword, AccessValue, AugmentsClause, Compliance, ComplianceGroup,
    ComplianceModule, ComplianceObject, Constraint, DefValClause, DefValContent, Definition,
    DefinitionsKind, Ident, ImportClause, IndexClause, IndexItem, Module, NamedNumber,
    ObjectTypeDef, ObjectVariation, OidAssignment, OidComponent, QuotedString, Range, RangeValue,
    SequenceField, StatusClause, StatusValue, SupportsModule, SyntaxClause, TextualConventionDef,
    TypeAssignmentDef, TypeSyntax, ValueAssignmentDef, Variation,
};
use crate::lexer::{Diagnostic, Lexer, Severity, Span, Token, TokenKind};
use alloc::string::String;
use alloc::vec::Vec;

/// MIB parser.
///
/// Parses a token stream into an AST. The parser is lenient by default,
/// collecting diagnostics and attempting to recover from errors.
pub struct Parser<'src> {
    /// Source text (for extracting token content).
    source: &'src [u8],
    /// Tokens from lexer.
    tokens: Vec<Token>,
    /// Current position in token stream.
    pos: usize,
    /// Collected diagnostics (lexer + parser).
    diagnostics: Vec<Diagnostic>,
}

impl<'src> Parser<'src> {
    /// Create a new parser for the given source bytes.
    #[must_use]
    pub fn new(source: &'src [u8]) -> Self {
        let lexer = Lexer::new(source);
        let (tokens, lexer_diagnostics) = lexer.tokenize();
        Self {
            source,
            tokens,
            pos: 0,
            diagnostics: lexer_diagnostics,
        }
    }

    /// Parse a complete module.
    #[must_use]
    pub fn parse_module(mut self) -> Module {
        let start = self.current_span().start;

        // Parse module header: ModuleName DEFINITIONS ::= BEGIN
        let (name, definitions_kind) = match self.parse_module_header() {
            Ok(header) => header,
            Err(diag) => {
                self.diagnostics.push(diag);
                // Create a placeholder module
                let span = Span::new(start, self.current_span().end);
                let mut module = Module::new(
                    Ident::new("UNKNOWN".into(), span),
                    DefinitionsKind::Definitions,
                    span,
                );
                module.diagnostics = self.diagnostics;
                return module;
            }
        };

        let mut module = Module::new(name, definitions_kind, Span::new(start, 0));

        // Parse IMPORTS if present
        if self.check(TokenKind::KwImports) {
            match self.parse_imports() {
                Ok(imports) => module.imports = imports,
                Err(diag) => self.diagnostics.push(diag),
            }
        }

        // Parse definitions until END
        while !self.check(TokenKind::KwEnd) && !self.is_eof() {
            match self.parse_definition() {
                Ok(def) => module.body.push(def),
                Err(diag) => {
                    self.diagnostics.push(diag);
                    // Try to recover to next definition
                    self.recover_to_definition();
                }
            }
        }

        // Expect END
        if self.check(TokenKind::KwEnd) {
            self.advance();
        } else if !self.is_eof() {
            self.diagnostics.push(self.error("expected END"));
        }

        module.span = Span::new(start, self.current_span().end);
        module.diagnostics = self.diagnostics;
        module
    }

    // === Token access methods ===

    /// Get the EOF token for this source.
    fn eof_token(&self) -> Token {
        Token {
            kind: TokenKind::Eof,
            span: Span::new(self.source.len() as u32, self.source.len() as u32),
        }
    }

    /// Check if we're at EOF.
    fn is_eof(&self) -> bool {
        self.peek().kind == TokenKind::Eof
    }

    /// Peek at current token.
    fn peek(&self) -> Token {
        self.tokens
            .get(self.pos)
            .copied()
            .unwrap_or_else(|| self.eof_token())
    }

    /// Peek at token n positions ahead.
    fn peek_nth(&self, n: usize) -> Token {
        self.tokens
            .get(self.pos + n)
            .copied()
            .unwrap_or_else(|| self.eof_token())
    }

    /// Advance and return current token.
    fn advance(&mut self) -> Token {
        let token = self.peek();
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        token
    }

    /// Check if current token is of given kind.
    fn check(&self, kind: TokenKind) -> bool {
        self.peek().kind == kind
    }

    /// Consume token of given kind, or return error.
    fn expect(&mut self, kind: TokenKind) -> Result<Token, Diagnostic> {
        if self.check(kind) {
            Ok(self.advance())
        } else {
            Err(self.error(&alloc::format!("expected {:?}", kind)))
        }
    }

    /// Get the span of the current token.
    fn current_span(&self) -> Span {
        self.peek().span
    }

    /// Extract text for a span.
    fn text(&self, span: Span) -> &str {
        let bytes = &self.source[span.start as usize..span.end as usize];
        core::str::from_utf8(bytes).unwrap_or("")
    }

    /// Create an error diagnostic at current position.
    fn error(&self, message: &str) -> Diagnostic {
        Diagnostic {
            severity: Severity::Error,
            span: self.current_span(),
            message: message.into(),
        }
    }

    /// Create an error diagnostic at a specific span.
    fn error_at(&self, span: Span, message: &str) -> Diagnostic {
        Diagnostic {
            severity: Severity::Error,
            span,
            message: message.into(),
        }
    }

    /// Parse a u32 from token text, emitting diagnostic on failure.
    /// Returns 0 as fallback to allow continued parsing.
    fn parse_u32(&mut self, span: Span, context: &str) -> u32 {
        match self.text(span).parse::<u32>() {
            Ok(v) => v,
            Err(_) => {
                self.diagnostics.push(self.error_at(
                    span,
                    &alloc::format!("invalid {} (not a valid u32)", context),
                ));
                0
            }
        }
    }

    /// Parse an i64 from token text, emitting diagnostic on failure.
    /// Returns 0 as fallback to allow continued parsing.
    fn parse_i64(&mut self, span: Span, context: &str) -> i64 {
        match self.text(span).parse::<i64>() {
            Ok(v) => v,
            Err(_) => {
                self.diagnostics.push(self.error_at(
                    span,
                    &alloc::format!("invalid {} (not a valid integer)", context),
                ));
                0
            }
        }
    }

    /// Parse a hex string to u64, emitting diagnostic on failure.
    /// Expected format: 'xxxx'H or 'xxxx'h
    /// Returns 0 as fallback to allow continued parsing.
    fn parse_hex(&mut self, span: Span, context: &str) -> u64 {
        let text = self.text(span);
        let hex_part = text
            .trim_start_matches('\'')
            .trim_end_matches(|c| c == '\'' || c == 'H' || c == 'h');

        if hex_part.is_empty() {
            self.diagnostics.push(self.error_at(
                span,
                &alloc::format!("empty {} value", context),
            ));
            return 0;
        }

        match u64::from_str_radix(hex_part, 16) {
            Ok(v) => v,
            Err(_) => {
                self.diagnostics.push(self.error_at(
                    span,
                    &alloc::format!("invalid {} (not valid hexadecimal)", context),
                ));
                0
            }
        }
    }

    // === Parsing methods ===

    /// Parse module header: `ModuleName DEFINITIONS ::= BEGIN`
    fn parse_module_header(&mut self) -> Result<(Ident, DefinitionsKind), Diagnostic> {
        // Module name (uppercase identifier)
        let name_token = self.expect_identifier()?;
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        // DEFINITIONS or PIB-DEFINITIONS
        let definitions_kind = if self.check(TokenKind::UppercaseIdent) {
            let token = self.advance();
            let text = self.text(token.span);
            if text == "PIB-DEFINITIONS" {
                DefinitionsKind::PibDefinitions
            } else {
                return Err(self.error("expected DEFINITIONS or PIB-DEFINITIONS"));
            }
        } else {
            self.expect(TokenKind::KwDefinitions)?;
            DefinitionsKind::Definitions
        };

        // ::=
        self.expect(TokenKind::ColonColonEqual)?;

        // BEGIN
        self.expect(TokenKind::KwBegin)?;

        Ok((name, definitions_kind))
    }

    /// Expect an identifier (uppercase or lowercase).
    fn expect_identifier(&mut self) -> Result<Token, Diagnostic> {
        if self.check(TokenKind::UppercaseIdent) || self.check(TokenKind::LowercaseIdent) {
            Ok(self.advance())
        } else {
            Err(self.error("expected identifier"))
        }
    }

    /// Expect an enum label (identifier or allowed keyword).
    /// In SMI enums, words like 'deprecated', 'current', 'optional' can be used as labels.
    fn expect_enum_label(&mut self) -> Result<Token, Diagnostic> {
        let kind = self.peek().kind;
        if kind == TokenKind::UppercaseIdent
            || kind == TokenKind::LowercaseIdent
            // Status keywords that can appear as enum labels
            || kind == TokenKind::KwCurrent
            || kind == TokenKind::KwDeprecated
            || kind == TokenKind::KwObsolete
            || kind == TokenKind::KwMandatory
            || kind == TokenKind::KwOptional
            // Other common keyword-like enum labels
            || kind == TokenKind::KwObject
            || kind == TokenKind::KwModule
            || kind == TokenKind::KwGroup
        {
            Ok(self.advance())
        } else {
            Err(self.error("expected enum label"))
        }
    }

    /// Parse IMPORTS clause.
    fn parse_imports(&mut self) -> Result<Vec<ImportClause>, Diagnostic> {
        self.expect(TokenKind::KwImports)?;
        let mut imports = Vec::new();

        // Parse groups: symbol, symbol, ... FROM ModuleName
        loop {
            // Check for end of imports (semicolon)
            if self.check(TokenKind::Semicolon) {
                self.advance();
                break;
            }

            // Check for unexpected end
            if self.is_eof() || self.check(TokenKind::KwEnd) {
                return Err(self.error("unexpected end of imports"));
            }

            let start = self.current_span().start;
            let mut symbols = Vec::new();

            // Parse symbols until FROM
            loop {
                // Accept keywords that can be imported (OBJECT-TYPE, etc.)
                let sym_token = if self.peek().kind.is_macro_keyword()
                    || self.peek().kind.is_type_keyword()
                    || self.check(TokenKind::UppercaseIdent)
                    || self.check(TokenKind::LowercaseIdent)
                {
                    self.advance()
                } else if self.check(TokenKind::KwFrom) {
                    break;
                } else {
                    return Err(self.error("expected symbol or FROM"));
                };

                symbols.push(Ident::new(self.text(sym_token.span).into(), sym_token.span));

                // Optional comma between symbols
                if self.check(TokenKind::Comma) {
                    self.advance();
                }
            }

            // FROM
            self.expect(TokenKind::KwFrom)?;

            // Module name
            let module_token = if self.check(TokenKind::UppercaseIdent) {
                self.advance()
            } else {
                return Err(self.error("expected module name after FROM"));
            };

            let from_module = Ident::new(self.text(module_token.span).into(), module_token.span);
            let span = Span::new(start, module_token.span.end);

            imports.push(ImportClause::new(symbols, from_module, span));
        }

        Ok(imports)
    }

    /// Parse a single definition.
    fn parse_definition(&mut self) -> Result<Definition, Diagnostic> {
        // Peek ahead to determine definition type
        let first = self.peek().kind;
        let second = self.peek_nth(1).kind;

        match (first, second) {
            // Value assignment: name OBJECT IDENTIFIER ::=
            (TokenKind::LowercaseIdent, TokenKind::KwObject)
                if self.peek_nth(2).kind == TokenKind::KwIdentifier =>
            {
                self.parse_value_assignment()
            }

            // OBJECT-TYPE
            (TokenKind::LowercaseIdent, TokenKind::KwObjectType) => self.parse_object_type(),

            // MODULE-IDENTITY
            (TokenKind::LowercaseIdent, TokenKind::KwModuleIdentity) => {
                self.parse_module_identity()
            }

            // OBJECT-IDENTITY
            (TokenKind::LowercaseIdent, TokenKind::KwObjectIdentity) => {
                self.parse_object_identity()
            }

            // NOTIFICATION-TYPE
            (TokenKind::LowercaseIdent, TokenKind::KwNotificationType) => {
                self.parse_notification_type()
            }

            // TRAP-TYPE
            (TokenKind::LowercaseIdent, TokenKind::KwTrapType) => self.parse_trap_type(),

            // TEXTUAL-CONVENTION
            (TokenKind::UppercaseIdent, TokenKind::KwTextualConvention) => {
                self.parse_textual_convention()
            }

            // OBJECT-GROUP
            (TokenKind::LowercaseIdent, TokenKind::KwObjectGroup) => self.parse_object_group(),

            // NOTIFICATION-GROUP
            (TokenKind::LowercaseIdent, TokenKind::KwNotificationGroup) => {
                self.parse_notification_group()
            }

            // MODULE-COMPLIANCE
            (TokenKind::LowercaseIdent, TokenKind::KwModuleCompliance) => {
                self.parse_module_compliance()
            }

            // AGENT-CAPABILITIES
            (TokenKind::LowercaseIdent, TokenKind::KwAgentCapabilities) => {
                self.parse_agent_capabilities()
            }

            // Type assignment or TEXTUAL-CONVENTION: TypeName ::=
            (TokenKind::UppercaseIdent, TokenKind::ColonColonEqual) => {
                // Check if this is a TC: TypeName ::= TEXTUAL-CONVENTION
                if self.peek_nth(2).kind == TokenKind::KwTextualConvention {
                    self.parse_textual_convention_with_assignment()
                } else {
                    self.parse_type_assignment()
                }
            }

            // MACRO definition (handled by lexer skip, but we might see the tokens)
            (TokenKind::UppercaseIdent, TokenKind::KwMacro) => self.parse_macro_definition(),

            // EXPORTS (skipped by lexer)
            (TokenKind::KwExports, _) => {
                // The lexer already skipped the content
                // Advance past EXPORTS and semicolon tokens
                self.advance(); // EXPORTS
                if self.check(TokenKind::Semicolon) {
                    self.advance();
                }
                // Try to parse the next definition
                self.parse_definition()
            }

            _ => Err(self.error(&alloc::format!(
                "unexpected token: {:?}",
                self.peek().kind
            ))),
        }
    }

    /// Parse value assignment: `name OBJECT IDENTIFIER ::= { ... }`
    fn parse_value_assignment(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::KwObject)?;
        self.expect(TokenKind::KwIdentifier)?;
        self.expect(TokenKind::ColonColonEqual)?;

        let oid = self.parse_oid_assignment()?;

        let span = Span::new(start, oid.span.end);
        Ok(Definition::ValueAssignment(ValueAssignmentDef {
            name,
            oid_assignment: oid,
            span,
        }))
    }

    /// Parse OID assignment: `{ parent subid ... }`
    fn parse_oid_assignment(&mut self) -> Result<OidAssignment, Diagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::LBrace)?;

        let mut components = Vec::new();

        while !self.check(TokenKind::RBrace) && !self.is_eof() {
            let comp_start = self.current_span().start;

            if self.check(TokenKind::Number) {
                // Numeric: 1, 3, 6, ...
                let token = self.advance();
                let value = self.parse_u32(token.span, "OID component");
                components.push(OidComponent::Number {
                    value,
                    span: token.span,
                });
            } else if self.check(TokenKind::LowercaseIdent) || self.check(TokenKind::UppercaseIdent)
            {
                // Name, possibly followed by (number) or .name (qualified)
                let first_token = self.advance();
                let first_name = Ident::new(self.text(first_token.span).into(), first_token.span);

                if self.check(TokenKind::Dot) {
                    // Qualified reference: Module.name or Module.name(number)
                    self.advance(); // consume dot

                    // Expect lowercase identifier after dot (symbol names are lowercase)
                    let name_token = self.expect(TokenKind::LowercaseIdent)?;
                    let name = Ident::new(self.text(name_token.span).into(), name_token.span);

                    if self.check(TokenKind::LParen) {
                        // QualifiedNamedNumber: Module.name(123)
                        self.advance(); // (
                        let num_token = self.expect(TokenKind::Number)?;
                        let number = self.parse_u32(num_token.span, "OID component");
                        let end_token = self.expect(TokenKind::RParen)?;
                        components.push(OidComponent::QualifiedNamedNumber {
                            module: first_name,
                            name,
                            number,
                            span: Span::new(comp_start, end_token.span.end),
                        });
                    } else {
                        // QualifiedName: Module.name
                        components.push(OidComponent::QualifiedName {
                            module: first_name,
                            name,
                            span: Span::new(comp_start, name_token.span.end),
                        });
                    }
                } else if self.check(TokenKind::LParen) {
                    // Named number: iso(1), org(3)
                    self.advance(); // (
                    let num_token = self.expect(TokenKind::Number)?;
                    let number = self.parse_u32(num_token.span, "OID component");
                    let end_token = self.expect(TokenKind::RParen)?;
                    components.push(OidComponent::NamedNumber {
                        name: first_name,
                        number,
                        span: Span::new(comp_start, end_token.span.end),
                    });
                } else {
                    // Just name: internet, ifEntry
                    components.push(OidComponent::Name(first_name));
                }
            } else {
                return Err(self.error("expected OID component"));
            }
        }

        let end_token = self.expect(TokenKind::RBrace)?;
        Ok(OidAssignment::new(
            components,
            Span::new(start, end_token.span.end),
        ))
    }

    /// Parse OBJECT-TYPE definition.
    fn parse_object_type(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::KwObjectType)?;

        // SYNTAX clause (required)
        self.expect(TokenKind::KwSyntax)?;
        let syntax = self.parse_syntax_clause()?;

        // Optional UNITS
        let units = if self.check(TokenKind::KwUnits) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // MAX-ACCESS or ACCESS (required)
        let access = self.parse_access_clause()?;

        // STATUS (technically required but some vendor MIBs omit it)
        let status = if self.check(TokenKind::KwStatus) {
            Some(self.parse_status_clause()?)
        } else {
            None
        };

        // DESCRIPTION (optional but common)
        let description = if self.check(TokenKind::KwDescription) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // REFERENCE (optional)
        let reference = if self.check(TokenKind::KwReference) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // INDEX or AUGMENTS (optional, for row entries)
        let (index, augments) = self.parse_index_or_augments()?;

        // DEFVAL (optional)
        let defval = if self.check(TokenKind::KwDefval) {
            Some(self.parse_defval_clause()?)
        } else {
            None
        };

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = Span::new(start, oid.span.end);

        Ok(Definition::ObjectType(ObjectTypeDef {
            name,
            syntax,
            units,
            access,
            status,
            description,
            reference,
            index,
            augments,
            defval,
            oid_assignment: oid,
            span,
        }))
    }

    /// Parse SYNTAX clause content.
    fn parse_syntax_clause(&mut self) -> Result<SyntaxClause, Diagnostic> {
        let start = self.current_span().start;
        let syntax = self.parse_type_syntax()?;
        let span = Span::new(start, syntax.span().end);
        Ok(SyntaxClause::new(syntax, span))
    }

    /// Parse type syntax.
    fn parse_type_syntax(&mut self) -> Result<TypeSyntax, Diagnostic> {
        let start = self.current_span().start;

        // Check for built-in types
        let base_syntax = match self.peek().kind {
            TokenKind::KwInteger | TokenKind::KwInteger32 => {
                self.advance();
                // Check for enum: INTEGER { ... }
                if self.check(TokenKind::LBrace) {
                    let named_numbers = self.parse_named_numbers()?;
                    let span = Span::new(start, self.current_span().start);
                    TypeSyntax::IntegerEnum {
                        base: None,
                        named_numbers,
                        span,
                    }
                } else {
                    TypeSyntax::TypeRef(Ident::new("Integer32".into(), Span::new(start, self.peek().span.start)))
                }
            }
            TokenKind::KwBits => {
                self.advance();
                // BITS can be a plain type reference (in SEQUENCE definitions)
                // or BITS { named-bit-list }
                if self.check(TokenKind::LBrace) {
                    self.advance();
                    let named_bits = self.parse_named_number_list()?;
                    self.expect(TokenKind::RBrace)?;
                    let span = Span::new(start, self.current_span().start);
                    TypeSyntax::Bits { named_bits, span }
                } else {
                    // Plain BITS type reference
                    TypeSyntax::TypeRef(Ident::new("BITS".into(), Span::new(start, self.peek().span.start)))
                }
            }
            TokenKind::KwOctet => {
                self.advance();
                self.expect(TokenKind::KwString)?;
                let span = Span::new(start, self.current_span().start);
                // Check for constraint
                if self.check(TokenKind::LParen) {
                    let constraint = self.parse_constraint()?;
                    let end = constraint.span().end;
                    TypeSyntax::Constrained {
                        base: alloc::boxed::Box::new(TypeSyntax::OctetString { span }),
                        constraint,
                        span: Span::new(start, end),
                    }
                } else {
                    TypeSyntax::OctetString { span }
                }
            }
            TokenKind::KwObject => {
                self.advance();
                self.expect(TokenKind::KwIdentifier)?;
                let span = Span::new(start, self.current_span().start);
                TypeSyntax::ObjectIdentifier { span }
            }
            TokenKind::KwSequence => {
                self.advance();
                if self.check(TokenKind::KwOf) {
                    // SEQUENCE OF EntryType
                    self.advance();
                    let entry_token = self.expect_identifier()?;
                    let entry_type =
                        Ident::new(self.text(entry_token.span).into(), entry_token.span);
                    let span = Span::new(start, entry_token.span.end);
                    TypeSyntax::SequenceOf { entry_type, span }
                } else {
                    // SEQUENCE { ... }
                    self.expect(TokenKind::LBrace)?;
                    let fields = self.parse_sequence_fields()?;
                    let end_token = self.expect(TokenKind::RBrace)?;
                    let span = Span::new(start, end_token.span.end);
                    TypeSyntax::Sequence { fields, span }
                }
            }
            // Other built-in type keywords
            TokenKind::KwCounter32
            | TokenKind::KwCounter64
            | TokenKind::KwGauge32
            | TokenKind::KwUnsigned32
            | TokenKind::KwTimeTicks
            | TokenKind::KwIpAddress
            | TokenKind::KwOpaque
            | TokenKind::KwCounter
            | TokenKind::KwGauge
            | TokenKind::KwNetworkAddress => {
                let token = self.advance();
                let name = self.text(token.span);
                TypeSyntax::TypeRef(Ident::new(name.into(), token.span))
            }
            // Type reference (uppercase identifier)
            TokenKind::UppercaseIdent => {
                let token = self.advance();
                let name = self.text(token.span);
                let ident = Ident::new(name.into(), token.span);

                // Check for constraint (parentheses) or enum value restriction (braces)
                if self.check(TokenKind::LParen) {
                    let constraint = self.parse_constraint()?;
                    let span = Span::new(start, constraint.span().end);
                    TypeSyntax::Constrained {
                        base: alloc::boxed::Box::new(TypeSyntax::TypeRef(ident)),
                        constraint,
                        span,
                    }
                } else if self.check(TokenKind::LBrace) {
                    // Enum value restriction: TypeRef { value1(1), value2(2) }
                    let named_numbers = self.parse_named_numbers()?;
                    let span = Span::new(start, self.current_span().start);
                    TypeSyntax::IntegerEnum {
                        base: Some(ident),
                        named_numbers,
                        span,
                    }
                } else {
                    TypeSyntax::TypeRef(ident)
                }
            }
            _ => return Err(self.error("expected type syntax")),
        };

        // Check for constraint on the base syntax
        if self.check(TokenKind::LParen) && !matches!(base_syntax, TypeSyntax::Constrained { .. }) {
            let constraint = self.parse_constraint()?;
            let span = Span::new(start, constraint.span().end);
            Ok(TypeSyntax::Constrained {
                base: alloc::boxed::Box::new(base_syntax),
                constraint,
                span,
            })
        } else {
            Ok(base_syntax)
        }
    }

    /// Parse named numbers: `{ name(value), ... }`
    fn parse_named_numbers(&mut self) -> Result<Vec<NamedNumber>, Diagnostic> {
        self.expect(TokenKind::LBrace)?;
        let result = self.parse_named_number_list()?;
        self.expect(TokenKind::RBrace)?;
        Ok(result)
    }

    /// Parse a list of named numbers (without braces).
    fn parse_named_number_list(&mut self) -> Result<Vec<NamedNumber>, Diagnostic> {
        let mut named_numbers = Vec::new();

        loop {
            if self.check(TokenKind::RBrace) || self.is_eof() {
                break;
            }

            let start = self.current_span().start;
            // Enum labels can be identifiers OR keywords like 'deprecated', 'current', 'optional'
            let name_token = self.expect_enum_label()?;
            let name = Ident::new(self.text(name_token.span).into(), name_token.span);

            self.expect(TokenKind::LParen)?;

            let is_negative = self.check(TokenKind::NegativeNumber);
            let num_token = if is_negative {
                self.advance()
            } else {
                self.expect(TokenKind::Number)?
            };
            let value = self.parse_i64(num_token.span, "named number value");

            let end_token = self.expect(TokenKind::RParen)?;
            let span = Span::new(start, end_token.span.end);

            named_numbers.push(NamedNumber::new(name, value, span));

            if self.check(TokenKind::Comma) {
                self.advance();
            } else {
                break;
            }
        }

        Ok(named_numbers)
    }

    /// Parse constraint: `(SIZE (0..255))` or `(0..65535)`
    fn parse_constraint(&mut self) -> Result<Constraint, Diagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::LParen)?;

        let constraint = if self.check(TokenKind::KwSize) {
            self.advance();
            self.expect(TokenKind::LParen)?;
            let ranges = self.parse_range_list()?;
            self.expect(TokenKind::RParen)?;
            let end_token = self.expect(TokenKind::RParen)?;
            Constraint::Size {
                ranges,
                span: Span::new(start, end_token.span.end),
            }
        } else {
            let ranges = self.parse_range_list()?;
            let end_token = self.expect(TokenKind::RParen)?;
            Constraint::Range {
                ranges,
                span: Span::new(start, end_token.span.end),
            }
        };

        Ok(constraint)
    }

    /// Parse a list of ranges: `0..255 | 1024..65535`
    fn parse_range_list(&mut self) -> Result<Vec<Range>, Diagnostic> {
        let mut ranges = Vec::new();

        loop {
            let start = self.current_span().start;
            let min = self.parse_range_value()?;

            let max = if self.check(TokenKind::DotDot) {
                self.advance();
                Some(self.parse_range_value()?)
            } else {
                None
            };

            let end = max
                .as_ref()
                .map(|v| match v {
                    RangeValue::Signed(_) | RangeValue::Unsigned(_) => self.current_span().start,
                    RangeValue::Ident(i) => i.span.end,
                })
                .unwrap_or(match &min {
                    RangeValue::Signed(_) | RangeValue::Unsigned(_) => self.current_span().start,
                    RangeValue::Ident(i) => i.span.end,
                });

            ranges.push(Range {
                min,
                max,
                span: Span::new(start, end),
            });

            if self.check(TokenKind::Pipe) {
                self.advance();
            } else {
                break;
            }
        }

        Ok(ranges)
    }

    /// Parse a range value (number, hex string, or identifier like MIN/MAX).
    fn parse_range_value(&mut self) -> Result<RangeValue, Diagnostic> {
        if self.check(TokenKind::Number) {
            let token = self.advance();
            let text = self.text(token.span);
            // Try parsing as u64 first to handle large unsigned values like Counter64 max
            if let Ok(value) = text.parse::<u64>() {
                Ok(RangeValue::Unsigned(value))
            } else {
                // Fallback to signed (shouldn't happen for positive numbers, but be safe)
                let value = self.parse_i64(token.span, "range value");
                Ok(RangeValue::Signed(value))
            }
        } else if self.check(TokenKind::NegativeNumber) {
            let token = self.advance();
            let value = self.parse_i64(token.span, "range value");
            Ok(RangeValue::Signed(value))
        } else if self.check(TokenKind::HexString) {
            // Hex string like 'ffffffff'h - parse to unsigned number
            let token = self.advance();
            let value = self.parse_hex(token.span, "hex range value");
            Ok(RangeValue::Unsigned(value))
        } else if self.check(TokenKind::UppercaseIdent) || self.check(TokenKind::ForbiddenKeyword) {
            // MIN and MAX are actually forbidden keywords but used here
            let token = self.advance();
            let name = self.text(token.span);
            Ok(RangeValue::Ident(Ident::new(name.into(), token.span)))
        } else {
            Err(self.error("expected range value"))
        }
    }

    /// Parse sequence fields.
    fn parse_sequence_fields(&mut self) -> Result<Vec<SequenceField>, Diagnostic> {
        let mut fields = Vec::new();

        loop {
            if self.check(TokenKind::RBrace) || self.is_eof() {
                break;
            }

            let start = self.current_span().start;
            let name_token = self.expect_identifier()?;
            let name = Ident::new(self.text(name_token.span).into(), name_token.span);

            let syntax = self.parse_type_syntax()?;
            let span = Span::new(start, syntax.span().end);

            fields.push(SequenceField { name, syntax, span });

            if self.check(TokenKind::Comma) {
                self.advance();
            }
        }

        Ok(fields)
    }

    /// Parse ACCESS or MAX-ACCESS clause.
    fn parse_access_clause(&mut self) -> Result<AccessClause, Diagnostic> {
        let start = self.current_span().start;

        let keyword = if self.check(TokenKind::KwMaxAccess) {
            self.advance();
            AccessKeyword::MaxAccess
        } else if self.check(TokenKind::KwAccess) {
            self.advance();
            AccessKeyword::Access
        } else if self.check(TokenKind::KwMinAccess) {
            self.advance();
            AccessKeyword::MinAccess
        } else {
            return Err(self.error("expected MAX-ACCESS, MIN-ACCESS, or ACCESS"));
        };

        let value = match self.peek().kind {
            TokenKind::KwReadOnly => {
                self.advance();
                AccessValue::ReadOnly
            }
            TokenKind::KwReadWrite => {
                self.advance();
                AccessValue::ReadWrite
            }
            TokenKind::KwReadCreate => {
                self.advance();
                AccessValue::ReadCreate
            }
            TokenKind::KwNotAccessible => {
                self.advance();
                AccessValue::NotAccessible
            }
            TokenKind::KwAccessibleForNotify => {
                self.advance();
                AccessValue::AccessibleForNotify
            }
            TokenKind::KwWriteOnly => {
                self.advance();
                AccessValue::WriteOnly
            }
            TokenKind::KwNotImplemented => {
                self.advance();
                AccessValue::NotImplemented
            }
            _ => return Err(self.error("expected access value")),
        };

        let span = Span::new(start, self.current_span().start);
        Ok(AccessClause {
            keyword,
            value,
            span,
        })
    }

    /// Parse STATUS clause.
    fn parse_status_clause(&mut self) -> Result<StatusClause, Diagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::KwStatus)?;

        let value = match self.peek().kind {
            TokenKind::KwCurrent => {
                self.advance();
                StatusValue::Current
            }
            TokenKind::KwDeprecated => {
                self.advance();
                StatusValue::Deprecated
            }
            TokenKind::KwObsolete => {
                self.advance();
                StatusValue::Obsolete
            }
            TokenKind::KwMandatory => {
                self.advance();
                StatusValue::Mandatory
            }
            TokenKind::KwOptional => {
                self.advance();
                StatusValue::Optional
            }
            _ => return Err(self.error("expected status value")),
        };

        let span = Span::new(start, self.current_span().start);
        Ok(StatusClause { value, span })
    }

    /// Parse INDEX or AUGMENTS clause.
    fn parse_index_or_augments(
        &mut self,
    ) -> Result<(Option<IndexClause>, Option<AugmentsClause>), Diagnostic> {
        if self.check(TokenKind::KwIndex) {
            let start = self.current_span().start;
            self.advance();
            self.expect(TokenKind::LBrace)?;

            let mut indexes = Vec::new();
            loop {
                if self.check(TokenKind::RBrace) || self.is_eof() {
                    break;
                }

                let item_start = self.current_span().start;
                let implied = if self.check(TokenKind::KwImplied) {
                    self.advance();
                    true
                } else {
                    false
                };

                let obj_token = self.expect_identifier()?;
                let object = Ident::new(self.text(obj_token.span).into(), obj_token.span);

                let span = Span::new(item_start, obj_token.span.end);
                indexes.push(IndexItem {
                    implied,
                    object,
                    span,
                });

                if self.check(TokenKind::Comma) {
                    self.advance();
                }
            }

            let end_token = self.expect(TokenKind::RBrace)?;
            let span = Span::new(start, end_token.span.end);

            Ok((Some(IndexClause::Index { indexes, span }), None))
        } else if self.check(TokenKind::KwAugments) {
            let start = self.current_span().start;
            self.advance();
            self.expect(TokenKind::LBrace)?;

            let target_token = self.expect_identifier()?;
            let target = Ident::new(self.text(target_token.span).into(), target_token.span);

            let end_token = self.expect(TokenKind::RBrace)?;
            let span = Span::new(start, end_token.span.end);

            Ok((None, Some(AugmentsClause { target, span })))
        } else {
            Ok((None, None))
        }
    }

    /// Parse DEFVAL clause.
    ///
    /// Per RFC 2578, DEFVAL values can be:
    /// - Integer: `DEFVAL { 0 }`, `DEFVAL { -1 }`
    /// - String: `DEFVAL { "public" }`
    /// - Enum label: `DEFVAL { enabled }`
    /// - BITS: `DEFVAL { { flag1, flag2 } }`
    /// - Hex string: `DEFVAL { 'FF00'H }`
    /// - Binary string: `DEFVAL { '1010'B }`
    /// - OID value: `DEFVAL { { iso 3 6 1 } }`
    fn parse_defval_clause(&mut self) -> Result<DefValClause, Diagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::KwDefval)?;
        self.expect(TokenKind::LBrace)?;

        let value = self.parse_defval_content()?;

        let end_token = self.expect(TokenKind::RBrace)?;
        let span = Span::new(start, end_token.span.end);

        Ok(DefValClause { value, span })
    }

    /// Parse the content inside a DEFVAL clause.
    fn parse_defval_content(&mut self) -> Result<DefValContent, Diagnostic> {
        let content_start = self.current_span().start;

        match self.peek().kind {
            // Negative number: -1, -100
            TokenKind::NegativeNumber => {
                let token = self.advance();
                let value = self.parse_i64(token.span, "DEFVAL integer");
                Ok(DefValContent::Integer(value))
            }

            // Positive number: 0, 100, 4294967296
            TokenKind::Number => {
                let token = self.advance();
                let text = self.text(token.span);
                // Try i64 first (most common), fall back to u64 for Counter64 values
                if let Ok(value) = text.parse::<i64>() {
                    Ok(DefValContent::Integer(value))
                } else if let Ok(value) = text.parse::<u64>() {
                    Ok(DefValContent::Unsigned(value))
                } else {
                    // Emit diagnostic for unparseable number
                    let value = self.parse_i64(token.span, "DEFVAL integer");
                    Ok(DefValContent::Integer(value))
                }
            }

            // Quoted string: "public", ""
            TokenKind::QuotedString => {
                let qs = self.parse_quoted_string()?;
                Ok(DefValContent::String(qs))
            }

            // Hex string: 'FF00'H
            TokenKind::HexString => {
                let token = self.advance();
                let text = self.text(token.span);
                // Strip the quotes and H suffix: 'FF00'H -> FF00
                let content = text
                    .trim_start_matches('\'')
                    .trim_end_matches('H')
                    .trim_end_matches('h')
                    .trim_end_matches('\'')
                    .to_string();
                Ok(DefValContent::HexString {
                    content,
                    span: token.span,
                })
            }

            // Binary string: '1010'B
            TokenKind::BinString => {
                let token = self.advance();
                let text = self.text(token.span);
                // Strip the quotes and B suffix: '1010'B -> 1010
                let content = text
                    .trim_start_matches('\'')
                    .trim_end_matches('B')
                    .trim_end_matches('b')
                    .trim_end_matches('\'')
                    .to_string();
                Ok(DefValContent::BinaryString {
                    content,
                    span: token.span,
                })
            }

            // Identifier: enum label or OID reference (enabled, true, sysName)
            TokenKind::LowercaseIdent | TokenKind::UppercaseIdent => {
                let token = self.advance();
                let ident = Ident::new(self.text(token.span).into(), token.span);
                Ok(DefValContent::Identifier(ident))
            }

            // Nested braces: BITS value or OID value
            // BITS: { flag1, flag2 } or { }
            // OID: { iso 3 6 1 } or { sysName 0 }
            TokenKind::LBrace => {
                self.advance(); // consume opening brace
                let inner_start = self.current_span().start;

                // Empty braces: BITS { {} }
                if self.check(TokenKind::RBrace) {
                    let end_token = self.advance();
                    let span = Span::new(inner_start, end_token.span.end);
                    return Ok(DefValContent::Bits {
                        labels: Vec::new(),
                        span,
                    });
                }

                // Peek to determine if this is BITS (comma-separated identifiers)
                // or OID (space-separated components possibly with numbers)
                let first_token = self.peek().kind;

                match first_token {
                    TokenKind::LowercaseIdent | TokenKind::UppercaseIdent => {
                        // Could be BITS { flag1, flag2 } or OID { sysName 0 }
                        // Look ahead to see if there's a comma (BITS) or number/paren (OID)
                        let ident_token = self.advance();
                        let ident = Ident::new(self.text(ident_token.span).into(), ident_token.span);

                        if self.check(TokenKind::Comma) || self.check(TokenKind::RBrace) {
                            // This is BITS: { flag1, flag2 }
                            let mut labels = vec![ident];
                            while self.check(TokenKind::Comma) {
                                self.advance(); // consume comma
                                if self.check(TokenKind::LowercaseIdent)
                                    || self.check(TokenKind::UppercaseIdent)
                                {
                                    let token = self.advance();
                                    labels.push(Ident::new(
                                        self.text(token.span).into(),
                                        token.span,
                                    ));
                                }
                            }
                            let end_token = self.expect(TokenKind::RBrace)?;
                            let span = Span::new(inner_start, end_token.span.end);
                            Ok(DefValContent::Bits { labels, span })
                        } else {
                            // This is OID: { sysName 0 } or { iso 3 6 1 }
                            let mut components = Vec::new();
                            // First component is the identifier we already parsed
                            if self.check(TokenKind::LParen) {
                                // Named number: iso(1)
                                self.advance(); // (
                                let num_token = self.expect(TokenKind::Number)?;
                                let number = self.parse_u32(num_token.span, "OID component");
                                let end_paren = self.expect(TokenKind::RParen)?;
                                components.push(OidComponent::NamedNumber {
                                    name: ident,
                                    number,
                                    span: Span::new(ident_token.span.start, end_paren.span.end),
                                });
                            } else {
                                // Just a name
                                components.push(OidComponent::Name(ident));
                            }

                            // Parse remaining components
                            while !self.check(TokenKind::RBrace) && !self.is_eof() {
                                if self.check(TokenKind::Number) {
                                    let token = self.advance();
                                    let value = self.parse_u32(token.span, "OID component");
                                    components.push(OidComponent::Number {
                                        value,
                                        span: token.span,
                                    });
                                } else if self.check(TokenKind::LowercaseIdent)
                                    || self.check(TokenKind::UppercaseIdent)
                                {
                                    let token = self.advance();
                                    let name =
                                        Ident::new(self.text(token.span).into(), token.span);
                                    if self.check(TokenKind::LParen) {
                                        self.advance();
                                        let num_token = self.expect(TokenKind::Number)?;
                                        let number =
                                            self.parse_u32(num_token.span, "OID component");
                                        let end_paren = self.expect(TokenKind::RParen)?;
                                        components.push(OidComponent::NamedNumber {
                                            name,
                                            number,
                                            span: Span::new(token.span.start, end_paren.span.end),
                                        });
                                    } else {
                                        components.push(OidComponent::Name(name));
                                    }
                                } else {
                                    // Unknown token, skip
                                    self.advance();
                                }
                            }
                            let end_token = self.expect(TokenKind::RBrace)?;
                            let span = Span::new(inner_start, end_token.span.end);
                            Ok(DefValContent::ObjectIdentifier { components, span })
                        }
                    }
                    TokenKind::Number => {
                        // This is OID: { 1 3 6 1 }
                        let mut components = Vec::new();
                        while !self.check(TokenKind::RBrace) && !self.is_eof() {
                            if self.check(TokenKind::Number) {
                                let token = self.advance();
                                let value = self.parse_u32(token.span, "OID component");
                                components.push(OidComponent::Number {
                                    value,
                                    span: token.span,
                                });
                            } else if self.check(TokenKind::LowercaseIdent)
                                || self.check(TokenKind::UppercaseIdent)
                            {
                                let token = self.advance();
                                let name = Ident::new(self.text(token.span).into(), token.span);
                                if self.check(TokenKind::LParen) {
                                    self.advance();
                                    let num_token = self.expect(TokenKind::Number)?;
                                    let number =
                                        self.parse_u32(num_token.span, "OID component");
                                    let end_paren = self.expect(TokenKind::RParen)?;
                                    components.push(OidComponent::NamedNumber {
                                        name,
                                        number,
                                        span: Span::new(token.span.start, end_paren.span.end),
                                    });
                                } else {
                                    components.push(OidComponent::Name(name));
                                }
                            } else {
                                break;
                            }
                        }
                        let end_token = self.expect(TokenKind::RBrace)?;
                        let span = Span::new(inner_start, end_token.span.end);
                        Ok(DefValContent::ObjectIdentifier { components, span })
                    }
                    _ => {
                        // Unknown content in braces, skip to closing brace
                        let mut depth = 1;
                        while depth > 0 && !self.is_eof() {
                            match self.peek().kind {
                                TokenKind::LBrace => {
                                    depth += 1;
                                    self.advance();
                                }
                                TokenKind::RBrace => {
                                    depth -= 1;
                                    if depth > 0 {
                                        self.advance();
                                    }
                                }
                                _ => {
                                    self.advance();
                                }
                            }
                        }
                        let end_token = self.expect(TokenKind::RBrace)?;
                        let span = Span::new(content_start, end_token.span.end);
                        Ok(DefValContent::Bits {
                            labels: Vec::new(),
                            span,
                        })
                    }
                }
            }

            // Unknown content - skip to closing brace
            _ => {
                let mut depth = 0;
                while !self.is_eof() {
                    match self.peek().kind {
                        TokenKind::LBrace => {
                            depth += 1;
                            self.advance();
                        }
                        TokenKind::RBrace => {
                            if depth == 0 {
                                break;
                            }
                            depth -= 1;
                            self.advance();
                        }
                        _ => {
                            self.advance();
                        }
                    }
                }
                // Return empty BITS as fallback for unparseable content
                let span = Span::new(content_start, self.current_span().start);
                Ok(DefValContent::Bits {
                    labels: Vec::new(),
                    span,
                })
            }
        }
    }

    /// Parse a quoted string.
    fn parse_quoted_string(&mut self) -> Result<QuotedString, Diagnostic> {
        if !self.check(TokenKind::QuotedString) {
            return Err(self.error("expected quoted string"));
        }
        let token = self.advance();
        let full_text = self.text(token.span);
        // Strip quotes
        let value = if full_text.len() >= 2 {
            full_text[1..full_text.len() - 1].to_string()
        } else {
            String::new()
        };
        Ok(QuotedString::new(value, token.span))
    }

    /// Parse MODULE-IDENTITY definition.
    fn parse_module_identity(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::KwModuleIdentity)?;

        // LAST-UPDATED
        self.expect(TokenKind::KwLastUpdated)?;
        let last_updated = self.parse_quoted_string()?;

        // ORGANIZATION
        self.expect(TokenKind::KwOrganization)?;
        let organization = self.parse_quoted_string()?;

        // CONTACT-INFO
        self.expect(TokenKind::KwContactInfo)?;
        let contact_info = self.parse_quoted_string()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REVISION clauses (optional, multiple)
        let mut revisions = Vec::new();
        while self.check(TokenKind::KwRevision) {
            let rev_start = self.current_span().start;
            self.advance();
            let date = self.parse_quoted_string()?;
            self.expect(TokenKind::KwDescription)?;
            let rev_description = self.parse_quoted_string()?;
            let span = Span::new(rev_start, rev_description.span.end);
            revisions.push(crate::ast::RevisionClause {
                date,
                description: rev_description,
                span,
            });
        }

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = Span::new(start, oid.span.end);

        Ok(Definition::ModuleIdentity(
            crate::ast::ModuleIdentityDef {
                name,
                last_updated,
                organization,
                contact_info,
                description,
                revisions,
                oid_assignment: oid,
                span,
            },
        ))
    }

    /// Parse OBJECT-IDENTITY definition.
    fn parse_object_identity(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::KwObjectIdentity)?;

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = if self.check(TokenKind::KwReference) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = Span::new(start, oid.span.end);

        Ok(Definition::ObjectIdentity(
            crate::ast::ObjectIdentityDef {
                name,
                status,
                description,
                reference,
                oid_assignment: oid,
                span,
            },
        ))
    }

    /// Parse NOTIFICATION-TYPE definition.
    fn parse_notification_type(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::KwNotificationType)?;

        // OBJECTS (optional)
        let objects = if self.check(TokenKind::KwObjects) {
            self.advance();
            self.expect(TokenKind::LBrace)?;
            let objs = self.parse_identifier_list()?;
            self.expect(TokenKind::RBrace)?;
            objs
        } else {
            Vec::new()
        };

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = if self.check(TokenKind::KwReference) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = Span::new(start, oid.span.end);

        Ok(Definition::NotificationType(
            crate::ast::NotificationTypeDef {
                name,
                objects,
                status,
                description,
                reference,
                oid_assignment: oid,
                span,
            },
        ))
    }

    /// Parse TRAP-TYPE definition (SMIv1).
    fn parse_trap_type(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::KwTrapType)?;

        // ENTERPRISE
        self.expect(TokenKind::KwEnterprise)?;
        let enterprise_token = self.expect_identifier()?;
        let enterprise = Ident::new(
            self.text(enterprise_token.span).into(),
            enterprise_token.span,
        );

        // VARIABLES (optional)
        let variables = if self.check(TokenKind::KwVariables) {
            self.advance();
            self.expect(TokenKind::LBrace)?;
            let vars = self.parse_identifier_list()?;
            self.expect(TokenKind::RBrace)?;
            vars
        } else {
            Vec::new()
        };

        // DESCRIPTION (optional)
        let description = if self.check(TokenKind::KwDescription) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // REFERENCE (optional)
        let reference = if self.check(TokenKind::KwReference) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // ::= number
        self.expect(TokenKind::ColonColonEqual)?;
        let num_token = self.expect(TokenKind::Number)?;
        let trap_number = self.parse_u32(num_token.span, "trap number");

        let span = Span::new(start, num_token.span.end);

        Ok(Definition::TrapType(crate::ast::TrapTypeDef {
            name,
            enterprise,
            variables,
            description,
            reference,
            trap_number,
            span,
        }))
    }

    /// Parse TEXTUAL-CONVENTION definition.
    fn parse_textual_convention(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::KwTextualConvention)?;

        // DISPLAY-HINT (optional)
        let display_hint = if self.check(TokenKind::KwDisplayHint) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = if self.check(TokenKind::KwReference) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // SYNTAX
        self.expect(TokenKind::KwSyntax)?;
        let syntax = self.parse_syntax_clause()?;

        let span = Span::new(start, syntax.span.end);

        Ok(Definition::TextualConvention(TextualConventionDef {
            name,
            display_hint,
            status,
            description,
            reference,
            syntax,
            span,
        }))
    }

    /// Parse TEXTUAL-CONVENTION definition with ::= syntax.
    /// Handles: `Name ::= TEXTUAL-CONVENTION ...`
    fn parse_textual_convention_with_assignment(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::ColonColonEqual)?;
        self.expect(TokenKind::KwTextualConvention)?;

        // DISPLAY-HINT (optional)
        let display_hint = if self.check(TokenKind::KwDisplayHint) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = if self.check(TokenKind::KwReference) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // SYNTAX
        self.expect(TokenKind::KwSyntax)?;
        let syntax = self.parse_syntax_clause()?;

        let span = Span::new(start, syntax.span.end);

        Ok(Definition::TextualConvention(TextualConventionDef {
            name,
            display_hint,
            status,
            description,
            reference,
            syntax,
            span,
        }))
    }

    /// Parse type assignment: `TypeName ::= TypeSyntax`
    fn parse_type_assignment(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::ColonColonEqual)?;

        let syntax = self.parse_type_syntax()?;
        let span = Span::new(start, syntax.span().end);

        Ok(Definition::TypeAssignment(TypeAssignmentDef {
            name,
            syntax,
            span,
        }))
    }

    /// Parse OBJECT-GROUP definition.
    fn parse_object_group(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::KwObjectGroup)?;

        // OBJECTS
        self.expect(TokenKind::KwObjects)?;
        self.expect(TokenKind::LBrace)?;
        let objects = self.parse_identifier_list()?;
        self.expect(TokenKind::RBrace)?;

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = if self.check(TokenKind::KwReference) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = Span::new(start, oid.span.end);

        Ok(Definition::ObjectGroup(crate::ast::ObjectGroupDef {
            name,
            objects,
            status,
            description,
            reference,
            oid_assignment: oid,
            span,
        }))
    }

    /// Parse NOTIFICATION-GROUP definition.
    fn parse_notification_group(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::KwNotificationGroup)?;

        // NOTIFICATIONS
        self.expect(TokenKind::KwNotifications)?;
        self.expect(TokenKind::LBrace)?;
        let notifications = self.parse_identifier_list()?;
        self.expect(TokenKind::RBrace)?;

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = if self.check(TokenKind::KwReference) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = Span::new(start, oid.span.end);

        Ok(Definition::NotificationGroup(
            crate::ast::NotificationGroupDef {
                name,
                notifications,
                status,
                description,
                reference,
                oid_assignment: oid,
                span,
            },
        ))
    }

    /// Parse MODULE-COMPLIANCE definition.
    fn parse_module_compliance(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::KwModuleCompliance)?;

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = if self.check(TokenKind::KwReference) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // Parse MODULE clauses
        let mut modules = Vec::new();
        while self.check(TokenKind::KwModule) {
            modules.push(self.parse_compliance_module()?);
        }

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = Span::new(start, oid.span.end);

        Ok(Definition::ModuleCompliance(
            crate::ast::ModuleComplianceDef {
                name,
                status,
                description,
                reference,
                modules,
                oid_assignment: oid,
                span,
            },
        ))
    }

    /// Parse MODULE clause in MODULE-COMPLIANCE.
    fn parse_compliance_module(&mut self) -> Result<ComplianceModule, Diagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::KwModule)?;

        // Optional module name (uppercase identifier)
        let module_name = if self.check(TokenKind::UppercaseIdent) {
            let name_token = self.advance();
            Some(Ident::new(
                self.text(name_token.span).into(),
                name_token.span,
            ))
        } else {
            None
        };

        // Optional module OID (rare)
        let module_oid = if self.check(TokenKind::LBrace) {
            Some(self.parse_oid_assignment()?)
        } else {
            None
        };

        // MANDATORY-GROUPS (optional)
        let mandatory_groups = if self.check(TokenKind::KwMandatoryGroups) {
            self.parse_mandatory_groups()?
        } else {
            Vec::new()
        };

        // GROUP and OBJECT refinements
        let mut compliances = Vec::new();
        while self.check(TokenKind::KwGroup) || self.check(TokenKind::KwObject) {
            if self.check(TokenKind::KwGroup) {
                compliances.push(Compliance::Group(self.parse_compliance_group()?));
            } else {
                compliances.push(Compliance::Object(self.parse_compliance_object()?));
            }
        }

        let end = self.current_span().start;
        Ok(ComplianceModule {
            module_name,
            module_oid,
            mandatory_groups,
            compliances,
            span: Span::new(start, end),
        })
    }

    /// Parse MANDATORY-GROUPS clause.
    fn parse_mandatory_groups(&mut self) -> Result<Vec<Ident>, Diagnostic> {
        self.expect(TokenKind::KwMandatoryGroups)?;
        self.expect(TokenKind::LBrace)?;
        let groups = self.parse_identifier_list()?;
        self.expect(TokenKind::RBrace)?;
        Ok(groups)
    }

    /// Parse GROUP clause in MODULE-COMPLIANCE.
    fn parse_compliance_group(&mut self) -> Result<ComplianceGroup, Diagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::KwGroup)?;
        let group = self.parse_identifier_as_ident()?;
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;
        let end = description.span.end;
        Ok(ComplianceGroup {
            group,
            description,
            span: Span::new(start, end),
        })
    }

    /// Parse OBJECT clause in MODULE-COMPLIANCE.
    fn parse_compliance_object(&mut self) -> Result<ComplianceObject, Diagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::KwObject)?;
        let object = self.parse_identifier_as_ident()?;

        // Optional SYNTAX
        let syntax = if self.check(TokenKind::KwSyntax) {
            self.advance();
            Some(self.parse_syntax_clause()?)
        } else {
            None
        };

        // Optional WRITE-SYNTAX
        let write_syntax = if self.check(TokenKind::KwWriteSyntax) {
            self.advance();
            Some(self.parse_syntax_clause()?)
        } else {
            None
        };

        // Optional MIN-ACCESS
        let min_access = if self.check(TokenKind::KwMinAccess) {
            Some(self.parse_access_clause()?)
        } else {
            None
        };

        // Required DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        let end = description.span.end;
        Ok(ComplianceObject {
            object,
            syntax,
            write_syntax,
            min_access,
            description,
            span: Span::new(start, end),
        })
    }

    /// Parse an identifier and return it as an Ident.
    fn parse_identifier_as_ident(&mut self) -> Result<Ident, Diagnostic> {
        let token = self.expect_identifier()?;
        Ok(Ident::new(self.text(token.span).into(), token.span))
    }

    /// Parse AGENT-CAPABILITIES definition.
    fn parse_agent_capabilities(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        self.expect(TokenKind::KwAgentCapabilities)?;

        // PRODUCT-RELEASE
        self.expect(TokenKind::KwProductRelease)?;
        let product_release = self.parse_quoted_string()?;

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = if self.check(TokenKind::KwReference) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // Parse SUPPORTS clauses
        let mut supports = Vec::new();
        while self.check(TokenKind::KwSupports) {
            supports.push(self.parse_supports_module()?);
        }

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = Span::new(start, oid.span.end);

        Ok(Definition::AgentCapabilities(
            crate::ast::AgentCapabilitiesDef {
                name,
                product_release,
                status,
                description,
                reference,
                supports,
                oid_assignment: oid,
                span,
            },
        ))
    }

    /// Parse SUPPORTS clause in AGENT-CAPABILITIES.
    fn parse_supports_module(&mut self) -> Result<SupportsModule, Diagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::KwSupports)?;

        // Module name (uppercase identifier)
        let module_name = self.parse_identifier_as_ident()?;

        // Optional module OID
        let module_oid = if self.check(TokenKind::LBrace) {
            Some(self.parse_oid_assignment()?)
        } else {
            None
        };

        // INCLUDES { groups }
        self.expect(TokenKind::KwIncludes)?;
        self.expect(TokenKind::LBrace)?;
        let includes = self.parse_identifier_list()?;
        self.expect(TokenKind::RBrace)?;

        // VARIATION clauses (zero or more)
        let mut variations = Vec::new();
        while self.check(TokenKind::KwVariation) {
            variations.push(self.parse_variation_clause()?);
        }

        let end = self.current_span().start;
        Ok(SupportsModule {
            module_name,
            module_oid,
            includes,
            variations,
            span: Span::new(start, end),
        })
    }

    /// Parse VARIATION clause in AGENT-CAPABILITIES.
    ///
    /// Can be either an object variation or a notification variation.
    /// We detect which based on the presence of SYNTAX/WRITE-SYNTAX/CREATION-REQUIRES/DEFVAL
    /// (which are only valid for objects, not notifications).
    fn parse_variation_clause(&mut self) -> Result<Variation, Diagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::KwVariation)?;

        // Object or notification name
        let name = self.parse_identifier_as_ident()?;

        // Check for object-specific clauses to determine type
        // Per RFC 2580: notifications can only have ACCESS and DESCRIPTION
        // Objects can have: SYNTAX, WRITE-SYNTAX, ACCESS, CREATION-REQUIRES, DEFVAL, DESCRIPTION

        // Optional SYNTAX (objects only)
        let syntax = if self.check(TokenKind::KwSyntax) {
            self.advance();
            Some(self.parse_syntax_clause()?)
        } else {
            None
        };

        // Optional WRITE-SYNTAX (objects only)
        let write_syntax = if self.check(TokenKind::KwWriteSyntax) {
            self.advance();
            Some(self.parse_syntax_clause()?)
        } else {
            None
        };

        // Optional ACCESS
        let access = if self.check(TokenKind::KwAccess) {
            Some(self.parse_access_clause()?)
        } else {
            None
        };

        // Optional CREATION-REQUIRES (objects only)
        let creation_requires = if self.check(TokenKind::KwCreationRequires) {
            self.advance();
            self.expect(TokenKind::LBrace)?;
            let objects = self.parse_identifier_list()?;
            self.expect(TokenKind::RBrace)?;
            Some(objects)
        } else {
            None
        };

        // Optional DEFVAL (objects only)
        let defval = if self.check(TokenKind::KwDefval) {
            Some(self.parse_defval_clause()?)
        } else {
            None
        };

        // Required DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        let end = description.span.end;

        // Determine if this is an object or notification variation
        // If any object-specific clause was present, it's an object variation
        if syntax.is_some()
            || write_syntax.is_some()
            || creation_requires.is_some()
            || defval.is_some()
        {
            Ok(Variation::Object(ObjectVariation {
                object: name,
                syntax,
                write_syntax,
                access,
                creation_requires,
                defval,
                description,
                span: Span::new(start, end),
            }))
        } else {
            // Could be either object or notification with just ACCESS and DESCRIPTION
            // We don't have enough info here to distinguish, so we treat it as an object
            // variation. The resolver can validate later if needed.
            // Actually, per RFC 2580, if only ACCESS is present with "not-implemented",
            // it could be a notification. For now, we'll use a heuristic: if ACCESS
            // is "not-implemented" and no other clauses, treat as notification.
            // But for simplicity, we'll treat everything with any object-compatible
            // fields as object, and only pure ACCESS+DESCRIPTION as potentially
            // notification. Since we can't know for sure without resolving the name,
            // we'll default to ObjectVariation.
            Ok(Variation::Object(ObjectVariation {
                object: name,
                syntax: None,
                write_syntax: None,
                access,
                creation_requires: None,
                defval: None,
                description,
                span: Span::new(start, end),
            }))
        }
    }

    /// Parse MACRO definition (just record its presence).
    fn parse_macro_definition(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = Ident::new(self.text(name_token.span).into(), name_token.span);

        // MACRO keyword triggers lexer skip state, so we just see MACRO then END
        self.expect(TokenKind::KwMacro)?;

        // Skip until END (lexer should have handled this, but just in case)
        while !self.check(TokenKind::KwEnd) && !self.is_eof() {
            self.advance();
        }

        let end_token = if self.check(TokenKind::KwEnd) {
            self.advance()
        } else {
            return Err(self.error("expected END for MACRO"));
        };

        let span = Span::new(start, end_token.span.end);

        Ok(Definition::MacroDefinition(
            crate::ast::MacroDefinitionDef { name, span },
        ))
    }

    /// Parse a comma-separated list of identifiers.
    fn parse_identifier_list(&mut self) -> Result<Vec<Ident>, Diagnostic> {
        let mut idents = Vec::new();

        loop {
            if self.check(TokenKind::RBrace) || self.is_eof() {
                break;
            }

            let token = self.expect_identifier()?;
            idents.push(Ident::new(self.text(token.span).into(), token.span));

            if self.check(TokenKind::Comma) {
                self.advance();
            } else {
                break;
            }
        }

        Ok(idents)
    }

    /// Recover to the next definition after an error.
    fn recover_to_definition(&mut self) {
        // Skip until we see a pattern that looks like a definition start
        loop {
            if self.is_eof() || self.check(TokenKind::KwEnd) {
                break;
            }

            let current = self.peek().kind;
            let next = self.peek_nth(1).kind;

            // Definition patterns:
            // - lowercase OBJECT-TYPE/etc
            // - uppercase ::= (type assignment)
            // - lowercase OBJECT IDENTIFIER
            if (current == TokenKind::LowercaseIdent && next.is_macro_keyword())
                || (current == TokenKind::UppercaseIdent && next == TokenKind::ColonColonEqual)
                || (current == TokenKind::UppercaseIdent && next == TokenKind::KwTextualConvention)
                || (current == TokenKind::LowercaseIdent
                    && next == TokenKind::KwObject
                    && self.peek_nth(2).kind == TokenKind::KwIdentifier)
            {
                break;
            }

            self.advance();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_module() {
        let source = b"TEST-MIB DEFINITIONS ::= BEGIN END";
        let parser = Parser::new(source);
        let module = parser.parse_module();

        assert_eq!(module.name.name, "TEST-MIB");
        assert_eq!(module.definitions_kind, DefinitionsKind::Definitions);
        assert!(module.body.is_empty());
    }

    #[test]
    fn test_parse_module_with_imports() {
        let source = b"TEST-MIB DEFINITIONS ::= BEGIN
            IMPORTS
                MODULE-IDENTITY, OBJECT-TYPE FROM SNMPv2-SMI
                DisplayString FROM SNMPv2-TC;
            END";
        let parser = Parser::new(source);
        let module = parser.parse_module();

        assert_eq!(module.name.name, "TEST-MIB");
        assert_eq!(module.imports.len(), 2);
        assert_eq!(module.imports[0].from_module.name, "SNMPv2-SMI");
        assert_eq!(module.imports[0].symbols.len(), 2);
        assert_eq!(module.imports[1].from_module.name, "SNMPv2-TC");
    }

    #[test]
    fn test_parse_value_assignment() {
        let source = b"TEST-MIB DEFINITIONS ::= BEGIN
            testObject OBJECT IDENTIFIER ::= { iso 3 }
            END";
        let parser = Parser::new(source);
        let module = parser.parse_module();

        assert_eq!(module.body.len(), 1);
        if let Definition::ValueAssignment(def) = &module.body[0] {
            assert_eq!(def.name.name, "testObject");
            assert_eq!(def.oid_assignment.components.len(), 2);
        } else {
            panic!("expected ValueAssignment");
        }
    }

    #[test]
    fn test_parse_simple_object_type() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testIndex OBJECT-TYPE
                SYNTAX Integer32
                MAX-ACCESS read-only
                STATUS current
                DESCRIPTION "Test description"
                ::= { testEntry 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        assert_eq!(module.body.len(), 1);
        if let Definition::ObjectType(def) = &module.body[0] {
            assert_eq!(def.name.name, "testIndex");
            assert_eq!(def.access.value, AccessValue::ReadOnly);
            assert_eq!(def.status.as_ref().unwrap().value, StatusValue::Current);
        } else {
            panic!("expected ObjectType");
        }
    }

    #[test]
    fn test_parse_textual_convention() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            TestString TEXTUAL-CONVENTION
                STATUS current
                DESCRIPTION "A test string"
                SYNTAX OCTET STRING (SIZE (0..255))
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        assert_eq!(module.body.len(), 1);
        if let Definition::TextualConvention(def) = &module.body[0] {
            assert_eq!(def.name.name, "TestString");
            assert_eq!(def.status.value, StatusValue::Current);
        } else {
            panic!("expected TextualConvention");
        }
    }

    #[test]
    fn test_parse_defval_integer() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testCounter OBJECT-TYPE
                SYNTAX Integer32
                MAX-ACCESS read-only
                STATUS current
                DESCRIPTION "Test"
                DEFVAL { 0 }
                ::= { testEntry 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ObjectType(def) = &module.body[0] {
            assert!(def.defval.is_some());
            let defval = def.defval.as_ref().unwrap();
            assert!(matches!(defval.value, DefValContent::Integer(0)));
        } else {
            panic!("expected ObjectType");
        }
    }

    #[test]
    fn test_parse_defval_string() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testString OBJECT-TYPE
                SYNTAX DisplayString
                MAX-ACCESS read-write
                STATUS current
                DESCRIPTION "Test"
                DEFVAL { "public" }
                ::= { testEntry 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ObjectType(def) = &module.body[0] {
            assert!(def.defval.is_some());
            let defval = def.defval.as_ref().unwrap();
            if let DefValContent::String(qs) = &defval.value {
                assert_eq!(qs.value, "public");
            } else {
                panic!("expected String DefValContent");
            }
        } else {
            panic!("expected ObjectType");
        }
    }

    #[test]
    fn test_parse_defval_enum_label() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testStatus OBJECT-TYPE
                SYNTAX INTEGER { enabled(1), disabled(2) }
                MAX-ACCESS read-write
                STATUS current
                DESCRIPTION "Test"
                DEFVAL { enabled }
                ::= { testEntry 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ObjectType(def) = &module.body[0] {
            assert!(def.defval.is_some());
            let defval = def.defval.as_ref().unwrap();
            if let DefValContent::Identifier(ident) = &defval.value {
                assert_eq!(ident.name, "enabled");
            } else {
                panic!("expected Identifier DefValContent, got {:?}", defval.value);
            }
        } else {
            panic!("expected ObjectType");
        }
    }

    #[test]
    fn test_parse_defval_bits() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testBits OBJECT-TYPE
                SYNTAX BITS { flag1(0), flag2(1) }
                MAX-ACCESS read-write
                STATUS current
                DESCRIPTION "Test"
                DEFVAL { { flag1, flag2 } }
                ::= { testEntry 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ObjectType(def) = &module.body[0] {
            assert!(def.defval.is_some());
            let defval = def.defval.as_ref().unwrap();
            if let DefValContent::Bits { labels, .. } = &defval.value {
                assert_eq!(labels.len(), 2);
                assert_eq!(labels[0].name, "flag1");
                assert_eq!(labels[1].name, "flag2");
            } else {
                panic!("expected Bits DefValContent, got {:?}", defval.value);
            }
        } else {
            panic!("expected ObjectType");
        }
    }

    #[test]
    fn test_parse_defval_empty_bits() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testBits OBJECT-TYPE
                SYNTAX BITS { flag1(0) }
                MAX-ACCESS read-write
                STATUS current
                DESCRIPTION "Test"
                DEFVAL { {} }
                ::= { testEntry 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ObjectType(def) = &module.body[0] {
            assert!(def.defval.is_some());
            let defval = def.defval.as_ref().unwrap();
            if let DefValContent::Bits { labels, .. } = &defval.value {
                assert!(labels.is_empty());
            } else {
                panic!("expected Bits DefValContent, got {:?}", defval.value);
            }
        } else {
            panic!("expected ObjectType");
        }
    }

    #[test]
    fn test_parse_defval_negative() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testOffset OBJECT-TYPE
                SYNTAX Integer32
                MAX-ACCESS read-write
                STATUS current
                DESCRIPTION "Test"
                DEFVAL { -100 }
                ::= { testEntry 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ObjectType(def) = &module.body[0] {
            assert!(def.defval.is_some());
            let defval = def.defval.as_ref().unwrap();
            assert!(matches!(defval.value, DefValContent::Integer(-100)));
        } else {
            panic!("expected ObjectType");
        }
    }

    #[test]
    fn test_parse_module_compliance_mandatory_groups() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testCompliance MODULE-COMPLIANCE
                STATUS current
                DESCRIPTION "Test compliance"
                MODULE
                    MANDATORY-GROUPS { testGroup1, testGroup2 }
                ::= { testCompliances 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        assert_eq!(module.body.len(), 1);
        if let Definition::ModuleCompliance(def) = &module.body[0] {
            assert_eq!(def.name.name, "testCompliance");
            assert_eq!(def.modules.len(), 1);
            let cm = &def.modules[0];
            assert!(cm.module_name.is_none()); // Current module
            assert_eq!(cm.mandatory_groups.len(), 2);
            assert_eq!(cm.mandatory_groups[0].name, "testGroup1");
            assert_eq!(cm.mandatory_groups[1].name, "testGroup2");
        } else {
            panic!("expected ModuleCompliance");
        }
    }

    #[test]
    fn test_parse_module_compliance_with_module_name() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testCompliance MODULE-COMPLIANCE
                STATUS current
                DESCRIPTION "Test compliance"
                MODULE OTHER-MIB
                    MANDATORY-GROUPS { otherGroup }
                ::= { testCompliances 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ModuleCompliance(def) = &module.body[0] {
            assert_eq!(def.modules.len(), 1);
            let cm = &def.modules[0];
            assert_eq!(cm.module_name.as_ref().unwrap().name, "OTHER-MIB");
            assert_eq!(cm.mandatory_groups.len(), 1);
        } else {
            panic!("expected ModuleCompliance");
        }
    }

    #[test]
    fn test_parse_module_compliance_group_refinement() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testCompliance MODULE-COMPLIANCE
                STATUS current
                DESCRIPTION "Test compliance"
                MODULE
                    MANDATORY-GROUPS { testGroup }
                    GROUP optionalGroup
                        DESCRIPTION "Optional group for advanced features"
                ::= { testCompliances 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ModuleCompliance(def) = &module.body[0] {
            let cm = &def.modules[0];
            assert_eq!(cm.mandatory_groups.len(), 1);
            assert_eq!(cm.compliances.len(), 1);
            if let crate::ast::Compliance::Group(g) = &cm.compliances[0] {
                assert_eq!(g.group.name, "optionalGroup");
                assert!(g.description.value.contains("Optional group"));
            } else {
                panic!("expected Group compliance");
            }
        } else {
            panic!("expected ModuleCompliance");
        }
    }

    #[test]
    fn test_parse_module_compliance_object_refinement() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testCompliance MODULE-COMPLIANCE
                STATUS current
                DESCRIPTION "Test compliance"
                MODULE
                    MANDATORY-GROUPS { testGroup }
                    OBJECT testObject
                        SYNTAX Integer32 (0..100)
                        MIN-ACCESS read-only
                        DESCRIPTION "Restricted object"
                ::= { testCompliances 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ModuleCompliance(def) = &module.body[0] {
            let cm = &def.modules[0];
            assert_eq!(cm.compliances.len(), 1);
            if let crate::ast::Compliance::Object(o) = &cm.compliances[0] {
                assert_eq!(o.object.name, "testObject");
                assert!(o.syntax.is_some());
                assert!(o.min_access.is_some());
                assert_eq!(
                    o.min_access.as_ref().unwrap().value,
                    AccessValue::ReadOnly
                );
                assert!(o.description.value.contains("Restricted"));
            } else {
                panic!("expected Object compliance");
            }
        } else {
            panic!("expected ModuleCompliance");
        }
    }

    #[test]
    fn test_parse_module_compliance_object_write_syntax() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testCompliance MODULE-COMPLIANCE
                STATUS current
                DESCRIPTION "Test compliance"
                MODULE
                    MANDATORY-GROUPS { testGroup }
                    OBJECT testString
                        SYNTAX DisplayString (SIZE (0..64))
                        WRITE-SYNTAX DisplayString (SIZE (1..32))
                        DESCRIPTION "String with different read/write sizes"
                ::= { testCompliances 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ModuleCompliance(def) = &module.body[0] {
            let cm = &def.modules[0];
            if let crate::ast::Compliance::Object(o) = &cm.compliances[0] {
                assert!(o.syntax.is_some());
                assert!(o.write_syntax.is_some());
                assert!(o.min_access.is_none());
            } else {
                panic!("expected Object compliance");
            }
        } else {
            panic!("expected ModuleCompliance");
        }
    }

    #[test]
    fn test_parse_module_compliance_multiple_modules() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testCompliance MODULE-COMPLIANCE
                STATUS current
                DESCRIPTION "Test compliance"
                MODULE
                    MANDATORY-GROUPS { localGroup }
                MODULE OTHER-MIB
                    MANDATORY-GROUPS { otherGroup }
                ::= { testCompliances 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ModuleCompliance(def) = &module.body[0] {
            assert_eq!(def.modules.len(), 2);
            assert!(def.modules[0].module_name.is_none());
            assert_eq!(
                def.modules[1].module_name.as_ref().unwrap().name,
                "OTHER-MIB"
            );
        } else {
            panic!("expected ModuleCompliance");
        }
    }

    #[test]
    fn test_parse_module_compliance_empty_module() {
        // MODULE without MANDATORY-GROUPS is valid (all groups optional)
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testCompliance MODULE-COMPLIANCE
                STATUS current
                DESCRIPTION "Test compliance"
                MODULE
                    GROUP optionalGroup
                        DESCRIPTION "Everything is optional"
                ::= { testCompliances 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ModuleCompliance(def) = &module.body[0] {
            let cm = &def.modules[0];
            assert!(cm.mandatory_groups.is_empty());
            assert_eq!(cm.compliances.len(), 1);
        } else {
            panic!("expected ModuleCompliance");
        }
    }

    #[test]
    fn test_parse_module_compliance_if_mib_style() {
        // Test based on real IF-MIB ifCompliance structure
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            ifCompliance MODULE-COMPLIANCE
                STATUS deprecated
                DESCRIPTION "A compliance statement for SNMP entities"

                MODULE
                    MANDATORY-GROUPS { ifGeneralGroup, ifStackGroup }

                    GROUP ifFixedLengthGroup
                    DESCRIPTION "Mandatory for character-oriented interfaces"

                    GROUP ifHCFixedLengthGroup
                    DESCRIPTION "Mandatory for high-speed fixed-length interfaces"

                    GROUP ifPacketGroup
                    DESCRIPTION "Mandatory for packet-oriented interfaces"

                    OBJECT ifLinkUpDownTrapEnable
                        MIN-ACCESS read-only
                        DESCRIPTION "Write access is not required."

                    OBJECT ifPromiscuousMode
                        MIN-ACCESS read-only
                        DESCRIPTION "Write access is not required."

                ::= { ifConformance 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        assert!(module.diagnostics.is_empty(), "Parse errors: {:?}", module.diagnostics);
        assert_eq!(module.body.len(), 1);

        if let Definition::ModuleCompliance(def) = &module.body[0] {
            assert_eq!(def.name.name, "ifCompliance");
            assert_eq!(def.status.value, StatusValue::Deprecated);
            assert_eq!(def.modules.len(), 1);

            let cm = &def.modules[0];
            assert!(cm.module_name.is_none()); // "this module"
            assert_eq!(cm.mandatory_groups.len(), 2);
            assert_eq!(cm.mandatory_groups[0].name, "ifGeneralGroup");
            assert_eq!(cm.mandatory_groups[1].name, "ifStackGroup");

            // Count GROUP and OBJECT compliances
            let groups: Vec<_> = cm
                .compliances
                .iter()
                .filter(|c| matches!(c, crate::ast::Compliance::Group(_)))
                .collect();
            let objects: Vec<_> = cm
                .compliances
                .iter()
                .filter(|c| matches!(c, crate::ast::Compliance::Object(_)))
                .collect();

            assert_eq!(groups.len(), 3);
            assert_eq!(objects.len(), 2);

            // Verify object refinements
            if let crate::ast::Compliance::Object(o) = &cm.compliances[3] {
                assert_eq!(o.object.name, "ifLinkUpDownTrapEnable");
                assert!(o.min_access.is_some());
                assert_eq!(
                    o.min_access.as_ref().unwrap().value,
                    AccessValue::ReadOnly
                );
            } else {
                panic!("expected Object compliance");
            }
        } else {
            panic!("expected ModuleCompliance");
        }
    }

    #[test]
    fn test_parse_module_compliance_no_modules() {
        // Edge case: MODULE-COMPLIANCE without any MODULE clauses
        // This is technically invalid per RFC 2580, but we should handle it gracefully
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            emptyCompliance MODULE-COMPLIANCE
                STATUS current
                DESCRIPTION "No module clauses"
                ::= { testCompliances 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::ModuleCompliance(def) = &module.body[0] {
            assert!(def.modules.is_empty());
        } else {
            panic!("expected ModuleCompliance");
        }
    }

    // === AGENT-CAPABILITIES tests ===

    #[test]
    fn test_parse_agent_capabilities_basic() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testAgent AGENT-CAPABILITIES
                PRODUCT-RELEASE "Version 1.0"
                STATUS current
                DESCRIPTION "Test agent capabilities"
                ::= { testCapabilities 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        assert_eq!(module.body.len(), 1);
        if let Definition::AgentCapabilities(def) = &module.body[0] {
            assert_eq!(def.name.name, "testAgent");
            assert_eq!(def.product_release.value, "Version 1.0");
            assert_eq!(def.status.value, StatusValue::Current);
            assert!(def.description.value.contains("Test agent"));
            assert!(def.supports.is_empty());
        } else {
            panic!("expected AgentCapabilities");
        }
    }

    #[test]
    fn test_parse_agent_capabilities_with_reference() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testAgent AGENT-CAPABILITIES
                PRODUCT-RELEASE "Version 1.0"
                STATUS current
                DESCRIPTION "Test agent"
                REFERENCE "RFC 9999"
                ::= { testCapabilities 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::AgentCapabilities(def) = &module.body[0] {
            assert!(def.reference.is_some());
            assert_eq!(def.reference.as_ref().unwrap().value, "RFC 9999");
        } else {
            panic!("expected AgentCapabilities");
        }
    }

    #[test]
    fn test_parse_agent_capabilities_supports_basic() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testAgent AGENT-CAPABILITIES
                PRODUCT-RELEASE "Version 1.0"
                STATUS current
                DESCRIPTION "Test agent"
                SUPPORTS IF-MIB
                    INCLUDES { ifGeneralGroup, ifStackGroup }
                ::= { testCapabilities 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::AgentCapabilities(def) = &module.body[0] {
            assert_eq!(def.supports.len(), 1);
            let sup = &def.supports[0];
            assert_eq!(sup.module_name.name, "IF-MIB");
            assert_eq!(sup.includes.len(), 2);
            assert_eq!(sup.includes[0].name, "ifGeneralGroup");
            assert_eq!(sup.includes[1].name, "ifStackGroup");
            assert!(sup.variations.is_empty());
        } else {
            panic!("expected AgentCapabilities");
        }
    }

    #[test]
    fn test_parse_agent_capabilities_variation_access() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testAgent AGENT-CAPABILITIES
                PRODUCT-RELEASE "Version 1.0"
                STATUS current
                DESCRIPTION "Test agent"
                SUPPORTS IF-MIB
                    INCLUDES { ifGeneralGroup }
                    VARIATION ifAdminStatus
                        ACCESS read-only
                        DESCRIPTION "Only read access supported"
                ::= { testCapabilities 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::AgentCapabilities(def) = &module.body[0] {
            assert_eq!(def.supports.len(), 1);
            let sup = &def.supports[0];
            assert_eq!(sup.variations.len(), 1);
            if let crate::ast::Variation::Object(v) = &sup.variations[0] {
                assert_eq!(v.object.name, "ifAdminStatus");
                assert_eq!(v.access.as_ref().unwrap().value, AccessValue::ReadOnly);
                assert!(v.description.value.contains("read access"));
            } else {
                panic!("expected Object variation");
            }
        } else {
            panic!("expected AgentCapabilities");
        }
    }

    #[test]
    fn test_parse_agent_capabilities_variation_syntax() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testAgent AGENT-CAPABILITIES
                PRODUCT-RELEASE "Version 1.0"
                STATUS current
                DESCRIPTION "Test agent"
                SUPPORTS IF-MIB
                    INCLUDES { ifGeneralGroup }
                    VARIATION ifType
                        SYNTAX INTEGER (1..50)
                        DESCRIPTION "Only first 50 types supported"
                ::= { testCapabilities 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::AgentCapabilities(def) = &module.body[0] {
            let sup = &def.supports[0];
            if let crate::ast::Variation::Object(v) = &sup.variations[0] {
                assert!(v.syntax.is_some());
                assert!(v.access.is_none());
            } else {
                panic!("expected Object variation");
            }
        } else {
            panic!("expected AgentCapabilities");
        }
    }

    #[test]
    fn test_parse_agent_capabilities_variation_write_syntax() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testAgent AGENT-CAPABILITIES
                PRODUCT-RELEASE "Version 1.0"
                STATUS current
                DESCRIPTION "Test agent"
                SUPPORTS IF-MIB
                    INCLUDES { ifGeneralGroup }
                    VARIATION ifAlias
                        SYNTAX DisplayString (SIZE (0..64))
                        WRITE-SYNTAX DisplayString (SIZE (0..32))
                        DESCRIPTION "Different read/write sizes"
                ::= { testCapabilities 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::AgentCapabilities(def) = &module.body[0] {
            let sup = &def.supports[0];
            if let crate::ast::Variation::Object(v) = &sup.variations[0] {
                assert!(v.syntax.is_some());
                assert!(v.write_syntax.is_some());
            } else {
                panic!("expected Object variation");
            }
        } else {
            panic!("expected AgentCapabilities");
        }
    }

    #[test]
    fn test_parse_agent_capabilities_creation_requires() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testAgent AGENT-CAPABILITIES
                PRODUCT-RELEASE "Version 1.0"
                STATUS current
                DESCRIPTION "Test agent"
                SUPPORTS IF-MIB
                    INCLUDES { ifStackGroup }
                    VARIATION ifStackEntry
                        CREATION-REQUIRES { ifStackHigherLayer, ifStackLowerLayer }
                        DESCRIPTION "Both layers required for row creation"
                ::= { testCapabilities 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::AgentCapabilities(def) = &module.body[0] {
            let sup = &def.supports[0];
            if let crate::ast::Variation::Object(v) = &sup.variations[0] {
                assert!(v.creation_requires.is_some());
                let cr = v.creation_requires.as_ref().unwrap();
                assert_eq!(cr.len(), 2);
                assert_eq!(cr[0].name, "ifStackHigherLayer");
                assert_eq!(cr[1].name, "ifStackLowerLayer");
            } else {
                panic!("expected Object variation");
            }
        } else {
            panic!("expected AgentCapabilities");
        }
    }

    #[test]
    fn test_parse_agent_capabilities_defval() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testAgent AGENT-CAPABILITIES
                PRODUCT-RELEASE "Version 1.0"
                STATUS current
                DESCRIPTION "Test agent"
                SUPPORTS IF-MIB
                    INCLUDES { ifGeneralGroup }
                    VARIATION ifLinkUpDownTrapEnable
                        DEFVAL { enabled }
                        DESCRIPTION "Default to enabled"
                ::= { testCapabilities 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::AgentCapabilities(def) = &module.body[0] {
            let sup = &def.supports[0];
            if let crate::ast::Variation::Object(v) = &sup.variations[0] {
                assert!(v.defval.is_some());
            } else {
                panic!("expected Object variation");
            }
        } else {
            panic!("expected AgentCapabilities");
        }
    }

    #[test]
    fn test_parse_agent_capabilities_multiple_supports() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testAgent AGENT-CAPABILITIES
                PRODUCT-RELEASE "Version 1.0"
                STATUS current
                DESCRIPTION "Test agent"
                SUPPORTS IF-MIB
                    INCLUDES { ifGeneralGroup }
                SUPPORTS IP-MIB
                    INCLUDES { ipGroup }
                ::= { testCapabilities 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::AgentCapabilities(def) = &module.body[0] {
            assert_eq!(def.supports.len(), 2);
            assert_eq!(def.supports[0].module_name.name, "IF-MIB");
            assert_eq!(def.supports[1].module_name.name, "IP-MIB");
        } else {
            panic!("expected AgentCapabilities");
        }
    }

    #[test]
    fn test_parse_agent_capabilities_multiple_variations() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testAgent AGENT-CAPABILITIES
                PRODUCT-RELEASE "Version 1.0"
                STATUS current
                DESCRIPTION "Test agent"
                SUPPORTS IF-MIB
                    INCLUDES { ifGeneralGroup }
                    VARIATION ifAdminStatus
                        ACCESS read-only
                        DESCRIPTION "Read-only"
                    VARIATION ifOperStatus
                        ACCESS read-only
                        DESCRIPTION "Read-only"
                ::= { testCapabilities 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::AgentCapabilities(def) = &module.body[0] {
            let sup = &def.supports[0];
            assert_eq!(sup.variations.len(), 2);
        } else {
            panic!("expected AgentCapabilities");
        }
    }

    #[test]
    fn test_parse_agent_capabilities_full_variation() {
        let source = br#"TEST-MIB DEFINITIONS ::= BEGIN
            testAgent AGENT-CAPABILITIES
                PRODUCT-RELEASE "Version 2.0"
                STATUS current
                DESCRIPTION "Full featured agent"
                SUPPORTS IF-MIB
                    INCLUDES { ifGeneralGroup, ifStackGroup }
                    VARIATION ifType
                        SYNTAX INTEGER (1..100)
                        WRITE-SYNTAX INTEGER (1..50)
                        ACCESS read-write
                        CREATION-REQUIRES { ifIndex }
                        DEFVAL { 1 }
                        DESCRIPTION "Limited interface types"
                ::= { testCapabilities 1 }
            END"#;
        let parser = Parser::new(source);
        let module = parser.parse_module();

        if let Definition::AgentCapabilities(def) = &module.body[0] {
            let sup = &def.supports[0];
            assert_eq!(sup.includes.len(), 2);
            assert_eq!(sup.variations.len(), 1);
            if let crate::ast::Variation::Object(v) = &sup.variations[0] {
                assert!(v.syntax.is_some());
                assert!(v.write_syntax.is_some());
                assert!(v.access.is_some());
                assert!(v.creation_requires.is_some());
                assert!(v.defval.is_some());
            } else {
                panic!("expected Object variation");
            }
        } else {
            panic!("expected AgentCapabilities");
        }
    }

    #[test]
    fn test_parse_qualified_name_oid() {
        // Test RFC 2578 Section 3.2 qualified OID syntax: Module.descriptor
        let source = b"TEST-MIB DEFINITIONS ::= BEGIN
            testObject OBJECT IDENTIFIER ::= { SNMPv2-SMI.enterprises 12345 }
            END";
        let parser = Parser::new(source);
        let module = parser.parse_module();

        assert_eq!(module.body.len(), 1);
        if let Definition::ValueAssignment(def) = &module.body[0] {
            assert_eq!(def.name.name, "testObject");
            assert_eq!(def.oid_assignment.components.len(), 2);

            // First component should be QualifiedName
            if let OidComponent::QualifiedName { module, name, .. } =
                &def.oid_assignment.components[0]
            {
                assert_eq!(module.name, "SNMPv2-SMI");
                assert_eq!(name.name, "enterprises");
            } else {
                panic!("expected QualifiedName component");
            }

            // Second component should be Number
            if let OidComponent::Number { value, .. } = &def.oid_assignment.components[1] {
                assert_eq!(*value, 12345);
            } else {
                panic!("expected Number component");
            }
        } else {
            panic!("expected ValueAssignment");
        }
    }

    #[test]
    fn test_parse_qualified_named_number_oid() {
        // Test RFC 2578 Section 3.2 qualified OID syntax: Module.descriptor(number)
        let source = b"TEST-MIB DEFINITIONS ::= BEGIN
            testObject OBJECT IDENTIFIER ::= { SNMPv2-SMI.enterprises(1) 12345 }
            END";
        let parser = Parser::new(source);
        let module = parser.parse_module();

        assert_eq!(module.body.len(), 1);
        if let Definition::ValueAssignment(def) = &module.body[0] {
            assert_eq!(def.name.name, "testObject");
            assert_eq!(def.oid_assignment.components.len(), 2);

            // First component should be QualifiedNamedNumber
            if let OidComponent::QualifiedNamedNumber {
                module,
                name,
                number,
                ..
            } = &def.oid_assignment.components[0]
            {
                assert_eq!(module.name, "SNMPv2-SMI");
                assert_eq!(name.name, "enterprises");
                assert_eq!(*number, 1);
            } else {
                panic!("expected QualifiedNamedNumber component");
            }

            // Second component should be Number
            if let OidComponent::Number { value, .. } = &def.oid_assignment.components[1] {
                assert_eq!(*value, 12345);
            } else {
                panic!("expected Number component");
            }
        } else {
            panic!("expected ValueAssignment");
        }
    }

    #[test]
    fn test_parse_mixed_qualified_oid() {
        // Test mixed qualified and unqualified components
        let source = b"TEST-MIB DEFINITIONS ::= BEGIN
            testObject OBJECT IDENTIFIER ::= { parent SNMPv2-SMI.enterprises 1 }
            END";
        let parser = Parser::new(source);
        let module = parser.parse_module();

        assert_eq!(module.body.len(), 1);
        if let Definition::ValueAssignment(def) = &module.body[0] {
            assert_eq!(def.oid_assignment.components.len(), 3);

            // First: unqualified name
            assert!(matches!(
                &def.oid_assignment.components[0],
                OidComponent::Name(ident) if ident.name == "parent"
            ));

            // Second: qualified name
            assert!(matches!(
                &def.oid_assignment.components[1],
                OidComponent::QualifiedName { module, name, .. }
                    if module.name == "SNMPv2-SMI" && name.name == "enterprises"
            ));

            // Third: number
            assert!(matches!(
                &def.oid_assignment.components[2],
                OidComponent::Number { value: 1, .. }
            ));
        } else {
            panic!("expected ValueAssignment");
        }
    }
}
