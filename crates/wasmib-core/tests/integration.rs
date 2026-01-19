//! Integration tests with real MIB files.

use wasmib_core::lexer::{Lexer, Severity, TokenKind};

/// Test tokenizing IF-MIB, a standard SNMP MIB module.
#[test]
fn test_tokenize_if_mib() {
    let source = include_str!("../../../.local/mibs/IF-MIB");
    let lexer = Lexer::new(source);
    let (tokens, diagnostics) = lexer.tokenize();

    // Should produce many tokens
    assert!(
        tokens.len() > 1000,
        "Expected many tokens, got {}",
        tokens.len()
    );

    // Should end with EOF
    assert_eq!(tokens.last().unwrap().kind, TokenKind::Eof);

    // Should have module header
    let kinds: Vec<_> = tokens.iter().take(4).map(|t| t.kind).collect();
    assert_eq!(kinds[0], TokenKind::UppercaseIdent); // IF-MIB
    assert_eq!(kinds[1], TokenKind::KwDefinitions);
    assert_eq!(kinds[2], TokenKind::ColonColonEqual);
    assert_eq!(kinds[3], TokenKind::KwBegin);

    // Count errors (should be few or none for well-formed MIBs)
    let errors: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();

    // Print any errors for debugging
    for err in &errors {
        eprintln!("Error: {}", err.message);
    }

    // IF-MIB is well-formed, expect no errors
    assert!(
        errors.is_empty(),
        "Expected no errors, got {}",
        errors.len()
    );
}

/// Test tokenizing SNMPv2-SMI which contains MACRO definitions (should be skipped).
#[test]
fn test_tokenize_snmpv2_smi() {
    let source = include_str!("../../../.local/mibs/SNMPv2-SMI");
    let lexer = Lexer::new(source);
    let (tokens, diagnostics) = lexer.tokenize();

    // Should produce tokens
    assert!(!tokens.is_empty(), "Expected tokens");

    // Should end with EOF
    assert_eq!(tokens.last().unwrap().kind, TokenKind::Eof);

    // Check for MACRO keyword (should be present since this is a base module)
    let has_macro = tokens.iter().any(|t| t.kind == TokenKind::KwMacro);
    assert!(has_macro, "Expected MACRO keyword in SNMPv2-SMI");

    // Count errors
    let errors: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();

    // Print any errors for debugging
    for err in &errors {
        eprintln!("Error: {}", err.message);
    }

    assert!(
        errors.is_empty(),
        "Expected no errors in SNMPv2-SMI, got {}",
        errors.len()
    );
}
