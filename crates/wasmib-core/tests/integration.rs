//! Integration tests with real MIB files.

use wasmib_core::ast::Definition;
use wasmib_core::hir::{self, HirDefinition, SmiLanguage};
use wasmib_core::lexer::{Lexer, Severity, TokenKind};
use wasmib_core::parser::Parser;

/// Test tokenizing IF-MIB, a standard SNMP MIB module.
#[test]
fn test_tokenize_if_mib() {
    let source = include_bytes!("../../../.local/mibs/IF-MIB");
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
    let source = include_bytes!("../../../.local/mibs/SNMPv2-SMI");
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

/// Test parsing IF-MIB.
#[test]
fn test_parse_if_mib() {
    let source = include_bytes!("../../../.local/mibs/IF-MIB");
    let parser = Parser::new(source);
    let module = parser.parse_module();

    // Check module name
    assert_eq!(module.name.name, "IF-MIB");

    // Check imports
    assert!(!module.imports.is_empty(), "Expected imports");

    // Check that we have import from SNMPv2-SMI
    let has_smi_import = module.imports.iter()
        .any(|i| i.from_module.name == "SNMPv2-SMI");
    assert!(has_smi_import, "Expected import from SNMPv2-SMI");

    // Check definitions
    assert!(!module.body.is_empty(), "Expected definitions");

    // Count definition types
    let mut object_types = 0;
    let mut textual_conventions = 0;
    let mut value_assignments = 0;
    let mut module_identities = 0;
    let mut object_groups = 0;
    let mut module_compliances = 0;

    for def in &module.body {
        match def {
            Definition::ObjectType(_) => object_types += 1,
            Definition::TextualConvention(_) => textual_conventions += 1,
            Definition::ValueAssignment(_) => value_assignments += 1,
            Definition::ModuleIdentity(_) => module_identities += 1,
            Definition::ObjectGroup(_) => object_groups += 1,
            Definition::ModuleCompliance(_) => module_compliances += 1,
            _ => {}
        }
    }

    println!("IF-MIB parsed:");
    println!("  MODULE-IDENTITY: {}", module_identities);
    println!("  OBJECT-TYPE: {}", object_types);
    println!("  TEXTUAL-CONVENTION: {}", textual_conventions);
    println!("  Value assignments: {}", value_assignments);
    println!("  OBJECT-GROUP: {}", object_groups);
    println!("  MODULE-COMPLIANCE: {}", module_compliances);
    println!("  Total definitions: {}", module.body.len());

    // IF-MIB should have MODULE-IDENTITY
    assert!(module_identities >= 1, "Expected at least one MODULE-IDENTITY");

    // IF-MIB should have many OBJECT-TYPEs
    assert!(object_types > 20, "Expected many OBJECT-TYPEs, got {}", object_types);

    // Count parse errors
    let errors: Vec<_> = module.diagnostics.iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();

    println!("  Parse errors: {}", errors.len());
    for err in &errors {
        eprintln!("    Error at {}: {}", err.span.start, err.message);
    }

    // Should parse with no or minimal errors
    assert!(
        errors.len() <= 5,
        "Expected few parse errors, got {}",
        errors.len()
    );
}

/// Test parsing multiple standard MIBs.
#[test]
fn test_parse_standard_mibs() {
    let mibs = [
        ("SNMPv2-MIB", include_bytes!("../../../.local/mibs/SNMPv2-MIB").as_slice()),
        ("HOST-RESOURCES-MIB", include_bytes!("../../../.local/mibs/HOST-RESOURCES-MIB").as_slice()),
        ("IP-MIB", include_bytes!("../../../.local/mibs/IP-MIB").as_slice()),
        ("TCP-MIB", include_bytes!("../../../.local/mibs/TCP-MIB").as_slice()),
        ("UDP-MIB", include_bytes!("../../../.local/mibs/UDP-MIB").as_slice()),
    ];

    let mut total_defs = 0;
    let mut total_errors = 0;

    for (name, content) in mibs {
        let parser = Parser::new(content);
        let module = parser.parse_module();

        let errors: Vec<_> = module.diagnostics.iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();

        println!("{}: {} defs, {} errors", name, module.body.len(), errors.len());

        if !errors.is_empty() {
            for e in errors.iter().take(3) {
                eprintln!("  at {}: {}", e.span.start, e.message);
            }
        }

        total_defs += module.body.len();
        total_errors += errors.len();

        // Each MIB should parse with minimal errors
        assert!(
            errors.len() <= 5,
            "{} had {} errors",
            name,
            errors.len()
        );
    }

    println!("Total: {} definitions parsed, {} errors", total_defs, total_errors);
}

// === HIR Lowering Tests ===

/// Test HIR lowering of IF-MIB.
#[test]
fn test_lower_if_mib() {
    let source = include_bytes!("../../../.local/mibs/IF-MIB");
    let parser = Parser::new(source);
    let ast_module = parser.parse_module();

    // Lower to HIR
    let hir_module = hir::lower_module(&ast_module);

    // Check module name
    assert_eq!(hir_module.name.name, "IF-MIB");

    // IF-MIB imports from SNMPv2-SMI, so should be detected as SMIv2
    assert_eq!(
        hir_module.language,
        SmiLanguage::Smiv2,
        "IF-MIB should be detected as SMIv2"
    );

    // Check imports are normalized
    let snmpv2_imports: Vec<_> = hir_module
        .imports
        .iter()
        .filter(|i| i.module.name == "SNMPv2-SMI")
        .collect();
    assert!(
        !snmpv2_imports.is_empty(),
        "Expected imports from SNMPv2-SMI"
    );

    // Check definitions
    assert!(
        !hir_module.definitions.is_empty(),
        "Expected definitions"
    );

    // Count HIR definition types
    let mut object_types = 0;
    let mut type_defs = 0;
    let mut value_assignments = 0;
    let mut notifications = 0;
    let mut module_identities = 0;
    let mut object_groups = 0;

    for def in &hir_module.definitions {
        match def {
            HirDefinition::ObjectType(_) => object_types += 1,
            HirDefinition::TypeDef(_) => type_defs += 1,
            HirDefinition::ValueAssignment(_) => value_assignments += 1,
            HirDefinition::Notification(_) => notifications += 1,
            HirDefinition::ModuleIdentity(_) => module_identities += 1,
            HirDefinition::ObjectGroup(_) => object_groups += 1,
            _ => {}
        }
    }

    println!("IF-MIB HIR:");
    println!("  Language: {}", hir_module.language);
    println!("  Imports: {}", hir_module.imports.len());
    println!("  MODULE-IDENTITY: {}", module_identities);
    println!("  OBJECT-TYPE: {}", object_types);
    println!("  TypeDef: {}", type_defs);
    println!("  Value assignments: {}", value_assignments);
    println!("  Notifications: {}", notifications);
    println!("  OBJECT-GROUP: {}", object_groups);
    println!("  Total definitions: {}", hir_module.definitions.len());

    // IF-MIB should have MODULE-IDENTITY
    assert!(module_identities >= 1, "Expected MODULE-IDENTITY");

    // IF-MIB should have many OBJECT-TYPEs
    assert!(
        object_types > 20,
        "Expected many OBJECT-TYPEs, got {}",
        object_types
    );

    // Check for errors
    let errors: Vec<_> = hir_module
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();

    println!("  Lowering errors: {}", errors.len());

    assert!(
        errors.len() <= 5,
        "Expected few errors, got {}",
        errors.len()
    );
}

/// Test that SMIv1 imports get normalized to SMIv2.
#[test]
fn test_hir_import_normalization() {
    // Create a minimal SMIv1-style MIB that imports Counter from RFC1155-SMI
    let source = br#"
TEST-MIB DEFINITIONS ::= BEGIN

IMPORTS
    Counter
        FROM RFC1155-SMI
    DisplayString
        FROM RFC1213-MIB;

END
"#;

    let parser = Parser::new(source);
    let ast_module = parser.parse_module();
    let hir_module = hir::lower_module(&ast_module);

    // Should be detected as SMIv1 (no SNMPv2 imports)
    assert_eq!(
        hir_module.language,
        SmiLanguage::Smiv1,
        "Should be detected as SMIv1"
    );

    // Counter import should be normalized
    let counter_import = hir_module
        .imports
        .iter()
        .find(|i| i.symbol.name == "Counter32");
    assert!(
        counter_import.is_some(),
        "Counter should be normalized to Counter32"
    );
    if let Some(imp) = counter_import {
        assert_eq!(
            imp.module.name, "SNMPv2-SMI",
            "Counter32 should come from SNMPv2-SMI"
        );
    }

    // DisplayString import should be normalized
    let ds_import = hir_module
        .imports
        .iter()
        .find(|i| i.symbol.name == "DisplayString");
    assert!(
        ds_import.is_some(),
        "DisplayString import should be present"
    );
    if let Some(imp) = ds_import {
        assert_eq!(
            imp.module.name, "SNMPv2-TC",
            "DisplayString should come from SNMPv2-TC"
        );
    }
}

/// Test HIR lowering of multiple standard MIBs.
#[test]
fn test_lower_standard_mibs() {
    let mibs = [
        (
            "SNMPv2-MIB",
            include_bytes!("../../../.local/mibs/SNMPv2-MIB").as_slice(),
        ),
        (
            "HOST-RESOURCES-MIB",
            include_bytes!("../../../.local/mibs/HOST-RESOURCES-MIB").as_slice(),
        ),
        (
            "IP-MIB",
            include_bytes!("../../../.local/mibs/IP-MIB").as_slice(),
        ),
        (
            "TCP-MIB",
            include_bytes!("../../../.local/mibs/TCP-MIB").as_slice(),
        ),
        (
            "UDP-MIB",
            include_bytes!("../../../.local/mibs/UDP-MIB").as_slice(),
        ),
    ];

    let mut total_defs = 0;

    for (name, content) in mibs {
        let parser = Parser::new(content);
        let ast_module = parser.parse_module();
        let hir_module = hir::lower_module(&ast_module);

        println!(
            "{}: {} imports, {} defs, language={}",
            name,
            hir_module.imports.len(),
            hir_module.definitions.len(),
            hir_module.language
        );

        // All these MIBs are SMIv2
        assert_eq!(
            hir_module.language,
            SmiLanguage::Smiv2,
            "{} should be SMIv2",
            name
        );

        total_defs += hir_module.definitions.len();
    }

    println!("Total: {} HIR definitions", total_defs);
}
