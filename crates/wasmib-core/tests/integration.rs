//! Integration tests with real MIB files.

use wasmib_core::ast::Definition as AstDefinition;
use wasmib_core::module::{self, Definition, SmiLanguage};
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
    let has_smi_import = module
        .imports
        .iter()
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
            AstDefinition::ObjectType(_) => object_types += 1,
            AstDefinition::TextualConvention(_) => textual_conventions += 1,
            AstDefinition::ValueAssignment(_) => value_assignments += 1,
            AstDefinition::ModuleIdentity(_) => module_identities += 1,
            AstDefinition::ObjectGroup(_) => object_groups += 1,
            AstDefinition::ModuleCompliance(_) => module_compliances += 1,
            _ => {}
        }
    }

    println!("IF-MIB parsed:");
    println!("  MODULE-IDENTITY: {module_identities}");
    println!("  OBJECT-TYPE: {object_types}");
    println!("  TEXTUAL-CONVENTION: {textual_conventions}");
    println!("  Value assignments: {value_assignments}");
    println!("  OBJECT-GROUP: {object_groups}");
    println!("  MODULE-COMPLIANCE: {module_compliances}");
    println!("  Total definitions: {}", module.body.len());

    // IF-MIB should have MODULE-IDENTITY
    assert!(
        module_identities >= 1,
        "Expected at least one MODULE-IDENTITY"
    );

    // IF-MIB should have many OBJECT-TYPEs
    assert!(
        object_types > 20,
        "Expected many OBJECT-TYPEs, got {object_types}"
    );

    // Count parse errors
    let errors: Vec<_> = module
        .diagnostics
        .iter()
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
    let mut total_errors = 0;

    for (name, content) in mibs {
        let parser = Parser::new(content);
        let module = parser.parse_module();

        let errors: Vec<_> = module
            .diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();

        println!(
            "{}: {} defs, {} errors",
            name,
            module.body.len(),
            errors.len()
        );

        if !errors.is_empty() {
            for e in errors.iter().take(3) {
                eprintln!("  at {}: {}", e.span.start, e.message);
            }
        }

        total_defs += module.body.len();
        total_errors += errors.len();

        // Each MIB should parse with minimal errors
        assert!(errors.len() <= 5, "{} had {} errors", name, errors.len());
    }

    println!("Total: {total_defs} definitions parsed, {total_errors} errors");
}

// === HIR Lowering Tests ===

/// Test HIR lowering of IF-MIB.
#[test]
fn test_lower_if_mib() {
    let source = include_bytes!("../../../.local/mibs/IF-MIB");
    let parser = Parser::new(source);
    let ast_module = parser.parse_module();

    // Lower to HIR
    let hir_module = module::lower_module(&ast_module);

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
    assert!(!hir_module.definitions.is_empty(), "Expected definitions");

    // Count HIR definition types
    let mut object_types = 0;
    let mut type_defs = 0;
    let mut value_assignments = 0;
    let mut notifications = 0;
    let mut module_identities = 0;
    let mut object_groups = 0;

    for def in &hir_module.definitions {
        match def {
            Definition::ObjectType(_) => object_types += 1,
            Definition::TypeDef(_) => type_defs += 1,
            Definition::ValueAssignment(_) => value_assignments += 1,
            Definition::Notification(_) => notifications += 1,
            Definition::ModuleIdentity(_) => module_identities += 1,
            Definition::ObjectGroup(_) => object_groups += 1,
            _ => {}
        }
    }

    println!("IF-MIB HIR:");
    println!("  Language: {}", hir_module.language);
    println!("  Imports: {}", hir_module.imports.len());
    println!("  MODULE-IDENTITY: {module_identities}");
    println!("  OBJECT-TYPE: {object_types}");
    println!("  TypeDef: {type_defs}");
    println!("  Value assignments: {value_assignments}");
    println!("  Notifications: {notifications}");
    println!("  OBJECT-GROUP: {object_groups}");
    println!("  Total definitions: {}", hir_module.definitions.len());

    // IF-MIB should have MODULE-IDENTITY
    assert!(module_identities >= 1, "Expected MODULE-IDENTITY");

    // IF-MIB should have many OBJECT-TYPEs
    assert!(
        object_types > 20,
        "Expected many OBJECT-TYPEs, got {object_types}"
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
        let hir_module = module::lower_module(&ast_module);

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
            "{name} should be SMIv2"
        );

        total_defs += hir_module.definitions.len();
    }

    println!("Total: {total_defs} HIR definitions");
}

// === Resolver Tests ===

use wasmib_core::resolver::Resolver;

/// Test that the resolver can process a single module with only built-in dependencies.
#[test]
fn test_resolver_snmpv2_mib() {
    let source = include_bytes!("../../../.local/mibs_mini/tier1_builtin_only/SNMPv2-MIB");
    let parser = Parser::new(source);
    let ast_module = parser.parse_module();
    let hir_module = module::lower_module(&ast_module);

    let resolver = Resolver::new();
    let result = resolver.resolve(vec![hir_module]);

    println!("SNMPv2-MIB resolved:");
    println!("  Modules: {}", result.model.module_count());
    println!("  Nodes: {}", result.model.node_count());
    println!("  Types: {}", result.model.type_count());
    println!("  Objects: {}", result.model.object_count());
    println!("  Diagnostics: {}", result.diagnostics.len());
    println!("  Unresolved: {}", result.model.unresolved().count());

    // Print some diagnostics for debugging
    for diag in result.diagnostics.iter().take(5) {
        println!("  Diag: {}", diag.message);
    }

    // Should have registered the module (8 base modules + 1 user module)
    assert_eq!(result.model.module_count(), 9);
    assert!(result.model.get_module_by_name("SNMPv2-MIB").is_some());

    // Should have resolved some nodes (built-ins + module content)
    assert!(
        result.model.node_count() > 10,
        "Expected many nodes, got {}",
        result.model.node_count()
    );

    // Check key OIDs exist from built-ins
    assert!(
        result.model.get_node_by_oid_str("1.3.6.1").is_some(),
        "internet OID missing"
    );
    assert!(
        result.model.get_node_by_oid_str("1.3.6.1.2.1").is_some(),
        "mib-2 OID missing"
    );
}

/// Test tier1: modules with only built-in dependencies.
#[test]
fn test_resolver_tier1_builtin_only() {
    // Load all tier1 files
    let files = [
        (
            "IANAifType-MIB",
            include_bytes!("../../../.local/mibs_mini/tier1_builtin_only/IANAifType-MIB")
                .as_slice(),
        ),
        (
            "INET-ADDRESS-MIB",
            include_bytes!("../../../.local/mibs_mini/tier1_builtin_only/INET-ADDRESS-MIB")
                .as_slice(),
        ),
        (
            "SNMPv2-MIB",
            include_bytes!("../../../.local/mibs_mini/tier1_builtin_only/SNMPv2-MIB").as_slice(),
        ),
    ];

    let mut hir_modules = Vec::new();

    for (name, source) in files {
        let parser = Parser::new(source);
        let ast_module = parser.parse_module();
        let hir_module = module::lower_module(&ast_module);
        println!("{}: {} defs", name, hir_module.definitions.len());
        hir_modules.push(hir_module);
    }

    let resolver = Resolver::new();
    let result = resolver.resolve(hir_modules);

    println!("\nTier1 resolved:");
    println!("  Modules: {}", result.model.module_count());
    println!("  Nodes: {}", result.model.node_count());
    println!("  Types: {}", result.model.type_count());
    println!("  Objects: {}", result.model.object_count());
    println!("  Complete: {}", result.is_complete());
    println!(
        "  Unresolved imports: {}",
        result.model.unresolved().imports.len()
    );
    println!(
        "  Unresolved types: {}",
        result.model.unresolved().types.len()
    );
    println!(
        "  Unresolved OIDs: {}",
        result.model.unresolved().oids.len()
    );

    // Print unresolved details
    let unresolved = result.model.unresolved();
    for imp in unresolved.imports.iter().take(5) {
        let from = result.model.get_str(imp.from_module);
        let sym = result.model.get_str(imp.symbol);
        println!("  Unresolved import: {from}::{sym}");
    }
    for oid in unresolved.oids.iter().take(5) {
        let def = result.model.get_str(oid.definition);
        let comp = result.model.get_str(oid.component);
        println!("  Unresolved OID: {def} -> {comp}");
    }

    // Should have all 3 user modules + 8 base modules
    assert_eq!(result.model.module_count(), 11);

    // Should have many nodes
    assert!(
        result.model.node_count() > 30,
        "Expected many nodes, got {}",
        result.model.node_count()
    );

    // Check some known OIDs exist
    assert!(
        result
            .model
            .get_node_by_oid_str("1.3.6.1.2.1.1.1")
            .is_some(),
        "sysDescr should exist"
    );
}

/// Test tier2: modules with cross-module dependencies.
#[test]
fn test_resolver_tier2_basic_deps() {
    let files = [
        (
            "IANAifType-MIB",
            include_bytes!("../../../.local/mibs_mini/tier2_basic_deps/IANAifType-MIB").as_slice(),
        ),
        (
            "INET-ADDRESS-MIB",
            include_bytes!("../../../.local/mibs_mini/tier2_basic_deps/INET-ADDRESS-MIB")
                .as_slice(),
        ),
        (
            "SNMPv2-MIB",
            include_bytes!("../../../.local/mibs_mini/tier2_basic_deps/SNMPv2-MIB").as_slice(),
        ),
        (
            "IF-MIB",
            include_bytes!("../../../.local/mibs_mini/tier2_basic_deps/IF-MIB").as_slice(),
        ),
    ];

    let mut hir_modules = Vec::new();

    for (name, source) in files {
        let parser = Parser::new(source);
        let ast_module = parser.parse_module();
        let hir_module = module::lower_module(&ast_module);
        println!(
            "{}: {} defs, {} imports",
            name,
            hir_module.definitions.len(),
            hir_module.imports.len()
        );
        hir_modules.push(hir_module);
    }

    let resolver = Resolver::new();
    let result = resolver.resolve(hir_modules);

    println!("\nTier2 resolved:");
    println!("  Modules: {}", result.model.module_count());
    println!("  Nodes: {}", result.model.node_count());
    println!("  Types: {}", result.model.type_count());
    println!("  Objects: {}", result.model.object_count());
    println!("  Complete: {}", result.is_complete());
    println!("  Unresolved: {}", result.model.unresolved().count());

    // Print unresolved details for debugging
    let unresolved = result.model.unresolved();
    for imp in unresolved.imports.iter().take(5) {
        let from = result.model.get_str(imp.from_module);
        let sym = result.model.get_str(imp.symbol);
        println!("  Unresolved import: {from}::{sym}");
    }

    // Should have all 4 user modules + 8 base modules
    assert_eq!(result.model.module_count(), 12);

    // Should have many nodes including IF-MIB content
    assert!(
        result.model.node_count() > 50,
        "Expected many nodes, got {}",
        result.model.node_count()
    );

    // Check IF-MIB specific OIDs
    // interfaces is at 1.3.6.1.2.1.2
    assert!(
        result.model.get_node_by_oid_str("1.3.6.1.2.1.2").is_some(),
        "interfaces OID should exist"
    );
}

/// Test tier3: complex dependencies.
#[test]
fn test_resolver_tier3_complex() {
    let files = [
        (
            "IANAifType-MIB",
            include_bytes!("../../../.local/mibs_mini/tier3_complex/IANAifType-MIB").as_slice(),
        ),
        (
            "INET-ADDRESS-MIB",
            include_bytes!("../../../.local/mibs_mini/tier3_complex/INET-ADDRESS-MIB").as_slice(),
        ),
        (
            "SNMPv2-MIB",
            include_bytes!("../../../.local/mibs_mini/tier3_complex/SNMPv2-MIB").as_slice(),
        ),
        (
            "IF-MIB",
            include_bytes!("../../../.local/mibs_mini/tier3_complex/IF-MIB").as_slice(),
        ),
        (
            "HOST-RESOURCES-MIB",
            include_bytes!("../../../.local/mibs_mini/tier3_complex/HOST-RESOURCES-MIB").as_slice(),
        ),
        (
            "HOST-RESOURCES-TYPES",
            include_bytes!("../../../.local/mibs_mini/tier3_complex/HOST-RESOURCES-TYPES")
                .as_slice(),
        ),
        (
            "IP-MIB",
            include_bytes!("../../../.local/mibs_mini/tier3_complex/IP-MIB").as_slice(),
        ),
    ];

    let mut hir_modules = Vec::new();

    for (name, source) in files {
        let parser = Parser::new(source);
        let ast_module = parser.parse_module();
        let hir_module = module::lower_module(&ast_module);
        println!("{}: {} defs", name, hir_module.definitions.len());
        hir_modules.push(hir_module);
    }

    let resolver = Resolver::new();
    let result = resolver.resolve(hir_modules);

    println!("\nTier3 resolved:");
    println!("  Modules: {}", result.model.module_count());
    println!("  Nodes: {}", result.model.node_count());
    println!("  Types: {}", result.model.type_count());
    println!("  Objects: {}", result.model.object_count());
    println!("  Complete: {}", result.is_complete());
    println!("  Unresolved: {}", result.model.unresolved().count());

    // Print unresolved for debugging
    let unresolved = result.model.unresolved();
    for imp in unresolved.imports.iter().take(3) {
        let from = result.model.get_str(imp.from_module);
        let sym = result.model.get_str(imp.symbol);
        println!("  Unresolved import: {from}::{sym}");
    }
    for oid in unresolved.oids.iter().take(3) {
        let def = result.model.get_str(oid.definition);
        let comp = result.model.get_str(oid.component);
        println!("  Unresolved OID: {def} -> {comp}");
    }

    // Should have all 7 user modules + 8 base modules
    assert_eq!(result.model.module_count(), 15);

    // Should have many nodes
    assert!(
        result.model.node_count() > 100,
        "Expected many nodes, got {}",
        result.model.node_count()
    );

    // Check some HOST-RESOURCES-MIB OIDs match libsmi
    // host is at 1.3.6.1.2.1.25
    assert!(
        result.model.get_node_by_oid_str("1.3.6.1.2.1.25").is_some(),
        "host OID should exist"
    );

    // hrMIBAdminInfo is at 1.3.6.1.2.1.25.7
    assert!(
        result
            .model
            .get_node_by_oid_str("1.3.6.1.2.1.25.7")
            .is_some(),
        "hrMIBAdminInfo OID should exist"
    );

    // hostResourcesMibModule is at 1.3.6.1.2.1.25.7.1
    assert!(
        result
            .model
            .get_node_by_oid_str("1.3.6.1.2.1.25.7.1")
            .is_some(),
        "hostResourcesMibModule OID should exist"
    );

    // Verify sysDescr from SNMPv2-MIB (1.3.6.1.2.1.1.1)
    assert!(
        result
            .model
            .get_node_by_oid_str("1.3.6.1.2.1.1.1")
            .is_some(),
        "sysDescr OID should exist"
    );

    // Verify ifIndex from IF-MIB (1.3.6.1.2.1.2.2.1.1)
    assert!(
        result
            .model
            .get_node_by_oid_str("1.3.6.1.2.1.2.2.1.1")
            .is_some(),
        "ifIndex OID should exist"
    );
}

/// Verify specific OIDs match libsmi output.
#[test]
fn test_oid_values_match_libsmi() {
    // Load tier3 files
    let files = [
        include_bytes!("../../../.local/mibs_mini/tier3_complex/IANAifType-MIB").as_slice(),
        include_bytes!("../../../.local/mibs_mini/tier3_complex/INET-ADDRESS-MIB").as_slice(),
        include_bytes!("../../../.local/mibs_mini/tier3_complex/SNMPv2-MIB").as_slice(),
        include_bytes!("../../../.local/mibs_mini/tier3_complex/IF-MIB").as_slice(),
        include_bytes!("../../../.local/mibs_mini/tier3_complex/HOST-RESOURCES-MIB").as_slice(),
        include_bytes!("../../../.local/mibs_mini/tier3_complex/HOST-RESOURCES-TYPES").as_slice(),
        include_bytes!("../../../.local/mibs_mini/tier3_complex/IP-MIB").as_slice(),
    ];

    let mut hir_modules = Vec::new();
    for source in files {
        let parser = Parser::new(source);
        let ast_module = parser.parse_module();
        hir_modules.push(module::lower_module(&ast_module));
    }

    let resolver = Resolver::new();
    let result = resolver.resolve(hir_modules);

    // Key OIDs verified against libsmi smidump output:
    let expected_oids = [
        // SNMPv2-MIB
        ("sysDescr", "1.3.6.1.2.1.1.1"),
        ("sysUpTime", "1.3.6.1.2.1.1.3"),
        ("snmpSet", "1.3.6.1.6.3.1.1.6"),
        // IF-MIB
        ("ifTable", "1.3.6.1.2.1.2.2"),
        ("ifEntry", "1.3.6.1.2.1.2.2.1"),
        ("ifIndex", "1.3.6.1.2.1.2.2.1.1"),
        ("ifMIB", "1.3.6.1.2.1.31"),
        // HOST-RESOURCES-MIB
        ("host", "1.3.6.1.2.1.25"),
        ("hrSystem", "1.3.6.1.2.1.25.1"),
        ("hrMIBAdminInfo", "1.3.6.1.2.1.25.7"),
        ("hostResourcesMibModule", "1.3.6.1.2.1.25.7.1"),
    ];

    for (name, expected_oid) in expected_oids {
        let node = result.model.get_node_by_oid_str(expected_oid);
        assert!(node.is_some(), "OID {expected_oid} ({name}) should exist");

        // Verify the node has the expected label
        if let Some(n) = node
            && let Some(def) = n.primary_definition()
        {
            let label = result.model.get_str(def.label);
            assert_eq!(
                label, name,
                "OID {expected_oid} should be named '{name}', got '{label}'"
            );
        }
    }

    println!("All {} OIDs verified against libsmi!", expected_oids.len());
}
