//! AST to HIR lowering.
//!
//! Transforms parsed AST into normalized HIR representation.
//! This module handles:
//! - Language detection from imports
//! - Import normalization
//! - Type normalization
//! - Status normalization
//! - Unification of SMIv1/SMIv2 forms

use super::definition::{
    HirAgentCapabilities, HirDefinition, HirIndexItem, HirModuleCompliance, HirModuleIdentity,
    HirNotification, HirNotificationGroup, HirObjectGroup, HirObjectIdentity, HirObjectType,
    HirRevision, HirTrapInfo, HirTypeDef, HirValueAssignment,
};
use super::module::{HirImport, HirModule};
use super::normalize::{is_smiv2_base_module, normalize_import, normalize_type_name};
use super::syntax::{HirConstraint, HirOidAssignment, HirOidComponent, HirRange, HirRangeValue, HirTypeSyntax};
use super::types::{HirAccess, HirStatus, SmiLanguage, Symbol};
use crate::ast::{
    self, AccessValue, Constraint, Definition, IndexClause, Module, OidComponent, RangeValue,
    StatusValue, TypeSyntax,
};
use crate::lexer::Diagnostic;
use alloc::vec::Vec;

/// Context for HIR lowering.
///
/// Tracks state during the lowering process.
#[derive(Debug, Default)]
pub struct LoweringContext {
    /// Diagnostics collected during lowering.
    pub diagnostics: Vec<Diagnostic>,
    /// Detected language (may be updated as imports are processed).
    pub language: SmiLanguage,
}

impl LoweringContext {
    /// Create a new lowering context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a diagnostic.
    pub fn add_diagnostic(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }
}

/// Lower an AST module to HIR.
///
/// This is the main entry point for HIR lowering. It:
/// 1. Detects the SMI language from imports
/// 2. Normalizes imports
/// 3. Lowers each definition
///
/// # Arguments
///
/// * `ast_module` - The parsed AST module
///
/// # Returns
///
/// A normalized HIR module with diagnostics.
#[must_use]
pub fn lower_module(ast_module: &Module) -> HirModule {
    let mut ctx = LoweringContext::new();

    // Create HIR module
    let mut hir_module = HirModule::new(
        Symbol::new(ast_module.name.name.clone()),
        ast_module.span,
    );

    // Lower imports and detect language
    hir_module.imports = lower_imports(&ast_module.imports, &mut ctx);
    hir_module.language = ctx.language;

    // Lower definitions
    for def in &ast_module.body {
        if let Some(hir_def) = lower_definition(def, &ctx) {
            hir_module.definitions.push(hir_def);
        }
    }

    // Collect diagnostics from AST and lowering
    hir_module.diagnostics = ast_module.diagnostics.clone();
    hir_module.diagnostics.extend(ctx.diagnostics);

    hir_module
}

/// Lower import clauses to HIR imports.
///
/// Also detects SMI language from imports.
fn lower_imports(import_clauses: &[ast::ImportClause], ctx: &mut LoweringContext) -> Vec<HirImport> {
    let mut imports = Vec::new();

    for clause in import_clauses {
        let from_module = &clause.from_module.name;

        // Detect language from imports
        if is_smiv2_base_module(from_module) {
            ctx.language = SmiLanguage::Smiv2;
        }

        // Flatten and normalize each symbol
        for symbol in &clause.symbols {
            let normalized = normalize_import(from_module, &symbol.name);
            imports.push(HirImport::new(
                normalized.module,
                normalized.symbol,
                clause.span,
            ));
        }
    }

    // Default to SMIv1 if no SMIv2 imports detected
    if ctx.language == SmiLanguage::Unknown {
        ctx.language = SmiLanguage::Smiv1;
    }

    imports
}

/// Lower a single definition to HIR.
///
/// Returns `None` for definitions that are filtered out (MACRO, Error).
fn lower_definition(def: &Definition, ctx: &LoweringContext) -> Option<HirDefinition> {
    match def {
        Definition::ObjectType(d) => Some(HirDefinition::ObjectType(lower_object_type(d, ctx))),
        Definition::ModuleIdentity(d) => {
            Some(HirDefinition::ModuleIdentity(lower_module_identity(d)))
        }
        Definition::ObjectIdentity(d) => {
            Some(HirDefinition::ObjectIdentity(lower_object_identity(d)))
        }
        Definition::NotificationType(d) => {
            Some(HirDefinition::Notification(lower_notification_type(d)))
        }
        Definition::TrapType(d) => Some(HirDefinition::Notification(lower_trap_type(d))),
        Definition::TextualConvention(d) => {
            Some(HirDefinition::TypeDef(lower_textual_convention(d)))
        }
        Definition::TypeAssignment(d) => Some(HirDefinition::TypeDef(lower_type_assignment(d))),
        Definition::ValueAssignment(d) => {
            Some(HirDefinition::ValueAssignment(lower_value_assignment(d)))
        }
        Definition::ObjectGroup(d) => Some(HirDefinition::ObjectGroup(lower_object_group(d))),
        Definition::NotificationGroup(d) => {
            Some(HirDefinition::NotificationGroup(lower_notification_group(d)))
        }
        Definition::ModuleCompliance(d) => {
            Some(HirDefinition::ModuleCompliance(lower_module_compliance(d)))
        }
        Definition::AgentCapabilities(d) => {
            Some(HirDefinition::AgentCapabilities(lower_agent_capabilities(d)))
        }
        // Filter out non-semantic definitions
        Definition::MacroDefinition(_) | Definition::Error(_) => None,
    }
}

// === Definition lowering functions ===

fn lower_object_type(def: &ast::ObjectTypeDef, _ctx: &LoweringContext) -> HirObjectType {
    HirObjectType {
        name: Symbol::new(def.name.name.clone()),
        syntax: lower_type_syntax(&def.syntax.syntax),
        units: def.units.as_ref().map(|u| u.value.clone()),
        access: lower_access(&def.access.value),
        status: def
            .status
            .as_ref()
            .map_or(HirStatus::Current, |s| lower_status(&s.value)),
        description: def.description.as_ref().map(|d| d.value.clone()),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        index: lower_index_clause(def.index.as_ref()),
        augments: def
            .augments
            .as_ref()
            .map(|a| Symbol::new(a.target.name.clone())),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_module_identity(def: &ast::ModuleIdentityDef) -> HirModuleIdentity {
    HirModuleIdentity {
        name: Symbol::new(def.name.name.clone()),
        last_updated: def.last_updated.value.clone(),
        organization: def.organization.value.clone(),
        contact_info: def.contact_info.value.clone(),
        description: def.description.value.clone(),
        revisions: def
            .revisions
            .iter()
            .map(|r| HirRevision {
                date: r.date.value.clone(),
                description: r.description.value.clone(),
            })
            .collect(),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_object_identity(def: &ast::ObjectIdentityDef) -> HirObjectIdentity {
    HirObjectIdentity {
        name: Symbol::new(def.name.name.clone()),
        status: lower_status(&def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_notification_type(def: &ast::NotificationTypeDef) -> HirNotification {
    HirNotification {
        name: Symbol::new(def.name.name.clone()),
        objects: def.objects.iter().map(|o| Symbol::new(o.name.clone())).collect(),
        status: lower_status(&def.status.value),
        description: Some(def.description.value.clone()),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        trap_info: None,
        oid: Some(lower_oid_assignment(&def.oid_assignment)),
        span: def.span,
    }
}

fn lower_trap_type(def: &ast::TrapTypeDef) -> HirNotification {
    HirNotification {
        name: Symbol::new(def.name.name.clone()),
        objects: def
            .variables
            .iter()
            .map(|v| Symbol::new(v.name.clone()))
            .collect(),
        status: HirStatus::Current, // TRAP-TYPE doesn't have STATUS
        description: def.description.as_ref().map(|d| d.value.clone()),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        trap_info: Some(HirTrapInfo {
            enterprise: Symbol::new(def.enterprise.name.clone()),
            trap_number: def.trap_number,
        }),
        oid: None, // TRAP-TYPE OID is derived from enterprise + trap_number
        span: def.span,
    }
}

fn lower_textual_convention(def: &ast::TextualConventionDef) -> HirTypeDef {
    HirTypeDef {
        name: Symbol::new(def.name.name.clone()),
        syntax: lower_type_syntax(&def.syntax.syntax),
        display_hint: def.display_hint.as_ref().map(|h| h.value.clone()),
        status: lower_status(&def.status.value),
        description: Some(def.description.value.clone()),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        is_textual_convention: true,
        span: def.span,
    }
}

fn lower_type_assignment(def: &ast::TypeAssignmentDef) -> HirTypeDef {
    HirTypeDef {
        name: Symbol::new(def.name.name.clone()),
        syntax: lower_type_syntax(&def.syntax),
        display_hint: None,
        status: HirStatus::Current,
        description: None,
        reference: None,
        is_textual_convention: false,
        span: def.span,
    }
}

fn lower_value_assignment(def: &ast::ValueAssignmentDef) -> HirValueAssignment {
    HirValueAssignment {
        name: Symbol::new(def.name.name.clone()),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_object_group(def: &ast::ObjectGroupDef) -> HirObjectGroup {
    HirObjectGroup {
        name: Symbol::new(def.name.name.clone()),
        objects: def.objects.iter().map(|o| Symbol::new(o.name.clone())).collect(),
        status: lower_status(&def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_notification_group(def: &ast::NotificationGroupDef) -> HirNotificationGroup {
    HirNotificationGroup {
        name: Symbol::new(def.name.name.clone()),
        notifications: def
            .notifications
            .iter()
            .map(|n| Symbol::new(n.name.clone()))
            .collect(),
        status: lower_status(&def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_module_compliance(def: &ast::ModuleComplianceDef) -> HirModuleCompliance {
    HirModuleCompliance {
        name: Symbol::new(def.name.name.clone()),
        status: lower_status(&def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_agent_capabilities(def: &ast::AgentCapabilitiesDef) -> HirAgentCapabilities {
    HirAgentCapabilities {
        name: Symbol::new(def.name.name.clone()),
        product_release: def.product_release.value.clone(),
        status: lower_status(&def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

// === Helper lowering functions ===

/// Lower AST type syntax to HIR type syntax with normalization.
fn lower_type_syntax(syntax: &TypeSyntax) -> HirTypeSyntax {
    match syntax {
        TypeSyntax::TypeRef(ident) => {
            // Normalize type name (Counter→Counter32, etc.)
            let normalized_name = normalize_type_name(&ident.name);
            HirTypeSyntax::TypeRef(Symbol::from_str(normalized_name))
        }
        TypeSyntax::IntegerEnum {
            named_numbers, ..
        } => HirTypeSyntax::IntegerEnum(
            named_numbers
                .iter()
                .map(|nn| (Symbol::new(nn.name.name.clone()), nn.value))
                .collect(),
        ),
        TypeSyntax::Bits { named_bits, .. } => HirTypeSyntax::Bits(
            named_bits
                .iter()
                .map(|nb| {
                    (
                        Symbol::new(nb.name.name.clone()),
                        nb.value as u32, // BITS positions are non-negative
                    )
                })
                .collect(),
        ),
        TypeSyntax::Constrained {
            base, constraint, ..
        } => HirTypeSyntax::Constrained {
            base: alloc::boxed::Box::new(lower_type_syntax(base)),
            constraint: lower_constraint(constraint),
        },
        TypeSyntax::SequenceOf { entry_type, .. } => {
            HirTypeSyntax::SequenceOf(Symbol::new(entry_type.name.clone()))
        }
        TypeSyntax::Sequence { fields, .. } => HirTypeSyntax::Sequence(
            fields
                .iter()
                .map(|f| (Symbol::new(f.name.name.clone()), lower_type_syntax(&f.syntax)))
                .collect(),
        ),
        TypeSyntax::OctetString { .. } => HirTypeSyntax::OctetString,
        TypeSyntax::ObjectIdentifier { .. } => HirTypeSyntax::ObjectIdentifier,
    }
}

/// Lower AST constraint to HIR constraint.
fn lower_constraint(constraint: &Constraint) -> HirConstraint {
    match constraint {
        Constraint::Size { ranges, .. } => {
            HirConstraint::Size(ranges.iter().map(lower_range).collect())
        }
        Constraint::Range { ranges, .. } => {
            HirConstraint::Range(ranges.iter().map(lower_range).collect())
        }
    }
}

/// Lower AST range to HIR range.
fn lower_range(range: &ast::Range) -> HirRange {
    HirRange {
        min: lower_range_value(&range.min),
        max: range.max.as_ref().map(lower_range_value),
    }
}

/// Lower AST range value to HIR range value.
fn lower_range_value(value: &RangeValue) -> HirRangeValue {
    match value {
        RangeValue::Number(n) => HirRangeValue::Number(*n),
        RangeValue::Ident(ident) => {
            // Handle MIN/MAX keywords
            match ident.name.as_str() {
                "MIN" => HirRangeValue::Min,
                "MAX" => HirRangeValue::Max,
                _ => HirRangeValue::Number(0), // Shouldn't happen, but fallback
            }
        }
    }
}

/// Lower AST OID assignment to HIR OID assignment.
fn lower_oid_assignment(oid: &ast::OidAssignment) -> HirOidAssignment {
    HirOidAssignment {
        components: oid.components.iter().map(lower_oid_component).collect(),
        span: oid.span,
    }
}

/// Lower AST OID component to HIR OID component.
fn lower_oid_component(comp: &OidComponent) -> HirOidComponent {
    match comp {
        OidComponent::Name(ident) => HirOidComponent::Name(Symbol::new(ident.name.clone())),
        OidComponent::Number { value, .. } => HirOidComponent::Number(*value),
        OidComponent::NamedNumber { name, number, .. } => HirOidComponent::NamedNumber {
            name: Symbol::new(name.name.clone()),
            number: *number,
        },
    }
}

/// Lower AST access value to HIR access.
fn lower_access(access: &AccessValue) -> HirAccess {
    match access {
        AccessValue::ReadOnly => HirAccess::ReadOnly,
        AccessValue::ReadWrite => HirAccess::ReadWrite,
        AccessValue::ReadCreate => HirAccess::ReadCreate,
        AccessValue::NotAccessible => HirAccess::NotAccessible,
        AccessValue::AccessibleForNotify => HirAccess::AccessibleForNotify,
        AccessValue::WriteOnly => HirAccess::WriteOnly,
        // SPPI-specific and AGENT-CAPABILITIES values map to closest equivalent
        AccessValue::NotImplemented => HirAccess::NotAccessible,
        AccessValue::Install => HirAccess::ReadWrite,
        AccessValue::InstallNotify => HirAccess::ReadWrite,
        AccessValue::ReportOnly => HirAccess::ReadOnly,
    }
}

/// Lower AST status value to HIR status with normalization.
fn lower_status(status: &StatusValue) -> HirStatus {
    match status {
        StatusValue::Current => HirStatus::Current,
        StatusValue::Deprecated => HirStatus::Deprecated,
        StatusValue::Obsolete => HirStatus::Obsolete,
        // SMIv1 normalization
        StatusValue::Mandatory => HirStatus::Current,
        StatusValue::Optional => HirStatus::Deprecated,
    }
}

/// Lower AST index clause to HIR index items.
fn lower_index_clause(clause: Option<&IndexClause>) -> Option<Vec<HirIndexItem>> {
    clause.map(|c| match c {
        IndexClause::Index { indexes, .. } | IndexClause::PibIndex { indexes, .. } => indexes
            .iter()
            .map(|i| HirIndexItem::new(Symbol::new(i.object.name.clone()), i.implied))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lower_access() {
        assert_eq!(lower_access(&AccessValue::ReadOnly), HirAccess::ReadOnly);
        assert_eq!(lower_access(&AccessValue::ReadWrite), HirAccess::ReadWrite);
        assert_eq!(lower_access(&AccessValue::ReadCreate), HirAccess::ReadCreate);
    }

    #[test]
    fn test_lower_status() {
        assert_eq!(lower_status(&StatusValue::Current), HirStatus::Current);
        assert_eq!(lower_status(&StatusValue::Deprecated), HirStatus::Deprecated);
        assert_eq!(lower_status(&StatusValue::Obsolete), HirStatus::Obsolete);
        // SMIv1 normalization
        assert_eq!(lower_status(&StatusValue::Mandatory), HirStatus::Current);
        assert_eq!(lower_status(&StatusValue::Optional), HirStatus::Deprecated);
    }
}
