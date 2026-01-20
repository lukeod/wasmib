//! Resolution phases.
//!
//! Resolution proceeds in six ordered phases:
//!
//! 1. **Registration**: Index all modules and definitions
//! 2. **Imports**: Resolve import references
//! 3. **Types**: Build type graph and resolve references
//! 4. **OIDs**: Build OID tree and resolve references
//! 5. **Semantics**: Infer node kinds, resolve table semantics
//! 6. **Deduplication**: Remove duplicate definitions from identical module copies

pub mod dedup;
pub mod imports;
pub mod oids;
pub mod registration;
pub mod semantics;
pub mod types;

pub use dedup::deduplicate_definitions;
pub use imports::resolve_imports;
#[cfg(feature = "tracing")]
pub use imports::resolve_imports_traced;
pub use oids::resolve_oids;
#[cfg(feature = "tracing")]
pub use oids::resolve_oids_traced;
pub use registration::register_modules;
pub use semantics::analyze_semantics;
pub use types::resolve_types;
