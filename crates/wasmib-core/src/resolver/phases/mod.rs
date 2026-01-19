//! Resolution phases.
//!
//! Resolution proceeds in five ordered phases:
//!
//! 1. **Registration**: Index all modules and definitions
//! 2. **Imports**: Resolve import references
//! 3. **Types**: Build type graph and resolve references
//! 4. **OIDs**: Build OID tree and resolve references
//! 5. **Semantics**: Infer node kinds, resolve table semantics

pub mod registration;
pub mod imports;
pub mod types;
pub mod oids;
pub mod semantics;

pub use registration::register_modules;
pub use imports::resolve_imports;
pub use types::resolve_types;
pub use oids::resolve_oids;
pub use semantics::analyze_semantics;
