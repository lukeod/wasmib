//! FFI exports for WASM host languages.
//!
//! Provides the minimal set of exports needed for host languages (Go, etc.)
//! to interact with wasmib via WASM.
//!
//! # Protocol
//!
//! 1. Host allocates memory via `wasmib_alloc`
//! 2. Host writes MIB source bytes to allocated memory
//! 3. Host calls `wasmib_load_module` to parse and stage
//! 4. Host calls `wasmib_dealloc` to free the source buffer
//! 5. Repeat steps 1-4 for each MIB file
//! 6. Host calls `wasmib_resolve` to build the model
//! 7. Host calls `wasmib_get_model` to retrieve serialized model
//! 8. Host calls `wasmib_get_diagnostics` for any warnings/errors
//! 9. Host calls `wasmib_reset` when done (optional, for reuse)
//!
//! # Memory Management
//!
//! - `wasmib_alloc`/`wasmib_dealloc` are for host-controlled buffers
//! - Returned pointers from `wasmib_get_*` are valid until next `wasmib_reset` or `wasmib_resolve`
//! - All returned data is length-prefixed: `[len: u32 LE][data: u8; len]`

use alloc::alloc::{Layout, alloc, dealloc};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::Ordering;

use wasmib_core::lexer::{Diagnostic, Severity};
use wasmib_core::module::{Module, lower_module};
use wasmib_core::parser::Parser;
use wasmib_core::resolver::Resolver;

/// Error codes returned by FFI functions.
pub mod error {
    /// Success.
    pub const SUCCESS: u32 = 0;
    /// Invalid pointer argument.
    pub const INVALID_POINTER: u32 = 1;
    /// Parse error (module could not be parsed).
    pub const PARSE_ERROR: u32 = 2;
    /// Resolution error.
    pub const RESOLVE_ERROR: u32 = 3;
    /// No model available (nothing staged or resolved).
    pub const NO_MODEL: u32 = 4;
    /// Internal error.
    pub const INTERNAL_ERROR: u32 = 5;
}

/// Global state for the WASM module.
///
/// SAFETY: WASM is single-threaded, so no synchronization needed.
/// We use `UnsafeCell` because `RefCell`'s const `new()` doesn't work with Vec in `no_std`.
struct WasmState {
    /// Staged HIR modules awaiting resolution.
    staged_modules: Vec<Module>,
    /// Accumulated diagnostics from parsing.
    parse_diagnostics: Vec<Diagnostic>,
    /// Accumulated diagnostics from resolution.
    resolve_diagnostics: Vec<Diagnostic>,
    /// Serialized model bytes (cached after `wasmib_get_model` call).
    serialized_model: Option<Vec<u8>>,
    /// Serialized diagnostics JSON (cached).
    serialized_diagnostics: Option<Vec<u8>>,
    /// Last error message.
    last_error: Option<Vec<u8>>,
}

impl WasmState {
    fn reset(&mut self) {
        self.staged_modules.clear();
        self.parse_diagnostics.clear();
        self.resolve_diagnostics.clear();
        self.serialized_model = None;
        self.serialized_diagnostics = None;
        self.last_error = None;
    }

    fn set_error(&mut self, msg: &str) {
        // Truncate message if it exceeds u32::MAX (only possible on 64-bit, not WASM)
        let len = u32::try_from(msg.len()).unwrap_or(u32::MAX);
        let msg_bytes = &msg.as_bytes()[..len as usize];
        let mut buf = Vec::with_capacity(4 + msg_bytes.len());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(msg_bytes);
        self.last_error = Some(buf);
    }
}

/// Global state container.
///
/// SAFETY: WASM is single-threaded. We initialize lazily on first access.
static STATE: GlobalState = GlobalState::new();

struct GlobalState {
    inner: UnsafeCell<Option<WasmState>>,
}

impl GlobalState {
    const fn new() -> Self {
        Self {
            inner: UnsafeCell::new(None),
        }
    }

    /// Get mutable access to the state, initializing if needed.
    ///
    /// SAFETY: WASM is single-threaded, so this is safe.
    #[allow(clippy::mut_from_ref)]
    fn get(&self) -> &mut WasmState {
        // SAFETY: WASM is single-threaded
        let inner = unsafe { &mut *self.inner.get() };
        inner.get_or_insert_with(|| WasmState {
            staged_modules: Vec::new(),
            parse_diagnostics: Vec::new(),
            resolve_diagnostics: Vec::new(),
            serialized_model: None,
            serialized_diagnostics: None,
            last_error: None,
        })
    }
}

// SAFETY: WASM is single-threaded
unsafe impl Sync for GlobalState {}

// === Memory Management ===

/// Allocate memory for host to write data.
///
/// Returns a pointer to the allocated memory, or null on failure.
/// The host must call `wasmib_dealloc` with the same pointer and size when done.
#[unsafe(no_mangle)]
pub extern "C" fn wasmib_alloc(size: u32) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }

    let Ok(layout) = Layout::from_size_align(size as usize, 8) else {
        return core::ptr::null_mut();
    };

    // SAFETY: Layout is valid, checked above
    unsafe { alloc(layout) }
}

/// Free previously allocated memory.
///
/// The pointer must have been returned by `wasmib_alloc` with the same size.
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // FFI: caller responsible for valid pointer
pub extern "C" fn wasmib_dealloc(ptr: *mut u8, size: u32) {
    if ptr.is_null() || size == 0 {
        return;
    }

    let Ok(layout) = Layout::from_size_align(size as usize, 8) else {
        return;
    };

    // SAFETY: Caller guarantees ptr was allocated with wasmib_alloc
    unsafe { dealloc(ptr, layout) }
}

// === Module Loading ===

/// Parse a MIB file and add to staging area.
///
/// The host must:
/// 1. Call `wasmib_alloc(len)` to get a buffer
/// 2. Write MIB source bytes to that buffer
/// 3. Call `wasmib_load_module(ptr, len)`
/// 4. Call `wasmib_dealloc(ptr, len)` when done
///
/// Returns: 0 = success, non-zero = error code.
/// On error, call `wasmib_get_error` for details.
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // FFI: caller responsible for valid pointer
pub extern "C" fn wasmib_load_module(ptr: *const u8, len: u32) -> u32 {
    if ptr.is_null() {
        STATE.get().set_error("null pointer");
        return error::INVALID_POINTER;
    }

    // SAFETY: Caller guarantees ptr points to len valid bytes
    let source = unsafe { core::slice::from_raw_parts(ptr, len as usize) };

    let state = STATE.get();

    // Clear cached outputs (new module invalidates them)
    state.serialized_model = None;
    state.serialized_diagnostics = None;

    // Parse
    let parser = Parser::new(source);
    let ast = parser.parse_module();

    // Collect parse diagnostics
    state.parse_diagnostics.extend(ast.diagnostics.clone());

    // Check for fatal errors (module name is "UNKNOWN" on failure)
    if ast.name.name == "UNKNOWN" {
        state.set_error("failed to parse module header");
        return error::PARSE_ERROR;
    }

    // Lower to HIR
    let hir = lower_module(ast);
    state.staged_modules.push(hir);

    error::SUCCESS
}

// === Resolution ===

/// Resolve all staged modules into a Model.
///
/// After calling this:
/// - Call `wasmib_get_model()` to retrieve the serialized model
/// - Call `wasmib_get_diagnostics()` to retrieve any warnings/errors
///
/// Returns: 0 = success, non-zero = error code.
#[unsafe(no_mangle)]
pub extern "C" fn wasmib_resolve() -> u32 {
    let state = STATE.get();

    if state.staged_modules.is_empty() {
        state.set_error("no modules staged for resolution");
        return error::NO_MODEL;
    }

    // Move staged modules out
    let modules = core::mem::take(&mut state.staged_modules);

    // Clear cached outputs
    state.serialized_model = None;
    state.serialized_diagnostics = None;

    // Resolve
    let resolver = Resolver::new();
    let result = resolver.resolve(modules);

    // Store resolve diagnostics
    state.resolve_diagnostics = result.diagnostics;

    // Serialize model to protobuf
    let bytes = crate::serialize::to_bytes(&result.model, None);

    // Check serialized size fits in u32 (only fails on 64-bit with >4GB output)
    let Ok(len) = u32::try_from(bytes.len()) else {
        state.set_error("serialized model too large (exceeds 4GB)");
        return error::INTERNAL_ERROR;
    };

    // Store with length prefix
    let mut output = Vec::with_capacity(4 + bytes.len());
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(&bytes);
    state.serialized_model = Some(output);

    error::SUCCESS
}

// === Model Retrieval ===

/// Get serialized Model bytes.
///
/// Returns pointer to length-prefixed data: `[len: u32 LE][data: u8; len]`
/// Returns null if no model available (call `wasmib_resolve` first).
///
/// The returned pointer is valid until the next `wasmib_reset()` or `wasmib_resolve()`.
#[unsafe(no_mangle)]
pub extern "C" fn wasmib_get_model() -> *const u8 {
    let state = STATE.get();

    if let Some(bytes) = &state.serialized_model {
        bytes.as_ptr()
    } else {
        state.set_error("no model available");
        core::ptr::null()
    }
}

// === Diagnostics ===

/// Get diagnostics as protobuf.
///
/// Returns pointer to length-prefixed protobuf bytes: `[len: u32 LE][data: u8; len]`
/// The protobuf is a `Diagnostics` message containing a repeated `Diagnostic`.
///
/// The returned pointer is valid until the next `wasmib_reset()` or `wasmib_resolve()`.
#[unsafe(no_mangle)]
#[allow(clippy::missing_panics_doc)] // Encoding only fails on OOM
pub extern "C" fn wasmib_get_diagnostics() -> *const u8 {
    use crate::serialize::{Diagnostic as ProtoDiagnostic, Diagnostics as ProtoDiagnostics};
    use micropb::MessageEncode;

    let state = STATE.get();

    // Return cached if available
    if let Some(ref bytes) = state.serialized_diagnostics {
        return bytes.as_ptr();
    }

    // Build protobuf Diagnostics message
    let items: Vec<ProtoDiagnostic> = state
        .parse_diagnostics
        .iter()
        .chain(state.resolve_diagnostics.iter())
        .map(|diag| ProtoDiagnostic {
            r#severity: match diag.severity {
                Severity::Error => 0,
                Severity::Warning => 1,
            },
            r#message: diag.message.clone(),
            r#start: diag.span.start,
            r#end: diag.span.end,
        })
        .collect();

    let diagnostics = ProtoDiagnostics { items };

    // Encode to protobuf bytes
    let mut proto_bytes = Vec::new();
    if diagnostics
        .encode(&mut micropb::PbEncoder::new(&mut proto_bytes))
        .is_err()
    {
        // Encoding failed (likely OOM) - return empty message
        static EMPTY_MSG: &[u8] = b"\x00\x00\x00\x00";
        return EMPTY_MSG.as_ptr();
    }

    // Check serialized size fits in u32 (only fails on 64-bit with >4GB output)
    let Ok(len) = u32::try_from(proto_bytes.len()) else {
        // Diagnostics too large - return empty message
        static EMPTY_MSG: &[u8] = b"\x00\x00\x00\x00";
        return EMPTY_MSG.as_ptr();
    };

    // Store with length prefix
    let mut output = Vec::with_capacity(4 + proto_bytes.len());
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(&proto_bytes);

    // Store and return pointer - insert() returns a reference, avoiding unwrap
    state.serialized_diagnostics.insert(output).as_ptr()
}

/// Get last error message.
///
/// Returns pointer to length-prefixed string: `[len: u32 LE][msg: u8; len]`
/// Returns null if no error occurred.
///
/// Note: Also checks for panics. If a panic occurred, returns "panic occurred"
/// even if no explicit error was set. This allows hosts to detect WASM panics.
#[unsafe(no_mangle)]
pub extern "C" fn wasmib_get_error() -> *const u8 {
    // Check for panic first - panic handler sets this flag
    if crate::PANICKED.load(Ordering::SeqCst) {
        // Return a static error message for panics
        // Format: [len: u32 LE][msg: u8; len]
        static PANIC_ERROR: &[u8] = b"\x0e\x00\x00\x00panic occurred";
        return PANIC_ERROR.as_ptr();
    }

    let state = STATE.get();
    match &state.last_error {
        Some(bytes) => bytes.as_ptr(),
        None => core::ptr::null(),
    }
}

// === Reset ===

/// Clear staged modules and model (for reuse).
///
/// Call this to free memory and start fresh.
#[unsafe(no_mangle)]
pub extern "C" fn wasmib_reset() {
    STATE.get().reset();
}
