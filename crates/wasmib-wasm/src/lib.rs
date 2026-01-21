//! wasmib-wasm: WASM FFI boundary
//!
//! This crate provides the WebAssembly interface for wasmib,
//! including memory management, serialization, and FFI exports.
//!
//! # FFI Exports
//!
//! The following functions are exported for host languages:
//!
//! - `wasmib_alloc(size) -> *mut u8` - Allocate memory
//! - `wasmib_dealloc(ptr, size)` - Free memory
//! - `wasmib_load_module(ptr, len) -> u32` - Parse and stage a MIB
//! - `wasmib_resolve() -> u32` - Resolve staged modules
//! - `wasmib_get_model() -> *const u8` - Get serialized model
//! - `wasmib_get_diagnostics() -> *const u8` - Get diagnostics JSON
//! - `wasmib_get_error() -> *const u8` - Get last error message
//! - `wasmib_reset()` - Clear all state

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use core::sync::atomic::AtomicBool;

/// Flag indicating a panic occurred in WASM.
///
/// The panic handler sets this to true; `wasmib_get_error()` checks it
/// so hosts can detect panics even though the handler must loop forever.
pub(crate) static PANICKED: AtomicBool = AtomicBool::new(false);

pub mod cache;
#[allow(unsafe_code)]
pub mod ffi;
pub mod serialize;

// Re-export FFI functions at crate root for WASM exports
pub use ffi::{
    wasmib_alloc, wasmib_dealloc, wasmib_get_diagnostics, wasmib_get_error, wasmib_get_model,
    wasmib_load_module, wasmib_reset, wasmib_resolve,
};

// SAFETY: The runtime environment must be single-threaded WASM.
#[cfg(target_arch = "wasm32")]
#[global_allocator]
#[allow(unsafe_code)]
static ALLOCATOR: talc::TalckWasm = unsafe { talc::TalckWasm::new_global() };

#[cfg(all(target_arch = "wasm32", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    use core::sync::atomic::Ordering;
    PANICKED.store(true, Ordering::SeqCst);
    loop {}
}

pub use wasmib_core;
