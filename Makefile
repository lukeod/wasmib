# wasmib Makefile
#
# Builds all Rust crates, the WASM module, and the Go bindings.

.PHONY: all build build-rust build-wasm build-go copy-wasm test test-rust test-go clean
.PHONY: check-deps check-rust check-wasm-target check-go

# Paths
WASM_TARGET := target/wasm32-unknown-unknown/release/wasmib_wasm.wasm
GO_EMBED_DIR := wasmib-go/embed
GO_WASM_PATH := $(GO_EMBED_DIR)/wasmib.wasm
WASM_TRIPLE := wasm32-unknown-unknown

# Colors for output (if terminal supports it)
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m # No Color

# Dependency checks
check-rust:
	@command -v cargo >/dev/null 2>&1 || { \
		echo "$(RED)Error: cargo not found$(NC)"; \
		echo "Install Rust via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
		exit 1; \
	}

check-wasm-target: check-rust
	@rustup target list --installed 2>/dev/null | grep -q "$(WASM_TRIPLE)" || { \
		echo "$(RED)Error: WASM target '$(WASM_TRIPLE)' not installed$(NC)"; \
		echo "Install via: rustup target add $(WASM_TRIPLE)"; \
		exit 1; \
	}

check-go:
	@command -v go >/dev/null 2>&1 || { \
		echo "$(RED)Error: go not found$(NC)"; \
		echo "Install Go from: https://go.dev/dl/"; \
		exit 1; \
	}

# Check all dependencies
check-deps: check-rust check-wasm-target check-go
	@echo "$(GREEN)All dependencies installed$(NC)"

# Default target: build everything
all: build

# Build all components
build: check-deps build-rust build-wasm copy-wasm build-go

# Build Rust crates (native)
build-rust: check-rust
	cargo build --release

# Build WASM module
build-wasm: check-wasm-target
	cargo build --release --target $(WASM_TRIPLE) --package wasmib-wasm

# Copy WASM to Go embed directory
copy-wasm: build-wasm
	@mkdir -p $(GO_EMBED_DIR)
	cp $(WASM_TARGET) $(GO_WASM_PATH)
	@echo "Copied WASM to $(GO_WASM_PATH)"

# Build Go project
build-go: check-go copy-wasm
	cd wasmib-go && go build ./...

# Run all tests
test: test-rust test-go

# Run Rust tests
test-rust: check-rust
	cargo test --workspace

# Run Go tests
test-go: check-go copy-wasm
	cd wasmib-go && go test -v ./...

# Clean build artifacts
clean:
	-cargo clean 2>/dev/null
	rm -f $(GO_WASM_PATH)
	-cd wasmib-go && go clean 2>/dev/null

# Development helpers
.PHONY: check fmt clippy

# Run cargo check
check: check-rust
	cargo check --workspace --all-targets

# Format code
fmt: check-rust
	cargo fmt --all

# Run clippy
clippy: check-rust
	cargo clippy --workspace --all-targets

# Quick rebuild of WASM and copy (for iteration)
.PHONY: wasm
wasm: build-wasm copy-wasm
	@echo "WASM rebuilt and copied"

# Help target
.PHONY: help
help:
	@echo "wasmib build targets:"
	@echo ""
	@echo "  make              Build everything (Rust, WASM, Go)"
	@echo "  make build        Same as above"
	@echo "  make build-rust   Build Rust crates (native)"
	@echo "  make build-wasm   Build WASM module"
	@echo "  make build-go     Build Go project"
	@echo "  make wasm         Quick rebuild WASM and copy"
	@echo ""
	@echo "  make test         Run all tests"
	@echo "  make test-rust    Run Rust tests only"
	@echo "  make test-go      Run Go tests only"
	@echo ""
	@echo "  make check-deps   Verify all dependencies are installed"
	@echo "  make check        Run cargo check"
	@echo "  make fmt          Format Rust code"
	@echo "  make clippy       Run clippy lints"
	@echo "  make clean        Clean build artifacts"
	@echo ""
	@echo "Dependencies:"
	@echo "  - Rust/cargo:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
	@echo "  - WASM target: rustup target add $(WASM_TRIPLE)"
	@echo "  - Go:          https://go.dev/dl/"
