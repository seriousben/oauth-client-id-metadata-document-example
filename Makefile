# OAuth Client ID Metadata Example - Development Makefile
# Simple targets for building, testing, and linting

.PHONY: help lint test build clean docker
.DEFAULT_GOAL := help

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  %-12s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# Fix code formatting and linting issues
lint: ## Fix formatting and linting issues
	cargo fmt --all
	cargo clippy --workspace --all-targets --all-features --fix --allow-dirty

# Run tests  
test: ## Run all tests
	cargo test --workspace

# Build the project
build: ## Build in debug mode
	cargo build --workspace

build-release: ## Build in release mode
	cargo build --release --workspace

# Docker operations
docker: ## Build and test Docker image
	docker build -t oauth-test:local .
	./scripts/release-test.sh oauth-test:local 3002

# Clean up
clean: ## Clean build artifacts
	cargo clean