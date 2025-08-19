# OAuth Client ID Metadata Example

## Project Structure and Rust Patterns

### Workspace Architecture

This project uses Cargo workspace pattern with three focused crates:

```
├── crates/
│   ├── oauth-metadata/     # Core OAuth and JWT logic
│   ├── oauth-server/       # HTTP server and endpoints  
│   └── integration-tests/  # End-to-end integration tests
├── Dockerfile              # Multi-stage container build
├── compose.yaml            # Docker Compose configuration
└── openapi.yaml           # API specification
```

### Rust Design Patterns

#### Separation of Concerns
- **oauth-metadata**: Pure business logic, no HTTP dependencies
- **oauth-server**: HTTP layer, minimal business logic
- **integration-tests**: Full-stack testing, realistic scenarios

#### Error Handling
- Uses `Result<T, E>` consistently throughout
- `anyhow::Error` for internal errors with context
- Proper error propagation from core logic to HTTP layer
- JSON error responses for client-facing endpoints

#### State Management
- `AppState` contains all shared components wrapped in `Arc<>`
- Thread-safe sharing across HTTP handlers
- Stateless service design (keys generated per startup)
- Environment-based configuration with sensible defaults

#### Type Safety
- Strong typing for all request/response structures
- `serde` derives for JSON serialization
- Optional fields properly modeled with `Option<T>`
- No use of `any` type or unsafe code

### Testing Patterns

#### Three-Layer Testing Strategy

1. **Unit Tests** (`#[cfg(test)]` modules in each crate)
   - Test individual functions and methods
   - Mock external dependencies where needed
   - Fast execution for tight feedback loops

2. **Integration Tests** (dedicated crate)
   - Test complete HTTP request/response cycles
   - Real JWT generation and validation
   - Cross-crate integration verification

3. **End-to-End Tests** (Docker-based via `release-test.sh`)
   - Full container testing with realistic environment
   - Tests published Docker images
   - Validates production-like deployments

#### Test Organization Patterns

```rust
// Table-driven tests with clear naming
#[tokio::test]
async fn test_jwt_endpoint_with_custom_client_id() {
    let app = create_app();
    let server = TestServer::new(app).unwrap();
    
    let response = server
        .post("/jwt")
        .json(&serde_json::json!({
            "client_id": "my-custom-client",
            "scope": "custom-scope"
        }))
        .await;
        
    response.assert_status_ok();
    // ... assertions
}
```

#### Docker Testing Consistency

**Development Environment:**
```bash
# Local development
cargo run -p oauth-server

# Docker Compose testing  
docker compose up
# Service available at http://localhost:3002
```

**CI/CD Testing:**
```bash
# Build and test Docker container
docker build -t oauth-test:latest .
./scripts/release-test.sh oauth-test:latest 3002

# Test published images
./scripts/release-test.sh ghcr.io/seriousben/oauth-client-id-metadata-example:latest
```

### Configuration Patterns

#### Environment Variables
- `PUBLIC_URL`: Service's public URL for JWT claims and metadata
- `RUST_LOG`: Standard Rust logging configuration
- Defaults provided for development, production overrides

#### Docker Configuration
- Multi-stage build for optimized container size
- `cargo-chef` for Docker layer caching
- Health checks with proper timeouts and retries
- Port mapping: container:3000 → host:3002

### Security Patterns

#### RSA Key Management
- Fresh RSA-2048 keys generated on startup
- Private keys never exposed via API
- Public keys distributed via JWKS endpoint
- No key persistence (stateless design)

#### JWT Security
- RS256 algorithm (RSA + SHA-256)
- 1-hour token expiration
- Unique JTI (JWT ID) per token
- Proper iss/sub/aud claim handling

### API Design Patterns

#### RESTful Endpoints
- Clear separation between OAuth approaches
- Proper HTTP methods (GET for reads, POST for token generation)
- Consistent JSON request/response formats
- Standard OAuth 2.0 response structure

#### Content Negotiation
- JSON request bodies with proper Content-Type validation
- Structured error responses with HTTP status codes
- OpenAPI specification for documentation

### Dependency Management

#### Core Dependencies
- **Web**: `axum` (modern, performant HTTP framework)
- **Crypto**: `rsa`, `jsonwebtoken` (industry-standard libraries)
- **Serialization**: `serde` (de-facto standard for Rust)
- **Async**: `tokio` (standard async runtime)

#### Development Dependencies
- **Testing**: `axum-test` for HTTP testing
- **Development**: `cargo-watch` for auto-reloading
- **CI/CD**: GitHub Actions with comprehensive pipeline

### CI/CD Patterns

#### GitHub Actions Workflow
- Multi-stage pipeline: test → docker-test → security-audit
- Matrix testing across Rust versions
- Docker multi-platform builds (amd64/arm64)
- Dependabot for automated dependency updates

#### Release Management
- Automated Docker image publishing to GHCR
- Semantic versioning via Git tags
- Comprehensive release testing script
- Production deployment validation

### Documentation Patterns

#### Multi-Level Documentation
- **README.md**: User-focused quick start and examples
- **CLAUDE.md**: Developer-focused implementation details
- **openapi.yaml**: API specification for integration
- **Inline docs**: Function-level documentation with examples

This architecture provides a solid foundation for OAuth 2.0 services while maintaining Rust best practices and modern development workflows.