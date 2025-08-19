# Integration Tests Crate

## Overview

This crate provides comprehensive end-to-end testing of the OAuth 2.0 client credentials service, validating the complete integration between the oauth-metadata and oauth-server crates.

## Test Architecture

### Test Categories

#### Full OAuth Flow Tests
- Complete end-to-end OAuth 2.0 workflows
- Tests both authentication approaches
- Validates JWT structure and claims  
- Ensures proper HTTP response codes and formats

#### Custom Configuration Tests
- Tests with different PUBLIC_URL configurations
- Validates environment variable handling
- Ensures proper metadata URL generation

#### Token Validation Tests
- JWT structure validation (header.payload.signature)
- Base64 decoding verification
- Claims validation (iss, sub, exp, iat, jti)
- Algorithm verification (RS256)

#### Error Handling Tests
- HTTP error response validation
- Invalid endpoint testing
- Proper error JSON format verification

#### Token Uniqueness Tests
- Multiple token generation
- Ensures unique JTI claims
- Validates different tokens for different client_ids

### Testing Patterns

#### HTTP Testing
Uses `axum_test::TestServer` for realistic HTTP testing:
- Real HTTP requests and responses
- Proper Content-Type handling
- Status code validation
- JSON response parsing

#### JSON Request Testing
Tests the JSON body format for `/jwt` endpoint:
```rust
.json(&serde_json::json!({
    "client_id": "test-client",
    "scope": "custom-scope"  
}))
```

#### JWT Validation
Comprehensive JWT structure validation:
- Split JWT into header.payload.signature parts
- Base64 decode each part
- Parse JSON from decoded parts
- Validate all required claims are present
- Check claim values and types

### Test Data Management

#### Test Isolation
- Each test creates fresh app state
- No shared state between tests
- Independent key generation per test

#### Configurable Testing
- Custom public URLs for different test scenarios
- Parameterized client_id and scope values
- Flexible token generation testing

### Integration Validation

#### Cross-Crate Integration
- Tests oauth-metadata core functionality through HTTP layer
- Validates oauth-server HTTP handling
- Ensures proper serialization/deserialization

#### OAuth Specification Compliance
- Validates OAuth 2.0 client credentials responses
- Tests JWT-Bearer token format compliance
- Ensures proper HTTP status codes per OAuth spec

#### Real-world Scenarios
- Simulates actual client usage patterns
- Tests both metadata discovery and direct JWT generation
- Validates different client identity scenarios

## Dependencies

### Testing Framework
- `tokio` - Async test runtime
- `axum-test` - HTTP endpoint testing
- `serde_json` - JSON manipulation and validation
- `base64` - JWT token decoding

### Core Integration
- `oauth-server` - HTTP server implementation
- `oauth-metadata` - Core OAuth functionality

## Test Execution

### Running Tests
```bash
# All integration tests
cargo test -p integration-tests

# Specific test
cargo test -p integration-tests test_full_oauth_flow

# With output
cargo test -p integration-tests -- --nocapture
```

### CI/CD Integration
- Runs in GitHub Actions pipeline
- Validates Docker container functionality
- Tests both local builds and published images
- Ensures compatibility across different environments