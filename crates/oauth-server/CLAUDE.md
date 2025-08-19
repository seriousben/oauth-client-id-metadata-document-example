# OAuth Server Crate

## Overview

This crate implements the HTTP server endpoints for the OAuth 2.0 client credentials service, providing both OAuth Client ID Metadata and private_key_jwt authentication approaches.

## Architecture

### Application State

The `AppState` struct holds shared components:
- `KeyManager`: RSA key generation and management
- `JwtIssuer`: JWT token creation and signing
- `OAuthClientMetadata`: Client metadata document
- `JsonWebKeySet`: Public key distribution

All components are wrapped in `Arc<>` for efficient sharing across handler threads.

### Endpoints

#### OAuth Client Metadata Approach
- `GET /oauth-client` - Returns client metadata document
- `POST /token` - Issues JWT with service identity (fixed iss/sub = public URL)

#### Private Key JWT Approach  
- `POST /jwt` - Issues JWT with customizable client_id (JSON body)
- Accepts optional `client_id` and `scope` parameters
- When `client_id` provided, overrides both `iss` and `sub` claims

#### Common Endpoints
- `GET /health` - Health check
- `GET /jwks` - JSON Web Key Set (public keys)

## Request/Response Patterns

### JSON Request Bodies
The `/jwt` endpoint uses JSON request bodies for parameters:

```json
{
  "client_id": "optional-client-id", 
  "scope": "optional-scope"
}
```

### Error Handling
All endpoints return proper HTTP status codes:
- `200 OK` - Successful operation
- `415 Unsupported Media Type` - Invalid Content-Type for JSON endpoints
- `500 Internal Server Error` - Server-side errors with JSON error response

### Response Format
Token responses follow OAuth 2.0 specification:

```json
{
  "access_token": "jwt-token-here",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "requested-scope"
}
```

## Testing Patterns

### Unit Testing
- Each handler has dedicated test functions
- Uses `axum_test::TestServer` for HTTP testing
- Tests both success and edge cases
- Validates response structure and status codes

### Test Organization
- Separate tests for each endpoint
- Test both with and without optional parameters
- Validate JWT structure and claims
- Test different authentication approaches

### Test Helpers
- `create_app()` - Default app with test state
- `create_app_with_state()` - Custom app state for specific tests
- `AppState::new_with_public_url()` - Custom public URL testing

## Environment Configuration

### Required Environment Variables
- `PUBLIC_URL` - Service's public URL (default: http://localhost:3000)
- Used for:
  - Default `iss` and `sub` claims in JWT tokens
  - `jwks_uri` in OAuth client metadata
  - Issuer identity in client metadata

### Development vs Production
- Development: Uses localhost URLs
- Production: Must set PUBLIC_URL to actual service domain
- All URLs should use HTTPS in production

## Dependencies

### Core Dependencies
- `axum` - Web framework and HTTP server
- `serde` - JSON serialization/deserialization  
- `tower-http` - HTTP middleware (tracing)
- `oauth-metadata` - Core OAuth logic (sibling crate)

### Test Dependencies
- `axum-test` - HTTP endpoint testing
- `serde_json` - JSON manipulation in tests
- `tokio` - Async runtime for tests