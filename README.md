# OAuth Client ID Metadata Example

A modern Rust HTTP service implementing OAuth 2.0 client credentials flow with client metadata according to Aaron Parecki's [OAuth Client ID Metadata Document draft specification](https://drafts.aaronpk.com/draft-parecki-oauth-client-id-metadata-document/).

## Overview

This service demonstrates and facilitates two different OAuth 2.0 authentication approaches:

### 🔐 **OAuth Client ID Metadata Approach**
- `POST /token` - Fixed JWT for OAuth client metadata flow (no parameters)
- `GET /oauth-client` - Client metadata document with service identity
- `GET /jwks` - JSON Web Key Set for token verification

### 🎯 **Custom Private Key JWT Approach**
- `POST /jwt` - Customizable JWT for private_key_jwt authentication
- Accepts `client_id` parameter to override issuer/subject claims
- Perfect for testing different client identities

### 📊 **Common Endpoints**
- `GET /health` - Health check endpoint

## Features

- **RS256 JWT Tokens**: Uses RSA-2048 keys for secure token signing
- **Client Metadata**: Full OAuth client metadata document support
- **JWKS Support**: JSON Web Key Set for public key distribution
- **Environment Configuration**: Configurable public URL via environment variable
- **Custom Client ID**: Support for custom client_id in token requests
- **Modern Rust**: Built with Rust 1.89.0 using workspace architecture
- **Docker Ready**: Multi-stage Docker builds with cargo-chef optimization

## Quick Start

### Using Docker Compose

```bash
# Clone the repository
git clone https://github.com/seriousben/oauth-client-id-metadata-example.git
cd oauth-client-id-metadata-example

# Start the service
docker compose up

# The service will be available at http://localhost:3002
```

### Using Pre-built Docker Image

```bash
# Pull and run the latest published image
docker run -p 3002:3000 \
  -e PUBLIC_URL=http://localhost:3002 \
  -e RUST_LOG=info \
  ghcr.io/seriousben/oauth-client-id-metadata-example:latest

# The service will be available at http://localhost:3002
```

### Local Development

```bash
# Install Rust 1.89.0+
# Build and run
cargo run -p oauth-server

# The service will be available at http://localhost:3000
```

## Authentication Approaches Explained

### 🔐 **OAuth Client ID Metadata Flow**

This approach implements Aaron Parecki's draft specification where the client publishes metadata about itself, including its public keys. The authorization server can then verify the client's identity by fetching this metadata.

**Flow:**
1. Client registers with authorization server using its metadata URL
2. Authorization server fetches client metadata from `GET /oauth-client`
3. Authorization server gets client's public keys from `GET /jwks`
4. Client uses `POST /token` to get access token (service identity)

```bash
# 1. Authorization server fetches client metadata
curl http://localhost:3002/oauth-client

# 2. Authorization server gets public keys for verification
curl http://localhost:3002/jwks

# 3. Client gets access token (uses service's identity)
curl -X POST http://localhost:3002/token
```

**Key characteristics:**
- ✅ Client identity is tied to the service itself (`iss` and `sub` = service URL)
- ✅ No client_id parameter needed - identity comes from metadata
- ✅ Authorization server discovers client keys via JWKS endpoint
- ✅ Perfect for service-to-service authentication

### 🎯 **Private Key JWT Authentication**

This is the traditional OAuth 2.0 private_key_jwt method where the client signs a JWT with its private key and presents different identities.

**Flow:**
1. Client signs JWT with its private key
2. JWT contains client_id as both issuer and subject
3. Authorization server verifies JWT signature using client's public key
4. Client presents different client_id values for different use cases

```bash
# Generate JWT for specific client identity
curl -X POST http://localhost:3002/jwt \
  -H "Content-Type: application/json" \
  -d '{"client_id":"my-app-prod","scope":"api:read"}'

# Generate JWT for different client identity
curl -X POST http://localhost:3002/jwt \
  -H "Content-Type: application/json" \
  -d '{"client_id":"my-app-staging","scope":"api:write"}'

# Use default service identity
curl -X POST http://localhost:3002/jwt \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Key characteristics:**
- ✅ Client can present different identities via `client_id` parameter
- ✅ `iss` and `sub` claims match the provided `client_id`
- ✅ Perfect for testing multiple client scenarios
- ✅ Traditional OAuth 2.0 private_key_jwt flow

## API Reference

### OAuth Client Metadata Endpoints

#### Get Client Metadata
```bash
GET /oauth-client
```

Response:
```json
{
  "client_id": "oauth-client-id-metadata-example",
  "client_name": "OAuth Client ID Metadata Example",
  "grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "RS256",
  "jwks_uri": "http://localhost:3002/jwks",
  "scope": "read write"
}
```

#### Get Service Access Token
```bash
POST /token
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

### Private Key JWT Endpoints

#### Generate Custom JWT
```bash
POST /jwt
Content-Type: application/json

{
  "client_id": "my-client",
  "scope": "custom-scope"
}
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "custom-scope"
}
```

**JSON Parameters:**
- `client_id` (optional) - Override issuer and subject claims
- `scope` (optional) - Custom scope for the token
- `aud` (optional) - Additional audience(s) to append to configured audience
  - Single: `"aud": "extra.example.com"`
  - Multiple: `"aud": ["extra1.example.com", "extra2.example.com"]`

### Common Endpoints

#### Get Public Keys (JWKS)
```bash
GET /jwks
```

Response:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "kid": "key-12345678",
      "n": "base64url-encoded-modulus...",
      "e": "AQAB"
    }
  ]
}
```

## Use Case Examples

### Example 1: OAuth Client Metadata Flow

Perfect for microservices that need to authenticate with each other using a well-known identity.

```bash
# Authorization server discovers client capabilities
curl http://localhost:3002/oauth-client | jq .

# Authorization server gets client's public keys
curl http://localhost:3002/jwks | jq '.keys[0] | {kty, alg, kid}'

# Client authenticates using its service identity
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:3002/token)
ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r .access_token)

# Decode token to see service identity (iss=sub=service_url)
echo $ACCESS_TOKEN | cut -d'.' -f2 | base64 -d | jq .
```

### Example 2: Private Key JWT Testing

Perfect for testing OAuth 2.0 implementations with different client identities.

```bash
# Test production client identity
PROD_TOKEN=$(curl -s -X POST http://localhost:3002/jwt \
  -H "Content-Type: application/json" \
  -d '{"client_id":"myapp-prod","scope":"api:read"}' | jq -r .access_token)
echo $PROD_TOKEN | cut -d'.' -f2 | base64 -d | jq '{iss, sub, scope}'

# Test staging client identity
STAGING_TOKEN=$(curl -s -X POST http://localhost:3002/jwt \
  -H "Content-Type: application/json" \
  -d '{"client_id":"myapp-staging","scope":"api:write"}' | jq -r .access_token)
echo $STAGING_TOKEN | cut -d'.' -f2 | base64 -d | jq '{iss, sub, scope}'

# Compare different client identities
echo "Production client iss/sub: myapp-prod"
echo "Staging client iss/sub: myapp-staging"
```

### Example 4: JWT Audience Configuration

Configure audiences for tokens to specify which services can accept them.

```bash
# Start service with configured audiences
docker run -p 3002:3000 \
  -e PUBLIC_URL=http://localhost:3002 \
  -e JWT_AUDIENCE=api.example.com,auth.example.com \
  -e RUST_LOG=info \
  ghcr.io/seriousben/oauth-client-id-metadata-example:latest

# Generate token with base audiences only
BASE_TOKEN=$(curl -s -X POST http://localhost:3002/token | jq -r .access_token)
echo "Base audiences:"
echo $BASE_TOKEN | cut -d'.' -f2 | base64 -d | jq .aud

# Generate token with additional audience
EXTRA_TOKEN=$(curl -s -X POST http://localhost:3002/jwt \
  -H "Content-Type: application/json" \
  -d '{"aud":"extra.service.com"}' | jq -r .access_token)
echo "With additional audience:"
echo $EXTRA_TOKEN | cut -d'.' -f2 | base64 -d | jq .aud

# Generate token with multiple additional audiences
MULTI_TOKEN=$(curl -s -X POST http://localhost:3002/jwt \
  -H "Content-Type: application/json" \
  -d '{"aud":["extra1.com","extra2.com"]}' | jq -r .access_token)
echo "With multiple additional audiences:"
echo $MULTI_TOKEN | cut -d'.' -f2 | base64 -d | jq .aud
```

### Example 3: Testing Authorization Server

Use this service to test how an authorization server handles both approaches.

```bash
# Test OAuth client metadata discovery
AUTH_SERVER="https://your-auth-server.com"
CLIENT_METADATA_URL="http://localhost:3002"

# 1. Register client with metadata URL
curl -X POST "$AUTH_SERVER/clients" \
  -H "Content-Type: application/json" \
  -d "{\"client_metadata_uri\": \"$CLIENT_METADATA_URL/oauth-client\"}"

# 2. Test private_key_jwt authentication
JWT_TOKEN=$(curl -s -X POST http://localhost:3002/jwt \
  -H "Content-Type: application/json" \
  -d '{"client_id":"test-client"}')
curl -X POST "$AUTH_SERVER/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=$JWT_TOKEN"
```

## Configuration

### Environment Variables

- `PUBLIC_URL` - The public URL of the service (default: `http://localhost:3000`)
- `RUST_LOG` - Log level (default: `info`)
- `JWT_AUDIENCE` - Audience claim(s) for JWT tokens (optional)
  - Single audience: `JWT_AUDIENCE=api.example.com`
  - Multiple audiences: `JWT_AUDIENCE=api1.example.com,api2.example.com`

### Docker Compose Configuration

```yaml
services:
  oauth-server:
    build: .
    ports:
      - "3002:3000"
    environment:
      - RUST_LOG=debug
      - PUBLIC_URL=http://localhost:3002
      - JWT_AUDIENCE=api.example.com,auth.example.com
```

## Token Details

The service issues RS256-signed JWT tokens with the following claims:

- `iss` (issuer) - Public URL or custom client_id
- `sub` (subject) - Public URL or custom client_id
- `aud` (audience) - Configurable via `JWT_AUDIENCE` environment variable or request body
- `exp` (expiration) - Current time + 1 hour
- `iat` (issued at) - Current timestamp
- `jti` (JWT ID) - Unique identifier
- `scope` - Requested scope as custom claim

### Default Behavior

- **Without client_id**: Uses `PUBLIC_URL` for both `iss` and `sub` claims
- **With client_id**: Uses the provided `client_id` for both `iss` and `sub` claims
- **Without JWT_AUDIENCE**: No audience claims in tokens
- **With JWT_AUDIENCE**: Base audience(s) included in all tokens
- **Request body `aud`**: Additional audiences appended to base audiences

## Development

### Project Structure

```
├── crates/
│   ├── oauth-metadata/     # Core OAuth metadata and JWT logic
│   ├── oauth-server/       # HTTP server and endpoints
│   └── integration-tests/  # End-to-end integration tests
├── Dockerfile              # Multi-stage Docker build
├── compose.yaml            # Docker Compose configuration
└── README.md
```

### Running Tests

```bash
# Unit tests
cargo test

# Integration tests
cargo test -p integration-tests

# Specific test
cargo test -p oauth-server test_token_endpoint

# Release/End-to-end tests
./scripts/release-test.sh                                    # Build and test locally
./scripts/release-test.sh ghcr.io/seriousben/oauth-client-id-metadata-example:latest  # Test published image
```

### Building

```bash
# Development build
cargo build

# Release build
cargo build --release

# Docker build
docker build -t oauth-client-id-metadata-example .
```

## Specification Compliance

This implementation follows the [OAuth Client ID Metadata Document draft specification](https://drafts.aaronpk.com/draft-parecki-oauth-client-id-metadata-document/) and includes:

- **Client Metadata Document**: Complete OAuth 2.0 client metadata structure
- **JWKS Integration**: Public key distribution via JSON Web Key Set
- **Client Credentials Flow**: Standard OAuth 2.0 client credentials grant type
- **JWT Bearer Tokens**: RS256-signed tokens with proper claims structure

## Security Considerations

- **RSA-2048 Keys**: Strong cryptographic keys generated at runtime
- **RS256 Signing**: Industry-standard JWT signing algorithm
- **Token Expiration**: 1-hour token lifetime for security
- **No Secrets in Logs**: Careful handling of sensitive information
- **HTTPS Ready**: Designed for production HTTPS deployment

## CI/CD

### GitHub Actions

This project includes comprehensive CI/CD workflows:

- **CI**: Runs tests, linting, and security audits on all PRs and pushes
- **Docker Publish**: Builds and publishes Docker images to GitHub Container Registry
- **Multi-platform**: Supports both `linux/amd64` and `linux/arm64` architectures
- **Security**: Includes `cargo audit` for vulnerability scanning
- **Integration Tests**: Full end-to-end testing of Docker containers

## Contributing

1. Ensure Rust 1.89.0+ is installed
2. Run tests: `cargo test`
3. Check formatting: `cargo fmt`
4. Run lints: `cargo clippy`
5. Test Docker build: `docker build .`
6. All PRs are automatically tested via GitHub Actions

## License

Apache-2.0
