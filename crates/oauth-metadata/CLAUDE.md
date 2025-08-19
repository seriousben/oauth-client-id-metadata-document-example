# OAuth Metadata Crate

## Overview

This crate implements the core OAuth 2.0 client credentials and JWT functionality, including RSA key management, JWT signing/verification, and OAuth client metadata document generation.

## Architecture

### Key Components

#### KeyManager
- Generates RSA-2048 key pairs at runtime
- Provides thread-safe access to private/public keys
- Handles key ID generation and management
- Uses RSA PKCS#1 PEM encoding

#### JwtIssuer  
- Creates and signs JWT tokens using RSA keys
- Supports both fixed identity and custom client_id modes
- Implements OAuth 2.0 client credentials response format
- Uses RS256 algorithm for JWT signing

#### OAuthClientMetadata
- Generates OAuth 2.0 client metadata documents
- Configures for client_credentials grant type
- Specifies private_key_jwt authentication method
- Includes JWKS URI for key distribution

#### JsonWebKeySet (JWKS)
- Exports RSA public keys in JWK format
- Provides key discovery for token verification
- Includes key type, algorithm, and key ID
- Compatible with standard JWT verification libraries

### JWT Claims Structure

Standard JWT claims:
- `iss` (issuer) - Service URL or custom client_id
- `sub` (subject) - Service URL or custom client_id  
- `aud` (audience) - Optional, not currently used
- `exp` (expiration) - Current time + 1 hour
- `iat` (issued at) - Current timestamp
- `jti` (JWT ID) - Unique token identifier

Custom claims:
- `scope` - OAuth scope as string (e.g., "read write")

### Token Response Format

Following OAuth 2.0 client_credentials specification:

```json
{
  "access_token": "eyJ0eXAi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

## RSA Key Management

### Key Generation
- Uses secure random number generation
- 2048-bit RSA keys for security
- Keys generated fresh on each service start
- No key persistence (stateless service)

### Key Formats
- Private keys: RSA PKCS#1 PEM format
- Public keys: JWK (JSON Web Key) format for JWKS
- Key IDs: Generated from public key hash

### Security Considerations
- Private keys never exposed via API
- Only public keys distributed via JWKS endpoint
- Keys rotated on service restart
- Uses industry-standard RSA-2048 + SHA-256

## OAuth 2.0 Compliance

### Client Credentials Flow
Implements RFC 6749 Section 4.4:
- Supports `client_credentials` grant type
- Returns proper token response format
- Includes standard OAuth response fields

### Client Authentication
Supports RFC 7523 private_key_jwt method:
- Client signs JWT with private key
- JWT includes client_id as iss/sub
- Authorization server verifies with client's public key

### Client Metadata
Implements draft OAuth Client ID Metadata Document:
- Self-describing client metadata
- Includes supported auth methods and algorithms
- Provides JWKS URI for key discovery

## Error Handling

### Result Types
All public functions return `Result<T, Box<dyn std::error::Error>>`:
- Proper error propagation
- Allows callers to handle errors appropriately
- Uses standard Rust error handling patterns

### Error Sources
- RSA key generation failures
- JWT encoding/signing errors
- JSON serialization failures
- Invalid input parameters

## Dependencies

### Core Dependencies
- `rsa` - RSA cryptography implementation
- `jsonwebtoken` - JWT creation and verification
- `serde` - Serialization framework
- `base64` - Base64 encoding utilities
- `sha2` - SHA-256 hashing
- `rand` - Secure random number generation

### Utility Dependencies  
- `anyhow` - Error handling convenience
- `uuid` - Unique ID generation for JWT claims