# OAuth 2.0 Client Test Service for Authorization Server Validation

## Table of Contents

1. [Abstract](#1-abstract)
2. [Introduction](#2-introduction)
3. [Definitions](#3-definitions)
4. [OAuth Client ID Metadata Document](#4-oauth-client-id-metadata-document)
5. [Client Authentication Methods](#5-client-authentication-methods)
6. [Protocol Endpoints](#6-protocol-endpoints)
7. [Security Considerations](#7-security-considerations)
8. [Deployment and Configuration](#8-deployment-and-configuration)
9. [Examples](#9-examples)
10. [Contributing](#10-contributing)
11. [References](#11-references)

## 1. Abstract

This document describes a test service for OAuth 2.0 client implementations supporting the [OAuth Client ID Metadata Document draft specification][oauth-client-id-metadata-document] as defined by Aaron Parecki. The implementation provides a complete OAuth 2.0 client credentials service that supports both pre-registered client authentication with private_key_jwt and the proposed Client ID Metadata Document approach for client discovery and verification.

This service allows testing a pure private_key_jwt implementation and a Client ID Metadata Document implementation using private_key_jwt. This service is NOT an implementation of the Client ID Metadata Document specification since it only implements the client part of it. It can be used to test an authorization server's implementation of the Client ID Metadata Document specification.

The service implements the client credentials grant type as specified in RFC 6749, with extensions for client metadata publishing as described in the [OAuth Client ID Metadata Document draft][oauth-client-id-metadata-document]. This allows authorization servers to discover client capabilities and public keys through standardized metadata endpoints.

### Endpoints

```bash
# Service health verification endpoint
curl https://oauth-client.example.com/health

# OAuth 2.0 client metadata document (RFC 7591)
curl https://oauth-client.example.com/oauth-client

# JSON Web Key Set for JWT verification (RFC 7517) 
curl https://oauth-client.example.com/jwks

# Client ID Metadata Document approach token endpoint
curl -X POST https://oauth-client.example.com/token

# Pre-registered client private_key_jwt authentication token endpoint
curl -X POST https://oauth-client.example.com/jwt
```

## 2. Introduction

### 2.1. Background

OAuth 2.0, as defined in RFC 6749, specifies client registration through pre-registration with the authorization server. While dynamic client registration (RFC 7591) provides a standardized protocol for automated client registration, neither approach provides straightforward mechanisms for establishing trust with specific clients based on their published identity, particularly in scenarios where clients need to be trusted based on their ability to control specific URLs or domains.

The [OAuth Client ID Metadata Document draft specification][oauth-client-id-metadata-document] addresses the same fundamental problem as dynamic client registration - allowing clients to communicate their capabilities and authentication methods to authorization servers - but provides a different approach that enables trust establishment through client-published metadata at well-known locations. This approach is particularly valuable in scenarios like the Model Context Protocol (MCP) specification, where clients need to establish trust based on their published identity and capabilities.

### 2.2. Protocol Overview

This implementation supports two distinct OAuth 2.0 client authentication approaches:

1. **Client ID Metadata Approach**: Clients publish metadata at a well-known location, allowing authorization servers to discover client capabilities and public keys dynamically using private_key_jwt as the asymmetric authentication method.

2. **Pre-registered Client with private_key_jwt**: Clients authenticate using signed JWT assertions as specified in RFC 7523, with pre-registered client credentials and customizable client identity claims. The private_key_jwt method is used as the asymmetric authentication method here.

### 2.3. Scope

This implementation creates an OAuth client that can serve a Client ID Metadata Document and issue JWTs to test authorization server implementations of both private_key_jwt authentication and Client ID Metadata Document discovery.

## 3. Definitions

- **Client Metadata Document**: A JSON document containing OAuth 2.0 client metadata as specified in RFC 7591 and extended by the [OAuth Client ID Metadata Document draft][oauth-client-id-metadata-document].
- **JWKS**: JSON Web Key Set as defined in RFC 7517, containing public keys for JWT verification.
- **Client Credentials Grant**: The OAuth 2.0 grant type defined in Section 4.4 of RFC 6749.
- **JWT Bearer Token**: A JSON Web Token used as an OAuth 2.0 access token, as specified in RFC 7519.

## 4. OAuth Client ID Metadata Document

### 4.1. Metadata Document Structure

The client metadata document is published at the `/oauth-client` endpoint and contains the following standardized metadata fields as defined in RFC 7591:

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

### 4.2. Metadata Discovery

Authorization servers MAY discover client capabilities by fetching the metadata document from the client's published metadata URI. The metadata document MUST be served with the `application/json` media type.

### 4.3. Public Key Distribution

Public keys for JWT verification MUST be published via the JSON Web Key Set (JWKS) endpoint as referenced in the metadata document's `jwks_uri` field. The JWKS document MUST conform to RFC 7517 specifications.

## 5. Client Authentication Methods

### 5.1. Client ID Metadata Approach

In this approach, the client identity is intrinsically tied to the service's public URL, following the [OAuth Client ID Metadata Document draft specification][oauth-client-id-metadata-document]. This model enables trust establishment based on the client's ability to control and serve content from their declared identity URL, providing a more straightforward trust mechanism compared to dynamic client registration flows.

The client authentication process follows these steps:

1. **Trust Establishment**: Authorization server can trust clients based on their ability to serve metadata from their declared identity URL
2. **Metadata Discovery**: Authorization server discovers client metadata from the published metadata document at the client's URL
3. **Key Distribution**: Authorization server retrieves client public keys from the JWKS endpoint referenced in the metadata
4. **Authentication**: Client requests access token using its service identity (iss = sub = service URL)
5. **Verification**: Authorization server verifies client identity through metadata validation and JWT signature verification using private_key_jwt as the asymmetric authentication method

This approach is particularly beneficial for scenarios where clients need to be trusted based on their published identity (such as in MCP implementations) rather than through explicit registration processes.

### 5.2. Pre-registered Client with private_key_jwt Authentication

This method implements RFC 7523 JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants with pre-registration. The client authentication process includes:

1. Client generates and signs JWT assertion with its private key
2. JWT contains client_id as both issuer (iss) and subject (sub) claims
3. Client presents JWT assertion to authorization server  
4. Authorization server verifies JWT signature using client's public key, where private_key_jwt serves as the asymmetric authentication method


## 6. Protocol Endpoints

### 6.1. Client Metadata Endpoint

**Endpoint**: `GET /oauth-client`

**Description**: Returns the OAuth 2.0 client metadata document as specified in RFC 7591.

**Response**: JSON document containing client metadata with `application/json` content type.

### 6.2. Token Endpoint (Client Metadata Approach)

**Endpoint**: `POST /token`

**Description**: Issues JWT access token using client metadata approach where client identity is derived from service metadata.

**Request Body**: Optional JSON object containing:
- `scope` (optional): Requested OAuth 2.0 scope
- `aud` (optional): Additional audience claims

**Response**: OAuth 2.0 access token response as specified in RFC 6749 Section 5.1.

### 6.3. JWT Generation Endpoint (private_key_jwt)

**Endpoint**: `POST /jwt`

**Description**: Generates customizable JWT for private_key_jwt authentication method as specified in RFC 7523.

**Request Body**: Optional JSON object containing:
- `client_id` (optional): Override for issuer and subject claims
- `scope` (optional): Requested OAuth 2.0 scope
- `aud` (optional): Additional audience claims

**Response**: OAuth 2.0 access token response as specified in RFC 6749 Section 5.1.

### 6.4. JSON Web Key Set Endpoint

**Endpoint**: `GET /jwks`

**Description**: Returns the JSON Web Key Set containing public keys for JWT verification as specified in RFC 7517.

**Response**: JWKS document with `application/json` content type.

### 6.5. Health Check Endpoint

**Endpoint**: `GET /health`

**Description**: Service health verification endpoint.

**Response**: JSON object indicating service status.

## 7. Security Considerations

**This service is intended for testing and development purposes only and is NOT suitable for production use.** The service generates ephemeral keys at startup, does not implement proper key rotation, and lacks the security hardening required for production OAuth 2.0 deployments.

## 8. Deployment and Configuration

### 8.1. Environment Variables

The service supports the following configuration parameters:

- `PUBLIC_URL`: The publicly accessible URL of the service (REQUIRED for production)
- `RUST_LOG`: Logging verbosity level (default: "info")
- `JWT_AUDIENCE`: Base audience claim(s) for issued tokens (OPTIONAL)
  - Single audience: `JWT_AUDIENCE=api.example.com`
  - Multiple audiences: `JWT_AUDIENCE=api1.example.com,api2.example.com`

### 8.2. Container Deployment

```bash
docker run -p 3002:3000 \
  -e PUBLIC_URL=https://oauth-client.example.com \
  -e JWT_AUDIENCE=api.example.com \
  -e RUST_LOG=info \
  ghcr.io/seriousben/oauth-client-id-metadata-example:latest
```

### 8.3. Docker Compose Configuration

```yaml
services:
  oauth-server:
    image: ghcr.io/seriousben/oauth-client-id-metadata-example:latest
    ports:
      - "3002:3000"
    environment:
      PUBLIC_URL: "https://oauth-client.example.com"
      JWT_AUDIENCE: "api.example.com,auth.example.com"
      RUST_LOG: "info"
```

## 9. Examples

### 9.1. Testing Authorization Server Client Discovery

```bash
# 1. Authorization server discovers client capabilities
curl https://oauth-client.example.com/oauth-client

# 2. Authorization server retrieves client public keys for JWT verification
curl https://oauth-client.example.com/jwks

# 3. Test your authorization server's client registration with metadata URI
curl -X POST https://your-auth-server.com/clients \
  -H "Content-Type: application/json" \
  -d '{"client_metadata_uri": "https://oauth-client.example.com/oauth-client"}'
```

### 9.2. Testing Authorization Server Token Exchange

```bash
# 1. Generate client JWT using Client ID Metadata Document approach
CLIENT_JWT=$(curl -s -X POST https://oauth-client.example.com/token | jq -r .access_token)

# 2. Test your authorization server's token endpoint with the client JWT
curl -X POST https://your-auth-server.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=$CLIENT_JWT"

# 3. Alternative: Generate JWT with specific client identity for testing
CUSTOM_JWT=$(curl -s -X POST https://oauth-client.example.com/jwt \
  -H "Content-Type: application/json" \
  -d '{"client_id": "test-client-123", "scope": "api:read"}' | jq -r .access_token)

# 4. Test authorization server with custom client JWT
curl -X POST https://your-auth-server.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=$CUSTOM_JWT"
```

### 9.3. Testing Authorization Server JWT Validation

```bash
# 1. Generate JWT with various client identities to test authorization server validation
PROD_JWT=$(curl -s -X POST https://oauth-client.example.com/jwt \
  -H "Content-Type: application/json" \
  -d '{"client_id": "my-service-prod", "scope": "api:read api:write"}' | jq -r .access_token)

STAGING_JWT=$(curl -s -X POST https://oauth-client.example.com/jwt \
  -H "Content-Type: application/json" \
  -d '{"client_id": "my-service-staging", "scope": "api:read"}' | jq -r .access_token)

# 2. Test authorization server's JWT validation with different client identities
echo "Testing production client:"
curl -X POST https://your-auth-server.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=$PROD_JWT"

echo "Testing staging client:"
curl -X POST https://your-auth-server.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=$STAGING_JWT"
```

### 9.4. Audience Configuration

```bash
# Token with base audiences (from JWT_AUDIENCE environment variable)
curl -X POST https://oauth-client.example.com/token

# Token with additional audience appended to base audiences
curl -X POST https://oauth-client.example.com/jwt \
  -H "Content-Type: application/json" \
  -d '{"aud": "https://extra-service.example.com"}'
```

### 9.5. JWT Token Verification

```bash
# Retrieve and decode access token
TOKEN=$(curl -s -X POST https://oauth-client.example.com/token | jq -r .access_token)

# Decode JWT header
echo $TOKEN | cut -d'.' -f1 | base64 -d | jq .

# Decode JWT payload  
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .
```

## 10. Contributing

### 10.1. Architecture

The implementation is structured as a Rust workspace containing three primary crates:

- `oauth-metadata`: Core OAuth metadata and JWT logic
- `oauth-server`: HTTP server and protocol endpoints
- `integration-tests`: End-to-end protocol validation tests

### 10.2. Development Setup

```bash
# Clone the repository
git clone https://github.com/seriousben/oauth-client-id-metadata-example.git
cd oauth-client-id-metadata-example

# Install Rust 1.89.0+
# Build the project
cargo build

# Run tests
cargo test

# Run the server locally
cargo run -p oauth-server
```

### 10.3. Cryptographic Implementation

- **Key Generation**: RSA-2048 key pairs generated at service startup
- **Signature Algorithm**: RS256 (RSA PKCS#1 v1.5 with SHA-256)
- **Key Distribution**: Public keys exposed via RFC 7517 compliant JWKS endpoint
- **Token Lifetime**: JWT access tokens expire after 3600 seconds (1 hour)

### 10.4. Testing

```bash
# Unit tests
cargo test --workspace

# Integration tests
cargo test -p integration-tests

# Docker integration tests
./scripts/release-test.sh

# Linting and formatting
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

## 11. References

- **RFC 6749**: The OAuth 2.0 Authorization Framework
- **RFC 7519**: JSON Web Token (JWT)
- **RFC 7517**: JSON Web Key (JWK)
- **RFC 7523**: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants
- **RFC 7591**: OAuth 2.0 Dynamic Client Registration Protocol
- **OAuth Client ID Metadata Document**: [Draft Specification by Aaron Parecki][oauth-client-id-metadata-document]

---

**Implementation Version**: 0.1.0  
**License**: Apache-2.0  
**Repository**: https://github.com/seriousben/oauth-client-id-metadata-document-example

<!-- Link References -->
[oauth-client-id-metadata-document]: https://github.com/aaronpk/draft-parecki-oauth-client-id-metadata-document