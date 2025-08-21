# OAuth Client ID Metadata Document Implementation

## Table of Contents

1. [Abstract](#1-abstract)
2. [Introduction](#2-introduction)
3. [Conventions and Terminology](#3-conventions-and-terminology)
4. [OAuth Client ID Metadata Document](#4-oauth-client-id-metadata-document)
5. [Client Authentication Methods](#5-client-authentication-methods)
6. [Implementation Details](#6-implementation-details)
7. [Protocol Endpoints](#7-protocol-endpoints)
8. [Security Considerations](#8-security-considerations)
9. [Deployment and Configuration](#9-deployment-and-configuration)
10. [Examples](#10-examples)
11. [References](#11-references)

## 1. Abstract

This document describes an implementation of the OAuth Client ID Metadata Document draft specification as defined by Aaron Parecki. The implementation provides a complete OAuth 2.0 client credentials service that supports both traditional private_key_jwt authentication and the proposed client ID metadata approach for client discovery and verification.

The service implements the client credentials grant type as specified in RFC 6749, with extensions for client metadata publishing as described in the OAuth Client ID Metadata Document draft. This allows authorization servers to discover client capabilities and public keys through standardized metadata endpoints.

## 2. Introduction

### 2.1. Background

OAuth 2.0, as defined in RFC 6749, provides a framework for authorization but leaves client registration and discovery mechanisms largely unspecified. The OAuth Client ID Metadata Document draft specification addresses this gap by defining a standardized method for clients to publish their metadata, including supported authentication methods and public key information.

### 2.2. Protocol Overview

This implementation supports two distinct OAuth 2.0 client authentication approaches:

1. **Client ID Metadata Approach**: Clients publish metadata at a well-known location, allowing authorization servers to discover client capabilities and public keys dynamically.

2. **Traditional private_key_jwt**: Clients authenticate using signed JWT assertions as specified in RFC 7523, with customizable client identity claims.

### 2.3. Scope

This implementation is intended for:
- Testing OAuth 2.0 authorization server implementations
- Demonstrating client metadata discovery mechanisms  
- Providing reference implementation of the draft specification
- Supporting development and validation of OAuth 2.0 integrations

## 3. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 3.1. Definitions

- **Client Metadata Document**: A JSON document containing OAuth 2.0 client metadata as specified in RFC 7591 and extended by the OAuth Client ID Metadata Document draft.
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

In this approach, the client identity is intrinsically tied to the service's public URL. The client authentication process follows these steps:

1. Authorization server discovers client metadata from the published metadata document
2. Authorization server retrieves client public keys from the JWKS endpoint  
3. Client requests access token using its service identity (iss = sub = service URL)
4. Authorization server verifies client identity through metadata validation

### 5.2. Traditional private_key_jwt Authentication

This method implements RFC 7523 JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants. The client authentication process includes:

1. Client generates and signs JWT assertion with its private key
2. JWT contains client_id as both issuer (iss) and subject (sub) claims
3. Client presents JWT assertion to authorization server  
4. Authorization server verifies JWT signature using client's public key

### 5.3. Supported Algorithms

This implementation supports RSA-based signatures with SHA-256 (RS256) as specified in RFC 7518. The use of RSA-2048 keys provides appropriate security strength for the intended use cases.

## 6. Implementation Details

### 6.1. Architecture

The implementation is structured as a Rust workspace containing three primary crates:

- `oauth-metadata`: Core OAuth metadata and JWT logic
- `oauth-server`: HTTP server and protocol endpoints
- `integration-tests`: End-to-end protocol validation tests

### 6.2. Cryptographic Implementation

- **Key Generation**: RSA-2048 key pairs generated at service startup
- **Signature Algorithm**: RS256 (RSA PKCS#1 v1.5 with SHA-256)
- **Key Distribution**: Public keys exposed via RFC 7517 compliant JWKS endpoint
- **Token Lifetime**: JWT access tokens expire after 3600 seconds (1 hour)

### 6.3. Token Claims Structure

JWT access tokens contain the following claims as specified in RFC 7519:

- `iss` (Issuer): Service URL or custom client identifier
- `sub` (Subject): Service URL or custom client identifier  
- `aud` (Audience): Optional, configurable audience claim(s)
- `exp` (Expiration Time): Current time + 3600 seconds
- `iat` (Issued At): Current timestamp
- `jti` (JWT ID): Unique token identifier
- `scope` (Custom): Requested OAuth 2.0 scope

## 7. Protocol Endpoints

### 7.1. Client Metadata Endpoint

**Endpoint**: `GET /oauth-client`

**Description**: Returns the OAuth 2.0 client metadata document as specified in RFC 7591.

**Response**: JSON document containing client metadata with `application/json` content type.

### 7.2. Token Endpoint (Client Metadata Approach)

**Endpoint**: `POST /token`

**Description**: Issues JWT access token using client metadata approach where client identity is derived from service metadata.

**Request Body**: Optional JSON object containing:
- `scope` (optional): Requested OAuth 2.0 scope
- `aud` (optional): Additional audience claims

**Response**: OAuth 2.0 access token response as specified in RFC 6749 Section 5.1.

### 7.3. JWT Generation Endpoint (private_key_jwt)

**Endpoint**: `POST /jwt`

**Description**: Generates customizable JWT for private_key_jwt authentication method as specified in RFC 7523.

**Request Body**: Optional JSON object containing:
- `client_id` (optional): Override for issuer and subject claims
- `scope` (optional): Requested OAuth 2.0 scope
- `aud` (optional): Additional audience claims

**Response**: OAuth 2.0 access token response as specified in RFC 6749 Section 5.1.

### 7.4. JSON Web Key Set Endpoint

**Endpoint**: `GET /jwks`

**Description**: Returns the JSON Web Key Set containing public keys for JWT verification as specified in RFC 7517.

**Response**: JWKS document with `application/json` content type.

### 7.5. Health Check Endpoint

**Endpoint**: `GET /health`

**Description**: Service health verification endpoint.

**Response**: JSON object indicating service status.

## 8. Security Considerations

### 8.1. Key Management

- Private keys are generated at service startup and are not persisted
- Public keys are distributed only through the JWKS endpoint
- RSA-2048 provides adequate security strength for the intended use cases
- Key rotation is achieved through service restart (appropriate for testing scenarios)

### 8.2. Token Security

- JWT tokens use RS256 signature algorithm for cryptographic verification
- Token lifetime is limited to 1 hour to minimize exposure window
- Unique JWT ID (jti) claims prevent token replay attacks
- Audience claims provide additional token scoping and validation

### 8.3. Transport Security

- Production deployments MUST use HTTPS transport encryption
- All metadata and key distribution endpoints SHOULD be served over TLS
- Client authentication tokens MUST be transmitted securely

### 8.4. Input Validation

- All JSON inputs are validated against defined schemas
- Content-Type validation ensures proper request formatting
- Empty request bodies are handled gracefully with default values

## 9. Deployment and Configuration

### 9.1. Environment Variables

The service supports the following configuration parameters:

- `PUBLIC_URL`: The publicly accessible URL of the service (REQUIRED for production)
- `RUST_LOG`: Logging verbosity level (default: "info")
- `JWT_AUDIENCE`: Base audience claim(s) for issued tokens (OPTIONAL)
  - Single audience: `JWT_AUDIENCE=api.example.com`
  - Multiple audiences: `JWT_AUDIENCE=api1.example.com,api2.example.com`

### 9.2. Container Deployment

```bash
docker run -p 3002:3000 \
  -e PUBLIC_URL=https://oauth-client.example.com \
  -e JWT_AUDIENCE=api.example.com \
  -e RUST_LOG=info \
  ghcr.io/seriousben/oauth-client-id-metadata-example:latest
```

### 9.3. Docker Compose Configuration

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

## 10. Examples

### 10.1. Client Metadata Discovery

```bash
# Authorization server discovers client capabilities
curl https://oauth-client.example.com/oauth-client

# Authorization server retrieves client public keys  
curl https://oauth-client.example.com/jwks
```

### 10.2. Client ID Metadata Authentication

```bash
# Client requests access token using service identity
curl -X POST https://oauth-client.example.com/token \
  -H "Content-Type: application/json" \
  -d '{"scope": "read write"}'
```

### 10.3. private_key_jwt Authentication

```bash
# Generate JWT with custom client identity
curl -X POST https://oauth-client.example.com/jwt \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-service-prod",
    "scope": "api:read api:write",
    "aud": "https://api.example.com"
  }'
```

### 10.4. Audience Configuration

```bash
# Token with base audiences (from JWT_AUDIENCE environment variable)
curl -X POST https://oauth-client.example.com/token

# Token with additional audience appended to base audiences
curl -X POST https://oauth-client.example.com/jwt \
  -H "Content-Type: application/json" \
  -d '{"aud": "https://extra-service.example.com"}'
```

### 10.5. JWT Token Verification

```bash
# Retrieve and decode access token
TOKEN=$(curl -s -X POST https://oauth-client.example.com/token | jq -r .access_token)

# Decode JWT header
echo $TOKEN | cut -d'.' -f1 | base64 -d | jq .

# Decode JWT payload  
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .
```

## 11. References

- **RFC 6749**: The OAuth 2.0 Authorization Framework
- **RFC 7519**: JSON Web Token (JWT)
- **RFC 7517**: JSON Web Key (JWK)
- **RFC 7523**: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants
- **RFC 7591**: OAuth 2.0 Dynamic Client Registration Protocol
- **OAuth Client ID Metadata Document**: [Draft Specification by Aaron Parecki](https://drafts.aaronpk.com/draft-parecki-oauth-client-id-metadata-document/)

---

**Implementation Version**: 0.1.0  
**License**: Apache-2.0  
**Repository**: https://github.com/seriousben/oauth-client-id-metadata-example