#!/bin/bash

# Release Test Script for OAuth 2.0 Client Credentials Service
# Performs comprehensive end-to-end testing against a running service
# Used for: release validation, CI/CD pipelines, integration testing
#
# Usage:
#   ./scripts/release-test.sh                                          # Test service on default URL
#   ./scripts/release-test.sh http://localhost:3003                    # Test service on custom URL
#   ./scripts/release-test.sh https://api.example.com                  # Test remote service
#
# Arguments:
#   $1 - Service URL (default: http://localhost:3002)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper function to decode JWT payload (handles base64url padding)
decode_jwt_payload() {
  local jwt_token="$1"
  local payload=$(echo "$jwt_token" | cut -d'.' -f2)

  # Add padding if needed for base64url
  local padding=$((4 - ${#payload} % 4))
  if [ $padding -lt 4 ]; then
    payload="${payload}$(printf '=%.0s' $(seq 1 $padding))"
  fi

  # Decode and suppress error messages
  echo "$payload" | base64 -d 2>/dev/null
}

echo -e "${BLUE}=== OAuth 2.0 Client Credentials Release Test ===${NC}"
echo ""

# Configuration
SERVICE_URL=${1:-"http://localhost:3002"}

# Extract host and port for display
if [[ $SERVICE_URL =~ ^https?://([^:/]+):?([0-9]*) ]]; then
  HOST=${BASH_REMATCH[1]}
  PORT=${BASH_REMATCH[2]:-$(if [[ $SERVICE_URL == https://* ]]; then echo 443; else echo 80; fi)}
else
  HOST="localhost"
  PORT="3002"
fi

echo "Configuration:"
echo "  Service URL: $SERVICE_URL"
echo "  Host: $HOST"
echo "  Port: $PORT"
echo ""

# Check if service is available
echo -e "${YELLOW}Checking service availability...${NC}"
if curl -f "$SERVICE_URL/health" > /dev/null 2>&1; then
  echo -e "${GREEN}✅ Service is running and accessible${NC}"
else
  echo -e "${RED}❌ Service is not available at $SERVICE_URL${NC}"
  echo "Please ensure the OAuth service is running before running this test."
  echo "You can start it with: docker compose up -d"
  exit 1
fi
echo ""

# Test endpoints
echo -e "${BLUE}=== Testing OAuth endpoints ===${NC}"
echo ""

# 1. Health check
echo -e "${YELLOW}1. Health check:${NC}"
if curl -f "$SERVICE_URL/health" > /dev/null 2>&1; then
  curl -s "$SERVICE_URL/health" | jq .
  echo -e "${GREEN}✅ Health check passed${NC}"
else
  echo -e "${RED}❌ Health check failed${NC}"
  exit 1
fi
echo ""

# 2. Default token  
echo -e "${YELLOW}2. Default token (uses client_id URL for iss/sub):${NC}"
DEFAULT_TOKEN=$(curl -s -X POST "$SERVICE_URL/client-id-document-token" | jq -r .access_token)
echo "Token payload:"
DEFAULT_PAYLOAD=$(decode_jwt_payload "$DEFAULT_TOKEN")
echo "$DEFAULT_PAYLOAD" | jq .
echo ""

# Verify default token claims
ISS=$(echo "$DEFAULT_PAYLOAD" | jq -r .iss)
SUB=$(echo "$DEFAULT_PAYLOAD" | jq -r .sub)
EXPECTED_CLIENT_ID="${SERVICE_URL}/oauth-client"
if [ "$ISS" = "$EXPECTED_CLIENT_ID" ] && [ "$SUB" = "$EXPECTED_CLIENT_ID" ]; then
  echo -e "${GREEN}✅ Default token correctly uses client_id URL${NC}"
else
  echo -e "${RED}❌ Default token iss/sub incorrect: iss=$ISS, sub=$SUB (expected: $EXPECTED_CLIENT_ID)${NC}"
  exit 1
fi
echo ""

# 3. Custom client_id JWT (private_key_jwt approach)
echo -e "${YELLOW}3. Custom client_id JWT (overrides iss/sub):${NC}"
CUSTOM_TOKEN=$(curl -s -X POST "$SERVICE_URL/private-key-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"test-client","scope":"test"}' | jq -r .access_token)
echo "Custom token payload:"
CUSTOM_PAYLOAD=$(decode_jwt_payload "$CUSTOM_TOKEN")
echo "$CUSTOM_PAYLOAD" | jq .
echo ""

# Verify custom token claims
CUSTOM_ISS=$(echo "$CUSTOM_PAYLOAD" | jq -r .iss)
CUSTOM_SUB=$(echo "$CUSTOM_PAYLOAD" | jq -r .sub)
if [ "$CUSTOM_ISS" = "test-client" ] && [ "$CUSTOM_SUB" = "test-client" ]; then
  echo -e "${GREEN}✅ Custom client_id correctly overrides iss/sub${NC}"
else
  echo -e "${RED}❌ Custom client_id iss/sub incorrect: iss=$CUSTOM_ISS, sub=$CUSTOM_SUB${NC}"
  exit 1
fi
echo ""

# 4. JWKS endpoint
echo -e "${YELLOW}4. JWKS endpoint (RSA public keys):${NC}"
if curl -f "$SERVICE_URL/jwks" > /dev/null 2>&1; then
  curl -s "$SERVICE_URL/jwks" | jq '.keys[0] | {kty, alg, kid}'
  echo -e "${GREEN}✅ JWKS endpoint working${NC}"
else
  echo -e "${RED}❌ JWKS endpoint failed${NC}"
  exit 1
fi
echo ""

# 5. OAuth client metadata
echo -e "${YELLOW}5. OAuth client metadata:${NC}"
if curl -f "$SERVICE_URL/oauth-client" > /dev/null 2>&1; then
  curl -s "$SERVICE_URL/oauth-client" | jq '{client_id, token_endpoint_auth_signing_alg, jwks_uri}'
  echo -e "${GREEN}✅ OAuth metadata endpoint working${NC}"
else
  echo -e "${RED}❌ OAuth metadata endpoint failed${NC}"
  exit 1
fi
echo ""

echo -e "${BLUE}=== JWT Algorithm Verification ===${NC}"
# Verify JWT headers use RS256
DEFAULT_HEADER=$(echo $DEFAULT_TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null)
CUSTOM_HEADER=$(echo $CUSTOM_TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null)

DEFAULT_ALG=$(echo "$DEFAULT_HEADER" | jq -r .alg)
CUSTOM_ALG=$(echo "$CUSTOM_HEADER" | jq -r .alg)

if [ "$DEFAULT_ALG" = "RS256" ] && [ "$CUSTOM_ALG" = "RS256" ]; then
  echo -e "${GREEN}✅ Both tokens use RS256 algorithm${NC}"
else
  echo -e "${RED}❌ Token algorithm verification failed: default=$DEFAULT_ALG, custom=$CUSTOM_ALG${NC}"
  exit 1
fi
echo ""


echo -e "${GREEN}🎉 All tests passed! OAuth 2.0 Client Credentials service is working correctly.${NC}"
echo ""
echo -e "${BLUE}Summary:${NC}"
echo "✅ Service is running and accessible"
echo "✅ Health check endpoint working"
echo "✅ Default token uses client_id URL for iss/sub"
echo "✅ Custom client_id JWT overrides iss/sub claims"
echo "✅ JWKS endpoint provides RSA public keys"
echo "✅ OAuth metadata endpoint working"
echo "✅ All JWTs use RS256 algorithm"
