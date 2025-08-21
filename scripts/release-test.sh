#!/bin/bash

# Release Test Script for OAuth 2.0 Client Credentials Service
# Performs comprehensive end-to-end testing of the built service
# Used for: release validation, CI/CD pipelines, publish verification
#
# Usage:
#   ./scripts/release-test.sh                                          # Build and test locally
#   ./scripts/release-test.sh oauth-test:v1.0                          # Test specific local image
#   ./scripts/release-test.sh ghcr.io/owner/repo:latest                # Test published image
#   ./scripts/release-test.sh oauth-test:local 3003                    # Use custom port
#
# Arguments:
#   $1 - Docker image tag (default: oauth-test:local)
#   $2 - Test port (default: 3002)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== OAuth 2.0 Client Credentials Release Test ===${NC}"
echo ""

# Configuration
IMAGE_TAG=${1:-"oauth-test:local"}
CONTAINER_NAME="oauth-release-test"
TEST_PORT=${2:-"3002"}
PUBLIC_URL="http://localhost:${TEST_PORT}"

echo "Configuration:"
echo "  Image: $IMAGE_TAG"
echo "  Container: $CONTAINER_NAME"  
echo "  Port: $TEST_PORT"
echo "  Public URL: $PUBLIC_URL"
echo ""

# Build the image if using default tag
if [ "$IMAGE_TAG" = "oauth-test:local" ]; then
  echo -e "${YELLOW}Building Docker image...${NC}"
  docker build -t oauth-test:local .
  echo -e "${GREEN}✅ Docker build successful${NC}"
else
  echo -e "${YELLOW}Using existing image: $IMAGE_TAG${NC}"
fi
echo ""

# Start the container
echo -e "${YELLOW}Starting Docker container...${NC}"
docker run -d --name $CONTAINER_NAME -p ${TEST_PORT}:3000 \
  -e PUBLIC_URL=$PUBLIC_URL \
  -e RUST_LOG=info \
  $IMAGE_TAG

# Wait for container to start
echo "Waiting for container to start..."
sleep 5

# Check if container is running
if ! docker ps | grep -q $CONTAINER_NAME; then
  echo -e "${RED}❌ Container failed to start${NC}"
  docker logs $CONTAINER_NAME
  exit 1
fi

echo -e "${GREEN}✅ Container started successfully${NC}"
echo ""

# Test endpoints
echo -e "${BLUE}=== Testing OAuth endpoints ===${NC}"
echo ""

# 1. Health check
echo -e "${YELLOW}1. Health check:${NC}"
if curl -f http://localhost:${TEST_PORT}/health > /dev/null 2>&1; then
  curl -s http://localhost:${TEST_PORT}/health | jq .
  echo -e "${GREEN}✅ Health check passed${NC}"
else
  echo -e "${RED}❌ Health check failed${NC}"
  exit 1
fi
echo ""

# 2. Default token
echo -e "${YELLOW}2. Default token (uses PUBLIC_URL for iss/sub):${NC}"
DEFAULT_TOKEN=$(curl -s -X POST http://localhost:${TEST_PORT}/client-id-document-token | jq -r .access_token)
echo "Token payload:"
echo $DEFAULT_TOKEN | cut -d'.' -f2 | base64 -d | jq .
echo ""

# Verify default token claims
DEFAULT_PAYLOAD=$(echo $DEFAULT_TOKEN | cut -d'.' -f2 | base64 -d)
ISS=$(echo "$DEFAULT_PAYLOAD" | jq -r .iss)
SUB=$(echo "$DEFAULT_PAYLOAD" | jq -r .sub)
if [ "$ISS" = "http://localhost:${TEST_PORT}" ] && [ "$SUB" = "http://localhost:${TEST_PORT}" ]; then
  echo -e "${GREEN}✅ Default token correctly uses PUBLIC_URL${NC}"
else
  echo -e "${RED}❌ Default token iss/sub incorrect: iss=$ISS, sub=$SUB${NC}"
  exit 1
fi
echo ""

# 3. Custom client_id JWT (private_key_jwt approach)
echo -e "${YELLOW}3. Custom client_id JWT (overrides iss/sub):${NC}"
CUSTOM_TOKEN=$(curl -s -X POST "http://localhost:${TEST_PORT}/private-key-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"test-client","scope":"test"}' | jq -r .access_token)
echo "Custom token payload:"
echo $CUSTOM_TOKEN | cut -d'.' -f2 | base64 -d | jq .
echo ""

# Verify custom token claims
CUSTOM_PAYLOAD=$(echo $CUSTOM_TOKEN | cut -d'.' -f2 | base64 -d)
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
if curl -f http://localhost:${TEST_PORT}/jwks > /dev/null 2>&1; then
  curl -s http://localhost:${TEST_PORT}/jwks | jq '.keys[0] | {kty, alg, kid}'
  echo -e "${GREEN}✅ JWKS endpoint working${NC}"
else
  echo -e "${RED}❌ JWKS endpoint failed${NC}"
  exit 1
fi
echo ""

# 5. OAuth client metadata
echo -e "${YELLOW}5. OAuth client metadata:${NC}"
if curl -f http://localhost:${TEST_PORT}/oauth-client > /dev/null 2>&1; then
  curl -s http://localhost:${TEST_PORT}/oauth-client | jq '{client_id, token_endpoint_auth_signing_alg, jwks_uri}'
  echo -e "${GREEN}✅ OAuth metadata endpoint working${NC}"
else
  echo -e "${RED}❌ OAuth metadata endpoint failed${NC}"
  exit 1
fi
echo ""

echo -e "${BLUE}=== JWT Algorithm Verification ===${NC}"
# Verify JWT headers use RS256
DEFAULT_HEADER=$(echo $DEFAULT_TOKEN | cut -d'.' -f1 | base64 -d)
CUSTOM_HEADER=$(echo $CUSTOM_TOKEN | cut -d'.' -f1 | base64 -d)

DEFAULT_ALG=$(echo "$DEFAULT_HEADER" | jq -r .alg)
CUSTOM_ALG=$(echo "$CUSTOM_HEADER" | jq -r .alg)

if [ "$DEFAULT_ALG" = "RS256" ] && [ "$CUSTOM_ALG" = "RS256" ]; then
  echo -e "${GREEN}✅ Both tokens use RS256 algorithm${NC}"
else
  echo -e "${RED}❌ Token algorithm verification failed: default=$DEFAULT_ALG, custom=$CUSTOM_ALG${NC}"
  exit 1
fi
echo ""

# Show container logs
echo -e "${BLUE}=== Container Logs (last 20 lines) ===${NC}"
docker logs $CONTAINER_NAME --tail 20
echo ""

# Cleanup
echo -e "${YELLOW}Cleaning up...${NC}"
docker stop $CONTAINER_NAME > /dev/null
docker rm $CONTAINER_NAME > /dev/null

# Only remove image if we built it locally
if [ "$IMAGE_TAG" = "oauth-test:local" ]; then
  docker rmi oauth-test:local > /dev/null
fi

echo -e "${GREEN}🎉 All tests passed! OAuth 2.0 Client Credentials service is working correctly.${NC}"
echo ""
echo -e "${BLUE}Summary:${NC}"
echo "✅ Docker build successful"
echo "✅ Container starts and runs"
echo "✅ Health check endpoint working"
echo "✅ Default token uses PUBLIC_URL for iss/sub"
echo "✅ Custom client_id JWT overrides iss/sub claims"  
echo "✅ JWKS endpoint provides RSA public keys"
echo "✅ OAuth metadata endpoint working"
echo "✅ All JWTs use RS256 algorithm"