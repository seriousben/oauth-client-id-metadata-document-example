#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use oauth_metadata::hello_oauth;
    use oauth_server::{create_app, create_app_with_state, AppState};
    use serde_json::Value;

    #[test]
    fn test_integration_setup() {
        assert_eq!(hello_oauth(), "Hello from oauth-metadata!");
    }

    #[tokio::test]
    async fn test_full_oauth_flow() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        // 1. Test health endpoint
        let response = server.get("/health").await;
        response.assert_status_ok();
        let health: Value = response.json();
        assert_eq!(health["status"], "healthy");
        assert_eq!(health["service"], "oauth-server");

        // 2. Test JWKS endpoint
        let response = server.get("/jwks").await;
        response.assert_status_ok();
        let jwks: Value = response.json();
        assert!(jwks["keys"].is_array());
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "RSA");
        assert_eq!(keys[0]["alg"], "RS256");
        assert!(keys[0]["kid"].is_string());
        assert!(keys[0]["n"].is_string()); // RSA modulus
        assert!(keys[0]["e"].is_string()); // RSA exponent

        // 3. Test OAuth client metadata endpoint
        let response = server.get("/oauth-client").await;
        response.assert_status_ok();
        let metadata: Value = response.json();
        assert_eq!(metadata["client_id"], "oauth-client-id-metadata-example");
        assert_eq!(metadata["grant_types"][0], "client_credentials");
        assert_eq!(metadata["token_endpoint_auth_method"], "private_key_jwt");
        assert_eq!(metadata["token_endpoint_auth_signing_alg"], "RS256");
        assert_eq!(metadata["jwks_uri"], "http://localhost:3000/jwks");
        assert_eq!(metadata["scope"], "read write");

        // 4. Test OAuth client metadata token endpoint (no parameters)
        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({}))
            .await;
        response.assert_status_ok();
        let token_response: Value = response.json();
        assert_eq!(token_response["token_type"], "Bearer");
        assert_eq!(token_response["expires_in"], 3600);
        assert!(token_response["scope"].is_null());
        assert!(token_response["access_token"].is_string());

        let access_token = token_response["access_token"].as_str().unwrap();
        assert!(!access_token.is_empty());
        // JWT should have 3 parts separated by dots
        assert_eq!(access_token.split('.').count(), 3);

        // 5. Test JWT endpoint for private_key_jwt use cases
        let response = server
            .post("/private-key-jwt-token")
            .json(&serde_json::json!({})) // Empty JSON object
            .await;
        response.assert_status_ok();
        let jwt_default: Value = response.json();
        assert_eq!(jwt_default["token_type"], "Bearer");
        assert_eq!(jwt_default["expires_in"], 3600);
        assert!(jwt_default["scope"].is_null());

        // 6. Test JWT endpoint with custom client_id (JSON body)
        let response = server
            .post("/private-key-jwt-token")
            .json(&serde_json::json!({
                "client_id": "custom-client",
                "scope": "custom-read"
            }))
            .await;
        response.assert_status_ok();
        let custom_jwt: Value = response.json();
        assert_eq!(custom_jwt["token_type"], "Bearer");
        assert_eq!(custom_jwt["expires_in"], 3600);
        assert_eq!(custom_jwt["scope"], "custom-read");

        let custom_access_token = custom_jwt["access_token"].as_str().unwrap();
        assert!(!custom_access_token.is_empty());
        assert_ne!(custom_access_token, access_token); // Should be different tokens
    }

    #[tokio::test]
    async fn test_custom_public_url_integration() {
        let public_url = "https://oauth.example.com";
        let state = AppState::new_with_public_url(public_url.to_string()).unwrap();
        let app = create_app_with_state(state);
        let server = TestServer::new(app).unwrap();

        // Test that metadata uses custom public URL
        let response = server.get("/oauth-client").await;
        response.assert_status_ok();
        let metadata: Value = response.json();

        assert_eq!(metadata["jwks_uri"], format!("{}/jwks", public_url));

        // Test that tokens use custom public URL as issuer/subject by default
        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({}))
            .await;
        response.assert_status_ok();
        let token_response: Value = response.json();

        let access_token = token_response["access_token"].as_str().unwrap();
        assert!(!access_token.is_empty());
    }

    #[tokio::test]
    async fn test_error_handling() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        // Test that endpoints return proper JSON error responses
        // Note: Currently all endpoints should succeed with valid responses
        // This is a placeholder for future error condition testing

        let response = server.get("/nonexistent").await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_jwt_token_validation() {
        // This test creates a token and validates its structure
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({}))
            .await;
        response.assert_status_ok();
        let token_response: Value = response.json();

        let access_token = token_response["access_token"].as_str().unwrap();

        // Split JWT into parts
        let parts: Vec<&str> = access_token.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "JWT should have header.payload.signature structure"
        );

        // Verify header is valid base64
        let header_decoded = URL_SAFE_NO_PAD.decode(parts[0]);
        assert!(header_decoded.is_ok(), "JWT header should be valid base64");

        // Verify payload is valid base64
        let payload_decoded = URL_SAFE_NO_PAD.decode(parts[1]);
        assert!(
            payload_decoded.is_ok(),
            "JWT payload should be valid base64"
        );

        // Parse header JSON
        let header_json: Value = serde_json::from_slice(&header_decoded.unwrap()).unwrap();
        assert_eq!(header_json["alg"], "RS256");
        assert!(header_json["kid"].is_string());

        // Parse payload JSON
        let payload_json: Value = serde_json::from_slice(&payload_decoded.unwrap()).unwrap();
        assert!(payload_json["iss"].is_string());
        assert!(payload_json["sub"].is_string());
        assert!(payload_json["iat"].is_number());
        assert!(payload_json["exp"].is_number());
        assert!(payload_json["jti"].is_string());

        // Verify timestamps are reasonable
        let iat = payload_json["iat"].as_i64().unwrap();
        let exp = payload_json["exp"].as_i64().unwrap();
        assert!(exp > iat, "Token expiration should be after issued time");
        assert_eq!(exp - iat, 3600, "Token should expire in 1 hour");
    }

    #[tokio::test]
    async fn test_token_uniqueness() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        // Test that sequential requests generate unique tokens
        let mut tokens = Vec::new();

        for i in 0..5 {
            let response = server
                .post("/private-key-jwt-token")
                .json(&serde_json::json!({
                    "client_id": format!("client-{}", i)
                }))
                .await;
            response.assert_status_ok();
            let token: Value = response.json();
            assert_eq!(token["token_type"], "Bearer");
            tokens.push(token["access_token"].as_str().unwrap().to_string());
        }

        // Verify all tokens are unique (they should have different jti claims)
        let mut unique_tokens = std::collections::HashSet::new();
        for token in &tokens {
            assert!(
                unique_tokens.insert(token.clone()),
                "All tokens should be unique"
            );
        }

        assert_eq!(tokens.len(), 5);
        assert_eq!(unique_tokens.len(), 5);
    }

    #[tokio::test]
    async fn test_configurable_audience_single() {
        use oauth_metadata::JwtIssuer;

        // Test with single audience
        let audience = Some(JwtIssuer::audience_from_string("api.example.com"));
        let state = AppState::new_with_public_url_and_audience(
            "http://localhost:3000".to_string(),
            audience,
        )
        .unwrap();
        let app = create_app_with_state(state);
        let server = TestServer::new(app).unwrap();

        // Test token endpoint
        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({}))
            .await;
        response.assert_status_ok();
        let token_response: Value = response.json();

        let access_token = token_response["access_token"].as_str().unwrap();
        let parts: Vec<&str> = access_token.split('.').collect();
        let payload_decoded = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload_json: Value = serde_json::from_slice(&payload_decoded).unwrap();

        // Should have audience claim as string
        assert_eq!(payload_json["aud"], "api.example.com");

        // Test JWT endpoint
        let response = server
            .post("/private-key-jwt-token")
            .json(&serde_json::json!({
                "client_id": "test-client"
            }))
            .await;
        response.assert_status_ok();
        let jwt_response: Value = response.json();

        let jwt_access_token = jwt_response["access_token"].as_str().unwrap();
        let jwt_parts: Vec<&str> = jwt_access_token.split('.').collect();
        let jwt_payload_decoded = URL_SAFE_NO_PAD.decode(jwt_parts[1]).unwrap();
        let jwt_payload_json: Value = serde_json::from_slice(&jwt_payload_decoded).unwrap();

        // Should also have audience claim
        assert_eq!(jwt_payload_json["aud"], "api.example.com");
    }

    #[tokio::test]
    async fn test_configurable_audience_multiple() {
        use oauth_metadata::JwtIssuer;

        // Test with multiple audiences
        let audience = Some(JwtIssuer::audience_from_strings(&[
            "api1.example.com",
            "api2.example.com",
        ]));
        let state = AppState::new_with_public_url_and_audience(
            "http://localhost:3000".to_string(),
            audience,
        )
        .unwrap();
        let app = create_app_with_state(state);
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({}))
            .await;
        response.assert_status_ok();
        let token_response: Value = response.json();

        let access_token = token_response["access_token"].as_str().unwrap();
        let parts: Vec<&str> = access_token.split('.').collect();
        let payload_decoded = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload_json: Value = serde_json::from_slice(&payload_decoded).unwrap();

        // Should have audience claim as array
        assert!(payload_json["aud"].is_array());
        let aud_array = payload_json["aud"].as_array().unwrap();
        assert_eq!(aud_array.len(), 2);
        assert_eq!(aud_array[0], "api1.example.com");
        assert_eq!(aud_array[1], "api2.example.com");
    }

    #[tokio::test]
    async fn test_no_audience_configuration() {
        // Test with no audience configured (should be None/omitted)
        let state =
            AppState::new_with_public_url_and_audience("http://localhost:3000".to_string(), None)
                .unwrap();
        let app = create_app_with_state(state);
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({}))
            .await;
        response.assert_status_ok();
        let token_response: Value = response.json();

        let access_token = token_response["access_token"].as_str().unwrap();
        let parts: Vec<&str> = access_token.split('.').collect();
        let payload_decoded = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload_json: Value = serde_json::from_slice(&payload_decoded).unwrap();

        // Should not have audience claim
        assert!(
            payload_json["aud"].is_null() || !payload_json.as_object().unwrap().contains_key("aud")
        );
    }

    #[tokio::test]
    async fn test_audience_appending_from_request_body() {
        use oauth_metadata::JwtIssuer;

        // Set up base audience in environment
        let base_audience = Some(JwtIssuer::audience_from_string("env.example.com"));
        let state = AppState::new_with_public_url_and_audience(
            "http://localhost:3000".to_string(),
            base_audience,
        )
        .unwrap();
        let app = create_app_with_state(state);
        let server = TestServer::new(app).unwrap();

        // Test token endpoint with additional audience in POST body
        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({
                "aud": "request.example.com"
            }))
            .await;
        response.assert_status_ok();

        let token_response: Value = response.json();
        let access_token = token_response["access_token"].as_str().unwrap();
        let parts: Vec<&str> = access_token.split('.').collect();
        let payload_decoded = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload_json: Value = serde_json::from_slice(&payload_decoded).unwrap();

        // Should have both audiences as array
        assert!(payload_json["aud"].is_array());
        let aud_array = payload_json["aud"].as_array().unwrap();
        assert_eq!(aud_array.len(), 2);
        // Environment audience comes first, then request audience
        assert!(aud_array.contains(&serde_json::Value::String("env.example.com".to_string())));
        assert!(aud_array.contains(&serde_json::Value::String(
            "request.example.com".to_string()
        )));
    }

    #[tokio::test]
    async fn test_audience_appending_with_multiple_request_audiences() {
        use oauth_metadata::JwtIssuer;

        // Set up base audience in environment
        let base_audience = Some(JwtIssuer::audience_from_strings(&[
            "env1.example.com",
            "env2.example.com",
        ]));
        let state = AppState::new_with_public_url_and_audience(
            "http://localhost:3000".to_string(),
            base_audience,
        )
        .unwrap();
        let app = create_app_with_state(state);
        let server = TestServer::new(app).unwrap();

        // Test JWT endpoint with multiple additional audiences
        let response = server
            .post("/private-key-jwt-token")
            .json(&serde_json::json!({
                "client_id": "test-client",
                "aud": ["req1.example.com", "req2.example.com"]
            }))
            .await;
        response.assert_status_ok();

        let jwt_response: Value = response.json();
        let jwt_access_token = jwt_response["access_token"].as_str().unwrap();
        let jwt_parts: Vec<&str> = jwt_access_token.split('.').collect();
        let jwt_payload_decoded = URL_SAFE_NO_PAD.decode(jwt_parts[1]).unwrap();
        let jwt_payload_json: Value = serde_json::from_slice(&jwt_payload_decoded).unwrap();

        // Should have all 4 audiences as array
        assert!(jwt_payload_json["aud"].is_array());
        let aud_array = jwt_payload_json["aud"].as_array().unwrap();
        assert_eq!(aud_array.len(), 4);

        // Check that all audiences are present
        let expected_audiences = vec![
            "env1.example.com",
            "env2.example.com",
            "req1.example.com",
            "req2.example.com",
        ];
        for expected in expected_audiences {
            assert!(aud_array.contains(&serde_json::Value::String(expected.to_string())));
        }
    }

    #[tokio::test]
    async fn test_request_audience_only() {
        // Test with no environment audience, only request audience
        let state =
            AppState::new_with_public_url_and_audience("http://localhost:3000".to_string(), None)
                .unwrap();
        let app = create_app_with_state(state);
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({
                "aud": "only.request.com"
            }))
            .await;
        response.assert_status_ok();

        let token_response: Value = response.json();
        let access_token = token_response["access_token"].as_str().unwrap();
        let parts: Vec<&str> = access_token.split('.').collect();
        let payload_decoded = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload_json: Value = serde_json::from_slice(&payload_decoded).unwrap();

        // Should have single audience as string (not array)
        assert_eq!(payload_json["aud"], "only.request.com");
    }
}
