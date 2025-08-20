use crate::{KeyManager, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::{pkcs1::EncodeRsaPrivateKey, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("JWT encoding failed: {0}")]
    Encoding(#[from] jsonwebtoken::errors::Error),
    #[error("Key conversion failed: {0}")]
    KeyConversion(String),
}

/// Standard JWT Claims as defined in RFC 7519
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JwtClaims {
    /// Issuer (iss)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Subject (sub)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Audience (aud) - can be a single string or array of strings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<serde_json::Value>,

    /// Expiration Time (exp) - Unix timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Not Before (nbf) - Unix timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Issued At (iat) - Unix timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// JWT ID (jti)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// OAuth Token Response as defined in RFC 6749
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Access token
    pub access_token: String,

    /// Token type - typically "Bearer"
    pub token_type: String,

    /// Expiration time in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,

    /// Scope of the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// JWT Token Issuer for RS256 tokens
pub struct JwtIssuer {
    key_manager: KeyManager,
    issuer: String,
    audience: Option<serde_json::Value>,
}

impl JwtIssuer {
    /// Create audience value from a single string
    pub fn audience_from_string(aud: &str) -> serde_json::Value {
        serde_json::Value::String(aud.to_string())
    }

    /// Create audience value from multiple strings
    pub fn audience_from_strings(audiences: &[&str]) -> serde_json::Value {
        let aud_array: Vec<serde_json::Value> = audiences
            .iter()
            .map(|s| serde_json::Value::String(s.to_string()))
            .collect();
        serde_json::Value::Array(aud_array)
    }

    /// Merge base audience with additional audiences
    /// Returns None if both are None, otherwise combines them into appropriate format
    pub fn merge_audiences(
        base: Option<&serde_json::Value>,
        additional: Option<&serde_json::Value>,
    ) -> Option<serde_json::Value> {
        match (base, additional) {
            (None, None) => None,
            (Some(base), None) => Some(base.clone()),
            (None, Some(additional)) => Some(additional.clone()),
            (Some(base), Some(additional)) => {
                let mut audiences = Vec::new();

                // Add base audiences
                match base {
                    serde_json::Value::String(s) => audiences.push(s.clone()),
                    serde_json::Value::Array(arr) => {
                        for val in arr {
                            if let serde_json::Value::String(s) = val {
                                audiences.push(s.clone());
                            }
                        }
                    }
                    _ => {} // Ignore other types
                }

                // Add additional audiences
                match additional {
                    serde_json::Value::String(s) => audiences.push(s.clone()),
                    serde_json::Value::Array(arr) => {
                        for val in arr {
                            if let serde_json::Value::String(s) = val {
                                audiences.push(s.clone());
                            }
                        }
                    }
                    _ => {} // Ignore other types
                }

                // Return appropriate format based on count
                match audiences.len() {
                    0 => None,
                    1 => Some(serde_json::Value::String(
                        audiences.into_iter().next().unwrap(),
                    )),
                    _ => Some(serde_json::Value::Array(
                        audiences
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    )),
                }
            }
        }
    }
    /// Create a new JWT issuer
    pub fn new(key_manager: KeyManager, issuer: String) -> Self {
        Self::new_with_audience(key_manager, issuer, None)
    }

    /// Create a new JWT issuer with configurable audience
    pub fn new_with_audience(
        key_manager: KeyManager,
        issuer: String,
        audience: Option<serde_json::Value>,
    ) -> Self {
        Self {
            key_manager,
            issuer,
            audience,
        }
    }

    /// Issue a JWT token with the given claims
    pub fn issue_token(&self, mut claims: JwtClaims) -> Result<String> {
        // Set standard claims if not provided
        let now = Utc::now();
        if claims.iss.is_none() {
            claims.iss = Some(self.issuer.clone());
        }
        if claims.iat.is_none() {
            claims.iat = Some(now.timestamp());
        }
        if claims.exp.is_none() {
            // Default to 1 hour expiration
            claims.exp = Some((now + Duration::hours(1)).timestamp());
        }
        // Note: aud is now set by the caller, so we don't override it here anymore

        // Create JWT header
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_manager.key_id().to_string());

        // Convert private key to EncodingKey
        let encoding_key = self
            .private_key_to_encoding_key(self.key_manager.private_key())
            .map_err(|e| crate::KeyError::Serialization(e.to_string()))?;

        // Encode the token
        let token = encode(&header, &claims, &encoding_key)
            .map_err(|e| crate::KeyError::Serialization(format!("JWT encoding failed: {}", e)))?;

        Ok(token)
    }

    /// Create a client credentials token response
    pub fn create_client_credentials_response(
        &self,
        scope: Option<String>,
    ) -> Result<TokenResponse> {
        self.create_client_credentials_response_with_client_id(scope, None)
    }

    /// Create a client credentials token response with optional custom client_id
    pub fn create_client_credentials_response_with_client_id(
        &self,
        scope: Option<String>,
        client_id: Option<String>,
    ) -> Result<TokenResponse> {
        self.create_client_credentials_response_with_audience(scope, client_id, None)
    }

    /// Create a client credentials token response with optional custom client_id and additional audience
    pub fn create_client_credentials_response_with_audience(
        &self,
        scope: Option<String>,
        client_id: Option<String>,
        additional_audience: Option<serde_json::Value>,
    ) -> Result<TokenResponse> {
        // Merge configured audience with additional audience from request
        let merged_audience =
            Self::merge_audiences(self.audience.as_ref(), additional_audience.as_ref());

        let mut claims = JwtClaims {
            iss: None,                      // Will be set by issue_token or overridden below
            sub: Some(self.issuer.clone()), // Use public URL as subject by default
            aud: merged_audience,           // Use merged audience
            exp: None,                      // Will be set by issue_token
            nbf: None,
            iat: None, // Will be set by issue_token
            jti: Some(uuid::Uuid::new_v4().to_string()),
            custom: HashMap::new(),
        };

        // If custom client_id is provided, use it to override issuer and subject
        if let Some(ref client_id_value) = client_id {
            claims.iss = Some(client_id_value.clone());
            claims.sub = Some(client_id_value.clone());
        }

        // Add scope as custom claim if provided
        if let Some(ref scope_value) = scope {
            claims.custom.insert(
                "scope".to_string(),
                serde_json::Value::String(scope_value.clone()),
            );
        }

        let access_token = self.issue_token(claims)?;

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: Some(3600), // 1 hour
            scope,
        })
    }

    /// Convert RSA PrivateKey to jsonwebtoken EncodingKey
    fn private_key_to_encoding_key(
        &self,
        private_key: &RsaPrivateKey,
    ) -> std::result::Result<EncodingKey, Box<dyn std::error::Error>> {
        // Use PKCS#1 PEM format for RSA keys with jsonwebtoken
        let pem_data = private_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;
        Ok(EncodingKey::from_rsa_pem(pem_data.as_bytes())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_issue_basic() {
        let key_manager = KeyManager::new().unwrap();
        let issuer = JwtIssuer::new(key_manager.clone(), "test-issuer".to_string());

        let claims = JwtClaims {
            sub: Some("test-subject".to_string()),
            ..Default::default()
        };

        let token = issuer.issue_token(claims).unwrap();

        // Just check that we can generate a token for now
        assert!(!token.is_empty());
        assert!(token.contains('.'));

        // Check that the token has the right structure (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_client_credentials_response() {
        let key_manager = KeyManager::new().unwrap();
        let issuer = JwtIssuer::new(key_manager, "test-issuer".to_string());

        let response = issuer
            .create_client_credentials_response(Some("read write".to_string()))
            .unwrap();

        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, Some(3600));
        assert_eq!(response.scope, Some("read write".to_string()));
        assert!(!response.access_token.is_empty());
    }

    #[test]
    fn test_client_credentials_response_with_custom_client_id() {
        let key_manager = KeyManager::new().unwrap();
        let issuer = JwtIssuer::new(key_manager, "test-issuer".to_string());

        let response = issuer
            .create_client_credentials_response_with_client_id(
                Some("custom-scope".to_string()),
                Some("custom-client-id".to_string()),
            )
            .unwrap();

        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, Some(3600));
        assert_eq!(response.scope, Some("custom-scope".to_string()));
        assert!(!response.access_token.is_empty());

        // TODO: In a real implementation, we would decode the JWT to verify
        // the custom client_id is used as iss and sub claims
    }

    #[test]
    fn test_jwt_with_single_audience() {
        let key_manager = KeyManager::new().unwrap();
        let audience = Some(JwtIssuer::audience_from_string("api.example.com"));
        let issuer =
            JwtIssuer::new_with_audience(key_manager.clone(), "test-issuer".to_string(), audience);

        let claims = JwtClaims {
            sub: Some("test-subject".to_string()),
            ..Default::default()
        };

        let token = issuer.issue_token(claims).unwrap();

        // Just check that we can generate a token
        assert!(!token.is_empty());
        assert!(token.contains('.'));

        // Check that the token has the right structure (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_jwt_with_multiple_audiences() {
        let key_manager = KeyManager::new().unwrap();
        let audience = Some(JwtIssuer::audience_from_strings(&[
            "api1.example.com",
            "api2.example.com",
        ]));
        let issuer =
            JwtIssuer::new_with_audience(key_manager.clone(), "test-issuer".to_string(), audience);

        let response = issuer
            .create_client_credentials_response(Some("read write".to_string()))
            .unwrap();

        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, Some(3600));
        assert_eq!(response.scope, Some("read write".to_string()));
        assert!(!response.access_token.is_empty());
    }

    #[test]
    fn test_audience_helper_functions() {
        // Test single audience
        let single = JwtIssuer::audience_from_string("test.example.com");
        assert_eq!(
            single,
            serde_json::Value::String("test.example.com".to_string())
        );

        // Test multiple audiences
        let multiple = JwtIssuer::audience_from_strings(&["api1.com", "api2.com", "api3.com"]);
        let expected_array = vec![
            serde_json::Value::String("api1.com".to_string()),
            serde_json::Value::String("api2.com".to_string()),
            serde_json::Value::String("api3.com".to_string()),
        ];
        assert_eq!(multiple, serde_json::Value::Array(expected_array));
    }

    #[test]
    fn test_merge_audiences() {
        // Test None + None = None
        let result = JwtIssuer::merge_audiences(None, None);
        assert_eq!(result, None);

        // Test Some + None = Some
        let base = JwtIssuer::audience_from_string("base.com");
        let result = JwtIssuer::merge_audiences(Some(&base), None);
        assert_eq!(result, Some(base.clone()));

        // Test None + Some = Some
        let additional = JwtIssuer::audience_from_string("additional.com");
        let result = JwtIssuer::merge_audiences(None, Some(&additional));
        assert_eq!(result, Some(additional.clone()));

        // Test single + single = array
        let base = JwtIssuer::audience_from_string("base.com");
        let additional = JwtIssuer::audience_from_string("additional.com");
        let result = JwtIssuer::merge_audiences(Some(&base), Some(&additional));
        let expected = JwtIssuer::audience_from_strings(&["base.com", "additional.com"]);
        assert_eq!(result, Some(expected));

        // Test array + single = array
        let base = JwtIssuer::audience_from_strings(&["base1.com", "base2.com"]);
        let additional = JwtIssuer::audience_from_string("additional.com");
        let result = JwtIssuer::merge_audiences(Some(&base), Some(&additional));
        let expected =
            JwtIssuer::audience_from_strings(&["base1.com", "base2.com", "additional.com"]);
        assert_eq!(result, Some(expected));

        // Test single + array = array
        let base = JwtIssuer::audience_from_string("base.com");
        let additional = JwtIssuer::audience_from_strings(&["add1.com", "add2.com"]);
        let result = JwtIssuer::merge_audiences(Some(&base), Some(&additional));
        let expected = JwtIssuer::audience_from_strings(&["base.com", "add1.com", "add2.com"]);
        assert_eq!(result, Some(expected));

        // Test array + array = array
        let base = JwtIssuer::audience_from_strings(&["base1.com", "base2.com"]);
        let additional = JwtIssuer::audience_from_strings(&["add1.com", "add2.com"]);
        let result = JwtIssuer::merge_audiences(Some(&base), Some(&additional));
        let expected =
            JwtIssuer::audience_from_strings(&["base1.com", "base2.com", "add1.com", "add2.com"]);
        assert_eq!(result, Some(expected));
    }

    #[test]
    fn test_client_credentials_response_with_additional_audience() {
        let key_manager = KeyManager::new().unwrap();
        let base_audience = Some(JwtIssuer::audience_from_string("api.example.com"));
        let issuer = JwtIssuer::new_with_audience(
            key_manager.clone(),
            "test-issuer".to_string(),
            base_audience,
        );

        // Test adding additional audience to configured base audience
        let additional = Some(JwtIssuer::audience_from_string("extra.example.com"));
        let response = issuer
            .create_client_credentials_response_with_audience(
                Some("read write".to_string()),
                None,
                additional,
            )
            .unwrap();

        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, Some(3600));
        assert_eq!(response.scope, Some("read write".to_string()));
        assert!(!response.access_token.is_empty());
    }
}
