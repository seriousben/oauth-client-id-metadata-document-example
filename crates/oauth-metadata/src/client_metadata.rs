use serde::{Deserialize, Serialize};
use serde_json::Value;

/// OAuth 2.0 Client Metadata as defined in the draft specification
/// https://drafts.aaronpk.com/draft-parecki-oauth-client-id-metadata-document/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClientMetadata {
    /// Client identifier
    pub client_id: String,
    
    /// Human-readable client name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    
    /// Array of grant types the client can use
    pub grant_types: Vec<String>,
    
    /// Client authentication method for the token endpoint
    pub token_endpoint_auth_method: String,
    
    /// JWS signature algorithm for client authentication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
    
    /// URL of the client's JSON Web Key Set
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    
    /// Client's JSON Web Key Set by value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Value>,
    
    /// Scope values the client can request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    
    /// Array of response types the client can use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,
    
    /// Array of redirect URIs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
}

/// Builder for OAuth Client Metadata
pub struct ClientMetadataBuilder {
    metadata: OAuthClientMetadata,
}

impl ClientMetadataBuilder {
    /// Create a new client metadata builder with required fields
    pub fn new(client_id: String) -> Self {
        Self {
            metadata: OAuthClientMetadata {
                client_id,
                client_name: None,
                grant_types: vec!["client_credentials".to_string()],
                token_endpoint_auth_method: "private_key_jwt".to_string(),
                token_endpoint_auth_signing_alg: Some("RS256".to_string()),
                jwks_uri: None,
                jwks: None,
                scope: None,
                response_types: None,
                redirect_uris: None,
            },
        }
    }

    /// Set the client name
    pub fn client_name<S: Into<String>>(mut self, name: S) -> Self {
        self.metadata.client_name = Some(name.into());
        self
    }

    /// Set the grant types
    pub fn grant_types(mut self, grant_types: Vec<String>) -> Self {
        self.metadata.grant_types = grant_types;
        self
    }

    /// Set the token endpoint authentication method
    pub fn token_endpoint_auth_method<S: Into<String>>(mut self, method: S) -> Self {
        self.metadata.token_endpoint_auth_method = method.into();
        self
    }

    /// Set the token endpoint authentication signing algorithm
    pub fn token_endpoint_auth_signing_alg<S: Into<String>>(mut self, alg: S) -> Self {
        self.metadata.token_endpoint_auth_signing_alg = Some(alg.into());
        self
    }

    /// Set the JWKS URI
    pub fn jwks_uri<S: Into<String>>(mut self, uri: S) -> Self {
        self.metadata.jwks_uri = Some(uri.into());
        self
    }

    /// Set the JWKS by value
    pub fn jwks(mut self, jwks: Value) -> Self {
        self.metadata.jwks = Some(jwks);
        self
    }

    /// Set the scope
    pub fn scope<S: Into<String>>(mut self, scope: S) -> Self {
        self.metadata.scope = Some(scope.into());
        self
    }

    /// Set the response types
    pub fn response_types(mut self, response_types: Vec<String>) -> Self {
        self.metadata.response_types = Some(response_types);
        self
    }

    /// Set the redirect URIs
    pub fn redirect_uris(mut self, redirect_uris: Vec<String>) -> Self {
        self.metadata.redirect_uris = Some(redirect_uris);
        self
    }

    /// Build the client metadata
    pub fn build(self) -> OAuthClientMetadata {
        self.metadata
    }
}

impl OAuthClientMetadata {
    /// Create a builder for client metadata
    pub fn builder<S: Into<String>>(client_id: S) -> ClientMetadataBuilder {
        ClientMetadataBuilder::new(client_id.into())
    }

    /// Create a default client metadata for client credentials flow
    pub fn default_client_credentials<S: Into<String>>(client_id: S, jwks_uri: S) -> Self {
        Self::builder(client_id)
            .client_name("OAuth Client ID Metadata Example")
            .jwks_uri(jwks_uri)
            .scope("read write")
            .build()
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> serde_json::Result<Value> {
        serde_json::to_value(self)
    }

    /// Deserialize from JSON
    pub fn from_json(value: &Value) -> serde_json::Result<Self> {
        serde_json::from_value(value.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_metadata_builder() {
        let metadata = OAuthClientMetadata::builder("test-client")
            .client_name("Test Client")
            .scope("read write execute")
            .jwks_uri("https://example.com/jwks")
            .build();

        assert_eq!(metadata.client_id, "test-client");
        assert_eq!(metadata.client_name, Some("Test Client".to_string()));
        assert_eq!(metadata.grant_types, vec!["client_credentials"]);
        assert_eq!(metadata.token_endpoint_auth_method, "private_key_jwt");
        assert_eq!(metadata.token_endpoint_auth_signing_alg, Some("RS256".to_string()));
        assert_eq!(metadata.jwks_uri, Some("https://example.com/jwks".to_string()));
        assert_eq!(metadata.scope, Some("read write execute".to_string()));
    }

    #[test]
    fn test_default_client_credentials() {
        let metadata = OAuthClientMetadata::default_client_credentials(
            "oauth-client-id-metadata-example",
            "http://localhost:3000/jwks"
        );

        assert_eq!(metadata.client_id, "oauth-client-id-metadata-example");
        assert_eq!(metadata.client_name, Some("OAuth Client ID Metadata Example".to_string()));
        assert_eq!(metadata.grant_types, vec!["client_credentials"]);
        assert_eq!(metadata.token_endpoint_auth_method, "private_key_jwt");
        assert_eq!(metadata.token_endpoint_auth_signing_alg, Some("RS256".to_string()));
        assert_eq!(metadata.jwks_uri, Some("http://localhost:3000/jwks".to_string()));
        assert_eq!(metadata.scope, Some("read write".to_string()));
    }

    #[test]
    fn test_serialization() {
        let metadata = OAuthClientMetadata::builder("test-client")
            .client_name("Test Client")
            .scope("read")
            .build();

        let json = metadata.to_json().unwrap();
        
        assert_eq!(json["client_id"], "test-client");
        assert_eq!(json["client_name"], "Test Client");
        assert_eq!(json["grant_types"][0], "client_credentials");
        assert_eq!(json["token_endpoint_auth_method"], "private_key_jwt");
        assert_eq!(json["token_endpoint_auth_signing_alg"], "RS256");
        assert_eq!(json["scope"], "read");

        // Test deserialization
        let deserialized = OAuthClientMetadata::from_json(&json).unwrap();
        assert_eq!(deserialized.client_id, metadata.client_id);
        assert_eq!(deserialized.client_name, metadata.client_name);
        assert_eq!(deserialized.scope, metadata.scope);
    }

    #[test]
    fn test_optional_fields() {
        let metadata = OAuthClientMetadata::builder("minimal-client").build();

        let json = metadata.to_json().unwrap();
        
        // Required fields should be present
        assert!(json.get("client_id").is_some());
        assert!(json.get("grant_types").is_some());
        assert!(json.get("token_endpoint_auth_method").is_some());

        // Optional fields should be omitted if None
        assert!(json.get("client_name").is_none());
        assert!(json.get("scope").is_none());
        assert!(json.get("redirect_uris").is_none());
    }
}