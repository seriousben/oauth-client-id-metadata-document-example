use crate::{KeyManager, Result};
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON Web Key Set (JWKS) as defined in RFC 7517
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKeySet {
    pub keys: Vec<JsonWebKey>,
}

/// JSON Web Key (JWK) as defined in RFC 7517
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKey {
    /// Key Type - "RSA" for RSA keys
    pub kty: String,
    /// Modulus (base64url-encoded)
    pub n: String,
    /// Exponent (base64url-encoded)
    pub e: String,
    /// Public Key Use - "sig" for signature
    #[serde(rename = "use")]
    pub key_use: String,
    /// Algorithm - "RS256" for RSA using SHA-256
    pub alg: String,
    /// Key ID
    pub kid: String,
}

impl JsonWebKeySet {
    /// Create a new JWKS with a single key from the KeyManager
    pub fn from_key_manager(key_manager: &KeyManager) -> Result<Self> {
        let jwk = JsonWebKey::from_key_manager(key_manager)?;
        Ok(Self { keys: vec![jwk] })
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> serde_json::Result<Value> {
        serde_json::to_value(self)
    }
}

impl JsonWebKey {
    /// Create a JWK from a KeyManager
    pub fn from_key_manager(key_manager: &KeyManager) -> Result<Self> {
        let public_key = key_manager.public_key();
        
        // Get modulus and exponent from RSA public key
        let n_bytes = public_key.n().to_bytes_be();
        let e_bytes = public_key.e().to_bytes_be();

        // Base64url encode the modulus and exponent
        let n = base64_url_encode(&n_bytes);
        let e = base64_url_encode(&e_bytes);

        Ok(Self {
            kty: "RSA".to_string(),
            n,
            e,
            key_use: "sig".to_string(),
            alg: "RS256".to_string(),
            kid: key_manager.key_id().to_string(),
        })
    }
}

/// Base64url encoding without padding as per RFC 7515
fn base64_url_encode(data: &[u8]) -> String {
    use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_creation() {
        let key_manager = KeyManager::new().unwrap();
        let jwk = JsonWebKey::from_key_manager(&key_manager).unwrap();
        
        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.key_use, "sig");
        assert_eq!(jwk.alg, "RS256");
        assert_eq!(jwk.kid, key_manager.key_id());
        
        // Modulus and exponent should be base64url encoded
        use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};
        let n_decoded = URL_SAFE_NO_PAD.decode(&jwk.n).unwrap();
        let e_decoded = URL_SAFE_NO_PAD.decode(&jwk.e).unwrap();
        
        // RSA 2048-bit key should have 256-byte modulus
        assert_eq!(n_decoded.len(), 256);
        // Common exponent is 65537 (3 bytes)
        assert!(e_decoded.len() <= 8);
    }

    #[test]
    fn test_jwks_creation() {
        let key_manager = KeyManager::new().unwrap();
        let jwks = JsonWebKeySet::from_key_manager(&key_manager).unwrap();
        
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, key_manager.key_id());
    }

    #[test]
    fn test_jwks_serialization() {
        let key_manager = KeyManager::new().unwrap();
        let jwks = JsonWebKeySet::from_key_manager(&key_manager).unwrap();
        
        let json = jwks.to_json().unwrap();
        assert!(json["keys"].is_array());
        assert_eq!(json["keys"].as_array().unwrap().len(), 1);
        
        let key = &json["keys"][0];
        assert_eq!(key["kty"], "RSA");
        assert_eq!(key["alg"], "RS256");
    }
}