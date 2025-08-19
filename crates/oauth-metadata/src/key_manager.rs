use rand::Rng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Key generation failed: {0}")]
    Generation(String),
    #[error("Key serialization failed: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, KeyError>;

/// Manages RS256 keys for JWT signing
#[derive(Clone)]
pub struct KeyManager {
    private_key: Arc<RsaPrivateKey>,
    key_id: String,
}

impl KeyManager {
    /// Create a new KeyManager with a randomly generated RS256 key (2048 bits)
    pub fn new() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| KeyError::Generation(e.to_string()))?;
        let key_id = Self::generate_key_id();

        Ok(Self {
            private_key: Arc::new(private_key),
            key_id,
        })
    }

    /// Create a KeyManager from an existing private key
    pub fn from_private_key(private_key: RsaPrivateKey, key_id: Option<String>) -> Self {
        let key_id = key_id.unwrap_or_else(Self::generate_key_id);

        Self {
            private_key: Arc::new(private_key),
            key_id,
        }
    }

    /// Get the private key
    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

    /// Get the public key
    pub fn public_key(&self) -> RsaPublicKey {
        self.private_key.to_public_key()
    }

    /// Get the key ID
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Generate a random key ID
    fn generate_key_id() -> String {
        let mut rng = rand::thread_rng();
        let random_bytes: [u8; 8] = rng.gen();
        format!("key-{}", hex::encode(random_bytes))
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new().expect("Failed to generate default key")
    }
}
