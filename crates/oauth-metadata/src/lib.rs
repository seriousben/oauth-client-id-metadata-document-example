mod client_metadata;
mod jwks;
mod jwt;
mod key_manager;

pub use client_metadata::*;
pub use jwks::*;
pub use jwt::*;
pub use key_manager::*;

pub fn hello_oauth() -> String {
    "Hello from oauth-metadata!".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_oauth() {
        assert_eq!(hello_oauth(), "Hello from oauth-metadata!");
    }
}
