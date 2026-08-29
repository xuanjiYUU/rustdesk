use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Context, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub struct Crypto {
    cipher: Aes256Gcm,
}

impl Crypto {
    pub fn new(master_key_base64: &str) -> Result<Self> {
        let key = STANDARD
            .decode(master_key_base64)
            .context("RUSTDESK_ACCOUNT_MASTER_KEY must be base64")?;
        if key.len() != 32 {
            bail!("RUSTDESK_ACCOUNT_MASTER_KEY must decode to exactly 32 bytes");
        }
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(&key).context("invalid master key")?,
        })
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        if plaintext.is_empty() {
            return Ok(String::new());
        }
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .map_err(|_| anyhow::anyhow!("password encryption failed"))?;
        let mut encoded = Vec::with_capacity(nonce.len() + ciphertext.len());
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        Ok(STANDARD.encode(encoded))
    }

    pub fn decrypt(&self, encrypted: &str) -> Result<String> {
        if encrypted.is_empty() {
            return Ok(String::new());
        }
        let encoded = STANDARD
            .decode(encrypted)
            .context("stored password is not valid base64")?;
        if encoded.len() <= 12 {
            bail!("stored password is truncated");
        }
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(&encoded[..12]), &encoded[12..])
            .map_err(|_| anyhow::anyhow!("stored password decryption failed"))?;
        String::from_utf8(plaintext).context("stored password is not UTF-8")
    }
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!("password hashing failed: {error}"))
}

pub fn verify_password(password: &str, encoded_hash: &str) -> bool {
    let Ok(hash) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

pub fn new_session_token() -> String {
    let mut token = [0_u8; 32];
    OsRng.fill_bytes(&mut token);
    STANDARD.encode(token)
}

pub fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_and_decrypts_password() {
        let crypto = Crypto::new(&STANDARD.encode([7_u8; 32])).unwrap();
        let encrypted = crypto.encrypt("secret-value").unwrap();
        assert_ne!(encrypted, "secret-value");
        assert_eq!(crypto.decrypt(&encrypted).unwrap(), "secret-value");
    }

    #[test]
    fn hashes_and_verifies_password() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong", &hash));
    }
}
