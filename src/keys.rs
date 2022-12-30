//! Wrapper types to support encoding and decoding ed25519 public and private keys
//! 

use core::ops::Deref;

use ed25519_dalek::{SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH};

use crate::ManifestError;

/// [PrivateKey] object wrapping [ed25519_dalek::SecretKey] with encode/decode support
#[derive(Debug)]
pub struct PrivateKey (ed25519_dalek::SecretKey);

impl From<ed25519_dalek::SecretKey> for PrivateKey {
    fn from(value: ed25519_dalek::SecretKey) -> Self {
        Self(value)
    }
}

impl Deref for PrivateKey {
    type Target = ed25519_dalek::SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        let b = self.0.as_bytes();
        let s = ed25519_dalek::SecretKey::from_bytes(b).unwrap();
        Self(s)
    }
}

impl core::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0.as_bytes() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl core::str::FromStr for PrivateKey {
    type Err = ManifestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut b = [0u8; SECRET_KEY_LENGTH];
        hex::decode_to_slice(s, &mut b)
            .map_err(|_e| ManifestError::InvalidHex )?;
        
        let k = ed25519_dalek::SecretKey::from_bytes(&b)
            .map_err(|_e| ManifestError::InvalidPrivateKey )?;

        Ok(Self(k))
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        ed25519_dalek::PublicKey::from(&self.0) == ed25519_dalek::PublicKey::from(&other.0)
    }
}

impl PrivateKey {
    pub fn inner(self) -> ed25519_dalek::SecretKey {
        self.0
    }
}

/// [PublicKey] object wrapping [ed25519_dalek::PublicKey] with encode/decode support
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey (ed25519_dalek::PublicKey);

impl From<ed25519_dalek::PublicKey> for PublicKey {
    fn from(value: ed25519_dalek::PublicKey) -> Self {
        Self(value)
    }
}

impl Deref for PublicKey {
    type Target = ed25519_dalek::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0.as_bytes() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl core::str::FromStr for PublicKey {
    type Err = ManifestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut b = [0u8; PUBLIC_KEY_LENGTH];
        hex::decode_to_slice(s, &mut b)
            .map_err(|_e| ManifestError::InvalidHex )?;
        
        let k = ed25519_dalek::PublicKey::from_bytes(&b)
            .map_err(|_e| ManifestError::InvalidPrivateKey )?;

        Ok(Self(k))
    }
}

impl PublicKey {
    pub fn inner(self) -> ed25519_dalek::PublicKey {
        self.0
    }
}

