//! Wrapper types to support encoding and decoding ed25519 public and private keys
//! 

use core::ops::Deref;

use encdec::{Encode, DecodeOwned};
use ed25519_dalek::{SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH};
use rand_core::{RngCore, CryptoRng};

use crate::ManifestError;

/// [PrivateKey] object wrapping [ed25519_dalek::SecretKey] with encode/decode support
#[derive(Debug)]
pub struct PrivateKey (ed25519_dalek::SecretKey);

impl PrivateKey {
    /// Generate a new private key using the provided RNG
    pub fn generate<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
        let k = ed25519_dalek::SecretKey::generate(rng);
        Self(k)
    }

    /// Unwrap the [PrivateKey] object into it's inner [ed25519_dalek::SecretKey]
    pub fn inner(self) -> ed25519_dalek::SecretKey {
        self.0
    }
}

/// Convert an [ed25519_dalek::SecretKey] into a [PrivateKey] object
impl From<ed25519_dalek::SecretKey> for PrivateKey {
    fn from(value: ed25519_dalek::SecretKey) -> Self {
        Self(value)
    }
}

/// Access the internal [ed25519_dalek::SecretKey] for cryptographic operations
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


/// [PublicKey] object wrapping [ed25519_dalek::PublicKey] with encode/decode support
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey (pub(crate) ed25519_dalek::PublicKey);

impl PublicKey {
    /// Unwrap the [PublicKey] object into it's inner [ed25519_dalek::PublicKey]
    pub fn inner(self) -> ed25519_dalek::PublicKey {
        self.0
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(value: &PrivateKey) -> Self {
        Self(ed25519_dalek::PublicKey::from(&value.0))
    }
}

impl From<&ed25519_dalek::SecretKey> for PublicKey {
    fn from(value: &ed25519_dalek::SecretKey) -> Self {
        Self(ed25519_dalek::PublicKey::from(value))
    }
}

impl From<ed25519_dalek::PublicKey> for PublicKey {
    fn from(value: ed25519_dalek::PublicKey) -> Self {
        Self(value)
    }
}

impl From<&ed25519_dalek::PublicKey> for PublicKey {
    fn from(value: &ed25519_dalek::PublicKey) -> Self {
        Self(value.clone())
    }
}

/// Access the internal [ed25519_dalek::PublicKey] for cryptographic operations
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

impl Encode for PublicKey {
    type Error = encdec::Error;

    fn encode_len(&self) -> Result<usize, Self::Error> {
        Ok(PUBLIC_KEY_LENGTH)
    }

    fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error> {
        // Check buffer length
        if buff.len() < PUBLIC_KEY_LENGTH {
            return Err(encdec::Error::Length);
        }
        // Write data
        buff[..PUBLIC_KEY_LENGTH].copy_from_slice(self.0.as_bytes());
        // Return write length
        Ok(PUBLIC_KEY_LENGTH)
    }
}

impl DecodeOwned for PublicKey {
    type Output = PublicKey;

    type Error = encdec::Error;

    fn decode_owned(buff: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        // Check buffer length
        if buff.len() < PUBLIC_KEY_LENGTH {
            return Err(encdec::Error::Length);
        }
        // Read data
        let mut d = [0u8; PUBLIC_KEY_LENGTH];
        d.copy_from_slice(&buff[..PUBLIC_KEY_LENGTH]);

        let public_key = ed25519_dalek::PublicKey::from_bytes(&d)
            .map_err(|_| encdec::Error::Length)?;

        Ok((Self(public_key), PUBLIC_KEY_LENGTH))
    }
}
