//! The [Manifest] specification
//! 

use bitflags::bitflags;
use encdec::{Encode, Decode, DecodeOwned};
use rand_core::{RngCore, CryptoRng};
use sha2::{Sha512, Digest};
use strum::{Display, EnumString, EnumVariantNames};
use ed25519_dalek::{SecretKey, PublicKey, PUBLIC_KEY_LENGTH, Keypair, Signature, SIGNATURE_LENGTH, SECRET_KEY_LENGTH};

use crate::ManifestError;

/// Manifest version identifier, MUST be 0x0001, MAY be extended in following versions
pub const MANIFEST_VERSION: u16 = 0x0001;

/// Encoded manifest length, constant to simplify parsing when included in binary form
pub const MANIFEST_LEN: usize = 2 + 2 
    + 4 + 32 
    + 2 + 2 + 32 
    + PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH;

/// Metadata format enumeration
#[derive(Clone, Debug, PartialEq, Display, EnumString, EnumVariantNames)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[repr(u16)]
pub enum MetadataFormat {
    Binary = 0x0000,
    Json = 0x0001,
    Cbor = 0x0002,
    Other = 0xFFFF,
}

bitflags! {
    /// Manifest information flags
    pub struct Flags: u16 {
        /// Indicate the signing key is transient / should not prompt for TOFU if available
        const TRANSIENT_KEY = 1 << 0;
    }
}

/// Applet manifest, links app and metadata checksums with overall applet signature
#[derive(Clone, Debug, PartialEq, Encode, DecodeOwned)]
pub struct Manifest {
    /// Manifest version (must be 1)
    pub version: u16,
    /// Manifest flags
    pub flags: u16,

    /// Application binary length
    pub app_len: u32,
    /// Application binary checksum (sha512)
    pub app_csum: [u8; 32],

    /// Metadata encoding kind
    pub meta_kind: u16,
    /// Metadata binary length
    pub meta_len: u16,
    /// Metadata binary checksum
    pub meta_csum: [u8; 32],

    /// Public key used to sign manifest
    /// 
    /// For released firmware allowed public keys should be pinned via bootloader,
    /// where release keys are not available transient keys will be used
    /// to construct a valid manifest object.
    pub key: [u8; PUBLIC_KEY_LENGTH],

    /// Signature over manifest data, against the specified public key
    pub sig: [u8; SIGNATURE_LENGTH],
}

impl Default for Manifest {
    /// Create a default / empty manifest object
    fn default() -> Self {
        Self { 
            version: MANIFEST_VERSION,
            flags: 0,
            app_len: 0,
            app_csum: [0u8; 32],
            meta_kind: 0,
            meta_len: 0,
            meta_csum: [0u8; 32],
            key: [0u8; PUBLIC_KEY_LENGTH],
            sig: [0u8; SIGNATURE_LENGTH],
        }
    }
}

impl Manifest {

    
    /// Fetch manifest flags
    pub fn flags(&self) -> Flags {
        Flags::from_bits_truncate(self.flags)
    }

    pub fn app_len(&self) -> usize {
        self.app_len as usize
    }

    pub fn meta_len(&self) -> usize {
        self.meta_len as usize
    }

    /// Sign manifest using provided (or transient) key
    pub fn sign<RNG: RngCore + CryptoRng + Default>(&mut self, signing_key: Option<SecretKey>) -> Result<(), ManifestError> {
        // Select between provided and transient keys
        let (secret_key, transient) = match signing_key {
            Some(v) => (v, false),
            None => (SecretKey::generate(&mut RNG::default()), true),
        };

        // Set public key and flags
        let public_key = PublicKey::from(&secret_key);
        self.key.copy_from_slice(public_key.as_bytes());
        
        let mut flags = self.flags();
        flags.set(Flags::TRANSIENT_KEY, transient);
        self.flags = flags.bits();

        // Generate manifest digest for signing
        let digest = self.digest();

        // Generate signature
        let keys = Keypair{ public: public_key, secret: secret_key };

        let sig = keys.sign_prehashed(digest, None)
            .map_err(|_e| ManifestError::SigningFailed)?;

        // Write signature to manifest
        self.sig.copy_from_slice(&sig.to_bytes());

        Ok(())
    }

    /// Verify manifest against allowed keys
    pub fn verify(&self, allowed_keys: &[PublicKey]) -> Result<(), ManifestError> {
        // Lookup signing key in allowed key listing
        let signing_key = match allowed_keys.iter().find(|k| k.as_bytes() == &self.key[..]) {
            Some(k) => k,
            None => return Err(ManifestError::NoMatchingKey),
        };

        // Generate manifest digest for verification
        let digest = self.digest();

        // Verify signature
        let sig = Signature::from_bytes(&self.sig)
            .map_err(|_e| ManifestError::InvalidSignature)?;

        signing_key.verify_prehashed(digest, None, &sig)
            .map_err(|e| ManifestError::VerificationFailed)?;

        Ok(())
    }

    /// Compute [Sha512] checksum for the provided data
    pub fn checksum(data: &[u8]) -> [u8; 32] {
        let mut d = Sha512::new();
        d.update(data);
        let h = d.finalize();

        let mut b = [0u8; 32];
        b.copy_from_slice(&h);

        b
    }

    /// Compute digest of manifest for signing
    /// 
    /// (this is equivalent to but avoids the need to encode prior to signing)
    fn digest(&self) -> Sha512 {
        let mut h = Sha512::new();

        h.update(&self.version.to_le_bytes());
        h.update(&self.flags.to_le_bytes());

        h.update(&self.app_len.to_le_bytes());
        h.update(&self.app_csum);

        h.update(&self.meta_kind.to_le_bytes());
        h.update(&self.meta_len.to_le_bytes());
        h.update(&self.meta_csum);

        h.update(&self.key);

        h
    }

}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    /// Check manifest length constant and encode/decode lengths match
    #[test]
    fn manifest_len() {
        let m = Manifest::default();
        assert_eq!(MANIFEST_LEN, m.encode_len().unwrap());
    }

    #[test]
    fn sign_verify() {
        let mut m = Manifest {
            version: MANIFEST_VERSION,
            flags: Flags::TRANSIENT_KEY.bits(),
            app_len: 64 * 1024,
            app_csum: [0xab; 32],
            meta_len: 1024,
            meta_csum: [0xbc; 32],
            ..Default::default()
        };

        // Setup secret keys
        let secret_key = SecretKey::generate(&mut OsRng{});
        let public_key = PublicKey::from(&secret_key);

        // Perform signing
        m.sign::<OsRng>(Some(secret_key)).expect("Signing failed");

        // Check manifest fields are updated
        assert_eq!(&m.key, public_key.as_bytes());
        assert_ne!(m.sig, [0u8; 64]);

        // Encode and decode manifest object
        let mut b = [0u8; 256];

        let n = m.encode(&mut b).unwrap();

        let (m1, n1) = Manifest::decode(&b[..n]).unwrap();
        assert_eq!(n, n1);

        // Verify decoded manifest
        m1.verify(&[public_key]).expect("Verification failed");
    }

}
