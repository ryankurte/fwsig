//! The [Manifest] specification
//! 

use core::ops::Deref;

use bitflags::bitflags;
use encdec::{Encode, Decode, DecodeOwned};
use rand_core::{RngCore, CryptoRng};
use sha2::{Sha512, Digest};
use strum::{Display, EnumString, EnumVariantNames};


use crate::{
    error::ManifestError,
    types::{PublicKey, Checksum, Signature, PrivateKey, Stringish},
    VerifyError,
};

/// Manifest version identifier, MUST be 0x0001, MAY be extended in following versions
pub const MANIFEST_VERSION: u16 = 0x0001;

/// Encoded manifest length, constant to simplify parsing when included in binary form
pub const MANIFEST_LEN: usize = 2 + 2 
    + 16 + 24
    + 4 + 32 
    + 2 + 2 + 32 
    + ed25519_dalek::PUBLIC_KEY_LENGTH
    + ed25519_dalek::SIGNATURE_LENGTH;

/// Metadata format enumeration
#[derive(Copy, Clone, Debug, PartialEq, Display, EnumString, EnumVariantNames)]
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
/// 
/// Encoding:
/// 
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       MANIFEST_VERSION        |         MANIFEST_FLAGS        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                            APP_NAME                           |
/// |                   (16-byte zero padded utf8)                  |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                           APP_VERSION                         /
/// /                   (24-byte zero padded utf8)                  /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        APP_LENGTH (u32)                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                         APP_CHECKSUM                          /
/// /                   (256-bit truncated SHA512)                  /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           META_KIND           |       META_LENGTH (u16)       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                        META_CHECKSUM                          /
/// /                   (256-bit truncated SHA512)                  /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                         SIGNING KEY                           /
/// /                      (ED25519 Public Key)                     /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                          SIGNATURE                            /
/// /                      (ED25519 Signature)                      /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// 
#[derive(Clone, Debug, PartialEq, Encode, DecodeOwned)]
pub struct Manifest {
    /// Manifest version (must be 1)
    pub version: u16,
    /// Manifest flags
    pub flags: u16,

    /// Application name (utf8, zero-padded)
    pub app_name: Stringish<16>,

    /// Application Version (utf8, zero-padded)
    pub app_version: Stringish<24>,

    /// Application binary length
    pub app_len: u32,
    /// Application binary checksum (sha512)
    pub app_csum: Checksum,

    /// Metadata encoding kind
    pub meta_kind: u16,
    /// Metadata binary length
    pub meta_len: u16,
    /// Metadata binary checksum
    pub meta_csum: Checksum,

    /// Public key used to sign manifest
    /// 
    /// For released firmware allowed public keys should be pinned via bootloader,
    /// where release keys are not available transient keys will be used
    /// to construct a valid manifest object.
    pub key: PublicKey,

    /// Signature over manifest data, against the specified public key
    pub sig: Signature,
}

impl Manifest {
    
    /// Fetch manifest flags
    pub fn flags(&self) -> Flags {
        Flags::from_bits_truncate(self.flags)
    }

    /// Fetch app name
    pub fn app_name(&self) -> &str {
        self.app_name.as_ref()
    }

    /// Fetch app version
    pub fn app_version(&self) -> &str {
        self.app_version.as_ref()
    }

    /// Fetch app length
    pub fn app_len(&self) -> usize {
        self.app_len as usize
    }

    /// Fetch metadata length
    pub fn meta_len(&self) -> usize {
        self.meta_len as usize
    }

    /// Sign manifest using provided key
    pub fn sign<RNG: RngCore + CryptoRng + Default>(&mut self, signing_key: PrivateKey) -> Result<(), ManifestError> {        
        // Generate manifest digest for signing
        let digest = self.digest();

        // Load keys
        let public_key = ed25519_dalek::PublicKey::from(signing_key.deref());
        let keys = ed25519_dalek::Keypair{ public: public_key, secret: signing_key.inner() };

        // Generate signature
        let sig = keys.sign_prehashed(digest, None)
            .map_err(|_e| ManifestError::SigningFailed)?;

        // Write signature to manifest
        self.sig = Signature::from(sig);

        Ok(())
    }

    /// Verify manifest signature against allowed keys
    pub fn verify(&self, allowed_keys: &[PublicKey]) -> Result<(), ManifestError> {
        // Lookup signing key in allowed key listing
        let signing_key = match allowed_keys.iter().find(|k| *k == &self.key) {
            Some(k) => k,
            None => return Err(ManifestError::NoMatchingKey),
        };

        // Generate manifest digest for verification
        let digest = self.digest();

        // Verify signature
        let sig = ed25519_dalek::Signature::try_from(&self.sig)?;

        signing_key.verify_prehashed(digest, None, &sig)
            .map_err(|e| ManifestError::VerificationFailed)?;

        Ok(())
    }


    /// Check application and metadata against manifest
    pub fn check(&self, app: &[u8], meta: &[u8]) -> Result<(), VerifyError> {
        // Ensure signature is valid / object is well formed
        self.check_sig()?;

        // Check app length and checksum
        let app_csum = Checksum::compute(app);
        self.check_app(app.len(), &app_csum)?;

        // Check meta length and checksum
        let meta_csum = Checksum::compute(meta);
        self.check_meta(meta.len(), &meta_csum)?;

        Ok(())
    }

    /// Check application and metadata against manifest using pre-computed values
    /// 
    /// This is useful where the app is not entirely in memory for checksum computations
    pub fn check_precomputed(&self, app_csum: &Checksum, app_len: usize, meta_csum: &Checksum, meta_len: usize) -> Result<(), VerifyError> {
        // Ensure signature is valid / object is well formed
        self.check_sig()?;

        // Check app length and checksum
        self.check_app(app_len, app_csum)?;

        // Check meta length and checksum
        self.check_meta(meta_len, meta_csum)?;
        
        // TODO: check signing key against allowed
        
        Ok(())
    }

    /// Internal helper to check the manifest signature is valid
    fn check_sig(&self) -> Result<(), VerifyError> {
        // Generate manifest digest for verification
        let digest = self.digest();

        // Check manifest signature (should _always_ be valid)
        let sig = ed25519_dalek::Signature::try_from(&self.sig)
            .map_err(|_| VerifyError::InvalidSignature)?;
        self.key.deref().verify_prehashed(digest, None, &sig)
            .map_err(|e| VerifyError::InvalidSignature)?;

        Ok(())
    }

    /// Internal helper to check app app length and checksum match
    fn check_app(&self, app_len: usize, app_csum: &Checksum) -> Result<(), VerifyError> {
        if app_len != self.app_len() {
            return Err(VerifyError::AppLengthMismatch)
        }
        if app_csum != &self.app_csum {
            return Err(VerifyError::AppChecksumMismatch)
        }
        Ok(())
    }

    /// Internal helper to check app app length and checksum match
    fn check_meta(&self, meta_len: usize, meta_csum: &Checksum) -> Result<(), VerifyError> {
        if meta_len != self.meta_len() {
            return Err(VerifyError::MetaLengthMismatch)
        }
        if meta_csum != &self.meta_csum {
            return Err(VerifyError::MetaChecksumMismatch)
        }
        Ok(())
    }

    /// Compute digest of manifest for signing
    /// 
    /// (this is equivalent to computing the digest over the encoded object,
    /// while avoiding the need to encode prior to signing)
    fn digest(&self) -> Sha512 {
        let mut h = Sha512::new();

        h.update(&self.version.to_le_bytes());
        h.update(&self.flags.to_le_bytes());

        h.update(&self.app_name.deref());
        h.update(&self.app_version.deref());

        h.update(&self.app_len.to_le_bytes());
        h.update(&self.app_csum.deref());

        h.update(&self.meta_kind.to_le_bytes());
        h.update(&self.meta_len.to_le_bytes());
        h.update(&self.meta_csum.deref());

        h.update(&self.key.deref());

        h
    }

}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SIGNATURE_LENGTH;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn sign_verify() {
        // Setup keys
        let private_key = PrivateKey::generate(&mut OsRng{});
        let public_key = PublicKey::from(&private_key);

        let mut m = Manifest {
            version: MANIFEST_VERSION,
            flags: Flags::TRANSIENT_KEY.bits(),
            app_name: "test_app".into(),
            app_version: "1.2.7".into(),
            app_len: 64 * 1024,
            app_csum: Checksum::compute(&[0xab; 32]),
            meta_len: 1024,
            meta_csum: Checksum::compute(&[0xbc; 32]),
            meta_kind: MetadataFormat::Binary as u16,
            key: public_key.clone(),
            sig: Signature::empty(),
        };

      
        // Perform signing
        m.sign::<OsRng>(private_key).expect("Signing failed");

        // Check manifest fields are updated
        assert_eq!(&m.key, &public_key);
        assert_ne!(m.sig.deref(), &[0u8; 64]);

        // Encode and decode manifest object
        let mut b = [0u8; 256];

        let n = m.encode(&mut b).unwrap();

        assert_eq!(n, MANIFEST_LEN);
        assert_eq!(m.encode_len().unwrap(), MANIFEST_LEN);


        let (m1, n1) = Manifest::decode(&b[..n]).unwrap();
        assert_eq!(n, n1);

        // Verify decoded manifest
        m1.verify(&[public_key]).expect("Verification failed");
    }

    #[test]
    fn digests_match() {
        // Setup keys
        let private_key = PrivateKey::generate(&mut OsRng{});
        let public_key = PublicKey::from(&private_key);

        // Build manifest object
        let m = Manifest {
            version: MANIFEST_VERSION,
            flags: Flags::TRANSIENT_KEY.bits(),
            app_name: "test_app".into(),
            app_version: "1.2.7".into(),
            app_len: 64 * 1024,
            app_csum: Checksum::compute(&[0xab; 32]),
            meta_len: 1024,
            meta_csum: Checksum::compute(&[0xbc; 32]),
            meta_kind: MetadataFormat::Binary as u16,
            key: public_key.clone(),
            sig: Signature::empty(),
        };

        // Compute piecewise (pre-encode) digest
        let d = m.digest().finalize();

        // Encode manifest object
        let mut b = [0u8; 256];
        let n = m.encode(&mut b).unwrap();

        // Compute complete (post-encode) digest
        let mut h = Sha512::new();
        h.update(&b[..MANIFEST_LEN - SIGNATURE_LENGTH]);
        let d1 = h.finalize();

        // Check pre- and post-encode digest methods match
        assert_eq!(d, d1);
        
    }
}
