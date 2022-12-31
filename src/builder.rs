//! [ManifestBuilder] for constructing [Manifest] objects

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, SecretKey};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{
    MetadataFormat, ManifestError, 
    types::{Checksum, PublicKey, PrivateKey, Signature},
    MANIFEST_VERSION};

use super::{Manifest, Flags};

/// Builder for constructing binary [Manifest] objects
#[derive(Clone, PartialEq, Debug)]
pub struct ManifestBuilder {
    version: u16,
    flags: Flags,

    app: Option<(u32, Checksum)>,
    meta: Option<(u16, MetadataFormat, Checksum)>,
    key: Option<PublicKey>,
}

impl ManifestBuilder {
    /// Create a new [ManifestBuilder] object
    pub fn new() -> Self {
        Self{ 
            version: MANIFEST_VERSION,
            flags: Flags::empty(),
            app: None,
            meta: None,
            key: None,
        }
    }

    /// Set manifest [Flags]
    pub fn flags(&mut self, flags: Flags) -> &mut Self {
        self.flags = flags;

        self
    }

    /// Add app binary to manifest as bytes
    pub fn app_bin(&mut self, d: &[u8]) -> &mut Self {
        self.app = Some((
            d.len() as u32,
            Checksum::compute(d),
        ));

        self
    }

    /// Add app binary to manifest via file
    #[cfg(feature = "std")]
    pub fn app_file(&mut self, f: &str) -> Result<&mut Self, std::io::Error> {
        let d = std::fs::read(f)?;
        Ok(self.app_bin(&d))
    }

    /// Add metadata binary to manifest as bytes
    pub fn meta_bin(&mut self, k: MetadataFormat, d: &[u8]) -> &mut Self {
        self.meta = Some((
            d.len() as u16,
            k,
            Checksum::compute(d),
        ));

        self
    }

    /// Add metadata binary to manifest via file
    #[cfg(feature = "std")]
    pub fn meta_file(&mut self, k: MetadataFormat, f: &str) -> Result<&mut Self, std::io::Error> {
        let d = std::fs::read(f)?;
        Ok(self.meta_bin(k, &d))
    }

    /// Complete manifest construction
    pub fn build<RNG: CryptoRng + RngCore + Default>(&mut self, signing_key: Option<PrivateKey>) -> Result<Manifest, ManifestError> {

        // Select signing key
        let (secret_key, transient) = match signing_key {
            Some(v) => (v, false),
            None => (PrivateKey::generate(&mut RNG::default()), true),
        };
        self.flags.set(Flags::TRANSIENT_KEY, transient);

        // Set public key and flags
        let public_key = PublicKey::from(&secret_key);
        

        // Retrieve app and meta info
        let app = match &self.app {
            Some(v) => v,
            None => return Err(ManifestError::MissingAppChecksum),
        };

        let meta = match &self.meta {
            Some(v) => v,
            None => return Err(ManifestError::MissingMetaChecksum),
        };
        
        // Build manifest
        let mut m = Manifest {
            version: self.version,
            flags: self.flags.bits(),

            app_len: app.0,
            app_csum: app.1.clone(),

            meta_len: meta.0,
            meta_kind: meta.1 as u16,
            meta_csum: meta.2.clone(),

            key: PublicKey::from(public_key),
            sig: Signature([0u8; SIGNATURE_LENGTH]),
        };

        // Sign completed manifest
        m.sign::<RNG>(secret_key)?;

        Ok(m)
    }

    pub fn validate(&self) -> Result<(), ()> {
        todo!()
    }

    pub fn sign(self) -> Result<Manifest, ()> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;



}
