//! [ManifestBuilder] for constructing [Manifest] objects

use ed25519_dalek::SecretKey;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{MetadataFormat, ManifestError};

use super::{Manifest, Flags};

/// Builder for constructing binary [Manifest] objects
#[derive(Clone, PartialEq, Debug)]
pub struct ManifestBuilder {
    m: Manifest,
}

impl ManifestBuilder {
    /// Create a new [ManifestBuilder] object
    pub fn new() -> Self {
        Self{ m: Default::default() }
    }

    /// Set manifest [Flags]
    pub fn flags(&mut self, flags: Flags) -> &mut Self {
        self.m.flags = flags.bits();

        self
    }

    /// Add app binary to manifest as bytes
    pub fn app_bin(&mut self, d: &[u8]) -> &mut Self {
        let mut h = Sha512::new();
        h.update(d);
        let h = h.finalize();

        self.m.app_len = d.len() as u32;
        self.m.app_csum.copy_from_slice(&h);

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
        let mut h = Sha512::new();
        h.update(d);
        let h = h.finalize();

        self.m.meta_kind = k as u16;
        self.m.meta_len = d.len() as u16;
        self.m.meta_csum.copy_from_slice(&h);

        self
    }

    /// Add metadata binary to manifest via file
    #[cfg(feature = "std")]
    pub fn meta_file(&mut self, k: MetadataFormat, f: &str) -> Result<&mut Self, std::io::Error> {
        let d = std::fs::read(f)?;
        Ok(self.meta_bin(k, &d))
    }

    /// Complete manifest construction
    pub fn build<RNG: CryptoRng + RngCore + Default>(&mut self, signing_key: Option<SecretKey>) -> Result<Manifest, ManifestError> {
        
        // TODO: check object validity?

        // Sign completed manifest
        let mut m = self.m.clone();
        m.sign::<RNG>(signing_key)?;

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
