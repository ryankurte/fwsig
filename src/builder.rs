//! [ManifestBuilder] for constructing [Manifest] objects

use core::str::FromStr;

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, SecretKey};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{
    MetadataFormat, ManifestError, 
    types::{Checksum, PublicKey, PrivateKey, Signature, Stringish},
    MANIFEST_VERSION};

use super::{Manifest, Flags};

/// Builder for constructing binary [Manifest] objects
#[derive(Clone, PartialEq, Debug)]
pub struct ManifestBuilder {
    info: Info,

    name: Stringish<16>,
    version: Stringish<24>,

    app: Option<(u32, Checksum)>,
    meta: Option<(u16, MetadataFormat, Checksum)>,
    key: Option<PublicKey>,
}

/// Manifest object info
#[derive(Clone, PartialEq, Debug)]
struct Info {
    version: u16,
    flags: Flags,
}

impl ManifestBuilder {
    /// Create a new [ManifestBuilder] object
    pub fn new() -> Self {
        Self{
            info: Info{
                version: MANIFEST_VERSION,
                flags: Flags::empty(),
            },
            name: Stringish::default(),
            version: Stringish::default(),
            app: None,
            meta: None,
            key: None,
        }
    }

    /// Set manifest [Flags]
    pub fn flags(&mut self, flags: Flags) -> &mut Self {
        self.info.flags = flags;

        self
    }

    /// Set application name
    pub fn name(&mut self, app_name: &str) -> Result<&mut Self, ()> {
        self.name = Stringish::from_str(app_name)?;
        Ok(self)
    }

    /// Set application version string
    pub fn version(&mut self, app_version: &str) -> Result<&mut Self, ()> {
        self.version = Stringish::from_str(app_version)?;
        Ok(self)
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
        self.info.flags.set(Flags::TRANSIENT_KEY, transient);

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
            version: self.info.version,
            flags: self.info.flags.bits(),

            app_name: self.name.clone(),
            app_version: self.version.clone(),

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
