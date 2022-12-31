//! Signature container type

use core::{
    ops::Deref,
    fmt::Display,
};

use ed25519_dalek::SIGNATURE_LENGTH;
use encdec::{Encode, Decode};

use crate::error::ManifestError;

/// ed25519 signature value
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
pub struct Signature(pub(crate) [u8; SIGNATURE_LENGTH]);

impl Signature {
    /// Create an empty / invalid signature
    pub fn empty() -> Self {
        Self([0u8; SIGNATURE_LENGTH])
    }
}

/// Create from [ed25519_dalek::Signature]
impl From<ed25519_dalek::Signature> for Signature {
    fn from(value: ed25519_dalek::Signature) -> Self {
        Signature(value.to_bytes())
    }
}

impl TryFrom<&Signature> for ed25519_dalek::Signature {
    type Error = ManifestError;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        ed25519_dalek::Signature::from_bytes(&value.0)
            .map_err(|_e| ManifestError::InvalidSignature)
    }
}

/// [Deref] to inner `&[u8; 64]` for access to data
impl Deref for Signature {
    type Target = [u8; SIGNATURE_LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// [Display] using hex encoding
impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ed25519_dalek::SIGNATURE_LENGTH;
    use encdec::{Encode, Decode};

    use super::Signature;

    #[test]
    fn encode_decode() {
        let mut data = [0u8; 64];
        for d in &mut data {
            *d = rand::random();
        }

        let v = Signature(data);

        let mut buff = [0u8; 256];
        let n = v.encode(&mut buff).unwrap();

        assert_eq!(n, SIGNATURE_LENGTH);
        assert_eq!(&buff[..SIGNATURE_LENGTH], &v[..SIGNATURE_LENGTH]);

        let (v1, n1) = Signature::decode(&buff[..n]).unwrap();

        assert_eq!(n1, SIGNATURE_LENGTH);
        assert_eq!(v1, v);
    }
}