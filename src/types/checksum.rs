//! Checksum container type

use core::{
    ops::Deref,
    fmt::Display,
};

use encdec::{Encode, Decode};
use sha2::{
    Sha512Trunc256, Digest,
    digest::{generic_array::GenericArray, consts::U32},
};

/// SHA512 checksum value
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
pub struct Checksum(pub(crate) [u8; 32]);

impl Checksum {
    /// Compute [Sha512Trunc256] checksum for the provided data
    pub fn compute(data: &[u8]) -> Self {
        let mut d = Sha512Trunc256::new();
        d.update(data);
        let h = d.finalize();

        let mut b = [0u8; 32];
        b.copy_from_slice(&h);

        Self(b)
    }
}

/// Create from digest output
impl From<GenericArray<u8, U32>> for Checksum {
    fn from(value: GenericArray<u8, U32>) -> Self {
        let mut b = [0u8; 32];

        b.copy_from_slice(&value);

        Self(b)
    }
}

/// [Deref] to inner `&[u8; 32]` for access to raw data
impl Deref for Checksum {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// [Display] using hex encoding
impl Display for Checksum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use encdec::{Encode, Decode};

    use super::Checksum;

    #[test]
    fn encode_decode() {
        let data: [u8; 32] = rand::random();
        let csum = Checksum::compute(&data);

        let mut buff = [0u8; 256];
        let n = csum.encode(&mut buff).unwrap();

        assert_eq!(n, 32);
        assert_eq!(&buff[..32], &csum[..32]);

        let (csum1, n1) = Checksum::decode(&buff[..n]).unwrap();

        assert_eq!(n1, 32);
        assert_eq!(csum1, csum);
    }
}