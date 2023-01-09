
use core::{fmt::{Display, Debug}, str::FromStr, ops::Deref};

use encdec::{Encode, Decode};

/// Constant length encoded, zero-padded, utf8 string
#[derive(Clone, PartialEq, Encode, Decode)]
pub struct Stringish<const N: usize>(pub(crate) [u8; N]);

/// Convert `&str` reference to [Stringish], fails if reference exceeds available length
impl<const N: usize> FromStr for Stringish<N> {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut d = [0u8; N];
        let b = s.as_bytes();

        // Check encoded length is viable
        if b.len() > N {
            return Err(())
        }

        // Copy string data
        d[..b.len()].copy_from_slice(b);

        Ok(Self(d))
    }
}

/// Convert `&str` reference to [Stringish], silently concatentates input if length is exceeded
impl<const N: usize> From<&str> for Stringish<N> {
    fn from(value: &str) -> Self {
        let b = value.as_bytes();
        let n = b.len().min(N);

        let mut d = [0u8; N];
        d[..n].copy_from_slice(&b[..n]);

        Self(d)
    }
}

/// Create a default (empty) stringish type
impl <const N: usize> Default for Stringish<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

/// Display [Stringish]
impl <const N: usize>Display for Stringish<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

/// Debug format [Stringish]
impl <const N: usize>Debug for Stringish<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Stringish").field(&self.as_ref()).finish()
    }
}

/// Access [Stringish] as `&str` reference
impl <const N: usize> AsRef<str> for Stringish<N> {
    fn as_ref(&self) -> &str {
        // Find end of string if shorter than N
        let n = self.0.iter().enumerate().find_map(|(n, c)| {
            if *c == 0 {
                return Some(n)
            } else {
                return None
            }
        }).unwrap_or(N);

        // Parse to UTF8
        match core::str::from_utf8(&self.0[..n]) {
            Ok(v) => v,
            Err(_) => "INVALID_U2F8",
        }
    }
}

/// Access [Stringish] internal bytes
impl <const N: usize> Deref for Stringish<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod test {
    use encdec::{Encode, Decode};

    use super::Stringish;

    #[test]
    fn deref() {
        let s = Stringish(*b"testing123\0\0\0\0\0\0");
        assert_eq!(s.as_ref(), "testing123");
    }

    #[test]
    fn encode_decode() {
        let s = Stringish(*b"testing123\0\0\0\0\0\0");

        let mut b = [0xffu8; 32];
        let n = s.encode(&mut b).unwrap();

        assert_eq!(n, 16);
        assert_eq!(&b[..16], &s.0[..16]);
        assert_eq!(&b[16..], &[0xff; 16]);

        let (s1, n1) = Stringish::<16>::decode(&b[..16]).unwrap();
        assert_eq!(n1, 16);

        assert_eq!(s1, s);
    }
}