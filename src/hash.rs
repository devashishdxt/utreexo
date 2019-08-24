use core::fmt;

/// Represents a hash value
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Hash(pub(crate) [u8; 64]);

impl Hash {
    /// Converts the hash to a byte slice
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Converts the hash to a byte slice
    #[inline]
    pub fn as_array(&self) -> &[u8; 64] {
        &self.0
    }
}

impl PartialEq<Hash> for Hash {
    #[inline]
    fn eq(&self, other: &Hash) -> bool {
        self.0[..] == other.0[..]
    }
}

impl PartialEq<[u8]> for Hash {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        &self.0[..] == other
    }
}

impl Eq for Hash {}

impl AsRef<[u8]> for Hash {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash(0x")?;
        for i in 0..64 {
            write!(f, "{:02x}", self.0[i])?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use blake2b_simd::blake2b;

    #[test]
    fn check_hash_debug() {
        let blake2b_hash = blake2b(b"hello");
        let hash = Hash(*blake2b_hash.as_array());

        assert_eq!(format!("{:?}", blake2b_hash), format!("{:?}", hash));
    }
}
