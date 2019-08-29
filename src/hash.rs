use core::fmt;

use blake2b_simd::Hash as Blake2Hash;

pub const HASH_SIZE: usize = 32;

/// Represents a hash value
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Hash(pub(crate) [u8; HASH_SIZE]);

impl From<[u8; HASH_SIZE]> for Hash {
    #[inline]
    fn from(inner: [u8; HASH_SIZE]) -> Hash {
        Hash(inner)
    }
}

impl From<Hash> for [u8; HASH_SIZE] {
    #[inline]
    fn from(hash: Hash) -> [u8; HASH_SIZE] {
        hash.0
    }
}

impl PartialEq<[u8]> for Hash {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        &self.0[..] == other
    }
}

impl AsRef<[u8]> for Hash {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash(0x")?;
        for i in 0..HASH_SIZE {
            write!(f, "{:02x}", self.0[i])?;
        }
        write!(f, ")")
    }
}

#[doc(hidden)]
impl From<Blake2Hash> for Hash {
    fn from(blake2_hash: Blake2Hash) -> Hash {
        let mut bytes: [u8; HASH_SIZE] = [0; HASH_SIZE];
        bytes.copy_from_slice(blake2_hash.as_bytes());
        Hash(bytes)
    }
}
