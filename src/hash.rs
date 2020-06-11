#[cfg(feature = "serde-1")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Blake3 hash
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde-1", derive(Serialize, Deserialize))]
pub struct Hash {
    #[cfg_attr(feature = "serde-1", serde(serialize_with = "serialize_hash"))]
    #[cfg_attr(feature = "serde-1", serde(deserialize_with = "deserialize_hash"))]
    inner: blake3::Hash,
}

impl Hash {
    /// Returns bytes of the hash
    pub fn as_bytes(&self) -> &[u8; blake3::OUT_LEN] {
        self.inner.as_bytes()
    }
}

impl From<[u8; blake3::OUT_LEN]> for Hash {
    fn from(bytes: [u8; blake3::OUT_LEN]) -> Self {
        Self {
            inner: bytes.into(),
        }
    }
}

impl From<Hash> for [u8; blake3::OUT_LEN] {
    fn from(hash: Hash) -> Self {
        hash.inner.into()
    }
}

impl PartialEq<[u8; blake3::OUT_LEN]> for Hash {
    fn eq(&self, other: &[u8; blake3::OUT_LEN]) -> bool {
        self.inner.eq(other)
    }
}

impl From<blake3::Hash> for Hash {
    fn from(hash: blake3::Hash) -> Self {
        Self { inner: hash }
    }
}

impl From<Hash> for blake3::Hash {
    fn from(hash: Hash) -> Self {
        hash.inner
    }
}

#[cfg(feature = "serde-1")]
fn serialize_hash<S>(hash: &blake3::Hash, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(hash.as_bytes())
}

#[cfg(feature = "serde-1")]
fn deserialize_hash<'de, D>(deserializer: D) -> Result<blake3::Hash, D::Error>
where
    D: Deserializer<'de>,
{
    let hash_raw: &[u8] = Deserialize::deserialize(deserializer)?;

    if hash_raw.len() != blake3::OUT_LEN {
        return Err(serde::de::Error::custom("Invalid hash length"));
    }

    let mut hash_bytes: [u8; blake3::OUT_LEN] = [0; blake3::OUT_LEN];
    hash_bytes.copy_from_slice(hash_raw);

    Ok(hash_bytes.into())
}
