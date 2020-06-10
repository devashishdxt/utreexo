use alloc::vec::Vec;

use blake3::Hash;

use crate::{hash_intermediate, Direction, Path};

/// Inclusion proof of a value in a merkle forest
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// Path is from leaf to root node
    pub(crate) path: Path,
    /// Leaf hash
    pub(crate) leaf_hash: Hash,
    /// Sibling hashes are from bottom to top
    pub(crate) sibling_hashes: Vec<Hash>,
}

impl Proof {
    /// Verifies current proof with given root hash
    pub(crate) fn verify(&self, root_hash: Hash) -> bool {
        // If height of path in proof and number of sibling hashes does not match, return false
        if self.sibling_hashes.len() != self.path.height() {
            return false;
        }

        // If number of sibling hashes is zero, i.e., height of path is zero, then compare leaf
        // hash directly to root hash
        if self.sibling_hashes.is_empty() {
            return root_hash == self.leaf_hash;
        }

        let path = self.path.directions();
        let mut sibling_hashes = self.sibling_hashes.iter();

        let mut hash = self.leaf_hash;

        for step in path {
            match sibling_hashes.next() {
                Some(ref sibling_hash) => {
                    hash = match step {
                        Direction::Left => hash_intermediate(sibling_hash, &hash),
                        Direction::Right => hash_intermediate(&hash, sibling_hash),
                    };
                }
                None => return false,
            }
        }

        hash == root_hash
    }
}
