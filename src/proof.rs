use alloc::vec::Vec;

use crate::{hash_intermediate, Direction, Hash, Path};

/// Inclusion proof of a value in a merkle forest
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    // Path is from root node to leaf
    pub(crate) path: Path,
    pub(crate) leaf_hash: Hash,
    // Sibling hashes are from top to bottom
    pub(crate) sibling_hashes: Vec<Hash>,
}

impl Proof {
    /// Returns height of path in proof
    #[inline]
    pub fn height(&self) -> usize {
        self.path.height()
    }

    /// Returns the number of leaves in the tree of this proof
    #[inline]
    pub fn leaves(&self) -> usize {
        self.path.leaves()
    }

    /// Verifies current proof with given root hash
    pub fn verify(&self, root_hash: Hash) -> bool {
        if self.sibling_hashes.is_empty() {
            return root_hash == self.leaf_hash;
        }

        let path = self.path.directions().rev();
        let mut sibling_hashes = self.sibling_hashes.iter().rev();

        let mut hash = self.leaf_hash;

        for step in path {
            hash = match step {
                Direction::Left => hash_intermediate(&hash, sibling_hashes.next().unwrap()),
                Direction::Right => hash_intermediate(sibling_hashes.next().unwrap(), &hash),
            }
        }

        hash == root_hash
    }
}
