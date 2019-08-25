use alloc::vec::Vec;

use blake2b_simd::Params;

use crate::{hash::HASH_SIZE, Direction, Hash, Path};

/// Inclusion proof of a value in a merkle forest
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    // Path is from leaf node to root node
    path: Path,
    leaf_hash: Hash,
    // Sibling hashes are from bottom to top
    sibling_hashes: Vec<Hash>,
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

        let path = self.path.directions();
        let mut sibling_hashes = self.sibling_hashes.iter();

        let mut hash = self.leaf_hash;

        for step in path {
            let mut params = Params::default();
            params.hash_length(HASH_SIZE);

            let mut state = params.to_state();

            // Add `1` byte to intermediate nodes to prevent second preimage attack
            // https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
            state.update(&[1]);

            match step {
                Direction::Left => {
                    state.update(hash.as_ref());
                    state.update(sibling_hashes.next().unwrap().as_ref());
                }
                Direction::Right => {
                    state.update(sibling_hashes.next().unwrap().as_ref());
                    state.update(hash.as_ref());
                }
            }

            hash = state.finalize().into();
        }

        hash == root_hash
    }
}
