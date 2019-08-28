use alloc::vec::Vec;

use crate::{hash_intermediate, hash_leaf, Direction, Hash, Path};

/// Inclusion proof of a value in a merkle forest
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof<T: AsRef<[u8]>> {
    /// Path is from root node to leaf
    pub(crate) path: Path,
    /// Leaf hash
    pub(crate) leaf_value: T,
    /// Sibling hashes are from top to bottom
    pub(crate) sibling_hashes: Vec<Hash>,
}

impl<T: AsRef<[u8]>> Proof<T> {
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
            return root_hash == hash_leaf(&self.leaf_value);
        }

        let path = self.path.directions().rev();
        let mut sibling_hashes = self.sibling_hashes.iter().rev();

        let mut hash = hash_leaf(&self.leaf_value);

        for step in path {
            hash = match step {
                Direction::Left => hash_intermediate(&hash, sibling_hashes.next().unwrap()),
                Direction::Right => hash_intermediate(sibling_hashes.next().unwrap(), &hash),
            }
        }

        hash == root_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bit_vec::BitVec;

    use crate::{hash_leaf, Path, HASH_SIZE};

    #[test]
    fn check_proof_leaves_and_height() {
        let path = Path(BitVec::from_elem(3, false));
        let leaf_value = "hello";
        let sibling_hashes = Vec::new();

        let proof = Proof {
            path,
            leaf_value,
            sibling_hashes,
        };

        assert_eq!(3, proof.height());
        assert_eq!(8, proof.leaves());
    }

    #[test]
    fn check_proof_verify() {
        let path = Path(BitVec::from_elem(3, false));
        let leaf_value = "hello";
        let leaf_hash = hash_leaf(&leaf_value);
        let sibling_hashes = vec![
            Hash::from([1; HASH_SIZE]),
            Hash::from([2; HASH_SIZE]),
            Hash::from([3; HASH_SIZE]),
        ];

        let proof = Proof {
            path,
            leaf_value,
            sibling_hashes: sibling_hashes.clone(),
        };

        let intermediate_hash_1 = hash_intermediate(leaf_hash, sibling_hashes[2]);
        let intermediate_hash_2 = hash_intermediate(intermediate_hash_1, sibling_hashes[1]);
        let root_hash = hash_intermediate(intermediate_hash_2, sibling_hashes[0]);

        assert!(proof.verify(root_hash));
        assert!(!proof.verify(intermediate_hash_2));
    }

    #[test]
    fn check_proof_verify_empty() {
        let path = Path(BitVec::new());
        let leaf_value = "hello";
        let leaf_hash = hash_leaf(&leaf_value);
        let sibling_hashes = Vec::new();

        let proof = Proof {
            path,
            leaf_value,
            sibling_hashes,
        };

        assert!(proof.verify(leaf_hash));
        assert!(!proof.verify(Hash::from([1; HASH_SIZE])));
    }
}
