use alloc::vec::Vec;

#[cfg(feature = "serde-1")]
use serde::{Deserialize, Serialize};

use crate::{hash_intermediate, hash_leaf, Hash, Proof, Utreexo};

/// Hash based in-memory accumulator
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde-1", derive(Serialize, Deserialize))]
pub struct MemoryAccumulator(Vec<Option<Hash>>);

impl MemoryAccumulator {
    /// Creates a new instance of memory accumulator
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns the root hashes of all the merkle trees in forest
    pub fn root_hashes(&self) -> &[Option<Hash>] {
        &self.0
    }

    /// Verifies inclusion proof of a value in accumulator
    fn verify(&self, proof: &Proof) -> bool {
        let height = proof.path.height();

        if self.0.len() < (height + 1) {
            return false;
        }

        if let Some(ref root_hash) = self.0[height] {
            proof.verify(*root_hash)
        } else {
            false
        }
    }
}

impl Utreexo for MemoryAccumulator {
    fn insert<T: AsRef<[u8]>>(&mut self, leaf_value: T) {
        let mut new_hash = hash_leaf(leaf_value);

        for hash in self.0.iter_mut() {
            match hash {
                Some(ref old_hash) => {
                    new_hash = hash_intermediate(old_hash, &new_hash);
                    *hash = None;
                }
                None => {
                    *hash = Some(new_hash);
                    return;
                }
            }
        }

        self.0.push(Some(new_hash));
    }

    fn delete(&mut self, proof: &Proof) -> bool {
        // Proof should be valid to delete a value from accumulator
        if !self.verify(proof) {
            return false;
        }

        let height = proof.path.height();

        let mut new_hash = None;

        for (hash, sibling_hash) in self
            .0
            .iter_mut()
            .take(height)
            .zip(proof.sibling_hashes.iter())
        {
            if let Some(ref mut new_hash) = new_hash {
                *new_hash = hash_intermediate(sibling_hash, new_hash);
            } else if hash.is_none() {
                *hash = Some(*sibling_hash)
            } else {
                // `unwrap()` is safe here because `None` condition was checked earlier
                new_hash = Some(hash_intermediate(sibling_hash, &hash.unwrap()));
                *hash = None;
            }
        }

        self.0[height] = new_hash;
        true
    }
}

#[cfg(test)]
mod tests {
    // To test accumulator, we need forest to generate incusion proofs

    use super::*;
    use crate::{MemoryForest, Prover};

    #[test]
    fn check_accumulator_ops() {
        let mut accumulator = MemoryAccumulator::new();
        let mut forest = MemoryForest::new();

        forest.insert([0; 32]);
        forest.insert([1; 32]);
        forest.insert([2; 32]);
        forest.insert([3; 32]);
        forest.insert([4; 32]);
        forest.insert([5; 32]);
        forest.insert([6; 32]);
        forest.insert([7; 32]);
        forest.insert([8; 32]);
        forest.insert([9; 32]);

        accumulator.insert([0; 32]);
        accumulator.insert([1; 32]);
        accumulator.insert([2; 32]);
        accumulator.insert([3; 32]);
        accumulator.insert([4; 32]);
        accumulator.insert([5; 32]);
        accumulator.insert([6; 32]);
        accumulator.insert([7; 32]);
        accumulator.insert([8; 32]);
        accumulator.insert([9; 32]);

        // Checking distribution of trees in merkle forest
        assert_eq!(4, accumulator.0.len());
        assert!(accumulator.0[0].is_none());
        assert!(accumulator.0[1].is_some());
        assert!(accumulator.0[2].is_none());
        assert!(accumulator.0[3].is_some());

        // Delete a leaf
        let proof = forest.prove(&[0; 32]);
        assert!(proof.is_some());
        let proof = proof.unwrap();
        assert!(forest.delete(&proof));
        assert!(accumulator.delete(&proof));

        // Checking distribution of trees in merkle forest
        assert_eq!(4, accumulator.0.len());
        assert!(accumulator.0[0].is_some());
        assert!(accumulator.0[1].is_none());
        assert!(accumulator.0[2].is_none());
        assert!(accumulator.0[3].is_some());

        // Delete a leaf
        let proof = forest.prove(&[1; 32]);
        assert!(proof.is_some());
        let proof = proof.unwrap();
        assert!(forest.delete(&proof));
        assert!(accumulator.delete(&proof));

        // Checking distribution of trees in merkle forest
        assert_eq!(4, accumulator.0.len());
        assert!(accumulator.0[0].is_none());
        assert!(accumulator.0[1].is_none());
        assert!(accumulator.0[2].is_none());
        assert!(accumulator.0[3].is_some());

        // Delete a leaf
        let proof = forest.prove(&[2; 32]);
        assert!(proof.is_some());
        let proof = proof.unwrap();
        assert!(forest.delete(&proof));
        assert!(accumulator.delete(&proof));

        // Checking distribution of trees in merkle forest
        assert_eq!(4, accumulator.0.len());
        assert!(accumulator.0[0].is_some());
        assert!(accumulator.0[1].is_some());
        assert!(accumulator.0[2].is_some());
        assert!(accumulator.0[3].is_none());

        // Delete a leaf
        let proof = forest.prove(&[3; 32]);
        assert!(proof.is_some());
        let proof = proof.unwrap();
        assert!(forest.delete(&proof));
        assert!(accumulator.delete(&proof));

        // Checking distribution of trees in merkle forest
        assert_eq!(4, accumulator.0.len());
        assert!(accumulator.0[0].is_none());
        assert!(accumulator.0[1].is_some());
        assert!(accumulator.0[2].is_some());
        assert!(accumulator.0[3].is_none());

        // Add a leaf
        forest.insert([0; 32]);
        accumulator.insert([0; 32]);

        // Checking distribution of trees in merkle forest
        assert_eq!(4, accumulator.0.len());
        assert!(accumulator.0[0].is_some());
        assert!(accumulator.0[1].is_some());
        assert!(accumulator.0[2].is_some());
        assert!(accumulator.0[3].is_none());

        // Delete a leaf
        let proof = forest.prove(&[0; 32]);
        assert!(proof.is_some());
        let proof = proof.unwrap();
        assert!(forest.delete(&proof));
        assert!(accumulator.delete(&proof));

        // Checking distribution of trees in merkle forest
        assert_eq!(4, accumulator.0.len());
        assert!(accumulator.0[0].is_none());
        assert!(accumulator.0[1].is_some());
        assert!(accumulator.0[2].is_some());
        assert!(accumulator.0[3].is_none());

        // Checking all the root hashes of trees in merkle forest and accumulator
        for (hash, tree) in accumulator.root_hashes().iter().zip(forest.trees().iter()) {
            match hash {
                None => assert!(tree.is_none()),
                Some(ref hash) => {
                    assert!(tree.is_some());
                    let tree_hash = tree.as_ref().unwrap().root_hash();
                    assert_eq!(hash, tree_hash);
                }
            }
        }
    }
}
