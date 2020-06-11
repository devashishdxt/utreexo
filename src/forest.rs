use alloc::vec::Vec;

#[cfg(feature = "serde-1")]
use serde::{Deserialize, Serialize};

use crate::{merge, Direction, Hash, Proof, Prover, Tree, Utreexo};

/// Merkle forest
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde-1", derive(Serialize, Deserialize))]
pub struct MemoryForest(Vec<Option<Tree>>);

impl MemoryForest {
    /// Creates a new instance of memory forest
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns all the trees in merkle forest
    pub fn trees(&self) -> &[Option<Tree>] {
        &self.0
    }

    /// Verifies inclusion proof of a value in forest
    fn verify(&self, proof: &Proof) -> bool {
        let height = proof.path.height();

        if self.0.len() < (height + 1) {
            return false;
        }

        if let Some(ref tree) = self.0[height] {
            proof.verify(*tree.root_hash())
        } else {
            false
        }
    }

    /// Returns a list of sibling trees corresponding to sibling hashes in proof. This function
    /// assumes that the proof is valid and may panic if the proof is not checked before calling
    /// this function.
    fn get_sibling_trees(&self, proof: &Proof) -> Vec<Tree> {
        let height = proof.path.height();

        // This line panics if merkle tree of given height does not exist. Therefore, proof should
        // be verified before calling this function.
        let mut tree = self.0[height]
            .as_ref()
            .expect("Expected merkle tree of given proof height. Proof is not valid.")
            .clone();

        let mut sibling_trees = Vec::with_capacity(height);

        for (sibling_hash, direction) in proof
            .sibling_hashes
            .iter()
            .rev()
            .zip(proof.path.directions().rev())
        {
            match tree.split() {
                (left_tree, Some(right_tree)) => match direction {
                    Direction::Right => {
                        assert_eq!(right_tree.root_hash(), sibling_hash, "Sibling hash does not match with sub-tree's root hash. Proof is invalid.");
                        sibling_trees.push(right_tree);
                        tree = left_tree;
                    }
                    Direction::Left => {
                        assert_eq!(left_tree.root_hash(), sibling_hash, "Sibling hash does not match with sub-tree's root hash. Proof is invalid.");
                        sibling_trees.push(left_tree);
                        tree = right_tree;
                    }
                },
                (_, None) => unreachable!(
                    "Number of times a tree can be split shoule be equal to its height."
                ),
            }
        }

        sibling_trees.reverse();
        sibling_trees
    }
}

impl Prover for MemoryForest {
    fn prove(&self, leaf_hash: &Hash) -> Option<Proof> {
        for tree in self.0.iter() {
            if let Some(ref tree) = tree {
                let proof = tree.prove(leaf_hash);

                if proof.is_some() {
                    return proof;
                }
            }
        }

        None
    }
}

impl Utreexo for MemoryForest {
    fn insert(&mut self, leaf_hash: Hash) {
        let mut new_tree = Tree::new(leaf_hash);

        for tree in self.0.iter_mut() {
            match tree {
                Some(ref old_tree) => {
                    new_tree = merge(old_tree, &new_tree);
                    *tree = None;
                }
                None => {
                    *tree = Some(new_tree);
                    return;
                }
            }
        }

        self.0.push(Some(new_tree));
    }

    fn delete(&mut self, proof: &Proof) -> bool {
        // Proof should be valid to delete a value from accumulator
        if !self.verify(proof) {
            return false;
        }

        let height = proof.path.height();
        let sibling_trees = self.get_sibling_trees(&proof);

        let mut new_tree = None;

        for (tree, sibling_tree) in self
            .0
            .iter_mut()
            .take(height)
            .zip(sibling_trees.into_iter())
        {
            if let Some(ref mut new_tree) = new_tree {
                *new_tree = merge(&sibling_tree, new_tree);
            } else if tree.is_none() {
                *tree = Some(sibling_tree)
            } else {
                // `unwrap()` is safe here because `None` condition was checked earlier
                new_tree = Some(merge(&sibling_tree, tree.as_ref().unwrap()));
                *tree = None;
            }
        }

        self.0[height] = new_tree;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_memory_forest_ops() {
        let mut forest = MemoryForest::new();

        forest.insert([0; 32].into());
        forest.insert([1; 32].into());
        forest.insert([2; 32].into());
        forest.insert([3; 32].into());
        forest.insert([4; 32].into());
        forest.insert([5; 32].into());
        forest.insert([6; 32].into());
        forest.insert([7; 32].into());
        forest.insert([8; 32].into());
        forest.insert([9; 32].into());

        // Checking distribution of trees in merkle forest
        assert_eq!(4, forest.0.len());
        assert!(forest.0[0].is_none());
        assert!(forest.0[1].is_some());
        assert!(forest.0[2].is_none());
        assert!(forest.0[3].is_some());

        // Delete a leaf
        let proof = forest.prove(&[0; 32].into());
        assert!(proof.is_some());
        assert!(forest.delete(&proof.unwrap()));

        // Checking distribution of trees in merkle forest
        assert_eq!(4, forest.0.len());
        assert!(forest.0[0].is_some());
        assert!(forest.0[1].is_none());
        assert!(forest.0[2].is_none());
        assert!(forest.0[3].is_some());

        // Delete a leaf
        let proof = forest.prove(&[1; 32].into());
        assert!(proof.is_some());
        assert!(forest.delete(&proof.unwrap()));

        // Checking distribution of trees in merkle forest
        assert_eq!(4, forest.0.len());
        assert!(forest.0[0].is_none());
        assert!(forest.0[1].is_none());
        assert!(forest.0[2].is_none());
        assert!(forest.0[3].is_some());

        // Delete a leaf
        let proof = forest.prove(&[2; 32].into());
        assert!(proof.is_some());
        assert!(forest.delete(&proof.unwrap()));

        // Checking distribution of trees in merkle forest
        assert_eq!(4, forest.0.len());
        assert!(forest.0[0].is_some());
        assert!(forest.0[1].is_some());
        assert!(forest.0[2].is_some());
        assert!(forest.0[3].is_none());

        // Delete a leaf
        let proof = forest.prove(&[3; 32].into());
        assert!(proof.is_some());
        assert!(forest.delete(&proof.unwrap()));

        // Checking distribution of trees in merkle forest
        assert_eq!(4, forest.0.len());
        assert!(forest.0[0].is_none());
        assert!(forest.0[1].is_some());
        assert!(forest.0[2].is_some());
        assert!(forest.0[3].is_none());

        // Add a leaf
        forest.insert([0; 32].into());

        // Checking distribution of trees in merkle forest
        assert_eq!(4, forest.0.len());
        assert!(forest.0[0].is_some());
        assert!(forest.0[1].is_some());
        assert!(forest.0[2].is_some());
        assert!(forest.0[3].is_none());

        // Check proof of a value not present in the set
        assert!(forest.prove(&[1; 32].into()).is_none());
    }
}
