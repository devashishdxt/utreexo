use alloc::vec::Vec;

use blake3::Hash;

use crate::{merge, Direction, Proof, Prover, Tree, Utreexo};

/// Merkle forest
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MemoryForest(Vec<Option<Tree>>);

impl MemoryForest {
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
