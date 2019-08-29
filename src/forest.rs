use alloc::{collections::BTreeMap, vec::Vec};
use core::convert::TryInto;

use crate::{
    hash_intermediate, hash_leaf, hash_many_leaves, num_nodes, Hash, Path, Proof, TreeRef,
    TreeRefMut,
};

/// Implementation of a merkle forest
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Forest {
    /// Number of leaves
    leaves: usize,
    /// Merkle forest
    forest: Vec<Hash>,
    /// Leaf distribution
    leaf_distribution: Vec<usize>,
    /// Path map for leaves
    path_map: BTreeMap<Hash, Path>,
}

impl Forest {
    /// Creates a new empty forest
    #[inline]
    pub fn new() -> Forest {
        Forest::default()
    }

    /// Returns the number of leaves currently stored in forest
    #[inline]
    pub fn leaves(&self) -> usize {
        self.leaves
    }

    /// Returns total number of nodes in forest
    #[inline]
    pub fn nodes(&self) -> usize {
        self.forest.len()
    }

    /// Returns `true` if the forest is empty, `false` otherwise
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.leaves == 0
    }

    /// Inserts a new value in forest
    #[inline]
    pub fn insert<T: AsRef<[u8]>>(&mut self, value: T) {
        // Calculate hash of `value` and insert it into forest
        self.insert_hash(hash_leaf(value))
    }

    /// Batch inserts new values in forest
    #[inline]
    pub fn extend<T: AsRef<[u8]>>(&mut self, values: &[T]) {
        for hash in hash_many_leaves(values) {
            self.insert_hash(hash)
        }
    }

    /// Generates inclusion proof of given leaf value
    pub fn prove<T: AsRef<[u8]>>(&self, value: T) -> Option<Proof<T>> {
        // Get hash of value
        let hash = hash_leaf(&value);

        // Get path of value from `path_map`
        let path = self.path_map.get(&hash)?.clone();

        // Calculate number of leaves in tree of the path
        let leaves = path.leaves();

        // Find the index of tree with above height in leaf distribution
        let index = self
            .leaf_distribution
            .binary_search_by(|p| p.cmp(&leaves).reverse())
            .unwrap();

        // Get tree ref with index
        let tree = self.get_tree_ref_with_index(index);

        // Prove
        tree.prove(value, path)
    }

    /// Verifies inclusion proof
    pub fn verify<T: AsRef<[u8]>>(&self, proof: &Proof<T>) -> bool {
        // Calculate number of leaves in tree of given proof
        let leaves = proof.leaves();

        // Find the index of tree with above height in leaf distribution
        let index = self
            .leaf_distribution
            .binary_search_by(|p| p.cmp(&leaves).reverse());

        match index {
            Err(_) => false,
            Ok(index) => {
                // Calculate the root index of tree with above height in forest
                // (number of places to skip to reach the tree + number of nodes in the tree)
                let root_index = self
                    .leaf_distribution
                    .iter()
                    .take(index)
                    .map(|num_leaves| num_nodes(*num_leaves))
                    .sum::<usize>()
                    + num_nodes(leaves)
                    - 1;

                let root_hash = self.forest[root_index];

                // Verify proof with root hash
                proof.verify(root_hash)
            }
        }
    }

    /// Deletes the leaf corresponding to given proof from tree
    pub fn delete<T: AsRef<[u8]>>(&mut self, proof: Proof<T>) -> bool {
        match self.leaf_distribution.len() {
            0 => false,
            _ => {
                // Find hash of rightmost leaf of rightmost tree in forest
                let last_tree_ref = self.get_tree_ref_with_index(self.leaf_distribution.len() - 1);
                let last_tree_height = last_tree_ref.height();
                let index_of_leaf_to_swap = self.nodes() - last_tree_height - 1;
                let hash_of_leaf_to_swap = self.forest[index_of_leaf_to_swap];

                // Calculate number of leaves in tree of given proof
                let leaves = proof.leaves();

                // Find the index of tree with above height in leaf distribution
                let index = self
                    .leaf_distribution
                    .binary_search_by(|p| p.cmp(&leaves).reverse());

                match index {
                    Err(_) => false,
                    Ok(index) => {
                        // Get mutable reference to tree with index
                        let mut tree_ref_mut = self.get_tree_ref_mut_with_index(index);

                        // Swap and return false if it was unsuccessful
                        if !tree_ref_mut.swap(&proof, hash_of_leaf_to_swap) {
                            false
                        } else {
                            // Split off rightmost `rightmost_tree_height + 1` nodes from tree
                            let index_to_split_off = self.forest.len() - (last_tree_height + 1);
                            let _ = self.forest.split_off(index_to_split_off);

                            // Update leaf distribution
                            let _ = self.leaf_distribution.pop();
                            for i in (0..last_tree_height).rev() {
                                self.leaf_distribution.push(
                                    2usize.pow(
                                        i.try_into().expect("Expected height to be in bounds"),
                                    ),
                                );
                            }

                            // Update leaves
                            self.leaves -= 1;

                            // Update path map
                            self.path_map.insert(hash_of_leaf_to_swap, proof.path);
                            self.path_map.remove(&hash_leaf(proof.leaf_value));

                            for i in 0..last_tree_height {
                                self.update_paths_for_index(self.leaf_distribution.len() - 1 - i);
                            }

                            true
                        }
                    }
                }
            }
        }
    }

    // Insert hash in forest if it does not already exists and run compression
    fn insert_hash(&mut self, hash: Hash) {
        if !self.path_map.contains_key(&hash) {
            self.forest.push(hash);
            self.leaves += 1;
            self.leaf_distribution.push(1);

            self.compress();
            self.update_paths();
        }
    }

    fn get_tree_ref_mut_with_index(&mut self, index: usize) -> TreeRefMut<'_> {
        // Calculate number of nodes before tree in forest
        let nodes_before_tree = self
            .leaf_distribution
            .iter()
            .take(index)
            .map(|leaves| num_nodes(*leaves))
            .sum();

        // Calculate number of nodes in tree
        let nodes_in_tree = num_nodes(self.leaf_distribution[index]);

        // Return tree ref with size
        TreeRefMut(&mut self.forest[nodes_before_tree..(nodes_before_tree + nodes_in_tree)])
    }

    fn get_tree_ref_with_index(&self, index: usize) -> TreeRef<'_> {
        // Calculate number of nodes before tree in forest
        let nodes_before_tree = self
            .leaf_distribution
            .iter()
            .take(index)
            .map(|leaves| num_nodes(*leaves))
            .sum();

        // Calculate number of nodes in tree
        let nodes_in_tree = num_nodes(self.leaf_distribution[index]);

        // Return tree ref with size
        TreeRef(&self.forest[nodes_before_tree..(nodes_before_tree + nodes_in_tree)])
    }

    /// Compresses forest by merging trees of equal length from right to left
    fn compress(&mut self) {
        while self.is_compressible() {
            // Get left and right tree refs
            let left_tree = self.get_tree_ref_with_index(self.leaf_distribution.len() - 2);
            let right_tree = self.get_tree_ref_with_index(self.leaf_distribution.len() - 1);

            // Calculate root hash of merged tree
            let root_hash = hash_intermediate(left_tree.root_hash(), right_tree.root_hash());

            // Push root hash in forest
            self.forest.push(root_hash);

            // Update leaf distribution
            let right_tree_leaves = self
                .leaf_distribution
                .pop()
                .expect("Expected right tree leaves");
            let left_tree_index = self.leaf_distribution.len() - 1;
            self.leaf_distribution[left_tree_index] += right_tree_leaves;
        }
    }

    /// Returns true if current tree can be compressed
    fn is_compressible(&self) -> bool {
        // Compression cannot be performed if the number of trees are either 0 or 1.
        // Compression has to be performed only when last two trees are of equal length.
        self.leaf_distribution.len() >= 2
            && self.leaf_distribution[self.leaf_distribution.len() - 1]
                == self.leaf_distribution[self.leaf_distribution.len() - 2]
    }

    /// Updates path for all the leaves after one insertion (updates paths for all the leaves in last tree)
    ///
    /// # Note
    ///
    /// This function should be called after each (insertion + compression) operation
    fn update_paths(&mut self) {
        self.update_paths_for_index(self.leaf_distribution.len() - 1);
    }

    /// Updates path for all the leaves for tree with given index
    fn update_paths_for_index(&mut self, index: usize) {
        // Get tree ref of index
        let tree_ref = self.get_tree_ref_with_index(index);

        // Get leaf hashes and leaf paths
        let leaf_hashes = tree_ref.leaf_hashes();
        let leaf_paths = tree_ref.leaf_paths();

        // Insert into path map
        self.path_map
            .extend(leaf_hashes.into_iter().zip(leaf_paths.into_iter()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::leaf_distribution;

    #[test]
    fn check_forest_flow() {
        let mut forest = Forest::new();
        assert!(forest.is_empty());

        forest.insert("hello0");
        assert!(!forest.is_empty());
        assert_eq!(1, forest.leaves());
        assert_eq!(1, forest.nodes());

        forest.insert("hello1");
        assert_eq!(2, forest.leaves());
        assert_eq!(3, forest.nodes());

        forest.extend(&["hello2", "hello3"]);
        assert_eq!(4, forest.leaves());
        assert_eq!(7, forest.nodes());

        forest.insert("hello4");
        assert_eq!(5, forest.leaves());
        assert_eq!(8, forest.nodes());

        forest.insert("hello5");
        assert_eq!(6, forest.leaves());
        assert_eq!(10, forest.nodes());

        forest.insert("hello6");
        assert_eq!(7, forest.leaves());
        assert_eq!(11, forest.nodes());

        let proof = forest.prove("hello0").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello1").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello2").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello3").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello4").expect("Expected a proof");
        assert_eq!(1, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello5").expect("Expected a proof");
        assert_eq!(1, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello6").expect("Expected a proof");
        assert_eq!(0, proof.height());
        assert!(forest.verify(&proof));

        assert_eq!(leaf_distribution(7), forest.leaf_distribution);

        assert!(forest.prove("hello7").is_none());

        forest.insert("hello7");
        assert_eq!(8, forest.leaves());
        assert_eq!(15, forest.nodes());

        let proof = forest.prove("hello7").expect("Expected a proof");
        assert_eq!(3, proof.height());
        assert!(forest.verify(&proof));

        assert!(forest.delete(proof));

        assert_eq!(7, forest.leaves());
        assert_eq!(11, forest.nodes());

        assert_eq!(leaf_distribution(7), forest.leaf_distribution);
        assert!(forest.prove("hello7").is_none());

        let proof = forest.prove("hello0").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello1").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello2").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello3").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello4").expect("Expected a proof");
        assert_eq!(1, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello5").expect("Expected a proof");
        assert_eq!(1, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello6").expect("Expected a proof");
        assert_eq!(0, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello3").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        assert!(forest.delete(proof));

        assert_eq!(6, forest.leaves());
        assert_eq!(10, forest.nodes());

        assert_eq!(leaf_distribution(6), forest.leaf_distribution);
        assert!(forest.prove("hello3").is_none());

        let proof = forest.prove("hello0").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello1").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello2").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello6").expect("Expected a proof");
        assert_eq!(2, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello4").expect("Expected a proof");
        assert_eq!(1, proof.height());
        assert!(forest.verify(&proof));

        let proof = forest.prove("hello5").expect("Expected a proof");
        assert_eq!(1, proof.height());
        assert!(forest.verify(&proof));
    }
}
