use alloc::{collections::BTreeMap, vec::Vec};

use bit_vec::BitVec;

use crate::{hash_intermediate, hash_leaf, hash_many_leaves, Direction, Hash, Path, Proof};

/// Implementation of a merkle forest
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Forest {
    /// Number of leaves
    leaves: usize,
    /// Merkle forest
    forest: Vec<Hash>,
    /// Leaf distribution
    leaf_distribution: Vec<usize>,
    /// Paths for leaves
    paths: BTreeMap<Hash, Path>,
}

impl Forest {
    /// Returns the number of leaves currently stored in forest
    #[inline]
    pub fn leaves(&self) -> usize {
        self.leaves
    }

    /// Returns total number of nodes in forest
    #[inline]
    pub fn len(&self) -> usize {
        self.forest.len()
    }

    /// Returns `true` if the forest is empty, `false` otherwise
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.leaves == 0
    }

    /// Inserts a new value in forest
    pub fn insert<T: AsRef<[u8]>>(&mut self, value: T) {
        // Calculate hash of `value`
        let hash = hash_leaf(value);

        // Insert hash in forest if it does not already exists and run compression
        if !self.paths.contains_key(&hash) {
            self.forest.push(hash);
            self.leaves += 1;
            self.leaf_distribution.push(1);

            self.compress();
        }
    }

    /// Batch inserts new values in forest
    pub fn extend<T: AsRef<[u8]>>(&mut self, values: &[T]) {
        for hash in hash_many_leaves(values) {
            if !self.paths.contains_key(&hash) {
                self.forest.push(hash);
                self.leaves += 1;
                self.leaf_distribution.push(1);

                self.compress();
            }
        }
    }

    /// Generates inclusion proof of given leaf value
    pub fn prove<T: AsRef<[u8]>>(&self, value: T) -> Option<Proof> {
        // Get hash of value
        let hash = hash_leaf(value);

        // Get path of value from `paths` map
        let path = self.paths.get(&hash)?.clone();

        // Calculate number of leaves and height of tree of the path
        let leaves = path.leaves();
        let height = path.height();

        // Find the index of tree with above height in leaf distribution
        let index = self
            .leaf_distribution
            .binary_search_by(|p| p.cmp(&leaves).reverse())
            .unwrap();

        // Calculate the root index of tree with above height in forest
        // (number of places to skip to reach the tree + number of nodes in the tree - 1)
        let root_index = self
            .leaf_distribution
            .iter()
            .take(index)
            .map(|num_leaves| num_nodes(*num_leaves))
            .sum::<usize>()
            + num_nodes(leaves)
            - 1;

        let mut accumulating_index = 0;

        // # Formulas
        //
        // Go to the right child:
        //   right child index = root_index - ((2 * accumulator_index) + 1)
        //   new accumulator index = (2 * accumulator_index) + 1
        //
        // Go to the left child:
        //   left child index = root_index - ((2 * accumulator_index) + 2)
        //   new accumulator index = (2 * accumulator_index) + 2

        let mut sibling_hashes = Vec::with_capacity(height);

        for direction in path.directions().rev() {
            match direction {
                Direction::Left => {
                    // Add hash of right index to sibling hashes and move accumulator to left index
                    sibling_hashes.push(self.forest[root_index - ((accumulating_index * 2) + 1)]);
                    accumulating_index = (accumulating_index * 2) + 2;
                }
                Direction::Right => {
                    // Add hash of left index to sibling hashes and move accumulator to right index
                    sibling_hashes.push(self.forest[root_index - ((accumulating_index * 2) + 2)]);
                    accumulating_index = (accumulating_index * 2) + 1;
                }
            }
        }

        let leaf_hash = self.forest[root_index - accumulating_index];

        // Reverse sibling hashes because proof expects these hashes from bottom to top
        sibling_hashes.reverse();

        // Sibling hashes should be full
        debug_assert_eq!(sibling_hashes.len(), sibling_hashes.capacity());

        Some(Proof {
            path,
            leaf_hash,
            sibling_hashes,
        })
    }

    /// Verifies inclusion proof
    pub fn verify(&self, proof: &Proof) -> bool {
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

    /// Compresses forest by merging trees of equal length from right to left
    fn compress(&mut self) {
        // Compression cannot be performed if the number of trees are either 0 or 1
        while self.leaf_distribution.len() >= 2
            && self.leaf_distribution[self.leaf_distribution.len() - 1]
                == self.leaf_distribution[self.leaf_distribution.len() - 2]
        {
            // Calculate number of hashes before last two trees
            let skip: usize = self
                .leaf_distribution
                .iter()
                .take(self.leaf_distribution.len() - 2)
                .map(|num_leaves| num_nodes(*num_leaves))
                .sum();

            // Split off the two trees to merge in two different `Vec`s
            let mut first_half = self.forest.split_off(skip);
            let second_half = first_half.split_off(first_half.len() / 2);

            // Number of leaves, nodes and height of both halves
            let leaves = self.leaf_distribution[self.leaf_distribution.len() - 1];
            let nodes = num_nodes(leaves);
            let height = height(leaves);

            // Length of both halves should be equal to number of nodes
            debug_assert_eq!(nodes, first_half.len());
            debug_assert_eq!(nodes, second_half.len());

            let mut items_to_take = leaves;
            let mut hashes = Vec::with_capacity((2 * nodes) + 1);

            let mut first_half_hashes = first_half.into_iter();
            let mut second_half_hashes = second_half.into_iter();

            for _ in 0..=height {
                // Take lowermost row from first half
                for _ in 0..items_to_take {
                    hashes.push(first_half_hashes.next().unwrap());
                }

                // Take lowermost row from second half
                for _ in 0..items_to_take {
                    hashes.push(second_half_hashes.next().unwrap());
                }

                // Update `items_to_take`
                items_to_take /= 2;
            }

            // Calculate new root and add it to hashes
            hashes.push(hash_intermediate(
                &hashes[hashes.len() - 2],
                &hashes[hashes.len() - 1],
            ));

            // After hashing for all the heights, hashes `Vec` should be full
            debug_assert_eq!(
                hashes.capacity(),
                hashes.len(),
                "Hashes are not filled completely while merging two balanced merkle trees"
            );

            self.forest.append(&mut hashes);

            // Modify leaf distribution
            let first_half_leaves = self.leaf_distribution.pop().unwrap();
            let second_half_leaves = self.leaf_distribution.pop().unwrap();
            self.leaf_distribution
                .push(first_half_leaves + second_half_leaves);
        }

        // Update path of leaves in set
        self.update_paths();
    }

    /// Updates path for all the leaves after one insertion
    ///
    /// # Note
    ///
    /// This function should be called after each (insertion + compression) operation
    fn update_paths(&mut self) {
        // Calculate number of hashes before last tree
        let skip: usize = self
            .leaf_distribution
            .iter()
            .take(self.leaf_distribution.len() - 1)
            .map(|num_leaves| num_nodes(*num_leaves))
            .sum();

        // Number of leaves in last tree
        let leaves = self.leaf_distribution[self.leaf_distribution.len() - 1];

        // Height of last tree
        let height = height(leaves);

        // Leaves to be updated
        let hashes = self.forest.iter().skip(skip).take(leaves);

        for hash in hashes {
            match self.paths.get_mut(hash) {
                None => {
                    let path = BitVec::from_elem(height, Direction::Right.into());
                    self.paths.insert(*hash, Path(path));
                }
                Some(ref mut path) => {
                    let steps_to_insert = height - path.height();
                    debug_assert!(steps_to_insert > 0);

                    path.0.reserve(steps_to_insert);
                    path.0.push(Direction::Left.into());

                    for _ in 0..(steps_to_insert - 1) {
                        path.0.push(Direction::Right.into());
                    }
                }
            }
        }
    }
}

/// Returns the number of nodes in a tree given the number of leaves (`2n - 1`)
#[inline]
fn num_nodes(num_leaves: usize) -> usize {
    if num_leaves == 0 {
        0
    } else {
        (2 * num_leaves) - 1
    }
}

/// Returns height of tree with given number of leaves
#[inline]
fn height(num_leaves: usize) -> usize {
    num_leaves.trailing_zeros() as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    const NUM_TESTING_LEAVES: usize = 1024; // 2^10

    #[test]
    fn check_flow() {
        let mut inputs = Vec::default();

        let mut forest = Forest::default();

        assert_eq!(0, forest.leaves());
        assert_eq!(num_nodes(forest.leaves()), forest.len());
        assert!(forest.is_empty());

        for i in 0..NUM_TESTING_LEAVES {
            let input = format!("hello{}", i);

            forest.insert(&input);
            inputs.push(input);

            assert_eq!(i + 1, forest.leaves());
            assert_eq!(
                leaf_distribution(forest.leaves())
                    .into_iter()
                    .map(num_nodes)
                    .sum::<usize>(),
                forest.len()
            );
            assert!(!forest.is_empty());
        }

        assert_eq!(NUM_TESTING_LEAVES, forest.paths.len());

        let mut batch_forest = Forest::default();
        batch_forest.extend(&inputs);

        assert_eq!(forest, batch_forest);
        assert!(forest.prove(format!("hello")).is_none());

        let proof = forest.prove(format!("hello512")).unwrap();
        assert!(forest.verify(&proof))
    }

    /// Returns leaf distribution in merkle forest for given number of leaf values
    fn leaf_distribution(mut num: usize) -> Vec<usize> {
        let mut distribution = <Vec<usize>>::default();

        let start = height(num);
        let finish = (core::mem::size_of::<usize>() * 8) - (num.leading_zeros() as usize);
        num >>= start;

        for i in start..finish {
            if num & 1 == 1 {
                distribution.push(2_usize.pow(i as u32));
            }
            num >>= 1;
        }

        distribution.reverse();
        distribution
    }
}
