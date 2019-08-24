use std::iter::repeat;

use blake2b_simd::{many::update_many, Hash as Blake2Hash, State};

use crate::Hash;

const MAX_ALLOWED_LEAVES: usize = usize::max_value() / 2;

/// Implementation of balanced merkle tree (assumes that the tree has 2<sup>i</sup> leaves)
#[derive(Debug)]
#[repr(transparent)]
pub struct BalancedMerkleTree(Vec<Blake2Hash>);

impl BalancedMerkleTree {
    /// Creates a new balance merkle tree with a single leaf node
    pub fn new_single<T: AsRef<[u8]>>(leaf: &T) -> Self {
        let mut state = State::new();

        // Add `0` byte to leaf nodes to prevent second preimage attack
        // https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
        state.update(&[0]);
        state.update(leaf.as_ref());

        Self(vec![state.finalize()])
    }

    /// Creates a new balanced merkle tree with given leaves. Returns `None` if number of leaves is not a power of two
    pub fn new<T: AsRef<[u8]>>(leaves: &[T]) -> Option<Self> {
        if !leaves.len().is_power_of_two() || leaves.len() > MAX_ALLOWED_LEAVES {
            // Returns `None` if number of leaves is not a power of two or if it is more than the maximum allowed value
            return None;
        }

        // A tree with `n` leaves contains `2n - 1` nodes
        let mut hashes = Vec::with_capacity((2 * leaves.len()) - 1);

        // Start with hashing all the leaves
        let mut states = vec![State::new(); leaves.len()];

        // Add `0` byte to leaf nodes to prevent second preimage attack
        // https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
        update_many(states.iter_mut().zip(repeat(&[0]).take(leaves.len())));
        update_many(states.iter_mut().zip(leaves.iter()));

        hashes.extend(states.iter().map(State::finalize));

        // Height of resulting merkle tree will be equal to trailing zeros in binary representation of its length
        let height = leaves.len().trailing_zeros();

        let mut skip = 0;
        let mut take = hashes.len();

        for _ in 0..height {
            // For each height, compute hashes of combined pairs of previous hashes
            states = vec![State::new(); take / 2];

            // Add `1` byte to intermediate nodes to prevent second preimage attack
            // https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
            update_many(states.iter_mut().zip(repeat(&[1]).take(take / 2)));
            update_many(states.iter_mut().zip(hashes.iter().skip(skip).step_by(2)));
            update_many(
                states
                    .iter_mut()
                    .zip(hashes.iter().skip(skip + 1).step_by(2)),
            );

            hashes.extend(states.iter().map(State::finalize));

            skip = take;
            take /= 2;
        }

        // After hashing for all the heights, hashes `Vec` should be full
        debug_assert_eq!(
            hashes.capacity(),
            hashes.len(),
            "Hashes are not filled completely while creating a balanced merkle tree"
        );

        Some(BalancedMerkleTree(hashes))
    }

    /// Returns the number of leaves in merkle tree
    #[inline]
    pub fn leaves(&self) -> usize {
        (self.0.len() + 1) / 2
    }

    /// Returns the height of merkle tree
    #[inline]
    pub fn height(&self) -> u32 {
        self.leaves().trailing_zeros()
    }

    /// Return root hash of merkle tree
    #[inline]
    pub fn root_hash(&self) -> Hash {
        Hash(*self.0[self.0.len() - 1].as_array())
    }

    /// Splits current merkle tree into two equal halves
    ///
    /// # Panics
    ///
    /// This function panics if current merkle tree cannot be split further, i.e., it only has one leaf
    pub fn split(self) -> (BalancedMerkleTree, BalancedMerkleTree) {
        let length = self.leaves();

        if length == 1 {
            panic!("Cannot split a merkle tree with only one leaf node");
        }

        let height = self.height();

        let mut first_half = Vec::with_capacity((self.0.len() - 1) / 2);
        let mut second_half = Vec::with_capacity((self.0.len() - 1) / 2);

        let mut hashes = self.0.into_iter();
        let mut items_to_take = length / 2;

        for _ in 0..height {
            // Fill first half with `items_to_take` hashes
            for _ in 0..items_to_take {
                first_half.push(hashes.next().unwrap());
            }

            // Fill second half with `items_to_take` hashes
            for _ in 0..items_to_take {
                second_half.push(hashes.next().unwrap());
            }

            // Update `items_to_take`
            items_to_take /= 2;
        }

        // After splitting is complete, both halves' `Vec` should be full
        debug_assert_eq!(
            first_half.len(),
            first_half.capacity(),
            "First half is not filled completely while splitting a merkle tree"
        );
        debug_assert_eq!(
            second_half.len(),
            second_half.capacity(),
            "Second half is not filled completely while splitting a merkle tree"
        );

        (
            BalancedMerkleTree(first_half),
            BalancedMerkleTree(second_half),
        )
    }

    /// Merges two balanced merkle trees of same length
    ///
    /// # Panics
    ///
    /// This function panics if the two merkle tree are of different lengths
    pub fn merge(
        first_half: BalancedMerkleTree,
        second_half: BalancedMerkleTree,
    ) -> BalancedMerkleTree {
        if first_half.leaves() != second_half.leaves() {
            panic!("Cannot merge two merkle trees with different lengths");
        }

        let height = first_half.height();

        let mut hashes = Vec::with_capacity(first_half.0.len() + second_half.0.len() + 1);

        let mut items_to_take = first_half.leaves();

        let mut first_half_hashes = first_half.0.into_iter();
        let mut second_half_hashes = second_half.0.into_iter();

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
        let mut state = State::new();

        // Add `1` byte to intermediate nodes to prevent second preimage attack
        // https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
        state.update(&[1]);
        state.update(hashes[hashes.len() - 2].as_ref());
        state.update(hashes[hashes.len() - 1].as_ref());

        hashes.push(state.finalize());

        // After hashing for all the heights, hashes `Vec` should be full
        debug_assert_eq!(
            hashes.capacity(),
            hashes.len(),
            "Hashes are not filled completely while merging two balanced merkle trees"
        );

        BalancedMerkleTree(hashes)
    }

    /// Returns the maximum number of leaves allowed in balanced merkle tree
    #[inline]
    pub fn max_leaves() -> usize {
        MAX_ALLOWED_LEAVES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_merkle_tree_size_0() {
        assert!(BalancedMerkleTree::new::<String>(&[]).is_none());
    }

    #[test]
    fn balanced_merkle_tree_size_1() {
        let inputs = vec![b"hello"];

        let root_hash = inputs.iter().map(leaf_hash).collect::<Vec<Blake2Hash>>()[0];

        let tree = BalancedMerkleTree::new_single(&inputs[0]);

        assert_eq!(Hash(*root_hash.as_array()), tree.root_hash());
        assert_eq!(1, tree.leaves());
        assert_eq!(0, tree.height());
    }

    #[test]
    fn balanced_merkle_tree_size_4() {
        let inputs = vec![b"hello"; 4];

        let leaf_hashes = inputs.iter().map(leaf_hash).collect::<Vec<Blake2Hash>>();
        let intermediate_hashes = vec![
            hash(leaf_hashes[0], leaf_hashes[1]),
            hash(leaf_hashes[2], leaf_hashes[3]),
        ];
        let root_hash = hash(intermediate_hashes[0], intermediate_hashes[1]);

        let tree = BalancedMerkleTree::new(&inputs).unwrap();

        assert_eq!(Hash(*root_hash.as_array()), tree.root_hash());
        assert_eq!(4, tree.leaves());
        assert_eq!(2, tree.height());

        let (first_half, second_half) = tree.split();

        assert_eq!(
            Hash(*intermediate_hashes[0].as_array()),
            first_half.root_hash()
        );
        assert_eq!(2, first_half.leaves());
        assert_eq!(1, first_half.height());

        assert_eq!(
            Hash(*intermediate_hashes[1].as_array()),
            second_half.root_hash()
        );
        assert_eq!(2, second_half.leaves());
        assert_eq!(1, second_half.height());

        let merged_tree = BalancedMerkleTree::merge(first_half, second_half);

        assert_eq!(Hash(*root_hash.as_array()), merged_tree.root_hash());
        assert_eq!(4, merged_tree.leaves());
        assert_eq!(2, merged_tree.height());
    }

    fn leaf_hash<T: AsRef<[u8]>>(a: T) -> Blake2Hash {
        let mut state = State::new();

        state.update(&[0]);
        state.update(a.as_ref());

        state.finalize()
    }

    fn hash<T: AsRef<[u8]>>(a: T, b: T) -> Blake2Hash {
        let mut state = State::new();

        state.update(&[1]);
        state.update(a.as_ref());
        state.update(b.as_ref());

        state.finalize()
    }
}
