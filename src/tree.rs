use alloc::vec::Vec;
use core::convert::TryInto;

use crate::{hash_intermediate, Hash, Path};

/// An owned `Vec` representing a merkle tree
//
// # Tree representation: Numbers are index/position of nodes in vector containing the full tree
//
//              14 <- Root hash
//              / \
//             /   \
//            /     \
//           /       \
//          /         \
//         /           \
//        /             \
//       6              13
//      / \             / \
//     /   \           /   \
//    /     \         /     \
//   2       5       9      12
//  / \     / \     / \     / \
// 0   1   3   4   7   8  10   11 <- Leaves
#[derive(Debug)]
#[repr(transparent)]
pub struct Tree(pub(crate) Vec<Hash>);

impl Tree {
    /// Returns `TreeRef` for current tree
    #[inline]
    pub fn as_ref(&self) -> TreeRef<'_> {
        TreeRef(&self.0)
    }

    /// Returns number of leaves in tree
    #[inline]
    pub fn leaves(&self) -> usize {
        self.as_ref().leaves()
    }

    /// Returns number of nodes in tree
    #[inline]
    pub fn nodes(&self) -> usize {
        self.as_ref().nodes()
    }

    /// Returns height of tree
    #[inline]
    pub fn height(&self) -> usize {
        self.as_ref().height()
    }

    /// Returns root hash of tree
    #[inline]
    pub fn root_hash(&self) -> Hash {
        self.as_ref().root_hash()
    }

    /// Returns hashes of all the leaves in tree
    #[inline]
    pub fn leaf_hashes(&self) -> Vec<Hash> {
        self.as_ref().leaf_hashes()
    }

    /// Returns paths to all the leaves in tree
    #[inline]
    pub fn leaf_paths(&self) -> Vec<Path> {
        self.as_ref().leaf_paths()
    }

    /// Returns left and right subtree of current tree
    ///
    /// # Panics
    ///
    /// This function panics if the tree cannot be split further (when there is only one leaf in the tree)
    pub fn split(mut self) -> (Tree, Tree) {
        assert!(
            self.nodes() <= 1,
            "Cannot split a tree with less than or equal to one node"
        );

        let right = Tree(self.0.split_off(self.nodes() / 2));
        self.0.shrink_to_fit();

        (self, right)
    }

    /// Merges `other` tree in current tree
    ///
    /// # Panics
    ///
    /// This function panics if both trees are of different height
    pub fn merge(&mut self, mut other: Tree) {
        let height = self.height();

        assert_eq!(
            height,
            other.height(),
            "Cannot merge trees with different heights"
        );

        let root_hash = hash_intermediate(self.root_hash(), other.root_hash());

        self.0.append(&mut other.0);
        self.0.push(root_hash);
        self.0.shrink_to_fit();

        debug_assert_eq!(height + 1, self.height());
    }
}

/// Reference to a slice representing a merkle tree
#[derive(Debug)]
#[repr(transparent)]
pub struct TreeRef<'a>(pub(crate) &'a [Hash]);

impl<'a> TreeRef<'a> {
    /// Returns number of leaves in tree
    #[inline]
    pub fn leaves(&self) -> usize {
        (self.nodes() / 2) + 1 // This should ideally be [(nodes + 1) / 2] but that may cause overflow.
    }

    /// Returns number of nodes in tree
    #[inline]
    pub fn nodes(&self) -> usize {
        debug_assert!(self.0.len() % 2 == 1);
        self.0.len()
    }

    /// Returns height of tree
    #[inline]
    pub fn height(&self) -> usize {
        self.leaves()
            .trailing_zeros()
            .try_into()
            .expect("Cannot calculate height for trees with too many leaves")
    }

    /// Returns root hash of tree
    #[inline]
    pub fn root_hash(&self) -> Hash {
        self.0[self.nodes() - 1]
    }

    /// Returns left and right subtree of current tree; `None` if the tree cannot be split further
    pub fn split(&self) -> Option<(TreeRef<'_>, TreeRef<'_>)> {
        if self.nodes() > 1 {
            let break_point = (self.nodes() - 1) / 2;
            Some((
                TreeRef(&self.0[0..break_point]),
                TreeRef(&self.0[break_point..(self.nodes() - 1)]),
            ))
        } else {
            None
        }
    }

    /// Returns hashes of all the leaves in tree
    pub fn leaf_hashes(&self) -> Vec<Hash> {
        let leaves = self.leaves();
        let height = self.height();

        if leaves == 1 {
            debug_assert_eq!(1, self.0.len());
            return self.0.to_vec();
        }

        let mut leaf_indexes = Vec::with_capacity(leaves);

        let mut index = 0;

        for i in (1..height).chain((1..height - 1).rev()) {
            leaf_indexes.push(self.0[index]);
            leaf_indexes.push(self.0[index + 1]);

            index += i + 2;
        }

        leaf_indexes.push(self.0[index]);
        leaf_indexes.push(self.0[index + 1]);

        leaf_indexes
    }

    /// Returns paths to all the leaves in tree
    #[inline]
    pub fn leaf_paths(&self) -> Vec<Path> {
        Path::for_height(self.height())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{hash_leaf, Direction};

    #[test]
    fn check_leaves_and_height() {
        let nodes = (0..15)
            .map(|value: usize| hash_leaf(&value.to_be_bytes()))
            .collect::<Vec<Hash>>();
        let tree = Tree(nodes);

        assert_eq!(15, tree.nodes());
        assert_eq!(8, tree.leaves());
        assert_eq!(3, tree.height());
    }

    #[test]
    fn check_leaf_hashes() {
        let nodes = (0..15)
            .map(|value: usize| hash_leaf(&value.to_be_bytes()))
            .collect::<Vec<Hash>>();
        let manual_leaf_hashes = vec![
            nodes[0], nodes[1], nodes[3], nodes[4], nodes[7], nodes[8], nodes[10], nodes[11],
        ];

        let tree = Tree(nodes);
        let leaf_hashes = tree.leaf_hashes();

        assert_eq!(leaf_hashes, manual_leaf_hashes);
    }

    #[test]
    fn check_leaf_paths() {
        let nodes = (0..15)
            .map(|value: usize| hash_leaf(&value.to_be_bytes()))
            .collect::<Vec<Hash>>();

        let tree = Tree(nodes);
        let leaf_paths = tree.leaf_paths();

        let mut first_leaf_directions = leaf_paths[0].directions();

        assert_eq!(Direction::Left, first_leaf_directions.next().unwrap());
        assert_eq!(Direction::Left, first_leaf_directions.next().unwrap());
        assert_eq!(Direction::Left, first_leaf_directions.next().unwrap());
        assert!(first_leaf_directions.next().is_none());

        let mut second_leaf_directions = leaf_paths[1].directions();

        assert_eq!(Direction::Left, second_leaf_directions.next().unwrap());
        assert_eq!(Direction::Left, second_leaf_directions.next().unwrap());
        assert_eq!(Direction::Right, second_leaf_directions.next().unwrap());
        assert!(second_leaf_directions.next().is_none());

        let mut third_leaf_directions = leaf_paths[2].directions();

        assert_eq!(Direction::Left, third_leaf_directions.next().unwrap());
        assert_eq!(Direction::Right, third_leaf_directions.next().unwrap());
        assert_eq!(Direction::Left, third_leaf_directions.next().unwrap());
        assert!(third_leaf_directions.next().is_none());

        let mut fourth_leaf_directions = leaf_paths[3].directions();

        assert_eq!(Direction::Left, fourth_leaf_directions.next().unwrap());
        assert_eq!(Direction::Right, fourth_leaf_directions.next().unwrap());
        assert_eq!(Direction::Right, fourth_leaf_directions.next().unwrap());
        assert!(fourth_leaf_directions.next().is_none());

        let mut fifth_leaf_directions = leaf_paths[4].directions();

        assert_eq!(Direction::Right, fifth_leaf_directions.next().unwrap());
        assert_eq!(Direction::Left, fifth_leaf_directions.next().unwrap());
        assert_eq!(Direction::Left, fifth_leaf_directions.next().unwrap());
        assert!(fifth_leaf_directions.next().is_none());

        let mut sixth_leaf_directions = leaf_paths[5].directions();

        assert_eq!(Direction::Right, sixth_leaf_directions.next().unwrap());
        assert_eq!(Direction::Left, sixth_leaf_directions.next().unwrap());
        assert_eq!(Direction::Right, sixth_leaf_directions.next().unwrap());
        assert!(sixth_leaf_directions.next().is_none());

        let mut seventh_leaf_directions = leaf_paths[6].directions();

        assert_eq!(Direction::Right, seventh_leaf_directions.next().unwrap());
        assert_eq!(Direction::Right, seventh_leaf_directions.next().unwrap());
        assert_eq!(Direction::Left, seventh_leaf_directions.next().unwrap());
        assert!(seventh_leaf_directions.next().is_none());

        let mut eighth_leaf_directions = leaf_paths[7].directions();

        assert_eq!(Direction::Right, eighth_leaf_directions.next().unwrap());
        assert_eq!(Direction::Right, eighth_leaf_directions.next().unwrap());
        assert_eq!(Direction::Right, eighth_leaf_directions.next().unwrap());
        assert!(eighth_leaf_directions.next().is_none());
    }
}
