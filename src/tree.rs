use alloc::vec::Vec;
use core::convert::TryInto;

use crate::{Hash, Path};

/// An owned `Vec` representing a merkle tree
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
        if self.nodes() <= 1 {
            panic!("Cannot split a tree with less than or equal to one node")
        }

        let right = Tree(self.0.split_off(self.nodes() / 2));
        self.0.shrink_to_fit();

        (self, right)
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
        debug_assert!(self.nodes() % 2 == 1);
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
