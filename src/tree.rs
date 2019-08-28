use alloc::vec::Vec;

use crate::{hash_leaf, height, Direction, Hash, Path, Proof};

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
        height(self.leaves())
    }

    /// Returns root hash of tree
    #[inline]
    pub fn root_hash(&self) -> Hash {
        self.0[self.nodes() - 1]
    }

    /// Returns left and right subtree of current tree; `None` if the tree cannot be split further
    pub fn split(&self) -> Option<(TreeRef<'a>, TreeRef<'a>)> {
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

    /// Generates inclusion proof for given leaf hash and path
    pub fn prove<T: AsRef<[u8]>>(self, leaf_value: T, path: Path) -> Option<Proof<T>> {
        let leaf_hash = hash_leaf(&leaf_value);
        let height = self.height();

        assert_eq!(
            height,
            path.height(),
            "Tree height and path height should be equal to generate a proof"
        );

        let mut sibling_hashes = Vec::with_capacity(height);

        let mut tree = self;

        for direction in path.directions() {
            let (left_subtree, right_subtree) =
                tree.split().expect("Expected sub-trees while proving");

            match direction {
                Direction::Left => {
                    sibling_hashes.push(right_subtree.root_hash());
                    tree = left_subtree;
                }
                Direction::Right => {
                    sibling_hashes.push(left_subtree.root_hash());
                    tree = right_subtree;
                }
            }
        }

        if tree.root_hash() == leaf_hash {
            Some(Proof {
                path,
                leaf_value,
                sibling_hashes,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{hash_leaf, Direction};

    #[test]
    fn check_tree_leaves_and_height() {
        let nodes = (0..15)
            .map(|value: usize| hash_leaf(&value.to_be_bytes()))
            .collect::<Vec<Hash>>();
        let tree = TreeRef(&nodes);

        assert_eq!(15, tree.nodes());
        assert_eq!(8, tree.leaves());
        assert_eq!(3, tree.height());
    }

    #[test]
    fn check_tree_leaf_hashes() {
        let nodes = (0..15)
            .map(|value: usize| hash_leaf(&value.to_be_bytes()))
            .collect::<Vec<Hash>>();
        let manual_leaf_hashes = vec![
            nodes[0], nodes[1], nodes[3], nodes[4], nodes[7], nodes[8], nodes[10], nodes[11],
        ];

        let tree = TreeRef(&nodes);
        let leaf_hashes = tree.leaf_hashes();

        assert_eq!(leaf_hashes, manual_leaf_hashes);
    }

    #[test]
    fn check_tree_leaf_paths() {
        let nodes = (0..15)
            .map(|value: usize| hash_leaf(&value.to_be_bytes()))
            .collect::<Vec<Hash>>();

        let tree = TreeRef(&nodes);
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
