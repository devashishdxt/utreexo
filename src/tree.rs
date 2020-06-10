use alloc::{vec, vec::Vec};
use core::convert::TryInto;

use blake3::Hash;
use indexmap::{indexset, IndexSet};

use crate::{hash_intermediate, Direction, Path, Proof};

/// Merkle tree
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
//
// In addition to all the nodes, tree also contains an ordered set of all the leaves
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    nodes: Vec<Hash>,
    leaves: IndexSet<Hash>,
}

impl Tree {
    /// Creates a new tree with given leaf_hash
    pub fn new(leaf_hash: Hash) -> Self {
        Self {
            nodes: vec![leaf_hash],
            leaves: indexset![leaf_hash],
        }
    }

    /// Returns the number of leaves in the tree
    pub fn leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Returns height of the tree
    pub fn height(&self) -> usize {
        let num_leaves = self.leaves();

        num_leaves
            .trailing_zeros()
            .try_into()
            .expect("Cannot calculate height for trees with too many leaves")
    }

    /// Returns root hash of merkle tree
    pub fn root_hash(&self) -> &Hash {
        self.nodes
            .last()
            .expect("Expected atleast one element in merkle tree.")
    }

    /// Returns inclusion proof of a leaf hash in the tree, if present
    pub fn prove(&self, hash: &Hash) -> Option<Proof> {
        let height = self.height();

        let position = self.leaves.get_index_of(hash)?;
        let path = Path::for_height_and_num(height, position);

        let mut sibling_hashes = Vec::with_capacity(height);

        let mut current_root_index = self.nodes.len() - 1;
        let mut current_base_index = 0;

        for direction in path.directions().rev() {
            match direction {
                Direction::Right => {
                    let sibling_index = current_root_index - 1;
                    sibling_hashes.push(self.nodes[sibling_index]);
                    current_root_index =
                        ((current_root_index - current_base_index) / 2) - 1 + current_base_index;
                }
                Direction::Left => {
                    let sibling_index =
                        ((current_root_index - current_base_index) / 2) - 1 + current_base_index;
                    sibling_hashes.push(self.nodes[sibling_index]);
                    current_root_index -= 1;
                    current_base_index = sibling_index + 1;
                }
            }
        }

        sibling_hashes.reverse();

        Some(Proof {
            path,
            leaf_hash: *hash,
            sibling_hashes,
        })
    }

    /// Splits a tree and returns both subtrees. If there is only one node in the tree, the right
    /// subtree will be returned as `None`.
    pub fn split(&self) -> (Self, Option<Self>) {
        if self.leaves() == 1 {
            return (self.clone(), None);
        }

        // First, we equally split nodes of merkle tree into two parts (excluding root node)
        assert!(
            self.nodes.len() % 2 == 1,
            "Merkle tree should contain odd number of nodes."
        );

        let nodes_to_take = (self.nodes.len() - 1) / 2;

        let left_tree_nodes = self.nodes[0..nodes_to_take].to_vec();
        let right_tree_nodes = self.nodes[nodes_to_take..(nodes_to_take * 2)].to_vec();

        // Next, we split leaves into two equal parts
        assert!(
            self.leaves() % 2 == 0,
            "Merkle tree should contain even number of leaves."
        );

        let leaves_to_take = self.leaves() / 2;

        let mut leaves_iter = self.leaves.clone().into_iter();

        let mut left_tree_leaves = IndexSet::with_capacity(leaves_to_take);
        let mut right_tree_leaves = IndexSet::with_capacity(leaves_to_take);

        for _ in 0..leaves_to_take {
            left_tree_leaves.insert(leaves_iter.next().expect("Expected leaf of merkle tree"));
        }

        for _ in 0..leaves_to_take {
            right_tree_leaves.insert(leaves_iter.next().expect("Expected leaf of merkle tree"));
        }

        assert!(
            leaves_iter.next().is_none(),
            "More than expected leaves in merkle tree."
        );

        let left_tree = Tree {
            nodes: left_tree_nodes,
            leaves: left_tree_leaves,
        };

        let right_tree = Tree {
            nodes: right_tree_nodes,
            leaves: right_tree_leaves,
        };

        (left_tree, Some(right_tree))
    }
}

/// Merges two merkle trees into one
pub fn merge(left: &Tree, right: &Tree) -> Tree {
    // Firstly, we merge all the nodes and add the new root node
    let mut new_nodes = Vec::with_capacity(left.nodes.len() + right.nodes.len() + 1);
    let new_root_hash = hash_intermediate(left.root_hash(), right.root_hash());

    new_nodes.extend_from_slice(&left.nodes);
    new_nodes.extend_from_slice(&right.nodes);
    new_nodes.push(new_root_hash);

    // Next, we merge leaves
    let mut new_leaves = IndexSet::with_capacity(left.leaves() + right.leaves());
    new_leaves.extend(left.leaves.iter());
    new_leaves.extend(right.leaves.iter());

    Tree {
        nodes: new_nodes,
        leaves: new_leaves,
    }
}
