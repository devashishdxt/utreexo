use alloc::vec::Vec;

use crate::{hash_intermediate, hash_leaf, height, Direction, Hash, Path, Proof};

/// Reference to a slice representing a merkle tree
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

#[derive(Debug)]
#[repr(transparent)]
pub struct TreeRefMut<'a>(pub(crate) &'a mut [Hash]);

impl<'a> TreeRefMut<'a> {
    /// Returns number of leaves in tree
    #[inline]
    pub fn leaves(&self) -> usize {
        TreeRef(&self.0).leaves()
    }

    /// Returns number of nodes in tree
    #[inline]
    pub fn nodes(&self) -> usize {
        TreeRef(&self.0).nodes()
    }

    /// Returns height of tree
    #[inline]
    pub fn height(&self) -> usize {
        TreeRef(&self.0).height()
    }

    /// Returns root hash of tree
    #[inline]
    pub fn root_hash(&self) -> Hash {
        TreeRef(&self.0).root_hash()
    }

    /// Swaps the leaf represented by proof with given leaf value. Returns true if the swap was successful, false
    /// otherwise.
    pub fn swap<T: AsRef<[u8]>>(&mut self, proof: &Proof<T>, mut leaf_hash: Hash) -> bool {
        // Verify the proof
        if !proof.verify(self.root_hash()) {
            return false;
        }

        // Compute all the new hashes along the path of proof by combining with sibling hash and new leaf hash from
        // bottom to top
        let mut new_hashes = Vec::with_capacity(self.height());
        new_hashes.push(leaf_hash);

        for (direction, sibling_hash) in proof
            .path
            .directions()
            .rev()
            .zip(proof.sibling_hashes.iter().rev())
        {
            match direction {
                Direction::Left => {
                    leaf_hash = hash_intermediate(&leaf_hash, sibling_hash);
                    new_hashes.push(leaf_hash);
                }
                Direction::Right => {
                    leaf_hash = hash_intermediate(sibling_hash, &leaf_hash);
                    new_hashes.push(leaf_hash);
                }
            }
        }

        // Replace hashes in tree with newly computed ones
        let mut change_index = self.nodes() - 1;
        let mut leaves = self.leaves();

        self.0[change_index] = new_hashes.pop().unwrap();

        for (direction, new_hash) in proof.path.directions().zip(new_hashes.into_iter().rev()) {
            change_index = match direction {
                Direction::Left => change_index - leaves,
                Direction::Right => change_index - 1,
            };
            leaves /= 2;

            self.0[change_index] = new_hash;
        }

        true
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

    #[test]
    fn check_tree_mut_swap() {
        let mut nodes: Vec<Hash> = vec![
            Hash([
                136, 202, 237, 37, 138, 97, 155, 131, 79, 133, 35, 167, 192, 253, 33, 244, 126,
                146, 253, 68, 178, 91, 170, 163, 94, 111, 174, 226, 139, 61, 36, 72,
            ]),
            Hash([
                16, 213, 143, 236, 146, 10, 49, 117, 246, 89, 0, 3, 95, 107, 35, 134, 142, 68, 131,
                119, 104, 163, 147, 201, 151, 178, 224, 236, 97, 132, 40, 193,
            ]),
            Hash([
                54, 245, 6, 0, 176, 199, 196, 15, 225, 46, 197, 76, 235, 170, 234, 219, 119, 70,
                180, 56, 75, 93, 156, 67, 160, 236, 123, 145, 230, 119, 17, 55,
            ]),
            Hash([
                143, 241, 197, 183, 121, 75, 93, 61, 251, 205, 244, 122, 252, 101, 162, 37, 169,
                174, 225, 146, 41, 152, 210, 8, 171, 164, 157, 253, 196, 119, 22, 203,
            ]),
            Hash([
                174, 125, 79, 205, 191, 118, 54, 239, 33, 2, 135, 163, 10, 250, 170, 255, 43, 209,
                67, 197, 62, 108, 243, 110, 168, 225, 165, 156, 171, 87, 215, 129,
            ]),
            Hash([
                111, 211, 203, 8, 19, 107, 209, 181, 151, 198, 166, 75, 217, 145, 229, 78, 31, 240,
                149, 106, 239, 138, 4, 180, 237, 7, 81, 156, 238, 142, 14, 46,
            ]),
            Hash([
                220, 188, 153, 27, 158, 122, 227, 229, 35, 20, 246, 100, 25, 0, 123, 114, 77, 172,
                228, 237, 4, 243, 125, 250, 34, 239, 116, 173, 97, 141, 225, 192,
            ]),
            Hash([
                58, 12, 126, 124, 167, 225, 218, 122, 26, 88, 72, 180, 197, 138, 224, 174, 5, 254,
                40, 46, 109, 182, 14, 188, 211, 62, 24, 176, 75, 179, 172, 77,
            ]),
            Hash([
                62, 218, 80, 28, 7, 168, 105, 147, 40, 170, 3, 72, 61, 46, 222, 214, 165, 6, 146,
                59, 109, 248, 38, 208, 40, 183, 98, 195, 39, 23, 143, 254,
            ]),
            Hash([
                173, 249, 191, 129, 80, 165, 165, 3, 54, 56, 212, 101, 128, 37, 253, 21, 101, 185,
                45, 43, 150, 219, 132, 119, 233, 125, 40, 66, 7, 252, 211, 68,
            ]),
            Hash([
                202, 46, 198, 39, 71, 207, 184, 229, 99, 156, 134, 212, 139, 55, 111, 28, 44, 205,
                227, 21, 175, 58, 85, 159, 247, 22, 102, 140, 114, 199, 211, 173,
            ]),
            Hash([
                109, 143, 62, 145, 120, 187, 227, 82, 62, 201, 224, 74, 179, 227, 179, 125, 114,
                41, 58, 13, 1, 228, 215, 124, 76, 74, 70, 198, 15, 130, 104, 171,
            ]),
            Hash([
                250, 170, 94, 220, 203, 113, 181, 199, 11, 144, 106, 208, 48, 221, 8, 70, 173, 229,
                220, 155, 164, 2, 80, 217, 73, 105, 143, 202, 43, 217, 120, 243,
            ]),
            Hash([
                84, 222, 160, 143, 83, 101, 102, 170, 157, 126, 43, 191, 118, 50, 144, 138, 247,
                136, 46, 222, 52, 164, 23, 1, 68, 138, 242, 84, 31, 22, 194, 120,
            ]),
            Hash([
                196, 129, 239, 177, 63, 217, 228, 216, 178, 151, 121, 51, 141, 52, 71, 56, 240,
                144, 139, 65, 92, 40, 98, 221, 139, 15, 34, 35, 47, 190, 131, 77,
            ]),
        ];
        let tree = TreeRef(&nodes);

        let leaf_path = tree.leaf_paths()[2].clone();
        let leaf_proof = tree.prove("hello2", leaf_path).unwrap();
        let tree = TreeRef(&nodes);
        leaf_proof.verify(tree.root_hash());

        let mut tree = TreeRefMut(&mut nodes);
        assert!(tree.swap(&leaf_proof, hash_leaf("hello8")));

        let tree = TreeRef(&nodes);

        let leaf_path = tree.leaf_paths()[2].clone();
        let leaf_proof = tree.prove("hello8", leaf_path).unwrap();
        let tree = TreeRef(&nodes);
        leaf_proof.verify(tree.root_hash());

        let leaf_path = tree.leaf_paths()[5].clone();
        let leaf_proof = tree.prove("hello5", leaf_path).unwrap();
        let tree = TreeRef(&nodes);
        leaf_proof.verify(tree.root_hash());
    }
}
