use crate::BalancedMerkleTree;

/// Represents a `Utreexo`
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct Utreexo(Vec<BalancedMerkleTree>);

impl Utreexo {
    /// Creates a new utreexo with given values
    pub fn new<T: AsRef<[u8]>>(mut values: &[T]) -> Self {
        if values.is_empty() {
            return Default::default();
        }

        let leaf_distribution = leaf_distribution(values.len());

        let mut trees = Vec::with_capacity(leaf_distribution.len());

        for num_leaves in leaf_distribution.into_iter() {
            let (current, future) = values.split_at(num_leaves);
            trees.push(BalancedMerkleTree::new(current).unwrap());
            values = future;
        }

        Utreexo(trees)
    }

    /// Inserts a new value into current utreexo
    #[inline]
    pub fn insert<T: AsRef<[u8]>>(&mut self, value: &T) {
        self.0.push(BalancedMerkleTree::new_single(value));
        self.compress();
    }

    /// Returns the number of balanced merkle trees in current utreexo
    #[inline]
    pub fn trees(&self) -> usize {
        self.0.len()
    }

    /// Returns the total number of leaves in current utreexo
    #[inline]
    pub fn leaves(&self) -> usize {
        self.0.iter().map(BalancedMerkleTree::leaves).sum()
    }

    /// Compresses current utreexo by merging trees of equal length from right to left
    fn compress(&mut self) {
        // Compression cannot be performed if the number of trees are either 0 or 1
        while self.trees() >= 2
            && self.0[self.trees() - 1].leaves() == self.0[self.trees() - 2].leaves()
        {
            let last_tree = self.0.pop().unwrap();
            let second_last_tree = self.0.pop().unwrap();

            let new_tree = BalancedMerkleTree::merge(second_last_tree, last_tree);

            self.0.push(new_tree);
        }

        debug_assert!(
            self.validate_leaf_distribution(),
            "Invalid leaf distribution in utreexo"
        );
    }

    /// Validates if leaves are correctly distributed in merkle forest
    fn validate_leaf_distribution(&self) -> bool {
        let leaf_distribution = leaf_distribution(self.leaves());

        for (num_leaves, tree) in leaf_distribution.into_iter().zip(self.0.iter()) {
            if num_leaves != tree.leaves() {
                return false;
            }
        }

        true
    }
}

/// Returns leaf distribution in merkle forest for given number of leaf values
fn leaf_distribution(mut num: usize) -> Vec<usize> {
    let mut distribution = <Vec<usize>>::default();

    for i in 0..std::mem::size_of::<usize>() {
        if num & 1 == 1 {
            distribution.push(2usize.pow(i as u32));
        }
        num >>= 1;
    }

    distribution.reverse();
    distribution
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_utreexo_addition() {
        let mut utreexo = Utreexo::default();

        utreexo.insert(b"hello");
        assert_eq!(1, utreexo.trees());
        assert_eq!(1, utreexo.leaves());

        utreexo.insert(b"hello");
        assert_eq!(1, utreexo.trees());
        assert_eq!(2, utreexo.leaves());

        utreexo.insert(b"hello");
        assert_eq!(2, utreexo.trees());
        assert_eq!(3, utreexo.leaves());

        utreexo.insert(b"hello");
        assert_eq!(1, utreexo.trees());
        assert_eq!(4, utreexo.leaves());

        utreexo.insert(b"hello");
        assert_eq!(2, utreexo.trees());
        assert_eq!(5, utreexo.leaves());

        utreexo.insert(b"hello");
        assert_eq!(2, utreexo.trees());
        assert_eq!(6, utreexo.leaves());

        utreexo.insert(b"hello");
        assert_eq!(3, utreexo.trees());
        assert_eq!(7, utreexo.leaves());

        utreexo.insert(b"hello");
        assert_eq!(1, utreexo.trees());
        assert_eq!(8, utreexo.leaves());
    }

    #[test]
    fn check_utreexo_array_creation() {
        let values = vec![b"hello"; 7];

        let mut utreexo = Utreexo::new(&values);
        assert_eq!(3, utreexo.trees());
        assert_eq!(7, utreexo.leaves());

        utreexo.insert(b"hello");
        assert_eq!(1, utreexo.trees());
        assert_eq!(8, utreexo.leaves());
    }
}
