#![forbid(unsafe_code)]
#![deny(missing_docs, unstable_features)]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

//! # Utreexo
extern crate alloc;

mod hash;
mod path;
mod proof;
mod utreexo;

pub(crate) use self::path::{Direction, Path};

pub use self::hash::Hash;
pub use self::proof::Proof;
pub use self::utreexo::Utreexo;

use alloc::{vec, vec::Vec};
use core::{
    convert::TryInto,
    iter::{repeat, Iterator},
};

use blake2b_simd::{many::update_many, Params};

use self::hash::HASH_SIZE;

/// Calculates hash of a leaf
pub(crate) fn hash_leaf<T: AsRef<[u8]>>(value: T) -> Hash {
    let mut params = Params::default();
    params.hash_length(HASH_SIZE);

    let mut state = params.to_state();

    // Add `0` byte to leaf nodes to prevent second preimage attack
    // https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
    state.update(&[0]);
    state.update(value.as_ref());

    state.finalize().into()
}

/// Calculates hash of many leaves
pub(crate) fn hash_many_leaves<T: AsRef<[u8]>>(values: &[T]) -> impl Iterator<Item = Hash> {
    let mut params = Params::default();
    params.hash_length(HASH_SIZE);

    let mut states = vec![params.to_state(); values.len()];

    // Add `0` byte to leaf nodes to prevent second preimage attack
    // https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
    update_many(states.iter_mut().zip(repeat(&[0]).take(values.len())));
    update_many(states.iter_mut().zip(values.iter()));

    states.into_iter().map(|state| state.finalize().into())
}

/// Calculates intermediate hash of two values
pub(crate) fn hash_intermediate<T: AsRef<[u8]>>(a: T, b: T) -> Hash {
    let mut params = Params::default();
    params.hash_length(HASH_SIZE);

    let mut state = params.to_state();

    // Add `1` byte to intermediate nodes to prevent second preimage attack
    // https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
    state.update(&[1]);
    state.update(a.as_ref());
    state.update(b.as_ref());

    state.finalize().into()
}

/// Returns the number of nodes in a tree given the number of leaves (`2n - 1`)
#[inline]
pub(crate) fn num_nodes(num_leaves: usize) -> usize {
    if num_leaves == 0 {
        0
    } else {
        (2 * num_leaves) - 1
    }
}

/// Returns height of tree with given number of leaves
#[inline]
pub(crate) fn height(num_leaves: usize) -> usize {
    num_leaves
        .trailing_zeros()
        .try_into()
        .expect("Cannot calculate height for trees with too many leaves")
}

/// Returns leaf distribution in merkle forest for given number of leaf values
#[allow(dead_code)]
pub(crate) fn leaf_distribution(mut num_leaves: usize) -> Vec<usize> {
    let mut distribution = <Vec<usize>>::default();

    let start = height(num_leaves);
    let finish = (core::mem::size_of::<usize>() * 8) - (num_leaves.leading_zeros() as usize);
    num_leaves >>= start;

    for i in start..finish {
        if num_leaves & 1 == 1 {
            distribution.push(2_usize.pow(i as u32));
        }
        num_leaves >>= 1;
    }

    distribution.reverse();
    distribution
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_leaf_distribution() {
        let leaf_distribution = leaf_distribution(15);
        assert_eq!(vec![8, 4, 2, 1], leaf_distribution);
    }

    #[test]
    fn check_num_nodes() {
        assert_eq!(0, num_nodes(0));
        assert_eq!(15, num_nodes(8));
    }

    #[test]
    fn check_height() {
        assert_eq!(3, height(8));
    }
}
