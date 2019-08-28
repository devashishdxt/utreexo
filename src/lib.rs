#![forbid(unsafe_code)]
#![deny(missing_docs, unstable_features)]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

//! # Utreexo
extern crate alloc;

mod forest;
mod hash;
mod path;
mod proof;
mod tree;

pub(crate) use self::path::{Direction, Path};

pub use self::forest::Forest;
pub use self::hash::Hash;
pub use self::proof::Proof;
pub use self::tree::{Tree, TreeRef, TreeRefMut};

use alloc::vec;
use core::iter::{repeat, Iterator};

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
