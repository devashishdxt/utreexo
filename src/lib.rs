#![forbid(unsafe_code)]
#![deny(missing_docs, unstable_features)]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

//! # Utreexo
extern crate alloc;

mod accumulator;
mod forest;
mod path;
mod proof;
mod prover;
mod tree;
mod utreexo;

pub(crate) use self::{
    path::{Direction, Path},
    tree::{merge, Tree},
};

pub use self::{
    accumulator::MemoryAccumulator, forest::MemoryForest, proof::Proof, prover::Prover,
    utreexo::Utreexo,
};
pub use blake3::Hash;

use blake3::Hasher;

/// Calculates hash of a leaf
pub fn hash_leaf(value: impl AsRef<[u8]>) -> Hash {
    let mut hasher = Hasher::new();

    // Add `0` byte to leaf nodes to prevent second preimage attack
    // https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
    hasher.update(&[0]);
    hasher.update(value.as_ref());

    hasher.finalize()
}

/// Calculates intermediate hash of two values
pub(crate) fn hash_intermediate(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Hasher::new();

    // Add `1` byte to intermediate nodes to prevent second preimage attack
    // https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
    hasher.update(&[1]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());

    hasher.finalize()
}
