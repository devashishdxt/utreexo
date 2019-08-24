#![forbid(unsafe_code)]
#![deny(missing_docs, unstable_features)]

//! # Utreexo

mod balanced_merkle_tree;
mod hash;

pub use balanced_merkle_tree::BalancedMerkleTree;
pub use hash::Hash;
