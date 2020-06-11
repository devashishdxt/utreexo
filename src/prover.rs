use crate::{Hash, Proof};

/// Trait for generating inclusion proofs of value in merkle forest
pub trait Prover {
    /// Returns proof of a leaf hash in merkle forest
    fn prove(&self, leaf_hash: &Hash) -> Option<Proof>;
}
