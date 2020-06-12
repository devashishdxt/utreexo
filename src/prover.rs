use crate::Proof;

/// Trait for generating inclusion proofs of value in merkle forest
pub trait Prover {
    /// Returns proof of a leaf value in merkle forest
    fn prove<T: AsRef<[u8]>>(&self, leaf_value: T) -> Option<Proof>;
}
