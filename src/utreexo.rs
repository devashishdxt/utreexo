use crate::{Hash, Proof};

/// Trait for all the operations of Utreexo accumulator
pub trait Utreexo {
    /// Inserts a new value in accumulator
    fn insert(&mut self, leaf_hash: Hash);

    /// Verifies and deletes value corresponding to given proof from accumulator. Returns true if the value was
    /// successfully verified and deleted, false otherwise
    fn delete(&mut self, proof: &Proof) -> bool;
}
