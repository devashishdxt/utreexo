use crate::Proof;

/// Trait for all the operations of Utreexo accumulator
pub trait Utreexo {
    /// Inserts a new value in accumulator
    fn insert<T: AsRef<[u8]>>(&mut self, leaf_value: T);

    /// Verifies and deletes value corresponding to given proof from accumulator. Returns true if the value was
    /// successfully verified and deleted, false otherwise
    fn delete(&mut self, proof: &Proof) -> bool;
}
