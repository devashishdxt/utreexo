use alloc::vec::Vec;

use crate::{hash_intermediate, hash_leaf, Hash, Proof};

/// Hash based accumulator
#[derive(Debug)]
#[repr(transparent)]
pub struct Utreexo(Vec<Option<Hash>>);

impl Utreexo {
    /// Inserts a new value in accumulator
    pub fn insert<T: AsRef<[u8]>>(&mut self, leaf_value: T) {
        let mut new_hash = hash_leaf(leaf_value);

        for hash in self.0.iter_mut() {
            match hash {
                Some(ref old_hash) => {
                    new_hash = hash_intermediate(old_hash, &new_hash);
                    *hash = None;
                }
                None => {
                    *hash = Some(new_hash);
                    return;
                }
            }
        }

        self.0.push(Some(new_hash));
    }

    /// Verifies inclusion proof of a value in accumulator
    pub fn verify<T: AsRef<[u8]>>(&self, proof: &Proof<T>) -> bool {
        let height = proof.height();

        if self.0.len() < (height + 1) {
            return false;
        }

        if let Some(ref root_hash) = self.0[height] {
            proof.verify(*root_hash)
        } else {
            false
        }
    }

    /// Deletes value corresponding to given proof from accumulator. Returns true if the value was deleted, false
    /// otherwise
    pub fn delete<T: AsRef<[u8]>>(&mut self, proof: &Proof<T>) -> bool {
        // Proof should be valid to delete a value from accumulator
        if !self.verify(proof) {
            return false;
        }

        let height = proof.height();

        let mut new_hash: Option<Hash> = None;

        for (hash, sibling_hash) in self
            .0
            .iter_mut()
            .take(height)
            .zip(proof.sibling_hashes.iter().rev())
        {
            if let Some(ref mut new_hash) = new_hash {
                *new_hash = hash_intermediate(sibling_hash, new_hash);
            } else if let None = hash {
                *hash = Some(*sibling_hash)
            } else {
                new_hash = Some(hash_intermediate(sibling_hash, &hash.unwrap()));
                *hash = None;
            }
        }

        if let Some(new_hash) = new_hash {
            if self.0.len() == height {
                self.0.push(Some(new_hash))
            } else {
                self.0[height] = Some(new_hash)
            }
        }

        true
    }
}
