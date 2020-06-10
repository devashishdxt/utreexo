use alloc::vec::Vec;

use blake3::Hash;

use crate::{hash_intermediate, Proof, Utreexo};

/// Hash based in-memory accumulator
#[derive(Debug)]
pub struct MemoryAccumulator(Vec<Option<Hash>>);

impl MemoryAccumulator {
    /// Verifies inclusion proof of a value in accumulator
    fn verify(&self, proof: &Proof) -> bool {
        let height = proof.path.height();

        if self.0.len() < (height + 1) {
            return false;
        }

        if let Some(ref root_hash) = self.0[height] {
            proof.verify(*root_hash)
        } else {
            false
        }
    }
}

impl Utreexo for MemoryAccumulator {
    fn insert(&mut self, leaf_hash: Hash) {
        let mut new_hash = leaf_hash;

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

    fn delete(&mut self, proof: &Proof) -> bool {
        // Proof should be valid to delete a value from accumulator
        if !self.verify(proof) {
            return false;
        }

        let height = proof.path.height();

        let mut new_hash = None;

        for (hash, sibling_hash) in self
            .0
            .iter_mut()
            .take(height)
            .zip(proof.sibling_hashes.iter())
        {
            if let Some(ref mut new_hash) = new_hash {
                *new_hash = hash_intermediate(sibling_hash, new_hash);
            } else if hash.is_none() {
                *hash = Some(*sibling_hash)
            } else {
                // `unwrap()` is safe here because `None` condition was checked earlier
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
