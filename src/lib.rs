#![forbid(unsafe_code)]
#![deny(missing_docs, unstable_features)]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

//! # Utreexo
extern crate alloc;

mod forest;
mod hash;
mod path;
mod proof;

pub(crate) use self::path::{Direction, Path};

pub use self::forest::Forest;
pub use self::hash::Hash;
pub use self::proof::Proof;
