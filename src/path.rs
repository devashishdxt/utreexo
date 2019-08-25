use core::iter::Iterator;

use bit_vec::{BitVec, Iter};

/// Represents path in a merkle proof
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Path(BitVec);

impl Path {
    /// Returns height of path
    #[inline]
    pub fn height(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over direction in path
    #[inline]
    pub fn directions(&self) -> Directions<'_> {
        Directions(self.0.iter())
    }
}

/// Represents direction to take in a merkle path
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Left direction
    Left,
    /// Right direction
    Right,
}

impl From<bool> for Direction {
    #[inline]
    fn from(b: bool) -> Direction {
        if b {
            Direction::Left
        } else {
            Direction::Right
        }
    }
}

/// Iterator over directions in a path
pub struct Directions<'a>(Iter<'a>);

impl<'a> Iterator for Directions<'a> {
    type Item = Direction;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Into::into)
    }
}
