use core::iter::{DoubleEndedIterator, Iterator};

use bit_vec::{BitVec, Iter};

/// Represents path in a merkle proof
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Path(pub(crate) BitVec);

impl Path {
    /// Returns height of path
    #[inline]
    pub fn height(&self) -> usize {
        self.0.len()
    }

    /// Returns the number of leaves in the tree of this path
    #[inline]
    pub fn leaves(&self) -> usize {
        2usize.pow(self.height() as u32)
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

impl From<Direction> for bool {
    fn from(direction: Direction) -> bool {
        match direction {
            Direction::Left => true,
            Direction::Right => false,
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

impl<'a> DoubleEndedIterator for Directions<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back().map(Into::into)
    }
}
