use alloc::vec::Vec;
use core::{
    convert::TryInto,
    iter::{DoubleEndedIterator, Iterator},
    ops::Not,
};

use bit_vec::{BitVec, Iter};

/// Represents path in a merkle proof (direction of path is from root to leaf)
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
        2usize.pow(
            self.height()
                .try_into()
                .expect("Cannot calculate number of leaves for very high trees"),
        )
    }

    /// Returns an iterator over direction in path
    #[inline]
    pub fn directions(&self) -> Directions<'_> {
        Directions(self.0.iter())
    }

    /// Returns paths for all the leaves in a tree of given height
    pub fn for_height(height: usize) -> Vec<Path> {
        let leaves = 2usize.pow(
            height
                .try_into()
                .expect("Cannot calculate paths for very high trees"),
        );

        let mut paths = Vec::with_capacity(leaves);

        for i in 0..leaves {
            paths.push(Path::for_height_and_num(height, i));
        }

        paths
    }

    /// Creates a new path of given height and using binary representation of given number
    ///
    /// # Example
    ///
    /// For `height = 3` and `num = 3`:
    ///
    /// - Binary representation of `3` is `00000011`
    /// - So, the resulting path of `height = 3` is `Path(011)`
    ///
    /// Similarly, for `height = 3` and `num = 4`, path will be `Path(100)`
    fn for_height_and_num(mut height: usize, num: usize) -> Path {
        let mut path = BitVec::with_capacity(height);

        while height > 0 {
            height -= 1;
            path.push(
                num & 2usize.pow(
                    height
                        .try_into()
                        .expect("Cannot calculate path for very high trees"),
                ) != 0,
            );
        }

        Path(path)
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

impl Not for Direction {
    type Output = Direction;

    fn not(self) -> Direction {
        match self {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        }
    }
}

impl From<bool> for Direction {
    #[inline]
    fn from(b: bool) -> Direction {
        if b {
            Direction::Right
        } else {
            Direction::Left
        }
    }
}

impl From<Direction> for bool {
    fn from(direction: Direction) -> bool {
        match direction {
            Direction::Left => false,
            Direction::Right => true,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_path_leaves_and_height() {
        let path = Path(BitVec::from_elem(3, false));

        assert_eq!(3, path.height());
        assert_eq!(8, path.leaves());
    }

    #[test]
    fn check_path_directions() {
        let path = Path(BitVec::from_elem(3, false));
        let mut directions = path.directions();

        assert_eq!(Direction::Left, directions.next().unwrap());
        assert_eq!(Direction::Left, directions.next().unwrap());
        assert_eq!(Direction::Left, directions.next().unwrap());
        assert!(directions.next().is_none());

        assert_eq!(Direction::Left, !Direction::Right);
        assert_eq!(Direction::Left, false.into());
        assert_eq!(Direction::Right, true.into());
    }

    #[test]
    fn check_path_for_height() {
        let paths = Path::for_height(2);

        assert_eq!(4, paths.len());

        let mut directions = paths[0].directions();

        assert_eq!(Direction::Left, directions.next().unwrap());
        assert_eq!(Direction::Left, directions.next().unwrap());
        assert!(directions.next().is_none());

        directions = paths[1].directions();

        assert_eq!(Direction::Left, directions.next().unwrap());
        assert_eq!(Direction::Right, directions.next().unwrap());
        assert!(directions.next().is_none());

        directions = paths[2].directions();

        assert_eq!(Direction::Right, directions.next().unwrap());
        assert_eq!(Direction::Left, directions.next().unwrap());
        assert!(directions.next().is_none());

        directions = paths[3].directions();

        assert_eq!(Direction::Right, directions.next().unwrap());
        assert_eq!(Direction::Right, directions.next().unwrap());
        assert!(directions.next().is_none());
    }
}
