use core::{
    convert::TryInto,
    iter::{DoubleEndedIterator, Iterator},
    ops::Not,
};

use bit_vec::{BitVec, Iter};

/// Represents path in a merkle proof (direction of path is from leaf to root)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path(pub(crate) BitVec);

impl Path {
    /// Returns height of path
    pub fn height(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over direction in path
    pub fn directions(&self) -> Directions<'_> {
        Directions(self.0.iter())
    }

    /// Creates a new path of given height and using binary representation of given number
    ///
    /// # Example
    ///
    /// For `height = 3` and `num = 3`:
    ///
    /// - Binary representation of `3` is `00000011`
    /// - So, the resulting path of `height = 3` is `Path(110)`, i.e., the reverse of last three
    ///   bits of binary representation
    ///
    /// Similarly, for `height = 3` and `num = 4`, path will be `Path(001)`
    pub fn for_height_and_num(height: usize, num: usize) -> Path {
        let mut path = BitVec::with_capacity(height);

        let mut count = 0;

        while count < height {
            path.push(
                num & 2usize.pow(
                    count
                        .try_into()
                        .expect("Cannot calculate path for very high trees"),
                ) != 0,
            );
            count += 1;
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

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Into::into)
    }
}

impl<'a> DoubleEndedIterator for Directions<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back().map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_path_height() {
        let path = Path(BitVec::from_elem(3, false));
        assert_eq!(3, path.height());
    }

    #[test]
    fn check_path_directions() {
        let path = Path(BitVec::from_elem(3, false));

        let mut directions = path.directions();

        assert_eq!(Some(Direction::Right), directions.next());
        assert_eq!(Some(Direction::Right), directions.next());
        assert_eq!(Some(Direction::Right), directions.next());
        assert_eq!(None, directions.next());
    }

    #[test]
    fn check_path_for_height_and_num() {
        let path = Path::for_height_and_num(3, 4);

        let mut directions = path.directions();

        assert_eq!(Some(Direction::Right), directions.next());
        assert_eq!(Some(Direction::Right), directions.next());
        assert_eq!(Some(Direction::Left), directions.next());
        assert_eq!(None, directions.next());
    }

    #[test]
    fn check_direction_conversions() {
        assert_eq!(Direction::Right, !Direction::Left);
        assert_eq!(Direction::Left, !Direction::Right);
        assert_eq!(Direction::Right, false.into());
        assert_eq!(Direction::Left, true.into());
    }
}
