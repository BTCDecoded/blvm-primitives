//! Specification-aware Vec wrapper for spec-lock formal verification

use core::ops::{Deref, DerefMut};
use std::clone::Clone;
use std::cmp::{Eq, PartialEq};
use std::hash::Hash;

use serde::{Deserialize, Serialize};

/// Specification-aware Vec wrapper
///
/// Transparent wrapper around `Vec<T>` for spec-lock and Z3 verification.
/// Behaves exactly like `Vec<T>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpecVec<T> {
    inner: Vec<T>,
}

impl<T> SpecVec<T> {
    /// Creates a new empty `SpecVec`
    pub fn new() -> Self {
        SpecVec { inner: Vec::new() }
    }

    /// Returns the number of elements in the vector
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the vector contains no elements
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Appends an element to the back of the vector
    pub fn push(&mut self, value: T) {
        self.inner.push(value);
    }

    /// Removes the last element and returns it, or `None` if empty
    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop()
    }
}

impl<T> From<Vec<T>> for SpecVec<T> {
    fn from(inner: Vec<T>) -> Self {
        SpecVec { inner }
    }
}

impl<T> From<SpecVec<T>> for Vec<T> {
    fn from(spec_vec: SpecVec<T>) -> Self {
        spec_vec.inner
    }
}

impl<T> Deref for SpecVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for SpecVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> Default for SpecVec<T> {
    fn default() -> Self {
        SpecVec::new()
    }
}

impl<T> AsRef<[T]> for SpecVec<T> {
    fn as_ref(&self) -> &[T] {
        self.inner.as_ref()
    }
}

impl<T> AsMut<[T]> for SpecVec<T> {
    fn as_mut(&mut self) -> &mut [T] {
        self.inner.as_mut()
    }
}

impl<T> IntoIterator for SpecVec<T> {
    type Item = T;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a SpecVec<T> {
    type Item = &'a T;
    type IntoIter = <&'a Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut SpecVec<T> {
    type Item = &'a mut T;
    type IntoIter = <&'a mut Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spec_vec_basic() {
        let mut vec: SpecVec<u8> = SpecVec::new();
        assert_eq!(vec.len(), 0);
        assert!(vec.is_empty());

        vec.push(42);
        assert_eq!(vec.len(), 1);
        assert!(!vec.is_empty());
        assert_eq!(vec[0], 42);

        let popped = vec.pop();
        assert_eq!(popped, Some(42));
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn test_spec_vec_from_vec() {
        let std_vec = vec![1, 2, 3];
        let spec_vec: SpecVec<i32> = SpecVec::from(std_vec);
        assert_eq!(spec_vec.len(), 3);
        assert_eq!(spec_vec[0], 1);
        assert_eq!(spec_vec[1], 2);
        assert_eq!(spec_vec[2], 3);
    }

    #[test]
    fn test_spec_vec_deref() {
        let mut spec_vec: SpecVec<String> = SpecVec::new();
        spec_vec.push("hello".to_string());

        // Can use Vec methods via Deref
        assert_eq!(spec_vec.len(), 1);
        spec_vec.clear();
        assert_eq!(spec_vec.len(), 0);
    }
}
