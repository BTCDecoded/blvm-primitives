//! Specification-aware HashMap wrapper for spec-lock formal verification

use core::hash::Hash;
use core::ops::{Deref, DerefMut};
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Specification-aware HashMap wrapper
///
/// Transparent wrapper around `HashMap<K, V>` for spec-lock and Z3 verification.
/// Behaves exactly like `HashMap<K, V>`.
#[derive(Clone, Debug)]
pub struct SpecHashMap<K, V> {
    inner: HashMap<K, V>,
}

impl<K, V> Serialize for SpecHashMap<K, V>
where
    K: Hash + Eq + Serialize,
    V: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

impl<'de, K, V> Deserialize<'de> for SpecHashMap<K, V>
where
    K: Hash + Eq + Deserialize<'de>,
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        HashMap::deserialize(deserializer).map(|inner| SpecHashMap { inner })
    }
}

impl<K, V> SpecHashMap<K, V>
where
    K: Hash + Eq,
{
    /// Creates an empty `SpecHashMap`
    pub fn new() -> Self {
        SpecHashMap {
            inner: HashMap::new(),
        }
    }

    /// Returns the number of elements in the map
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the map contains no elements
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Inserts a key-value pair into the map
    ///
    /// Returns the previous value if the key existed, `None` otherwise
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    /// Returns a reference to the value corresponding to the key
    pub fn get(&self, key: &K) -> Option<&V> {
        self.inner.get(key)
    }

    /// Removes a key from the map, returning the value if it existed
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.remove(key)
    }
}

impl<K, V> From<HashMap<K, V>> for SpecHashMap<K, V> {
    fn from(inner: HashMap<K, V>) -> Self {
        SpecHashMap { inner }
    }
}

impl<K, V> From<SpecHashMap<K, V>> for HashMap<K, V> {
    fn from(spec_hashmap: SpecHashMap<K, V>) -> Self {
        spec_hashmap.inner
    }
}

impl<K, V> Deref for SpecHashMap<K, V> {
    type Target = HashMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<K, V> DerefMut for SpecHashMap<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<K, V> Default for SpecHashMap<K, V>
where
    K: Hash + Eq,
{
    fn default() -> Self {
        SpecHashMap::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spec_hashmap_basic() {
        let mut map: SpecHashMap<String, i32> = SpecHashMap::new();
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());

        let old = map.insert("key".to_string(), 42);
        assert_eq!(old, None);
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());

        assert_eq!(map.get(&"key".to_string()), Some(&42));

        let removed = map.remove(&"key".to_string());
        assert_eq!(removed, Some(42));
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_spec_hashmap_from_hashmap() {
        let mut std_map = HashMap::new();
        std_map.insert("a".to_string(), 1);
        std_map.insert("b".to_string(), 2);

        let spec_map: SpecHashMap<String, i32> = SpecHashMap::from(std_map);
        assert_eq!(spec_map.len(), 2);
        assert_eq!(spec_map.get(&"a".to_string()), Some(&1));
        assert_eq!(spec_map.get(&"b".to_string()), Some(&2));
    }

    #[test]
    fn test_spec_hashmap_deref() {
        let mut spec_map: SpecHashMap<u32, String> = SpecHashMap::new();
        spec_map.insert(1, "one".to_string());

        // Can use HashMap methods via Deref
        assert!(spec_map.contains_key(&1));
        assert!(!spec_map.contains_key(&2));
    }
}
