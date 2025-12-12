//! A generic metadata-only filesystem tree with path validation.
//!
//! This module is adapted from [composefs-rs](https://github.com/containers/composefs-rs)
//! to provide secure path handling when building trees from potentially untrusted tar archives.
//!
//! The key security feature is that all path operations reject:
//! - `.` (current directory) components
//! - `..` (parent directory) components
//! - Windows-style path prefixes
//!
//! This prevents path canonicalization attacks where a malicious tar might contain
//! entries like `/foo/bar` and `/foo/subdir/../bar` that should resolve to the same path.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    path::{Component, Path},
};

use thiserror::Error;

/// Errors that can occur when working with the filesystem tree.
#[derive(Error, Debug)]
pub enum TreeError {
    /// The filename contains invalid components (e.g., "..", ".", or Windows prefixes).
    #[error("Invalid filename {0:?}")]
    InvalidFilename(Box<OsStr>),
    /// The specified directory entry does not exist.
    #[error("Directory entry {0:?} does not exist")]
    NotFound(Box<OsStr>),
    /// The entry exists but is not a directory when a directory was expected.
    #[error("Directory entry {0:?} is not a subdirectory")]
    NotADirectory(Box<OsStr>),
    /// The entry is a directory when a non-directory was expected.
    #[error("Directory entry {0:?} is a directory")]
    IsADirectory(Box<OsStr>),
}

/// A filesystem inode representing either a directory or a leaf node with data T.
#[derive(Debug, Clone)]
pub enum Inode<T> {
    /// A directory inode containing named entries.
    Directory(BTreeMap<Box<OsStr>, Inode<T>>),
    /// A leaf inode (file, symlink, etc.) with associated data.
    Leaf(T),
}

impl<T> Default for Inode<T> {
    fn default() -> Self {
        Inode::Directory(BTreeMap::new())
    }
}

impl<T> Inode<T> {
    /// Create a new empty directory inode.
    pub fn new_directory() -> Self {
        Inode::Directory(BTreeMap::new())
    }

    /// Create a new leaf inode with the given data.
    pub fn new_leaf(data: T) -> Self {
        Inode::Leaf(data)
    }

    /// Returns true if this inode is a directory.
    pub fn is_directory(&self) -> bool {
        matches!(self, Inode::Directory(_))
    }

    /// Returns true if this inode is a leaf.
    pub fn is_leaf(&self) -> bool {
        matches!(self, Inode::Leaf(_))
    }

    /// Get a reference to the directory entries, if this is a directory.
    pub fn as_directory(&self) -> Option<&BTreeMap<Box<OsStr>, Inode<T>>> {
        match self {
            Inode::Directory(entries) => Some(entries),
            Inode::Leaf(_) => None,
        }
    }

    /// Get a mutable reference to the directory entries, if this is a directory.
    pub fn as_directory_mut(&mut self) -> Option<&mut BTreeMap<Box<OsStr>, Inode<T>>> {
        match self {
            Inode::Directory(entries) => Some(entries),
            Inode::Leaf(_) => None,
        }
    }

    /// Get a reference to the leaf data, if this is a leaf.
    pub fn as_leaf(&self) -> Option<&T> {
        match self {
            Inode::Leaf(data) => Some(data),
            Inode::Directory(_) => None,
        }
    }

    /// Get a mutable reference to the leaf data, if this is a leaf.
    pub fn as_leaf_mut(&mut self) -> Option<&mut T> {
        match self {
            Inode::Leaf(data) => Some(data),
            Inode::Directory(_) => None,
        }
    }
}

/// A complete filesystem tree with a root directory.
///
/// The tree provides secure path operations that reject `.`, `..`, and prefix components
/// to prevent path traversal attacks from malicious tar archives.
#[derive(Debug, Clone, Default)]
pub struct FileSystem<T> {
    /// The root directory of the filesystem.
    root: BTreeMap<Box<OsStr>, Inode<T>>,
}

impl<T> FileSystem<T> {
    /// Create a new empty filesystem.
    pub fn new() -> Self {
        Self {
            root: BTreeMap::new(),
        }
    }

    /// Get a reference to the root directory entries.
    pub fn root(&self) -> &BTreeMap<Box<OsStr>, Inode<T>> {
        &self.root
    }

    /// Get a mutable reference to the root directory entries.
    pub fn root_mut(&mut self) -> &mut BTreeMap<Box<OsStr>, Inode<T>> {
        &mut self.root
    }

    /// Validate a path component, rejecting `.`, `..`, and prefix components.
    fn validate_component(component: Component<'_>, pathname: &OsStr) -> Result<(), TreeError> {
        match component {
            Component::RootDir => Ok(()),
            Component::Prefix(..) | Component::CurDir | Component::ParentDir => {
                Err(TreeError::InvalidFilename(pathname.into()))
            }
            Component::Normal(_) => Ok(()),
        }
    }

    /// Gets a reference to a subdirectory at the given path.
    ///
    /// The path may be absolute or relative. It may not contain `.`, `..`, or prefix components.
    ///
    /// # Errors
    ///
    /// - `InvalidFilename` if the path contains `.`, `..`, or prefix components
    /// - `NotFound` if the directory doesn't exist
    /// - `NotADirectory` if a component exists but is not a directory
    pub fn get_directory(
        &self,
        pathname: &OsStr,
    ) -> Result<&BTreeMap<Box<OsStr>, Inode<T>>, TreeError> {
        let path = Path::new(pathname);
        let mut current = &self.root;

        for component in path.components() {
            Self::validate_component(component, pathname)?;

            if let Component::Normal(filename) = component {
                match current.get(filename) {
                    Some(Inode::Directory(entries)) => current = entries,
                    Some(Inode::Leaf(_)) => return Err(TreeError::NotADirectory(filename.into())),
                    None => return Err(TreeError::NotFound(filename.into())),
                }
            }
        }

        Ok(current)
    }

    /// Gets a mutable reference to a subdirectory at the given path.
    pub fn get_directory_mut(
        &mut self,
        pathname: &OsStr,
    ) -> Result<&mut BTreeMap<Box<OsStr>, Inode<T>>, TreeError> {
        let path = Path::new(pathname);
        let mut current = &mut self.root;

        for component in path.components() {
            Self::validate_component(component, pathname)?;

            if let Component::Normal(filename) = component {
                match current.get_mut(filename) {
                    Some(Inode::Directory(entries)) => current = entries,
                    Some(Inode::Leaf(_)) => return Err(TreeError::NotADirectory(filename.into())),
                    None => return Err(TreeError::NotFound(filename.into())),
                }
            }
        }

        Ok(current)
    }

    /// Ensures all parent directories exist for the given path, creating them if needed.
    /// Returns a mutable reference to the parent directory.
    ///
    /// # Errors
    ///
    /// - `InvalidFilename` if the path contains `.`, `..`, or prefix components
    /// - `NotADirectory` if a component exists but is not a directory
    pub fn ensure_parent_dirs(
        &mut self,
        pathname: &OsStr,
    ) -> Result<&mut BTreeMap<Box<OsStr>, Inode<T>>, TreeError> {
        let path = Path::new(pathname);
        let mut current = &mut self.root;

        // Get parent path components (all but the last)
        let parent = match path.parent() {
            Some(p) => p,
            None => return Ok(current),
        };

        for component in parent.components() {
            Self::validate_component(component, pathname)?;

            if let Component::Normal(filename) = component {
                // Use entry API to insert directory if not present
                let entry = current
                    .entry(Box::from(filename))
                    .or_insert_with(Inode::new_directory);
                match entry {
                    Inode::Directory(entries) => current = entries,
                    Inode::Leaf(_) => return Err(TreeError::NotADirectory(filename.into())),
                }
            }
        }

        Ok(current)
    }

    /// Splits a pathname into parent directory and filename.
    /// Validates the path and returns the parent directory reference and the filename.
    ///
    /// # Errors
    ///
    /// - `InvalidFilename` if the path is empty or contains invalid components
    pub fn split<'p>(
        &self,
        pathname: &'p OsStr,
    ) -> Result<(&BTreeMap<Box<OsStr>, Inode<T>>, &'p OsStr), TreeError> {
        let path = Path::new(pathname);

        let filename = path
            .file_name()
            .ok_or_else(|| TreeError::InvalidFilename(pathname.into()))?;

        let parent_dir = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                self.get_directory(parent.as_os_str())?
            }
            _ => &self.root,
        };

        Ok((parent_dir, filename))
    }

    /// Splits a pathname into parent directory and filename (mutable version).
    pub fn split_mut<'p>(
        &mut self,
        pathname: &'p OsStr,
    ) -> Result<(&mut BTreeMap<Box<OsStr>, Inode<T>>, &'p OsStr), TreeError> {
        let path = Path::new(pathname);

        let filename = path
            .file_name()
            .ok_or_else(|| TreeError::InvalidFilename(pathname.into()))?;

        let parent_dir = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                self.get_directory_mut(parent.as_os_str())?
            }
            _ => &mut self.root,
        };

        Ok((parent_dir, filename))
    }

    /// Insert an inode at the given path, creating parent directories as needed.
    ///
    /// If the path already exists, the old value is replaced.
    ///
    /// # Errors
    ///
    /// - `InvalidFilename` if the path contains `.`, `..`, or prefix components
    /// - `NotADirectory` if a parent component exists but is not a directory
    pub fn insert(&mut self, pathname: &OsStr, inode: Inode<T>) -> Result<(), TreeError> {
        let path = Path::new(pathname);

        let filename = path
            .file_name()
            .ok_or_else(|| TreeError::InvalidFilename(pathname.into()))?;

        // Validate all components first
        for component in path.components() {
            Self::validate_component(component, pathname)?;
        }

        let parent = self.ensure_parent_dirs(pathname)?;
        parent.insert(Box::from(filename), inode);
        Ok(())
    }

    /// Remove an entry at the given path.
    ///
    /// Returns the removed inode if it existed, or None if not found.
    /// If removing a directory, all children are removed as well.
    ///
    /// # Errors
    ///
    /// - `InvalidFilename` if the path contains `.`, `..`, or prefix components
    pub fn remove(&mut self, pathname: &OsStr) -> Result<Option<Inode<T>>, TreeError> {
        let path = Path::new(pathname);

        // Validate path
        for component in path.components() {
            Self::validate_component(component, pathname)?;
        }

        let filename = match path.file_name() {
            Some(f) => f,
            None => return Ok(None), // Root path, nothing to remove
        };

        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                match self.get_directory_mut(parent.as_os_str()) {
                    Ok(dir) => dir,
                    Err(TreeError::NotFound(_)) => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
            _ => &mut self.root,
        };

        Ok(parent.remove(filename))
    }

    /// Remove all entries under a directory path (but keep the directory itself).
    ///
    /// This is used for opaque whiteouts which clear directory contents from lower layers.
    ///
    /// # Errors
    ///
    /// - `InvalidFilename` if the path contains `.`, `..`, or prefix components
    pub fn clear_directory(&mut self, pathname: &OsStr) -> Result<(), TreeError> {
        let path = Path::new(pathname);

        // Validate path
        for component in path.components() {
            Self::validate_component(component, pathname)?;
        }

        // Empty path means clear root
        if path.as_os_str().is_empty() {
            self.root.clear();
            return Ok(());
        }

        let filename = match path.file_name() {
            Some(f) => f,
            None => {
                // Root path
                self.root.clear();
                return Ok(());
            }
        };

        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                match self.get_directory_mut(parent.as_os_str()) {
                    Ok(dir) => dir,
                    Err(TreeError::NotFound(_)) => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
            _ => &mut self.root,
        };

        if let Some(Inode::Directory(entries)) = parent.get_mut(filename) {
            entries.clear();
        }

        Ok(())
    }

    /// Look up an entry at the given path.
    ///
    /// # Errors
    ///
    /// - `InvalidFilename` if the path contains `.`, `..`, or prefix components
    pub fn lookup(&self, pathname: &OsStr) -> Result<Option<&Inode<T>>, TreeError> {
        let path = Path::new(pathname);

        // Validate path
        for component in path.components() {
            Self::validate_component(component, pathname)?;
        }

        let filename = match path.file_name() {
            Some(f) => f,
            None => return Ok(None),
        };

        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                match self.get_directory(parent.as_os_str()) {
                    Ok(dir) => dir,
                    Err(TreeError::NotFound(_)) => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
            _ => &self.root,
        };

        Ok(parent.get(filename))
    }

    /// Iterate over all leaf entries in the tree, yielding (path, &T) pairs.
    ///
    /// Paths are returned in sorted order.
    pub fn iter_leaves(&self) -> impl Iterator<Item = (String, &T)> {
        LeafIterator::new(&self.root)
    }

    /// Consume the tree and return an iterator over all leaf entries.
    pub fn into_leaves(self) -> impl Iterator<Item = (String, T)> {
        IntoLeafIterator::new(self.root)
    }
}

/// Iterator over leaf entries in a filesystem tree.
struct LeafIterator<'a, T> {
    stack: Vec<(
        &'a BTreeMap<Box<OsStr>, Inode<T>>,
        String,
        std::collections::btree_map::Iter<'a, Box<OsStr>, Inode<T>>,
    )>,
}

impl<'a, T> LeafIterator<'a, T> {
    fn new(root: &'a BTreeMap<Box<OsStr>, Inode<T>>) -> Self {
        Self {
            stack: vec![(root, String::new(), root.iter())],
        }
    }
}

impl<'a, T> Iterator for LeafIterator<'a, T> {
    type Item = (String, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (_, prefix, iter) = self.stack.last_mut()?;

            match iter.next() {
                Some((name, inode)) => {
                    let path = if prefix.is_empty() {
                        name.to_string_lossy().into_owned()
                    } else {
                        format!("{}/{}", prefix, name.to_string_lossy())
                    };

                    match inode {
                        Inode::Leaf(data) => return Some((path, data)),
                        Inode::Directory(entries) => {
                            self.stack.push((entries, path, entries.iter()));
                        }
                    }
                }
                None => {
                    self.stack.pop();
                }
            }
        }
    }
}

/// Owning iterator over leaf entries in a filesystem tree.
struct IntoLeafIterator<T> {
    stack: Vec<(
        String,
        std::collections::btree_map::IntoIter<Box<OsStr>, Inode<T>>,
    )>,
}

impl<T> IntoLeafIterator<T> {
    fn new(root: BTreeMap<Box<OsStr>, Inode<T>>) -> Self {
        Self {
            stack: vec![(String::new(), root.into_iter())],
        }
    }
}

impl<T> Iterator for IntoLeafIterator<T> {
    type Item = (String, T);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (prefix, iter) = self.stack.last_mut()?;

            match iter.next() {
                Some((name, inode)) => {
                    let path = if prefix.is_empty() {
                        name.to_string_lossy().into_owned()
                    } else {
                        format!("{}/{}", prefix, name.to_string_lossy())
                    };

                    match inode {
                        Inode::Leaf(data) => return Some((path, data)),
                        Inode::Directory(entries) => {
                            self.stack.push((path, entries.into_iter()));
                        }
                    }
                }
                None => {
                    self.stack.pop();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_lookup() {
        let mut fs: FileSystem<u32> = FileSystem::new();

        fs.insert(OsStr::new("file.txt"), Inode::new_leaf(42))
            .unwrap();

        let result = fs.lookup(OsStr::new("file.txt")).unwrap();
        assert!(matches!(result, Some(Inode::Leaf(42))));
    }

    #[test]
    fn test_insert_nested_creates_parents() {
        let mut fs: FileSystem<u32> = FileSystem::new();

        fs.insert(OsStr::new("a/b/c/file.txt"), Inode::new_leaf(123))
            .unwrap();

        // Check intermediate directories were created
        assert!(fs.get_directory(OsStr::new("a")).is_ok());
        assert!(fs.get_directory(OsStr::new("a/b")).is_ok());
        assert!(fs.get_directory(OsStr::new("a/b/c")).is_ok());

        let result = fs.lookup(OsStr::new("a/b/c/file.txt")).unwrap();
        assert!(matches!(result, Some(Inode::Leaf(123))));
    }

    #[test]
    fn test_reject_dotdot() {
        let mut fs: FileSystem<u32> = FileSystem::new();

        let result = fs.insert(OsStr::new("foo/../bar"), Inode::new_leaf(1));
        assert!(matches!(result, Err(TreeError::InvalidFilename(_))));
    }

    #[test]
    fn test_reject_dot() {
        let mut fs: FileSystem<u32> = FileSystem::new();

        let result = fs.insert(OsStr::new("./foo"), Inode::new_leaf(1));
        assert!(matches!(result, Err(TreeError::InvalidFilename(_))));
    }

    #[test]
    fn test_remove() {
        let mut fs: FileSystem<u32> = FileSystem::new();

        fs.insert(OsStr::new("a/b/file.txt"), Inode::new_leaf(1))
            .unwrap();
        fs.insert(OsStr::new("a/b/other.txt"), Inode::new_leaf(2))
            .unwrap();

        let removed = fs.remove(OsStr::new("a/b/file.txt")).unwrap();
        assert!(matches!(removed, Some(Inode::Leaf(1))));

        // Other file should still exist
        assert!(fs.lookup(OsStr::new("a/b/other.txt")).unwrap().is_some());

        // Removed file should be gone
        assert!(fs.lookup(OsStr::new("a/b/file.txt")).unwrap().is_none());
    }

    #[test]
    fn test_remove_directory_removes_children() {
        let mut fs: FileSystem<u32> = FileSystem::new();

        fs.insert(OsStr::new("a/b/file1.txt"), Inode::new_leaf(1))
            .unwrap();
        fs.insert(OsStr::new("a/b/file2.txt"), Inode::new_leaf(2))
            .unwrap();
        fs.insert(OsStr::new("a/c/file3.txt"), Inode::new_leaf(3))
            .unwrap();

        // Remove directory 'a/b'
        let removed = fs.remove(OsStr::new("a/b")).unwrap();
        assert!(matches!(removed, Some(Inode::Directory(_))));

        // Children should be gone
        assert!(fs.lookup(OsStr::new("a/b")).unwrap().is_none());
        assert!(fs.lookup(OsStr::new("a/b/file1.txt")).unwrap().is_none());

        // Sibling directory should still exist
        assert!(fs.lookup(OsStr::new("a/c/file3.txt")).unwrap().is_some());
    }

    #[test]
    fn test_clear_directory() {
        let mut fs: FileSystem<u32> = FileSystem::new();

        fs.insert(OsStr::new("a/b/file1.txt"), Inode::new_leaf(1))
            .unwrap();
        fs.insert(OsStr::new("a/b/file2.txt"), Inode::new_leaf(2))
            .unwrap();
        fs.insert(OsStr::new("a/c/file3.txt"), Inode::new_leaf(3))
            .unwrap();

        // Clear directory 'a/b' contents but keep directory itself
        fs.clear_directory(OsStr::new("a/b")).unwrap();

        // Directory 'a/b' should still exist but be empty
        let dir = fs.get_directory(OsStr::new("a/b")).unwrap();
        assert!(dir.is_empty());

        // Sibling should be unaffected
        assert!(fs.lookup(OsStr::new("a/c/file3.txt")).unwrap().is_some());
    }

    #[test]
    fn test_iter_leaves() {
        let mut fs: FileSystem<u32> = FileSystem::new();

        fs.insert(OsStr::new("b.txt"), Inode::new_leaf(2)).unwrap();
        fs.insert(OsStr::new("a/x.txt"), Inode::new_leaf(10))
            .unwrap();
        fs.insert(OsStr::new("a/y.txt"), Inode::new_leaf(11))
            .unwrap();
        fs.insert(OsStr::new("c.txt"), Inode::new_leaf(3)).unwrap();

        let leaves: Vec<_> = fs.iter_leaves().collect();

        // Should be sorted
        assert_eq!(leaves.len(), 4);
        assert_eq!(leaves[0], ("a/x.txt".to_string(), &10));
        assert_eq!(leaves[1], ("a/y.txt".to_string(), &11));
        assert_eq!(leaves[2], ("b.txt".to_string(), &2));
        assert_eq!(leaves[3], ("c.txt".to_string(), &3));
    }

    #[test]
    fn test_absolute_paths_work() {
        let mut fs: FileSystem<u32> = FileSystem::new();

        // Absolute paths should work (leading / is treated as root)
        fs.insert(OsStr::new("/foo/bar.txt"), Inode::new_leaf(1))
            .unwrap();

        // Should be accessible with or without leading /
        assert!(fs.lookup(OsStr::new("foo/bar.txt")).unwrap().is_some());
        assert!(fs.lookup(OsStr::new("/foo/bar.txt")).unwrap().is_some());
    }

    #[test]
    fn test_into_leaves() {
        let mut fs: FileSystem<u32> = FileSystem::new();

        fs.insert(OsStr::new("a.txt"), Inode::new_leaf(1)).unwrap();
        fs.insert(OsStr::new("b/c.txt"), Inode::new_leaf(2))
            .unwrap();

        let leaves: Vec<_> = fs.into_leaves().collect();

        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[0], ("a.txt".to_string(), 1));
        assert_eq!(leaves[1], ("b/c.txt".to_string(), 2));
    }
}
