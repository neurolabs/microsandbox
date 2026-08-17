//! Deny-list matcher for bind mounts.
//!
//! A `deny` list is a set of gitignore-style patterns that hide matching
//! paths from a bind mount, enforced host-side in the passthrough backend.
//! Component-only patterns (no `/`, e.g. `.env`, `*.log`) are matched against
//! the entry name anywhere in the tree (gitignore semantics). Path patterns
//! (containing `/`, e.g. `dir/secret`, `**/env.secret`) are matched against
//! the full path relative to the mount root.

use std::path::{Path, PathBuf};

use ignore::{Match, gitignore::Gitignore, gitignore::GitignoreBuilder};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A matcher for a bind-mount `deny` list of gitignore-style patterns.
///
/// Wraps [`ignore::gitignore::Gitignore`]. The matcher is never empty; an
/// empty deny list matches nothing.
#[derive(Debug)]
pub(crate) struct DenyList {
    matcher: Gitignore,
    /// Whether any pattern is a path pattern (contains `/`).
    ///
    /// When `false`, every pattern matches only a single component name
    /// anywhere in the tree, so entries can be checked without reconstructing
    /// the parent path.
    has_path_patterns: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DenyList {
    /// Build a matcher from the given patterns.
    ///
    /// Patterns are parsed with gitignore semantics. Invalid patterns are
    /// skipped; a fully invalid or empty list yields a matcher that denies
    /// nothing.
    pub(crate) fn new(patterns: &[String]) -> Self {
        let mut builder = GitignoreBuilder::new(Path::new("/"));
        let mut has_path_patterns = false;
        for pattern in patterns {
            has_path_patterns |= pattern.contains('/');
            let _ = builder.add_line(None, pattern);
        }
        let matcher = builder.build().unwrap_or_else(|_| Gitignore::empty());
        Self {
            matcher,
            has_path_patterns,
        }
    }

    /// Whether any pattern is a path pattern (contains `/`).
    pub(crate) fn has_path_patterns(&self) -> bool {
        self.has_path_patterns
    }

    /// Whether the single entry `name` matches the deny list.
    ///
    /// Only meaningful when [`Self::has_path_patterns`] is `false`; path
    /// patterns cannot match a bare component name.
    pub(crate) fn matches_basename(&self, name: &[u8]) -> bool {
        self.is_ignored(name_as_path(name))
    }

    /// Whether the full relative path `rel` (relative to the mount root)
    /// matches the deny list.
    pub(crate) fn matches_path(&self, rel: &[u8]) -> bool {
        self.is_ignored(name_as_path(rel))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

impl DenyList {
    fn is_ignored(&self, path: &Path) -> bool {
        matches!(self.matcher.matched(path, false), Match::Ignore(_))
    }
}

/// Build a `Path` from raw entry-name bytes.
///
/// On Unix the bytes are used verbatim (arbitrary non-UTF8 names are legal);
/// elsewhere they are treated lossily. The bytes must not contain a trailing
/// NUL.
fn name_as_path(bytes: &[u8]) -> &Path {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Path::new(std::ffi::OsStr::from_bytes(bytes))
    }
    #[cfg(not(unix))]
    {
        Path::new(std::str::from_utf8(bytes).unwrap_or(""))
    }
}

/// Join entry-name components into a relative `PathBuf`.
///
/// Used to reconstruct a mount-relative path from the inode anchor chain.
pub(crate) fn join_path(components: &[Vec<u8>]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut path = PathBuf::new();
        for component in components {
            path.push(std::ffi::OsStr::from_bytes(component));
        }
        path
    }
    #[cfg(not(unix))]
    {
        let mut path = PathBuf::new();
        for component in components {
            path.push(String::from_utf8_lossy(component).into_owned());
        }
        path
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn deny(patterns: &[&str]) -> DenyList {
        let owned: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        DenyList::new(&owned)
    }

    #[test]
    fn empty_list_denies_nothing() {
        let list = deny(&[]);
        assert!(!list.matches_basename(b"anything"));
        assert!(!list.matches_path(b"dir/anything"));
    }

    #[test]
    fn basename_pattern_matches_anywhere() {
        let list = deny(&[".env", "*.log"]);
        assert!(list.has_path_patterns() == false);
        assert!(list.matches_basename(b".env"));
        assert!(list.matches_basename(b"debug.log"));
        assert!(!list.matches_basename(b"env"));
        assert!(!list.matches_basename(b"keep.txt"));
    }

    #[test]
    fn path_pattern_matches_full_path() {
        let list = deny(&["dir/secret", "**/env.secret"]);
        assert!(list.has_path_patterns());
        assert!(list.matches_path(b"dir/secret"));
        assert!(list.matches_path(b"a/b/c/env.secret"));
        assert!(!list.matches_path(b"dir/other"));
        assert!(!list.matches_path(b"secret"));
    }

    #[test]
    fn path_pattern_does_not_match_basename() {
        let list = deny(&["dir/secret"]);
        assert!(!list.matches_basename(b"secret"));
    }

    #[test]
    fn invalid_pattern_is_skipped() {
        let list = deny(&["[unclosed"]);
        assert!(!list.matches_basename(b"anything"));
    }
}
