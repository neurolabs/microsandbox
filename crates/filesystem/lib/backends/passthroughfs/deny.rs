//! Deny-list matcher for bind mounts.
//!
//! A `deny` list is a set of gitignore-style patterns that hide matching
//! paths from a bind mount, enforced host-side in the passthrough backend.
//! Component-only patterns (no `/`, e.g. `.env`, `*.log`) are matched against
//! the entry name anywhere in the tree (gitignore semantics). Path patterns
//! (containing `/`, e.g. `dir/secret`, `**/env.secret`) are matched against
//! the full path relative to the mount root.
//!
//! Cross-platform: the matcher lives at the passthrough level so both the
//! Unix and Windows passthrough backends can use it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ignore::{Match, gitignore::Gitignore, gitignore::GitignoreBuilder};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Prefix of the probe file created in the mount root to detect a
/// case-insensitive filesystem, mirroring git's `core.ignorecase`
/// auto-detection (git creates a file and then `access`es a differently-cased
/// variant of its name).
///
/// The prefix must contain ASCII letters so a case-flipped sibling name can be
/// formed. A process-unique numeric suffix keeps concurrent builders from
/// colliding.
const CASE_PROBE_PREFIX: &str = "MsBCaSePrObE";
/// Probe file prefix lowercased, used to validate case-insensitivity.
fn case_validation_prefix() -> String {
    CASE_PROBE_PREFIX.to_ascii_lowercase()
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A matcher for a bind-mount `deny` list of gitignore-style patterns.
///
/// Wraps [`ignore::gitignore::Gitignore`]. The matcher is never empty; an
/// empty deny list matches nothing.
///
/// Matching honors the case-sensitivity of the mount root's filesystem. When
/// the root sits on a case-insensitive filesystem (Windows NTFS, default
/// macOS APFS, etc.), patterns and candidate names are folded so a pattern like
/// `.env` also hides `.ENV` and `.Env`; otherwise matching is byte-exact. This
/// mirrors git's `core.ignorecase` behavior for `.gitignore`.
#[derive(Debug)]
pub(crate) struct DenyList {
    matcher: Gitignore,
    /// Whether any pattern needs the full mount-relative path (has an interior
    /// `/`, i.e. a separator that is not merely a trailing dir-only marker).
    ///
    /// When `false`, every pattern matches a single component name anywhere in
    /// the tree, so entries can be checked without reconstructing the parent
    /// path.
    needs_path_reconstruction: bool,
    /// Whether any pattern is directory-only (ends with `/`, e.g. `node_modules/`).
    ///
    /// Only dir-only patterns depend on the entry's type, so callers must learn
    /// `is_dir` when this is `true`.
    has_dir_only_patterns: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DenyList {
    /// Build a matcher from the given patterns.
    ///
    /// `root` is the mount root on the host. It is probed to detect whether its
    /// filesystem is case-insensitive; when it is, patterns are matched
    /// case-insensitively (see the type docs).
    ///
    /// Patterns are parsed with gitignore semantics. Invalid patterns are
    /// skipped; a fully invalid or empty list yields a matcher that denies
    /// nothing.
    pub(crate) fn new(root: &Path, patterns: &[String]) -> Self {
        let mut builder = GitignoreBuilder::new(Path::new("/"));
        let mut needs_path_reconstruction = false;
        let mut has_dir_only_patterns = false;
        for pattern in patterns {
            needs_path_reconstruction |= pattern.trim_end_matches('/').contains('/');
            has_dir_only_patterns |= pattern.ends_with('/');
            let _ = builder.add_line(None, pattern);
        }
        let _ = builder.case_insensitive(mount_is_case_insensitive(root));
        let matcher = builder.build().unwrap_or_else(|_| Gitignore::empty());
        Self {
            matcher,
            needs_path_reconstruction,
            has_dir_only_patterns,
        }
    }

    /// Whether any pattern needs the full mount-relative path (interior `/`).
    pub(crate) fn needs_path_reconstruction(&self) -> bool {
        self.needs_path_reconstruction
    }

    /// Whether any pattern is directory-only (trailing `/`).
    pub(crate) fn has_dir_only_patterns(&self) -> bool {
        self.has_dir_only_patterns
    }

    /// Whether the single entry `name` matches the deny list.
    ///
    /// Only meaningful when [`Self::needs_path_reconstruction`] is `false`; a
    /// path pattern cannot match a bare component name. `name` is a single
    /// component, matched at any depth (gitignore component semantics).
    ///
    /// `is_dir` reports whether the entry is a directory; only dir-only
    /// patterns (trailing `/`) depend on it.
    pub(crate) fn matches_basename(&self, name: &[u8], is_dir: bool) -> bool {
        debug_assert!(!self.needs_path_reconstruction);
        self.is_ignored(name_as_path(name), is_dir)
    }

    /// Whether the full mount-relative path `rel` (relative to the mount root)
    /// matches the deny list.
    ///
    /// Used when [`Self::needs_path_reconstruction`] is `true`.
    ///
    /// `is_dir` reports whether the entry is a directory; see
    /// [`Self::matches_basename`].
    pub(crate) fn matches_path(&self, rel: &[u8], is_dir: bool) -> bool {
        self.is_ignored(name_as_path(rel), is_dir)
    }

    fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        matches!(self.matcher.matched(path, is_dir), Match::Ignore(_))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Monotonic counter used to make the case-sensitivity probe name unique within
/// the process, so concurrent builders on the same mount root do not collide.
static CASE_PROBE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Detect whether the filesystem holding `root` respectively the folder 'root'
/// is case-insensitive.
///
/// Almost all Linux/Unix filesystems: sensitive.
/// APFS / HFS+: insensitive by default, can be formatted case-sensitive.
/// FAT: insensitive.
/// NTFS: insensitive by default, can be configured per directory.
///
/// We don't detect case sensitivity per directory, but per mount.
///
/// Uses git's `core.ignorecase` probe: create a probe file with a known
/// mixed-case name, then check whether a case variant of that name
/// resolves to the same file. If it does, the filesystem folds case and deny
/// patterns must be matched case-insensitively.
///
/// A failed probe defaults to `true` (case-insensitive) rather than `false`:
/// over-matching only hides a few differently-cased names that almost never
/// coexist, whereas under-matching on a case-insensitive host would let a
/// pattern like `.env` be bypassed by requesting `.ENV`.
fn mount_is_case_insensitive(root: &Path) -> bool {
    let seq = CASE_PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
    let probe_name = format!("{CASE_PROBE_PREFIX}-{}-{seq}", std::process::id());
    let validation_name = format!("{}-{}-{seq}", case_validation_prefix(), std::process::id());
    let probe = root.join(&probe_name);
    let validation = root.join(&validation_name);

    let result = (|| -> std::io::Result<bool> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)?;
        std::io::Write::write_all(&mut file, b"probe")?;
        // If the case-flipped name resolves, the same file was found by a
        // differently-cased name, so the filesystem is case-insensitive.
        let insensitive = std::fs::symlink_metadata(&validation).is_ok();
        std::fs::remove_file(&probe)?;
        Ok(insensitive)
    })();

    result.unwrap_or(true)
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn deny(patterns: &[&str]) -> DenyList {
        let owned: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        let root = std::env::temp_dir().join(format!("msb-deny-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let list = DenyList::new(&root, &owned);
        let _ = std::fs::remove_dir_all(&root);
        list
    }

    #[test]
    fn mount_is_case_insensitive_cleans_up_fs() {
        // neither for unix nor for windows we can assert the check deterministically.
        // Therefore, we only assert the probe leaves no residue.
        let root = std::env::temp_dir().join(format!("msb-deny-probe-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let _ = mount_is_case_insensitive(&root);
        let empty = std::fs::read_dir(&root).unwrap().count();
        assert_eq!(empty, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_list_denies_nothing() {
        let list = deny(&[]);
        assert!(!list.matches_basename(b"anything", false));
        assert!(!list.matches_path(b"dir/anything", false));
    }

    #[test]
    fn basename_pattern_matches_anywhere() {
        let list = deny(&[".env", "*.log"]);
        assert!(!list.needs_path_reconstruction());
        assert!(!list.has_dir_only_patterns());
        assert!(list.matches_basename(b".env", false));
        assert!(list.matches_basename(b"debug.log", false));
        assert!(!list.matches_basename(b"env", false));
        assert!(!list.matches_basename(b"keep.log.txt", false));
        assert!(list.matches_path(b"dir/.env", false));
        assert!(list.matches_path(b"dir/debug.log", false));
    }

    #[test]
    fn path_pattern_matches_full_path() {
        let list = deny(&["dir/secret", "**/env.secret"]);
        assert!(list.needs_path_reconstruction());
        assert!(!list.has_dir_only_patterns());
        assert!(list.matches_path(b"dir/secret", false));
        assert!(list.matches_path(b"a/b/c/env.secret", false));
        assert!(!list.matches_path(b"dir/other", false));
        assert!(!list.matches_path(b"secret", false));
    }

    #[test]
    fn path_pattern_does_not_match_basename() {
        let list = deny(&["dir/secret"]);
        assert!(!list.matches_path(b"secret", false));
    }

    #[test]
    fn bracket_pattern_matches() {
        let list = deny(&["[a-z]"]);
        assert!(list.matches_basename(b"a", false));
        assert!(list.matches_basename(b"z", false));
        assert!(!list.matches_basename(b"0", false));
    }

    #[test]
    fn invalid_pattern_is_skipped() {
        let list = deny(&["[a-z"]);
        assert!(!list.matches_basename(b"a", false));
    }

    #[test]
    fn dir_only_path_pattern_matches_directory_but_not_file() {
        let list = deny(&["node_modules/"]);
        assert!(!list.needs_path_reconstruction());
        assert!(list.has_dir_only_patterns());
        assert!(list.matches_basename(b"node_modules", true));
        assert!(!list.matches_basename(b"node_modules", false));
        assert!(list.matches_path(b"node_modules", true));
        assert!(!list.matches_path(b"node_modules", false));
        assert!(!list.matches_path(b"node_modules.js", false));
    }

    #[test]
    fn dir_only_nested_path_pattern_matches_directory_but_not_file() {
        let list = deny(&["sub/node_modules/"]);
        assert!(list.needs_path_reconstruction());
        assert!(list.has_dir_only_patterns());
        assert!(list.matches_path(b"sub/node_modules", true));
        assert!(!list.matches_path(b"sub/node_modules", false));
        assert!(!list.matches_path(b"sub/node_modules.js", false));
    }

    #[test]
    fn interior_slash_pattern_needs_path_reconstruction() {
        let list = deny(&["sub/.env"]);
        assert!(list.needs_path_reconstruction());
        assert!(!list.has_dir_only_patterns());
    }

    #[test]
    fn trailing_slash_dir_only_uses_basename_fast_path() {
        let list = deny(&["node_modules/"]);
        assert!(!list.needs_path_reconstruction());
        assert!(list.has_dir_only_patterns());
        assert!(list.matches_basename(b"node_modules", true));
        assert!(!list.matches_basename(b"node_modules", false));
        assert!(!list.matches_basename(b"node_modules.js", false));
    }

    #[test]
    fn mixed_component_and_path_patterns_set_both_flags() {
        let list = deny(&["node_modules/", "sub/.env"]);
        assert!(list.needs_path_reconstruction());
        assert!(list.has_dir_only_patterns());
    }

    #[test]
    fn negation_enables_allowlist_mode() {
        let list = deny(&["*", "!keep.txt"]);
        assert!(list.matches_basename(b"other.txt", false));
        assert!(!list.matches_basename(b"keep.txt", false));
        assert!(list.matches_basename(b".env", false));
    }
}
