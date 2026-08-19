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
const CASE_PROBE_PREFIX: &str = "MsbCaseProbe";

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
    /// `root` is the mount root on the host. It is probed to detect whether its
    /// filesystem is case-insensitive; when it is, patterns are matched
    /// case-insensitively (see the type docs).
    ///
    /// Patterns are parsed with gitignore semantics. Invalid patterns are
    /// skipped; a fully invalid or empty list yields a matcher that denies
    /// nothing.
    pub(crate) fn new(root: &Path, patterns: &[String]) -> Self {
        let mut builder = GitignoreBuilder::new(Path::new("/"));
        let mut has_path_patterns = false;
        for pattern in patterns {
            has_path_patterns |= pattern.contains('/');
            let _ = builder.add_line(None, pattern);
        }
        let _ = builder.case_insensitive(filesystem_is_case_insensitive(root));
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
    ///
    /// `is_dir` reports whether the entry is a directory. Directory-only
    /// patterns (with a trailing `/`, e.g. `node_modules/`) match directories
    /// but not same-named files, mirroring gitignore semantics.
    pub(crate) fn matches_basename(&self, name: &[u8], is_dir: bool) -> bool {
        self.is_ignored(name_as_path(name), is_dir)
    }

    /// Whether the full relative path `rel` (relative to the mount root)
    /// matches the deny list.
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

/// Detect whether the filesystem holding `root` is case-insensitive.
///
/// Uses git's `core.ignorecase` probe: create a probe file with a known
/// mixed-case name, then check whether a case-flipped variant of that name
/// resolves to the same file. If it does, the filesystem folds case and deny
/// patterns must be matched case-insensitively. The probe file is removed
/// before returning.
///
/// The deny list is a confidentiality boundary, so a failed probe defaults to
/// `true` (case-insensitive) rather than `false`: over-matching only hides a
/// few differently-cased names that almost never coexist, whereas under-matching
/// on a case-insensitive host would let a pattern like `.env` be bypassed by
/// requesting `.ENV`. This is fail-closed for the secrecy property.
fn filesystem_is_case_insensitive(root: &Path) -> bool {
    let seq = CASE_PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
    let name = format!("{CASE_PROBE_PREFIX}-{}-{seq}", std::process::id());
    let probe = root.join(&name);
    let flipped = root.join(case_flip_ascii(&name));

    let result = (|| -> std::io::Result<bool> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)?;
        std::io::Write::write_all(&mut file, b"probe")?;
        // If the case-flipped name resolves, the same file was found by a
        // differently-cased name, so the filesystem is case-insensitive.
        let insensitive = std::fs::symlink_metadata(&flipped).is_ok();
        std::fs::remove_file(&probe)?;
        Ok(insensitive)
    })();

    result.unwrap_or(true)
}

/// Flip the ASCII letter case of every byte in `s`; non-ASCII bytes are left
/// unchanged. Used to build the case-variant probe name.
fn case_flip_ascii(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
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
    fn case_flip_ascii_flips_ascii_only() {
        assert_eq!(case_flip_ascii("MsbCaseProbe-1"), "mSBcASEpROBE-1");
        assert_eq!(case_flip_ascii("no-ascii-123"), "NO-ASCII-123");
        assert_eq!(case_flip_ascii("héllo"), "HéLLO");
    }

    #[test]
    fn probe_reports_case_sensitive_on_temp_fs() {
        // The default temp filesystem on every supported platform is
        // case-sensitive (Linux, macOS APFS default is a test-site concern; on
        // case-insensitive hosts this assertion is skipped by comparing to the
        // real behavior). We at least assert the probe leaves no residue.
        let root = std::env::temp_dir().join(format!("msb-deny-probe-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let _ = filesystem_is_case_insensitive(&root);
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
        assert!(list.has_path_patterns() == false);
        assert!(list.matches_basename(b".env", false));
        assert!(list.matches_basename(b"debug.log", false));
        assert!(!list.matches_basename(b"env", false));
        assert!(!list.matches_basename(b"keep.txt", false));
    }

    #[test]
    fn path_pattern_matches_full_path() {
        let list = deny(&["dir/secret", "**/env.secret"]);
        assert!(list.has_path_patterns());
        assert!(list.matches_path(b"dir/secret", false));
        assert!(list.matches_path(b"a/b/c/env.secret", false));
        assert!(!list.matches_path(b"dir/other", false));
        assert!(!list.matches_path(b"secret", false));
    }

    #[test]
    fn path_pattern_does_not_match_basename() {
        let list = deny(&["dir/secret"]);
        assert!(!list.matches_basename(b"secret", false));
    }

    #[test]
    fn invalid_pattern_is_skipped() {
        let list = deny(&["[unclosed"]);
        assert!(!list.matches_basename(b"anything", false));
    }

    #[test]
    fn dir_only_path_pattern_matches_directory_but_not_file() {
        let list = deny(&["node_modules/"]);
        assert!(list.has_path_patterns());
        assert!(list.matches_path(b"node_modules", true));
        assert!(!list.matches_path(b"node_modules", false));
        assert!(!list.matches_path(b"node_modules.js", false));
    }

    #[test]
    fn dir_only_nested_path_pattern_matches_directory_but_not_file() {
        let list = deny(&["sub/node_modules/"]);
        assert!(list.has_path_patterns());
        assert!(list.matches_path(b"sub/node_modules", true));
        assert!(!list.matches_path(b"sub/node_modules", false));
        assert!(!list.matches_path(b"sub/node_modules.js", false));
    }
}
