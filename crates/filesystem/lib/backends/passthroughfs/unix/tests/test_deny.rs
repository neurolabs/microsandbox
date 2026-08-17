//! Tests for the bind-mount deny-list enforcement.

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests: component-only pattern (basename) matching
//--------------------------------------------------------------------------------------------------

/// A denied basename is invisible via lookup.
#[test]
fn test_deny_basename_lookup() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".env".to_string()],
        ..cfg
    });
    sb.host_create_file(".env", b"secret");
    sb.host_create_file("visible.txt", b"ok");

    TestSandbox::assert_errno(sb.lookup_root(".env"), LINUX_ENOENT);

    // Non-denied file still works.
    let entry = sb.lookup_root("visible.txt").unwrap();
    assert_eq!(entry.inode, 3);
}

//--------------------------------------------------------------------------------------------------
// Tests: create/mkdir EACCES on denied names
//--------------------------------------------------------------------------------------------------

/// Creating a denied basename via FUSE returns EACCES.
#[test]
fn test_deny_create_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".secrets".to_string()],
        ..cfg
    });

    TestSandbox::assert_errno(sb.fuse_create_root(".secrets"), LINUX_EACCES);

    // Normal create still works.
    let (entry, _handle) = sb.fuse_create_root("normal.txt").unwrap();
    assert_eq!(entry.inode, 3);
}

/// Creating a hidden directory returns EACCES from the deny list.
#[test]
fn test_deny_mkdir_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".hidden_dir".to_string(), "no_create.txt".to_string()],
        ..cfg
    });

    TestSandbox::assert_errno(sb.fuse_mkdir_root(".hidden_dir"), LINUX_EACCES);

    // Normal dirs work.
    sb.fuse_mkdir_root("visible_dir").unwrap();

    // Verify visible_dir is accessible.
    sb.lookup_root("visible_dir").unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests: rename EACCES on denied names
//--------------------------------------------------------------------------------------------------

/// Renaming into a denied target name returns EACCES.
#[test]
fn test_deny_rename_to_denied_target() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".forbidden".to_string()],
        ..cfg
    });

    // Create a source file first.
    let (_entry, _handle) = sb.fuse_create_root("source.txt").unwrap();

    // Rename to denied name.
    TestSandbox::assert_errno(
        sb.fs.rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("source.txt"),
            ROOT_INODE,
            &TestSandbox::cstr(".forbidden"),
            0,
        ),
        LINUX_EACCES,
    );

    // Rename to normal name still works.
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("source.txt"),
            ROOT_INODE,
            &TestSandbox::cstr("renamed.txt"),
            0,
        )
        .unwrap();

    // Verify renamed file is accessible.
    sb.lookup_root("renamed.txt").unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests: readdir filtering
//--------------------------------------------------------------------------------------------------

/// Denied entries are omitted from readdir.
#[test]
fn test_deny_readdir_omits_entries() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".env".to_string(), "*.log".to_string()],
        ..cfg
    });
    sb.host_create_file(".env", b"hidden");
    sb.host_create_file("data.log", b"hidden");
    sb.host_create_file("visible.txt", b"ok");

    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 4096, 0)
        .unwrap();

    let has_env = entries.iter().any(|e| e.name == b".env");
    let has_log = entries.iter().any(|e| e.name == b"data.log");
    let has_visible = entries.iter().any(|e| e.name == b"visible.txt");

    assert!(!has_env, ".env should be hidden from readdir");
    assert!(!has_log, "data.log should be hidden from readdir");
    assert!(has_visible, "visible.txt should be in readdir");
}

//--------------------------------------------------------------------------------------------------
// Tests: unlink/rmdir EACCES
//--------------------------------------------------------------------------------------------------

/// Unlink of a denied name returns EACCES.
#[test]
fn test_deny_unlink_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".do-not-delete".to_string()],
        ..cfg
    });

    // Create a hidden file.
    sb.host_create_file(".do-not-delete", b"protected");

    // Unlink should fail with EACCES (denied by deny-list).
    TestSandbox::assert_errno(
        sb.fs
            .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr(".do-not-delete")),
        LINUX_EACCES,
    );
}

/// Rmdir of a denied directory returns EACCES.
#[test]
fn test_deny_rmdir_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".protected-dir".to_string()],
        ..cfg
    });

    // Create a hidden directory.
    sb.host_create_dir(".protected-dir");

    // Rmdir should fail with EACCES.
    TestSandbox::assert_errno(
        sb.fs
            .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr(".protected-dir")),
        LINUX_EACCES,
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: non-denied operations unaffected
//--------------------------------------------------------------------------------------------------

/// Non-denied names remain fully read-write.
#[test]
fn test_deny_normal_ops_unchanged() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".env".to_string()],
        ..cfg
    });

    // Create, write, read all work on non-denied names.
    let (entry, handle) = sb.fuse_create_root("writeable.txt").unwrap();
    let written = sb
        .fuse_write(entry.inode, handle, b"hello deny", 0)
        .unwrap();
    assert_eq!(written, 10);

    let (handle, _) = sb
        .fs
        .open(sb.ctx(), entry.inode, false, LINUX_O_RDWR)
        .unwrap();
    let data = sb.fuse_read(entry.inode, handle.unwrap(), 10, 0).unwrap();
    assert_eq!(data, b"hello deny");

    // Unlink works on normal files.
    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("writeable.txt"))
        .unwrap();

    // After unlink, lookup returns ENOENT.
    TestSandbox::assert_errno(sb.lookup_root("writeable.txt"), LINUX_ENOENT);
}

//--------------------------------------------------------------------------------------------------
// Tests: path-pattern (nested) matching
//--------------------------------------------------------------------------------------------------

/// A nested path pattern hides the matching path but not its siblings.
#[test]
fn test_deny_path_pattern_lookup() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["sub/.env".to_string()],
        ..cfg
    });
    sb.host_create_dir("sub");
    sb.host_create_file("sub/.env", b"secret");
    sb.host_create_file("sub/visible.txt", b"ok");

    // The parent dir is reachable.
    let dir = sb.lookup_root("sub").unwrap();
    assert_eq!(dir.inode, 3);

    // The denied nested file is hidden.
    TestSandbox::assert_errno(sb.lookup(dir.inode, ".env"), LINUX_ENOENT);

    // A sibling in the same dir is visible.
    let visible = sb.lookup(dir.inode, "visible.txt").unwrap();
    assert_eq!(visible.inode, 4);
}

/// A recursive path pattern hides nested matches at any depth.
#[test]
fn test_deny_recursive_path_pattern() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["**/env.secret".to_string()],
        ..cfg
    });
    sb.host_create_dir("a");
    sb.host_create_dir("a/b");
    sb.host_create_file("a/b/env.secret", b"secret");

    let a = sb.lookup_root("a").unwrap();
    let b = sb.lookup(a.inode, "b").unwrap();
    TestSandbox::assert_errno(sb.lookup(b.inode, "env.secret"), LINUX_ENOENT);
}

/// Path patterns also gate create within a hidden subtree.
#[test]
fn test_deny_path_pattern_create() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["sub/.secret".to_string()],
        ..cfg
    });
    sb.host_create_dir("sub");
    let dir = sb.lookup_root("sub").unwrap();

    TestSandbox::assert_errno(sb.fuse_create(dir.inode, ".secret", 0o644), LINUX_EACCES);

    // Sibling create is unaffected.
    sb.fuse_create(dir.inode, "normal.txt", 0o644).unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests: rename from a denied source name
//--------------------------------------------------------------------------------------------------

/// Renaming a denied source name away is rejected.
#[test]
fn test_deny_rename_from_denied_source() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".forbidden".to_string()],
        ..cfg
    });

    // A denied name already exists on the host.
    sb.host_create_file(".forbidden", b"hidden");

    // Renaming it away is rejected.
    TestSandbox::assert_errno(
        sb.fs.rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr(".forbidden"),
            ROOT_INODE,
            &TestSandbox::cstr("freed.txt"),
            0,
        ),
        LINUX_EACCES,
    );
}
