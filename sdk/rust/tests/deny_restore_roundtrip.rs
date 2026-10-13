//! End-to-end coverage for bind-mount `deny` policy durability across restore.
//!
//! This test boots real microVMs and therefore stays ignored during ordinary
//! workspace tests. Run it explicitly on a supported host with:
//!
//! ```sh
//! cargo test -p microsandbox --test deny_restore_roundtrip -- --ignored
//! ```

use microsandbox::{Sandbox, Snapshot};
use test_utils::msb_test;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn cleanup(name: &str) {
    if let Ok(handle) = Sandbox::get(name).await {
        let _ = handle.kill().await;
        let _ = handle.remove().await;
    }
}

/// A bind `deny` policy must be captured in the snapshot manifest, re-applied on
/// restore, and must refuse a restore that drops it.
#[msb_test]
async fn deny_policy_survives_snapshot_restore_and_hides_the_path() {
    let suffix = std::process::id();
    let source_name = format!("deny-src-{suffix}");
    let child_name = format!("deny-child-{suffix}");
    let snapshot_name = format!("deny-snap-{suffix}");

    let host = tempfile::tempdir().unwrap();
    std::fs::write(host.path().join(".env"), b"secret").unwrap();
    std::fs::write(host.path().join("visible.txt"), b"ok").unwrap();

    cleanup(&source_name).await;
    cleanup(&child_name).await;

    let source = Sandbox::builder(&source_name)
        .image("alpine:3.20")
        .cpus(1)
        .memory(512)
        .replace()
        .volume("/data", |mount| mount.bind(host.path()).deny([".env"]))
        .create()
        .await
        .expect("create deny-bearing source");

    let live = source
        .shell("test ! -e /data/.env && test -f /data/visible.txt")
        .await
        .expect("exercise source deny policy");
    assert!(
        live.status().success,
        "source must hide .env: stdout=`{}` stderr=`{}`",
        live.stdout().unwrap_or_default(),
        live.stderr().unwrap_or_default()
    );

    let snapshot = Snapshot::builder(&snapshot_name)
        .from_sandbox(&source_name)
        .create()
        .await
        .expect("snapshot");

    // (a) the deny policy round-trips through the snapshot manifest.
    let policies = snapshot
        .manifest()
        .external_mount_policies()
        .expect("read captured deny policy");
    let has_policy = policies.as_ref().is_some_and(|policies| {
        policies
            .iter()
            .any(|policy| policy.guest_path == "/data" && policy.deny == [".env".to_string()])
    });
    assert!(has_policy, "captured deny policy is missing: {policies:?}");

    let _ = source.stop().await;
    cleanup(&source_name).await;

    // (b) restoring with the deny list preserved keeps .env hidden.
    let child = Sandbox::restore(&snapshot_name)
        .name(&child_name)
        .cpus(1)
        .memory(512)
        .volume("/data", |mount| mount.bind(host.path()).deny([".env"]))
        .restore()
        .await
        .expect("restore with preserved deny");
    let restored = child
        .shell("test ! -e /data/.env && test -f /data/visible.txt")
        .await
        .expect("exercise restored deny policy");
    assert!(
        restored.status().success,
        "restored sandbox must hide .env: stdout=`{}` stderr=`{}`",
        restored.stdout().unwrap_or_default(),
        restored.stderr().unwrap_or_default()
    );
    let _ = child.stop().await;
    cleanup(&child_name).await;

    // A restore that drops the captured deny list must be refused, never silently weaken it.
    let weakened = Sandbox::restore(&snapshot_name)
        .name(&child_name)
        .volume("/data", |mount| mount.bind(host.path()))
        .restore()
        .await;
    assert!(
        weakened.is_err(),
        "restore that drops the captured deny list must be refused"
    );
    if let Ok(child) = weakened {
        let _ = child.stop().await;
    }
    cleanup(&child_name).await;
}
