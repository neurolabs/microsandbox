//! Guest paths of external mounts that a disk snapshot does not carry.

use serde::{Deserialize, Serialize};

use super::Manifest;
use crate::error::{SnapshotManifestError, SnapshotManifestResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Optional (not must-understand) key listing guest paths whose host-side backing is not captured.
pub const EXTERNAL_MOUNTS_EXTENSION: &str = "microsandbox.external-mounts";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExternalMountsExtension {
    guest_paths: Vec<String>,
    /// Captured host-side deny policy per guest path.
    ///
    /// Additive and omitted when no mount carries a deny list, so a deny-less
    /// manifest keeps the exact bytes an older reader already released.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    policies: Vec<ExternalMountPolicy>,
}

/// A captured bind-mount host-side deny policy, keyed by guest path.
///
/// Only bind mounts carry a deny list today; the policy is recorded separately
/// from the guest paths so a restore can detect a weakened deny list without
/// changing the digest of snapshots that carry none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalMountPolicy {
    /// Guest mount path the policy applies to.
    pub guest_path: String,
    /// Captured gitignore-style deny patterns.
    pub deny: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Manifest {
    /// Record the guest paths of source mounts this snapshot does not carry. Never host paths.
    ///
    /// The extension is advisory for older readers, so it is never added to `requires`.
    pub fn set_external_mounts(
        &mut self,
        mut guest_paths: Vec<String>,
    ) -> SnapshotManifestResult<()> {
        guest_paths.sort();
        guest_paths.dedup();

        if guest_paths.is_empty() {
            self.extensions.remove(EXTERNAL_MOUNTS_EXTENSION);
            return Ok(());
        }

        let value = serde_json::to_value(ExternalMountsExtension {
            guest_paths,
            policies: Vec::new(),
        })
        .map_err(|error| SnapshotManifestError::ManifestParse(error.to_string()))?;
        self.extensions
            .insert(EXTERNAL_MOUNTS_EXTENSION.into(), value);

        Ok(())
    }

    /// Record the captured deny policy for each host-backed bind mount.
    ///
    /// Must be called after [`Manifest::set_external_mounts`] so the recorded
    /// guest paths remain the source of truth. A mount with an empty deny list
    /// contributes no entry, so a deny-less snapshot keeps its released bytes.
    pub fn set_external_mount_policies(
        &mut self,
        mut policies: Vec<ExternalMountPolicy>,
    ) -> SnapshotManifestResult<()> {
        policies.retain(|policy| !policy.deny.is_empty());
        policies.sort_by(|left, right| left.guest_path.cmp(&right.guest_path));

        if policies.is_empty() {
            return Ok(());
        }

        let guest_paths = self.external_mounts()?;
        let value = serde_json::to_value(ExternalMountsExtension {
            guest_paths,
            policies,
        })
        .map_err(|error| SnapshotManifestError::ManifestParse(error.to_string()))?;
        self.extensions
            .insert(EXTERNAL_MOUNTS_EXTENSION.into(), value);

        Ok(())
    }

    /// Read the recorded deny policy; snapshots without the policy field record `None`.
    ///
    /// `None` means the snapshot predates deny-policy capture (or carried no
    /// deny list); callers must treat it as unknown, never as an empty list.
    pub fn external_mount_policies(
        &self,
    ) -> SnapshotManifestResult<Option<Vec<ExternalMountPolicy>>> {
        let Some(value) = self.extensions.get(EXTERNAL_MOUNTS_EXTENSION) else {
            return Ok(None);
        };
        if value.get("policies").is_none() {
            return Ok(None);
        }

        let extension: ExternalMountsExtension =
            serde_json::from_value(value.clone()).map_err(|error| {
                SnapshotManifestError::ManifestParse(format!("invalid external mounts: {error}"))
            })?;

        Ok(Some(extension.policies))
    }

    /// Read the recorded guest paths; snapshots without the extension record none.
    pub fn external_mounts(&self) -> SnapshotManifestResult<Vec<String>> {
        let Some(value) = self.extensions.get(EXTERNAL_MOUNTS_EXTENSION) else {
            return Ok(Vec::new());
        };

        let extension: ExternalMountsExtension =
            serde_json::from_value(value.clone()).map_err(|error| {
                SnapshotManifestError::ManifestParse(format!("invalid external mounts: {error}"))
            })?;

        Ok(extension.guest_paths)
    }
}
