//! Prevent older binaries from silently discarding persisted bind-mount deny lists.
//!
//! The schema itself does not change; the migration record is the compatibility
//! marker. `VolumeMount`'s deserializer tolerates unknown fields, so an older
//! binary would read a config whose bind mount carries a `deny` list, ignore the
//! field, and restart the sandbox with the hidden host paths exposed. Recording
//! this migration makes older binaries refuse an ahead database, and `down()`
//! refuses a downgrade while any sandbox still carries a deny list.

use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Guard persisted bind-mount deny lists against older catalog readers.
pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261012_000001_bind_mount_deny_config"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // The migration row itself is the compatibility marker.
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // An older binary would deserialize either saved config while silently
        // dropping the deny list, so preflight both before the marker row is
        // removed and the database becomes downgradeable again.
        let rows = manager
            .get_connection()
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT name, config, active_config FROM sandbox".to_owned(),
            ))
            .await?;

        for row in rows {
            let name: String = row.try_get("", "name")?;
            let config: String = row.try_get("", "config")?;
            reject_persisted_deny(&name, "config", &config)?;

            if let Some(active_config) = row.try_get::<Option<String>>("", "active_config")? {
                reject_persisted_deny(&name, "active_config", &active_config)?;
            }
        }

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn reject_persisted_deny(name: &str, column: &str, raw: &str) -> Result<(), DbErr> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|error| {
        DbErr::Migration(format!(
            "bind_mount_deny_downgrade_unrepresentable: sandbox '{name}' {column} is invalid JSON: {error}"
        ))
    })?;

    // Read raw JSON so a later policy cannot be dropped by deserialization. Only
    // an absent, null, or empty deny list is safe to discard. `SandboxConfig`
    // flattens `SandboxSpec`, so mounts live at the top level (`/mounts`), not
    // under `/spec`; see the guest-clock migration for the same shape.
    let has_deny = value
        .pointer("/mounts")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|mounts| {
            mounts.iter().any(|mount| {
                mount
                    .get("deny")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|deny| !deny.is_empty())
            })
        });

    if has_deny {
        return Err(DbErr::Migration(format!(
            "bind_mount_deny_downgrade_unrepresentable: sandbox '{name}' {column} contains a bind-mount deny list that an older binary would discard; keep a compatible binary or remove this sandbox before downgrading"
        )));
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_types::{
        HostPermissions, MountOptions, SandboxSpec, StatVirtualization, VolumeMount,
    };
    use sea_orm_migration::sea_orm::{
        ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement,
    };

    use super::*;
    use crate::{Migrator, MigratorTrait};

    async fn database(config: &str, active: Option<&str>) -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO sandbox (name, config, active_config, status, ephemeral) VALUES ('deny-fixture', ?, ?, 'Stopped', 0)",
            [config.into(), active.into()],
        ))
        .await
        .unwrap();
        db
    }

    async fn saved_state(db: &DatabaseConnection) -> (String, Option<String>, Vec<String>) {
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT config, active_config FROM sandbox WHERE name = 'deny-fixture'",
            ))
            .await
            .unwrap()
            .unwrap();
        let migrations = Migrator::get_applied_migrations(db)
            .await
            .unwrap()
            .into_iter()
            .map(|migration| migration.name().to_owned())
            .collect();
        (
            row.try_get("", "config").unwrap(),
            row.try_get("", "active_config").unwrap(),
            migrations,
        )
    }

    /// A durable sandbox config carrying one bind mount with the given deny list.
    ///
    /// Built from the shared `SandboxSpec`, whose fields `SandboxConfig` flattens
    /// into the persisted JSON — so this is the exact production shape, with
    /// `mounts` at the top level.
    fn config(deny: Vec<String>) -> String {
        let mut spec = SandboxSpec::default();
        spec.mounts.push(VolumeMount::Bind {
            host: "/host/data".into(),
            guest: "/data".into(),
            options: MountOptions::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            follow_root_symlinks: false,
            quota_mib: None,
            deny,
        });
        serde_json::to_string(&spec).unwrap()
    }

    /// A durable sandbox config with no mounts at all.
    fn config_without_mounts() -> String {
        serde_json::to_string(&SandboxSpec::default()).unwrap()
    }

    /// Pin the assumption the guard depends on: persisted configs flatten the
    /// spec, so `mounts` (and `deny` within them) live at the top level, not
    /// under `spec`. A regression here would make the downgrade guard dead code.
    #[test]
    fn persisted_config_places_mounts_at_top_level() {
        let value: serde_json::Value = serde_json::from_str(&config(vec![".env".into()])).unwrap();
        assert!(
            value.get("spec").is_none(),
            "SandboxConfig flattens SandboxSpec"
        );
        assert_eq!(value["mounts"][0]["deny"][0], ".env");
    }

    /// Proof that the pre-fix pointer `/spec/mounts` never detected a real deny
    /// list, while `/mounts` does. Runs the exact predicate from
    /// [`reject_persisted_deny`] against the production-shaped JSON.
    #[test]
    fn old_spec_pointer_was_dead_for_production_shape() {
        let raw = config(vec!["sub/.env".into()]);
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();

        let deny_under = |pointer: &str| {
            value
                .pointer(pointer)
                .and_then(serde_json::Value::as_array)
                .is_some_and(|mounts| {
                    mounts.iter().any(|mount| {
                        mount
                            .get("deny")
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(|deny| !deny.is_empty())
                    })
                })
        };

        eprintln!(
            "production config shape:\n{}",
            serde_json::to_string_pretty(&value).unwrap()
        );
        eprintln!("/spec/mounts detects deny = {}", deny_under("/spec/mounts"));
        eprintln!("/mounts detects deny      = {}", deny_under("/mounts"));

        assert!(
            !deny_under("/spec/mounts"),
            "the old pointer must be proven dead on real data"
        );
        assert!(
            deny_under("/mounts"),
            "the new pointer must detect the deny list"
        );
    }

    /// Number of applied migrations from the newest down to (and including) this
    /// marker. Keeps the downgrade test independent of markers added after it.
    fn steps_to_deny_marker() -> u32 {
        let all = Migrator::migrations();
        let index = all
            .iter()
            .position(|migration| migration.name() == Migration.name())
            .expect("deny marker migration is listed");
        (all.len() - index) as u32
    }

    #[tokio::test]
    async fn downgrade_refuses_deny_in_desired_or_active_config() {
        let deny = config(vec!["sub/.env".to_string()]);
        let empty = config(Vec::new());
        for column in ["config", "active_config"] {
            let (desired, active) = if column == "config" {
                (deny.as_str(), empty.as_str())
            } else {
                (empty.as_str(), deny.as_str())
            };
            let db = database(desired, Some(active)).await;
            let before = saved_state(&db).await;

            let error = Migration.down(&SchemaManager::new(&db)).await.unwrap_err();

            let message = error.to_string();
            assert!(
                message.contains("bind_mount_deny_downgrade_unrepresentable"),
                "{message}"
            );
            assert!(message.contains("deny-fixture"), "{message}");
            assert!(message.contains(column), "{message}");
            assert_eq!(saved_state(&db).await, before);
        }
    }

    #[tokio::test]
    async fn downgrade_and_reupgrade_preserve_deny_free_configs() {
        for raw in [
            config_without_mounts(),
            config(Vec::new()),
            // A config whose serialized form predates `mounts` entirely.
            r#"{"name":"legacy"}"#.to_string(),
        ] {
            for active in [None, Some(raw.as_str())] {
                let db = database(&raw, active).await;
                let before = saved_state(&db).await;

                let steps = steps_to_deny_marker();
                Migrator::down(&db, Some(steps)).await.unwrap();

                let after = saved_state(&db).await;
                assert_eq!(after.0, before.0);
                assert_eq!(after.1, before.1);
                assert_eq!(before.2.len() - after.2.len(), steps as usize);
                assert!(!after.2.iter().any(|id| id == Migration.name()));

                Migrator::up(&db, None).await.unwrap();
                assert_eq!(saved_state(&db).await, before);
            }
        }
    }
}
