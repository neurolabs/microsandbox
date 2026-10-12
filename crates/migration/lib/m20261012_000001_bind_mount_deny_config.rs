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
    // an absent, null, or empty deny list is safe to discard.
    let has_deny = value
        .pointer("/spec/mounts")
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

    fn with_deny() -> String {
        r#"{"spec":{"mounts":[{"type":"Bind","host":"/host/data","guest":"/data","deny":["sub/.env"]}]}}"#
            .to_string()
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
        let empty = r#"{"spec":{"mounts":[{"type":"Bind","host":"/host/data","guest":"/data","deny":[]}]}}"#;
        for column in ["config", "active_config"] {
            let deny = with_deny();
            let (config, active) = if column == "config" {
                (deny.as_str(), empty)
            } else {
                (empty, deny.as_str())
            };
            let db = database(config, Some(active)).await;
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
            r#"{"spec":{"mounts":[]}}"#.to_string(),
            r#"{"spec":{"mounts":[{"type":"Bind","host":"/host/data","guest":"/data","deny":[]}]}}"#
                .to_string(),
            r#"{"spec":{"mounts":[{"type":"Bind","host":"/host/data","guest":"/data"}]}}"#
                .to_string(),
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
