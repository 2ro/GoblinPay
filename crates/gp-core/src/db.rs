//! SQLite persistence via raw `sqlx` (no ORM). One database file, zero-ops,
//! trivial backup. DB access stays behind this thin module so a later
//! Postgres swap is contained.

use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

/// Embedded migrations from the workspace-level `migrations/` directory.
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Open (creating if missing) the SQLite database at `db_path` and bring the
/// schema up to date. Called once at startup.
///
/// A single pooled connection: SQLite serializes writers anyway, and one
/// connection keeps the migrator (and every write) free of "database is
/// locked" contention. Fine for a low-traffic receive-only till; a later
/// Postgres swap for the multi-store backend lifts the ceiling.
pub async fn init(db_path: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true)
        .busy_timeout(std::time::Duration::from_secs(10))
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}

/// A migrated in-memory database on a single shared connection, for tests.
#[cfg(test)]
pub(crate) async fn test_pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("open in-memory sqlite");
    MIGRATOR.run(&pool).await.expect("run migrations");
    pool
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn table_names(pool: &SqlitePool) -> Vec<String> {
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn init_creates_db_and_applies_migrations() {
        let path = std::env::temp_dir().join(format!("gp-db-test-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let pool = init(path.to_str().unwrap()).await.unwrap();
        let tables = table_names(&pool).await;
        assert!(tables.contains(&"payment".to_string()), "{tables:?}");
        assert!(tables.contains(&"invoice".to_string()), "{tables:?}");
        pool.close().await;

        // Re-opening an existing database re-runs the migrator harmlessly.
        let pool = init(path.to_str().unwrap()).await.unwrap();
        assert!(table_names(&pool).await.contains(&"payment".to_string()));
        pool.close().await;

        let _ = std::fs::remove_file(&path);
    }
}
