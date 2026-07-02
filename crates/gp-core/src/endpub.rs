//! Per-user endpubs with optional rolling rotation (milestone 5b,
//! multi-tenant receiving).
//!
//! An admin assigns one receiving identity ("endpub") per end-user. The
//! endpub is a stateless child of the server nsec keyed by `(user_id, epoch)`
//! (see [`crate::derive`]), so the database stores only the assignment and the
//! rotation clock, never a private key. All funds still land in the one Grin
//! wallet; the endpub only decides which user an incoming payment credits.
//!
//! Optional rotation advances a user's epoch on a per-user (or global default)
//! interval, rolling their advertised endpub. An overlap window keeps the last
//! N epochs watched, so a payment sent to a just-rotated endpub still lands and
//! still maps to that user.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::{derive, ids};

/// A tenant user. `rotate_interval` is a per-user override in seconds
/// (`NULL` = global default, `0` = rotation off). `epoch` is the current
/// (highest) endpub epoch.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub rotate_interval: Option<i64>,
    pub epoch: i64,
    pub last_rotated_at: String,
    pub created_at: String,
}

/// One endpub assignment: a user's receiving pubkey at a given epoch. The
/// pubkey is the derived x-only hex (public, never a secret).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Endpub {
    pub user_id: String,
    pub epoch: i64,
    pub pubkey: String,
    pub created_at: String,
}

/// A user with their current endpub and running balance (admin listing).
#[derive(Debug, Clone, Serialize)]
pub struct UserBalance {
    pub user_id: String,
    pub epoch: i64,
    pub endpub: String,
    /// Total received nanogrin credited to this user.
    pub balance: i64,
}

/// Create a user (id auto-generated when `id` is `None`) and assign their
/// epoch-0 endpub. Returns the user and their first endpub.
pub async fn create_user(
    pool: &SqlitePool,
    master_sk: &[u8; 32],
    id: Option<String>,
    rotate_interval: Option<i64>,
) -> Result<(User, Endpub), sqlx::Error> {
    let id = id.unwrap_or_else(ids::random_id);
    sqlx::query(
        "INSERT INTO user (id, rotate_interval, epoch, last_rotated_at, created_at) \
         VALUES (?1, ?2, 0, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
                 strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
    )
    .bind(&id)
    .bind(rotate_interval)
    .execute(pool)
    .await?;
    let endpub = assign(pool, master_sk, &id, 0).await?;
    let user = get_user(pool, &id).await?.ok_or(sqlx::Error::RowNotFound)?;
    Ok((user, endpub))
}

/// Assign (idempotently) the endpub for `(user_id, epoch)`, deriving its
/// pubkey. Returns the assignment row.
async fn assign(
    pool: &SqlitePool,
    master_sk: &[u8; 32],
    user_id: &str,
    epoch: i64,
) -> Result<Endpub, sqlx::Error> {
    let pubkey = derive::endpub_pubkey_hex(master_sk, user_id, epoch);
    sqlx::query(
        "INSERT OR IGNORE INTO endpub_assignment (user_id, epoch, pubkey, created_at) \
         VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
    )
    .bind(user_id)
    .bind(epoch)
    .bind(&pubkey)
    .execute(pool)
    .await?;
    sqlx::query_as::<_, Endpub>(
        "SELECT user_id, epoch, pubkey, created_at FROM endpub_assignment \
         WHERE user_id = ?1 AND epoch = ?2",
    )
    .bind(user_id)
    .bind(epoch)
    .fetch_one(pool)
    .await
}

/// Fetch a user by id.
pub async fn get_user(pool: &SqlitePool, id: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, rotate_interval, epoch, last_rotated_at, created_at FROM user WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// The user's current (highest-epoch) endpub.
pub async fn current_endpub(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Option<Endpub>, sqlx::Error> {
    sqlx::query_as::<_, Endpub>(
        "SELECT user_id, epoch, pubkey, created_at FROM endpub_assignment \
         WHERE user_id = ?1 ORDER BY epoch DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// Set (or clear, with `None`) a user's per-user rotation interval in seconds.
pub async fn set_rotate_interval(
    pool: &SqlitePool,
    user_id: &str,
    interval: Option<i64>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE user SET rotate_interval = ?2 WHERE id = ?1")
        .bind(user_id)
        .bind(interval)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Force-rotate a user now: advance their epoch and assign the new endpub.
/// Returns the new endpub.
pub async fn rotate(
    pool: &SqlitePool,
    master_sk: &[u8; 32],
    user_id: &str,
) -> Result<Endpub, sqlx::Error> {
    let user = get_user(pool, user_id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;
    let next = user.epoch + 1;
    sqlx::query(
        "UPDATE user SET epoch = ?2, last_rotated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE id = ?1",
    )
    .bind(user_id)
    .bind(next)
    .execute(pool)
    .await?;
    assign(pool, master_sk, user_id, next).await
}

/// Rotate every user whose rotation clock has elapsed (per-user interval, else
/// `global_interval`; `0`/`None` = off). Called by a periodic tick. Returns
/// the number of users rotated. Rotation is staggered by each user's own
/// clock, never a flag-day.
pub async fn rotate_due(
    pool: &SqlitePool,
    master_sk: &[u8; 32],
    global_interval: i64,
) -> Result<usize, sqlx::Error> {
    let users = sqlx::query_as::<_, User>(
        "SELECT id, rotate_interval, epoch, last_rotated_at, created_at FROM user",
    )
    .fetch_all(pool)
    .await?;
    let mut rotated = 0;
    for user in users {
        let interval = user.rotate_interval.unwrap_or(global_interval);
        if interval <= 0 {
            continue;
        }
        // Elapsed since last rotation, in whole seconds, computed in SQL to
        // avoid a Rust-side clock dependency.
        let elapsed: i64 = sqlx::query_scalar(
            "SELECT CAST(strftime('%s', 'now') AS INTEGER) \
                  - CAST(strftime('%s', ?1) AS INTEGER)",
        )
        .bind(&user.last_rotated_at)
        .fetch_one(pool)
        .await?;
        if elapsed >= interval {
            rotate(pool, master_sk, &user.id).await?;
            rotated += 1;
        }
    }
    Ok(rotated)
}

/// The union of pubkeys to subscribe to: for every user, the current epoch and
/// the previous `overlap` epochs. This is what gp-nostr watches so a payment
/// to a just-rotated endpub still lands within the window.
pub async fn watched_pubkeys(pool: &SqlitePool, overlap: i64) -> Result<Vec<Endpub>, sqlx::Error> {
    let overlap = overlap.max(0);
    sqlx::query_as::<_, Endpub>(
        "SELECT a.user_id, a.epoch, a.pubkey, a.created_at \
         FROM endpub_assignment a JOIN user u ON u.id = a.user_id \
         WHERE a.epoch >= u.epoch - ?1 \
         ORDER BY a.user_id, a.epoch",
    )
    .bind(overlap)
    .fetch_all(pool)
    .await
}

/// Resolve a received pubkey to its `(user_id, epoch)`, if it is any assigned
/// endpub (crediting works for any stored assignment, even one just rotated
/// past the watch window).
pub async fn user_for_pubkey(
    pool: &SqlitePool,
    pubkey: &str,
) -> Result<Option<(String, i64)>, sqlx::Error> {
    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT user_id, epoch FROM endpub_assignment WHERE pubkey = ?1 LIMIT 1")
            .bind(pubkey)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// Every user with their current endpub and running received balance.
pub async fn list_with_balances(pool: &SqlitePool) -> Result<Vec<UserBalance>, sqlx::Error> {
    let users = sqlx::query_as::<_, User>(
        "SELECT id, rotate_interval, epoch, last_rotated_at, created_at FROM user \
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(users.len());
    for user in users {
        let endpub = current_endpub(pool, &user.id)
            .await?
            .map(|e| e.pubkey)
            .unwrap_or_default();
        let balance: i64 =
            sqlx::query_scalar("SELECT COALESCE(SUM(amount), 0) FROM payment WHERE user_id = ?1")
                .bind(&user.id)
                .fetch_one(pool)
                .await?;
        out.push(UserBalance {
            user_id: user.id,
            epoch: user.epoch,
            endpub,
            balance,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    async fn pool() -> SqlitePool {
        db::test_pool().await
    }

    const MASTER: [u8; 32] = [5u8; 32];

    #[tokio::test]
    async fn create_user_assigns_a_deterministic_endpub() {
        let pool = pool().await;
        let (user, endpub) = create_user(&pool, &MASTER, Some("alice".into()), None)
            .await
            .unwrap();
        assert_eq!(user.epoch, 0);
        assert_eq!(endpub.epoch, 0);
        // Stateless: the stored pubkey equals a fresh derivation.
        assert_eq!(
            endpub.pubkey,
            derive::endpub_pubkey_hex(&MASTER, "alice", 0)
        );
        // And it resolves back to the user.
        assert_eq!(
            user_for_pubkey(&pool, &endpub.pubkey).await.unwrap(),
            Some(("alice".into(), 0))
        );
    }

    #[tokio::test]
    async fn rotation_keeps_old_epochs_payable_within_the_window() {
        let pool = pool().await;
        let (_u, first) = create_user(&pool, &MASTER, Some("bob".into()), None)
            .await
            .unwrap();
        let second = rotate(&pool, &MASTER, "bob").await.unwrap();
        assert_eq!(second.epoch, 1);
        assert_ne!(first.pubkey, second.pubkey);

        // Both epochs still credit the same user (crediting is not gated on
        // the watch window)...
        assert_eq!(
            user_for_pubkey(&pool, &first.pubkey).await.unwrap(),
            Some(("bob".into(), 0))
        );
        assert_eq!(
            user_for_pubkey(&pool, &second.pubkey).await.unwrap(),
            Some(("bob".into(), 1))
        );

        // ...and with overlap >= 1 the just-rotated old endpub is still watched.
        let watched: Vec<String> = watched_pubkeys(&pool, 1)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.pubkey)
            .collect();
        assert!(
            watched.contains(&first.pubkey),
            "overlap keeps epoch 0 watched"
        );
        assert!(watched.contains(&second.pubkey));

        // With no overlap only the current epoch is watched.
        let watched0: Vec<String> = watched_pubkeys(&pool, 0)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.pubkey)
            .collect();
        assert_eq!(watched0, vec![second.pubkey.clone()]);
    }

    #[tokio::test]
    async fn rotate_due_respects_intervals() {
        let pool = pool().await;
        // interval 0 (off): never rotates even though last_rotated is old.
        create_user(&pool, &MASTER, Some("off".into()), Some(0))
            .await
            .unwrap();
        // A short interval with a backdated clock rotates.
        create_user(&pool, &MASTER, Some("due".into()), Some(10))
            .await
            .unwrap();
        sqlx::query("UPDATE user SET last_rotated_at = '2000-01-01T00:00:00Z' WHERE id = 'due'")
            .execute(&pool)
            .await
            .unwrap();

        let rotated = rotate_due(&pool, &MASTER, 0).await.unwrap();
        assert_eq!(rotated, 1);
        assert_eq!(get_user(&pool, "due").await.unwrap().unwrap().epoch, 1);
        assert_eq!(get_user(&pool, "off").await.unwrap().unwrap().epoch, 0);
    }
}
