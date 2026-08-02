use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

mod backlink;
mod blob;
mod delegation;
mod event_notifier;
mod gitops;
mod infra;
mod oauth;
mod repo;
mod session;
mod sso;
mod user;
// User/account queries are being converted in sections before enabling this module.
// The remaining repositories are enabled as they are ported to SQLite.
pub use backlink::SqliteBacklinkRepository;
pub use blob::SqliteBlobRepository;
pub use delegation::SqliteDelegationRepository;
pub use event_notifier::SqliteRepoEventNotifier;
pub use gitops::SqliteGitOpsRepository;
pub use infra::SqliteInfraRepository;
pub use oauth::SqliteOAuthRepository;
pub use repo::SqliteRepoRepository;
pub use session::SqliteSessionRepository;
pub use sso::SqliteSsoRepository;
pub use user::SqliteUserRepository;

pub(crate) mod col;

use tranquil_db_traits::{
    BacklinkRepository, BlobRepository, DelegationRepository, GitOpsRepository, InfraRepository,
    OAuthRepository, RepoEventNotifier, RepoRepository, SessionRepository, SsoRepository,
    UserRepository,
};

pub struct SqliteRepositories {
    pub user: Arc<dyn UserRepository>,
    pub pool: Option<SqlitePool>,
    pub backlink: Arc<dyn BacklinkRepository>,
    pub blob: Arc<dyn BlobRepository>,
    pub delegation: Arc<dyn DelegationRepository>,
    pub infra: Arc<dyn InfraRepository>,
    pub oauth: Arc<dyn OAuthRepository>,
    pub repo: Arc<dyn RepoRepository>,
    pub sso: Arc<dyn SsoRepository>,
    pub event_notifier: Arc<dyn RepoEventNotifier>,
    pub session: Arc<dyn SessionRepository>,
    pub gitops: Arc<dyn GitOpsRepository>,
}

impl SqliteRepositories {
    pub fn new(pool: SqlitePool) -> Self {
        let notifier = Arc::new(SqliteRepoEventNotifier::new(256));
        let gitops = Arc::new(SqliteGitOpsRepository::new(pool.clone()));
        Self {
            user: Arc::new(SqliteUserRepository::new(pool.clone())),
            backlink: Arc::new(SqliteBacklinkRepository::new(pool.clone())),
            blob: Arc::new(SqliteBlobRepository::new(pool.clone())),
            delegation: Arc::new(SqliteDelegationRepository::new(pool.clone())),
            infra: Arc::new(SqliteInfraRepository::new(pool.clone())),
            oauth: Arc::new(SqliteOAuthRepository::new(pool.clone())),
            repo: Arc::new(SqliteRepoRepository::new(pool.clone())),
            sso: Arc::new(SqliteSsoRepository::new(pool.clone())),
            event_notifier: notifier,
            session: Arc::new(SqliteSessionRepository::new(pool.clone())),
            pool: Some(pool),
            gitops,
        }
    }
}

fn column<T: std::str::FromStr>(
    value: String,
    name: tranquil_db_traits::ColumnRef,
) -> Result<T, tranquil_db_traits::DbError> {
    value
        .parse()
        .map_err(|_| tranquil_db_traits::DbError::InvalidColumn(name))
}

fn opt_column<T: std::str::FromStr>(
    value: Option<String>,
    name: tranquil_db_traits::ColumnRef,
) -> Result<Option<T>, tranquil_db_traits::DbError> {
    value.map(|value| column(value, name)).transpose()
}

fn legacy_column<T: std::str::FromStr>(
    value: String,
    name: tranquil_db_traits::ColumnRef,
) -> Option<T> {
    match value.parse() {
        Ok(value) => Some(value),
        Err(_) => {
            tracing::warn!(column = %name, value = %value, "ignoring an invalid legacy column value");
            None
        }
    }
}

fn column_vec<T: std::str::FromStr>(
    values: Vec<String>,
    name: tranquil_db_traits::ColumnRef,
) -> Result<Vec<T>, tranquil_db_traits::DbError> {
    values
        .into_iter()
        .map(|value| column(value, name))
        .collect()
}

/// Shared SQLite connection setup for the SQLite repository backend.
///
/// The database is configured for a single-node deployment with Litestream:
/// WAL mode keeps readers available while the writer is active, while the
/// busy timeout lets concurrent requests wait briefly instead of failing on
/// transient write contention.
#[derive(Clone)]
pub struct SqliteDatabase {
    pub pool: SqlitePool,
}

pub(crate) fn map_sqlite_error(error: sqlx::Error) -> tranquil_db_traits::DbError {
    match error {
        sqlx::Error::RowNotFound => tranquil_db_traits::DbError::NotFound,
        sqlx::Error::Database(database_error) => {
            let message = database_error.message().to_string();
            if message.contains("UNIQUE") || message.contains("FOREIGN KEY") {
                tranquil_db_traits::DbError::Constraint(message)
            } else {
                tranquil_db_traits::DbError::Query(message)
            }
        }
        sqlx::Error::PoolTimedOut => {
            tranquil_db_traits::DbError::Connection("Pool timed out".into())
        }
        other => tranquil_db_traits::DbError::Other(other.to_string()),
    }
}

impl SqliteDatabase {
    pub async fn connect(
        database_url: &str,
        max_connections: u32,
        min_connections: u32,
        acquire_timeout_secs: u64,
    ) -> Result<Self, sqlx::Error> {
        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(30));

        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .min_connections(min_connections.min(max_connections))
            .acquire_timeout(Duration::from_secs(acquire_timeout_secs))
            .connect_with(options)
            .await?;

        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations-sqlite").run(&self.pool).await
    }
}

#[cfg(test)]
mod tests {
    use super::{SqliteDatabase, SqliteRepositories};
    use sqlx::Row;
    use tranquil_db_traits::{
        CommsChannel, CreateAccountError, CreatePasswordAccountInput, SequenceNumber,
    };
    use tranquil_types::{CidLink, Did, Handle, PasswordHash, Tid};

    #[tokio::test]
    async fn configures_litestream_friendly_pragmas() {
        let path =
            std::env::temp_dir().join(format!("tranquil-sqlite-test-{}.db", uuid::Uuid::new_v4()));
        let url = format!("sqlite://{}", path.display());
        let database = SqliteDatabase::connect(&url, 4, 1, 5).await.unwrap();
        database.migrate().await.unwrap();

        let journal_mode: String = sqlx::query("PRAGMA journal_mode")
            .fetch_one(&database.pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
        let foreign_keys: i64 = sqlx::query("PRAGMA foreign_keys")
            .fetch_one(&database.pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();

        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(foreign_keys, 1);

        let table_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'users'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(table_count, 1);

        let repositories = SqliteRepositories::new(database.pool.clone());
        assert_eq!(repositories.user.count_users().await.unwrap(), 0);

        let did = Did::new("did:plc:sqliteintegration").unwrap();
        let handle = Handle::new("sqlite-integration.test").unwrap();
        let input = CreatePasswordAccountInput {
            handle: handle.clone(),
            email: None,
            did: did.clone(),
            password_hash: PasswordHash::new("test-password-hash"),
            preferred_comms_channel: CommsChannel::Email,
            discord_username: None,
            telegram_username: None,
            signal_username: None,
            deactivated_at: None,
            inbound_migration: false,
            encrypted_key_bytes: vec![0; 32],
            encryption_version: 0,
            reserved_key_id: None,
            commit_cid: CidLink::new("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku")
                .unwrap(),
            repo_rev: Tid::new("3k2aaaaaaaaaa").unwrap(),
            genesis_block_cids: Vec::new(),
            invite_code: None,
            birthdate_pref: None,
        };
        let created = repositories
            .user
            .create_password_account(&input)
            .await
            .unwrap();
        assert!(created.is_admin);
        assert_eq!(repositories.user.count_users().await.unwrap(), 1);
        assert_eq!(repositories.repo.count_repos().await.unwrap(), 1);
        assert_eq!(
            repositories
                .user
                .get_by_did(&did)
                .await
                .unwrap()
                .unwrap()
                .handle,
            handle
        );
        let mut duplicate_input = input.clone();
        duplicate_input.did = Did::new("did:plc:sqliteintegration2").unwrap();
        let duplicate = repositories
            .user
            .create_password_account(&duplicate_input)
            .await;
        assert!(matches!(duplicate, Err(CreateAccountError::HandleTaken)));

        repositories
            .infra
            .upsert_server_config("sqlite.test", "enabled")
            .await
            .unwrap();
        assert_eq!(
            repositories
                .infra
                .get_server_config("sqlite.test")
                .await
                .unwrap()
                .as_deref(),
            Some("enabled")
        );
        assert_eq!(
            repositories
                .infra
                .get_server_configs(&["sqlite.test", "missing"])
                .await
                .unwrap(),
            vec![("sqlite.test".to_owned(), "enabled".to_owned())]
        );
        repositories
            .infra
            .delete_server_config("sqlite.test")
            .await
            .unwrap();
        assert!(
            repositories
                .infra
                .get_server_config("sqlite.test")
                .await
                .unwrap()
                .is_none()
        );

        sqlx::query("INSERT INTO repo_seq (did, event_type) VALUES ($1, 'identity')")
            .bind(did.as_str())
            .execute(&database.pool)
            .await
            .unwrap();
        assert_eq!(
            repositories.repo.assign_pending_sequences().await.unwrap(),
            1
        );
        assert_eq!(repositories.repo.get_max_seq().await.unwrap().as_i64(), 1);
        assert_eq!(
            repositories
                .repo
                .get_events_since_seq(SequenceNumber::ZERO, None)
                .await
                .unwrap()
                .len(),
            1
        );

        database.pool.close().await;
        let _ = std::fs::remove_file(path);
    }
}
