#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

pub use tranquil_db_traits::*;

use std::sync::Arc;
use tranquil_db_traits as traits;

#[cfg(feature = "postgres")]
pub use postgres::PostgresRepositories;
#[cfg(feature = "sqlite")]
pub use sqlite::{SqliteDatabase, SqliteRepositories};

/// Backend-neutral repository handles used by the PDS runtime.
pub struct RepositorySet {
    pub user: Arc<dyn traits::UserRepository>,
    pub oauth: Arc<dyn traits::OAuthRepository>,
    pub session: Arc<dyn traits::SessionRepository>,
    pub delegation: Arc<dyn traits::DelegationRepository>,
    pub repo: Arc<dyn traits::RepoRepository>,
    pub blob: Arc<dyn traits::BlobRepository>,
    pub infra: Arc<dyn traits::InfraRepository>,
    pub backlink: Arc<dyn traits::BacklinkRepository>,
    pub sso: Arc<dyn traits::SsoRepository>,
    pub event_notifier: Arc<dyn traits::RepoEventNotifier>,
}

#[cfg(feature = "postgres")]
impl From<PostgresRepositories> for RepositorySet {
    fn from(value: PostgresRepositories) -> Self {
        Self {
            user: value.user,
            oauth: value.oauth,
            session: value.session,
            delegation: value.delegation,
            repo: value.repo,
            blob: value.blob,
            infra: value.infra,
            backlink: value.backlink,
            sso: value.sso,
            event_notifier: value.event_notifier,
        }
    }
}

#[cfg(feature = "sqlite")]
impl From<sqlite::SqliteRepositories> for RepositorySet {
    fn from(value: sqlite::SqliteRepositories) -> Self {
        Self {
            user: value.user,
            oauth: value.oauth,
            session: value.session,
            delegation: value.delegation,
            repo: value.repo,
            blob: value.blob,
            infra: value.infra,
            backlink: value.backlink,
            sso: value.sso,
            event_notifier: value.event_notifier,
        }
    }
}
