#[cfg(feature = "postgres")]
pub use tranquil_repo::PostgresBlockStore;

#[cfg(feature = "sqlite")]
#[derive(Clone)]
pub struct SqliteBlockStore {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "sqlite")]
impl SqliteBlockStore {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "sqlite")]
fn sqlite_repo_error(error: impl std::fmt::Display) -> RepoError {
    RepoError::storage(std::io::Error::other(error.to_string()))
}

#[cfg(feature = "sqlite")]
impl BlockStore for SqliteBlockStore {
    async fn get(&self, cid: &Cid) -> Result<Option<Bytes>, RepoError> {
        let row = sqlx::query("SELECT data FROM blocks WHERE cid = $1")
            .bind(cid.to_bytes())
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlite_repo_error)?;
        row.map(|row| sqlx::Row::try_get::<Vec<u8>, _>(&row, "data").map(Bytes::from))
            .transpose()
            .map_err(sqlite_repo_error)
    }

    async fn put(&self, data: &[u8]) -> Result<Cid, RepoError> {
        use multihash::Multihash;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let multihash = Multihash::wrap(0x12, &hash).map_err(sqlite_repo_error)?;
        let cid = Cid::new_v1(0x71, multihash);
        sqlx::query("INSERT INTO blocks (cid, data) VALUES ($1, $2) ON CONFLICT (cid) DO NOTHING")
            .bind(cid.to_bytes())
            .bind(data)
            .execute(&self.pool)
            .await
            .map_err(sqlite_repo_error)?;
        Ok(cid)
    }

    async fn has(&self, cid: &Cid) -> Result<bool, RepoError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocks WHERE cid = $1")
            .bind(cid.to_bytes())
            .fetch_one(&self.pool)
            .await
            .map_err(sqlite_repo_error)?;
        Ok(count > 0)
    }

    async fn put_many(
        &self,
        blocks: impl IntoIterator<Item = (Cid, Bytes)> + Send,
    ) -> Result<(), RepoError> {
        let blocks: Vec<_> = blocks.into_iter().collect();
        let mut tx = self.pool.begin().await.map_err(sqlite_repo_error)?;
        for (cid, data) in blocks {
            sqlx::query(
                "INSERT INTO blocks (cid, data) VALUES ($1, $2) ON CONFLICT (cid) DO NOTHING",
            )
            .bind(cid.to_bytes())
            .bind(data.as_ref())
            .execute(&mut *tx)
            .await
            .map_err(sqlite_repo_error)?;
        }
        tx.commit().await.map_err(sqlite_repo_error)
    }

    async fn get_many(&self, cids: &[Cid]) -> Result<Vec<Option<Bytes>>, RepoError> {
        let mut result = Vec::with_capacity(cids.len());
        for cid in cids {
            result.push(self.get(cid).await?);
        }
        Ok(result)
    }

    async fn apply_commit(&self, commit: CommitData) -> Result<(), RepoError> {
        self.put_many(commit.blocks).await
    }
}

pub type TrackingBlockStore = tranquil_repo::TrackingBlockStore<AnyBlockStore>;

use bytes::Bytes;
use cid::Cid;
use jacquard_repo::error::RepoError;
use jacquard_repo::repo::CommitData;
use jacquard_repo::storage::BlockStore;
use tranquil_store::blockstore::{RepairOutcome, TranquilBlockStore};
use tranquil_store::{RealIO, SystemClock};

#[derive(Clone)]
pub enum AnyBlockStore {
    #[cfg(feature = "postgres")]
    Postgres(PostgresBlockStore),
    #[cfg(feature = "sqlite")]
    Sqlite(SqliteBlockStore),
    TranquilStore(TranquilBlockStore<RealIO, SystemClock>),
}

impl AnyBlockStore {
    #[cfg(feature = "postgres")]
    pub fn as_postgres(&self) -> Option<&PostgresBlockStore> {
        match self {
            Self::Postgres(s) => Some(s),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(_) => None,
            Self::TranquilStore(_) => None,
        }
    }

    pub fn as_tranquil_store(&self) -> Option<&TranquilBlockStore<RealIO, SystemClock>> {
        match self {
            Self::TranquilStore(s) => Some(s),
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => None,
            #[cfg(feature = "sqlite")]
            Self::Sqlite(_) => None,
        }
    }

    pub async fn decrement_refs(&self, cids: &[Cid]) -> Result<(), RepoError> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => Ok(()),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(_) => Ok(()),
            Self::TranquilStore(s) => s.decrement_refs(cids).await,
        }
    }

    pub async fn repair_structure(
        &self,
        entries: &[(String, Cid)],
        expected_root: Cid,
    ) -> Result<RepairOutcome, RepoError> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(s) => {
                let nodes =
                    tranquil_store::blockstore::rebuild_mst_nodes(entries, expected_root).await?;
                let nodes_total = nodes.len();
                let cids: Vec<Cid> = nodes.iter().map(|(cid, _)| *cid).collect();
                let present = s.get_many(&cids).await?;
                let missing: Vec<(Cid, Bytes)> = nodes
                    .into_iter()
                    .zip(present)
                    .filter_map(|((cid, bytes), found)| found.is_none().then_some((cid, bytes)))
                    .collect();
                let nodes_repaired = missing.len() as u64;
                if !missing.is_empty() {
                    s.put_many(missing).await?;
                }
                Ok(RepairOutcome {
                    nodes_total,
                    nodes_repaired,
                })
            }
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => {
                let nodes =
                    tranquil_store::blockstore::rebuild_mst_nodes(entries, expected_root).await?;
                let nodes_total = nodes.len();
                let cids: Vec<Cid> = nodes.iter().map(|(cid, _)| *cid).collect();
                let present = s.get_many(&cids).await?;
                let missing: Vec<(Cid, Bytes)> = nodes
                    .into_iter()
                    .zip(present)
                    .filter_map(|((cid, bytes), found)| found.is_none().then_some((cid, bytes)))
                    .collect();
                let nodes_repaired = missing.len() as u64;
                if !missing.is_empty() {
                    s.put_many(missing).await?;
                }
                Ok(RepairOutcome {
                    nodes_total,
                    nodes_repaired,
                })
            }
            Self::TranquilStore(s) => {
                tranquil_store::blockstore::rebuild_and_repair_mst(s, entries, expected_root).await
            }
        }
    }
}

impl BlockStore for AnyBlockStore {
    async fn get(&self, cid: &Cid) -> Result<Option<Bytes>, RepoError> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(s) => s.get(cid).await,
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.get(cid).await,
            Self::TranquilStore(s) => s.get(cid).await,
        }
    }

    async fn put(&self, data: &[u8]) -> Result<Cid, RepoError> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(s) => s.put(data).await,
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.put(data).await,
            Self::TranquilStore(s) => s.put(data).await,
        }
    }

    async fn has(&self, cid: &Cid) -> Result<bool, RepoError> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(s) => s.has(cid).await,
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.has(cid).await,
            Self::TranquilStore(s) => s.has(cid).await,
        }
    }

    async fn put_many(
        &self,
        blocks: impl IntoIterator<Item = (Cid, Bytes)> + Send,
    ) -> Result<(), RepoError> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(s) => s.put_many(blocks).await,
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.put_many(blocks).await,
            Self::TranquilStore(s) => s.put_many(blocks).await,
        }
    }

    async fn get_many(&self, cids: &[Cid]) -> Result<Vec<Option<Bytes>>, RepoError> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(s) => s.get_many(cids).await,
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.get_many(cids).await,
            Self::TranquilStore(s) => s.get_many(cids).await,
        }
    }

    async fn apply_commit(&self, commit: CommitData) -> Result<(), RepoError> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(s) => s.apply_commit(commit).await,
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.apply_commit(commit).await,
            Self::TranquilStore(s) => s.apply_commit(commit).await,
        }
    }
}
