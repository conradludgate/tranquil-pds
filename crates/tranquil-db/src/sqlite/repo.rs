use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};
use tranquil_db_traits::{
    AccountStatus, CommitEventData, DbError, EventBlockInline, EventBlocks, FullRecordInfo,
    ImportBlock, ImportRecord, ImportRepoError, PruneCount, RecordInfo, RecordWithTakedown,
    RepoAccountInfo, RepoEventType, RepoInfo, RepoListItem, RepoRepository, RepoWithoutRev,
    SequenceNumber, SequencedEvent, UserNeedingRecordBlobsBackfill, UserWithoutBlocks,
};
use tranquil_types::{AtUri, CidLink, Did, Handle, Nsid, Rkey, Tid};
use uuid::Uuid;

use super::col;
use super::map_sqlite_error;

macro_rules! sqlite_query {
    ($sql:expr $(,)?) => { sqlx::query($sql) };
    ($sql:expr, $($arg:expr),+ $(,)?) => {{
        let mut query = sqlx::query($sql);
        $(query = query.bind($arg);)*
        query
    }};
}

macro_rules! sqlite_query_unchecked {
    ($sql:expr $(,)?) => { sqlx::query($sql) };
    ($sql:expr, $($arg:expr),+ $(,)?) => {{
        let mut query = sqlx::query($sql);
        $(query = query.bind(($arg).to_owned());)*
        query
    }};
}

macro_rules! sqlite_query_scalar_unchecked {
    ($sql:expr $(,)?) => { sqlx::query_scalar($sql) };
    ($sql:expr, $($arg:expr),+ $(,)?) => {{
        let mut query = sqlx::query_scalar($sql);
        $(query = query.bind(($arg).to_owned());)*
        query
    }};
}

macro_rules! sqlite_query_as_unchecked {
    ($out:path, $sql:expr $(, $arg:expr)* $(,)?) => {{
        let mut query = sqlx::query_as::<_, $out>($sql);
        $(query = query.bind(($arg).to_owned());)*
        query
    }};
}
use super::{column, column_vec, legacy_column, opt_column};

#[derive(sqlx::FromRow)]
struct RecordRow {
    rkey: String,
    record_cid: String,
}

#[derive(sqlx::FromRow)]
struct SequencedEventRow {
    seq: i64,
    did: String,
    created_at: String,
    event_type: String,
    commit_cid: Option<String>,
    prev_cid: Option<String>,
    prev_data_cid: Option<String>,
    ops: Option<String>,
    blobs: Option<String>,
    block_cids: Option<Vec<u8>>,
    block_data: Option<Vec<u8>>,
    blocks_cids: Option<String>,
    handle: Option<String>,
    active: Option<i64>,
    status: Option<String>,
    rev: Option<String>,
}

fn encode_json<T: serde::Serialize>(value: &T) -> Result<String, DbError> {
    serde_json::to_string(value)
        .map_err(|error| DbError::Other(format!("failed to serialize SQLite JSON: {error}")))
}

fn encode_block_pairs(value: &[Vec<u8>]) -> Result<Vec<u8>, DbError> {
    serde_json::to_vec(value)
        .map_err(|error| DbError::Other(format!("failed to serialize SQLite blocks: {error}")))
}

fn decode_block_pairs(value: Option<Vec<u8>>) -> Result<Option<Vec<Vec<u8>>>, DbError> {
    value
        .map(|value| {
            serde_json::from_slice(&value)
                .map_err(|error| DbError::Other(format!("invalid SQLite blocks: {error}")))
        })
        .transpose()
}

fn parse_optional_timestamp(value: Option<String>) -> Result<Option<DateTime<Utc>>, DbError> {
    value
        .map(|value| {
            DateTime::parse_from_rfc3339(&value)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|error| DbError::Other(format!("invalid SQLite timestamp: {error}")))
        })
        .transpose()
}

fn row_to_event_blocks(
    block_cids: Option<Vec<Vec<u8>>>,
    block_data: Option<Vec<Vec<u8>>>,
    legacy_blocks_cids: Option<Vec<String>>,
) -> Result<Option<EventBlocks>, DbError> {
    match (block_cids, block_data) {
        (Some(cids), Some(data)) if cids.len() == data.len() => match cids.is_empty() {
            true => legacy_fallback(legacy_blocks_cids),
            false => Ok(Some(EventBlocks::Inline(
                cids.into_iter()
                    .zip(data)
                    .map(|(cid_bytes, data)| EventBlockInline { cid_bytes, data })
                    .collect(),
            ))),
        },
        (Some(_), Some(_)) => Err(DbError::CorruptData(
            "repo_seq.block_cids/block_data length mismatch",
        )),
        (Some(_), None) | (None, Some(_)) => Err(DbError::CorruptData(
            "repo_seq.block_cids/block_data partially populated",
        )),
        (None, None) => legacy_fallback(legacy_blocks_cids),
    }
}

fn legacy_fallback(
    legacy_blocks_cids: Option<Vec<String>>,
) -> Result<Option<EventBlocks>, DbError> {
    match legacy_blocks_cids {
        Some(cids) if !cids.is_empty() => Ok(Some(EventBlocks::LegacyCids(column_vec(
            cids,
            col::REPO_SEQ_BLOCKS_CIDS,
        )?))),
        _ => Ok(None),
    }
}

fn inline_to_paired_blocks(blocks: Option<&[EventBlockInline]>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    blocks
        .map(|bs| {
            bs.iter()
                .map(|b| (b.cid_bytes.clone(), b.data.clone()))
                .unzip()
        })
        .unwrap_or_default()
}

fn inline_into_paired_blocks(
    blocks: Option<Vec<EventBlockInline>>,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    blocks
        .map(|bs| bs.into_iter().map(|b| (b.cid_bytes, b.data)).unzip())
        .unwrap_or_default()
}

fn map_sequenced_row(r: SequencedEventRow) -> Result<SequencedEvent, DbError> {
    let status = r
        .status
        .as_deref()
        .and_then(AccountStatus::parse)
        .or_else(|| r.active.filter(|a| *a != 0).map(|_| AccountStatus::Active));
    let blocks = row_to_event_blocks(
        decode_block_pairs(r.block_cids)?,
        decode_block_pairs(r.block_data)?,
        r.blocks_cids
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(|error| DbError::Other(format!("invalid SQLite block CID list: {error}")))?,
    )?;
    let created_at = DateTime::parse_from_rfc3339(&r.created_at)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| DbError::Other(format!("invalid SQLite event timestamp: {error}")))?;
    let event_type = match r.event_type.as_str() {
        "commit" => RepoEventType::Commit,
        "identity" => RepoEventType::Identity,
        "account" => RepoEventType::Account,
        "sync" => RepoEventType::Sync,
        _ => return Err(DbError::CorruptData("invalid repo event type")),
    };
    Ok(SequencedEvent {
        seq: r.seq.into(),
        did: column(r.did, col::REPO_SEQ_DID)?,
        created_at,
        event_type,
        commit_cid: opt_column(r.commit_cid, col::REPO_SEQ_COMMIT_CID)?,
        prev_cid: opt_column(r.prev_cid, col::REPO_SEQ_PREV_CID)?,
        prev_data_cid: opt_column(r.prev_data_cid, col::REPO_SEQ_PREV_DATA_CID)?,
        ops: r
            .ops
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(|error| DbError::Other(format!("invalid SQLite event JSON: {error}")))?,
        blobs: r
            .blobs
            .map(|blobs| serde_json::from_str::<Vec<String>>(&blobs))
            .transpose()
            .map_err(|error| DbError::Other(format!("invalid SQLite blob list: {error}")))?
            .map(|blobs| column_vec(blobs, col::REPO_SEQ_BLOBS))
            .transpose()?,
        blocks,
        handle: r
            .handle
            .and_then(|h| legacy_column(h, col::REPO_SEQ_HANDLE)),
        active: r.active.map(|value| value != 0),
        status,
        rev: opt_column(r.rev, col::REPO_SEQ_REV)?,
    })
}

fn collect_sequenced_rows(rows: Vec<SequencedEventRow>) -> Vec<SequencedEvent> {
    rows.into_iter()
        .filter_map(|r| {
            let seq = r.seq;
            map_sequenced_row(r)
                .inspect_err(|e| {
                    tracing::error!(seq, error = %e, "skipping a repo_seq row that doesn't decode");
                })
                .ok()
        })
        .collect()
}

const SEQUENCER_BATCH_SIZE: i64 = 1000;

async fn notify_repo_pending(pool: &SqlitePool) {
    let _ = pool;
}

async fn assign_one_batch(
    mut tx: sqlx::Transaction<'_, sqlx::Sqlite>,
    pool: &SqlitePool,
) -> Result<i64, DbError> {
    let pending_ids: Vec<i64> = sqlite_query_scalar_unchecked!(
        r#"SELECT id as "id!" FROM repo_seq WHERE seq IS NULL ORDER BY id LIMIT $1"#,
        SEQUENCER_BATCH_SIZE
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(map_sqlite_error)?;

    let count = pending_ids.len() as i64;
    if count == 0 {
        tx.commit().await.map_err(map_sqlite_error)?;
        return Ok(0);
    }

    let start: i64 =
        sqlite_query_scalar_unchecked!("SELECT COALESCE(MAX(seq), 0) + 1 FROM repo_seq")
            .fetch_one(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
    let mut assigned = 0;
    for (offset, id) in pending_ids.into_iter().enumerate() {
        let result = sqlite_query!(
            "UPDATE repo_seq SET seq = $1 WHERE id = $2",
            start + offset as i64,
            id
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;
        assigned += result.rows_affected();
    }

    tx.commit().await.map_err(map_sqlite_error)?;
    if assigned > 0 {
        notify_repo_pending(pool).await;
    }
    Ok(count)
}

pub struct SqliteRepoRepository {
    pool: SqlitePool,
}

impl SqliteRepoRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RepoRepository for SqliteRepoRepository {
    async fn update_repo_status(
        &self,
        _did: &Did,
        _takedown: Option<bool>,
        _takedown_ref: Option<&str>,
        _deactivated: Option<bool>,
    ) -> Result<(), DbError> {
        Ok(())
    }

    async fn create_repo(
        &self,
        user_id: Uuid,
        _did: &Did,
        _handle: &Handle,
        repo_root_cid: &CidLink,
        repo_rev: &Tid,
    ) -> Result<(), DbError> {
        sqlite_query_unchecked!(
            "INSERT INTO repos (user_id, repo_root_cid, repo_rev) VALUES ($1, $2, $3)",
            user_id,
            repo_root_cid.as_str(),
            repo_rev.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn update_repo_root(
        &self,
        user_id: Uuid,
        repo_root_cid: &CidLink,
        repo_rev: &Tid,
    ) -> Result<(), DbError> {
        sqlite_query_unchecked!(
            "UPDATE repos SET repo_root_cid = $1, repo_rev = $2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE user_id = $3",
            repo_root_cid.as_str(),
            repo_rev.as_str(),
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn update_repo_rev(&self, user_id: Uuid, repo_rev: &Tid) -> Result<(), DbError> {
        sqlite_query_unchecked!(
            "UPDATE repos SET repo_rev = $1 WHERE user_id = $2",
            repo_rev.as_str(),
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn delete_repo(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlite_query_unchecked!("DELETE FROM repos WHERE user_id = $1", user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn get_repo_root_for_update(&self, user_id: Uuid) -> Result<Option<CidLink>, DbError> {
        let result = sqlite_query_scalar_unchecked!(
            "SELECT repo_root_cid FROM repos WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        opt_column(result, col::REPOS_REPO_ROOT_CID)
    }

    async fn get_repo(&self, user_id: Uuid) -> Result<Option<RepoInfo>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT user_id, repo_root_cid, repo_rev FROM repos WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            let user_id = r
                .try_get::<Vec<u8>, _>("user_id")
                .map_err(map_sqlite_error)
                .and_then(|value| {
                    Uuid::from_slice(&value).map_err(|e| DbError::Other(e.to_string()))
                })?;
            let repo_root_cid = r.try_get("repo_root_cid").map_err(map_sqlite_error)?;
            let repo_rev = r.try_get("repo_rev").map_err(map_sqlite_error)?;
            Ok(RepoInfo {
                user_id,
                repo_root_cid: column(repo_root_cid, col::REPOS_REPO_ROOT_CID)?,
                repo_rev: opt_column(repo_rev, col::REPOS_REPO_REV)?,
            })
        })
        .transpose()
    }

    async fn get_repo_root_by_did(&self, did: &Did) -> Result<Option<CidLink>, DbError> {
        let result = sqlite_query_scalar_unchecked!(
            "SELECT r.repo_root_cid FROM repos r JOIN users u ON r.user_id = u.id WHERE u.did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        opt_column(result, col::REPOS_REPO_ROOT_CID)
    }

    async fn count_repos(&self) -> Result<i64, DbError> {
        let count = sqlite_query_scalar_unchecked!(r#"SELECT COUNT(*) as "count!" FROM repos"#)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(count)
    }

    async fn get_repos_without_rev(&self) -> Result<Vec<RepoWithoutRev>, DbError> {
        let rows = sqlite_query_unchecked!(
            "SELECT user_id, repo_root_cid FROM repos WHERE repo_rev IS NULL"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                let user_id = r
                    .try_get::<Vec<u8>, _>("user_id")
                    .map_err(map_sqlite_error)
                    .and_then(|value| {
                        Uuid::from_slice(&value).map_err(|e| DbError::Other(e.to_string()))
                    })?;
                let repo_root_cid = r.try_get("repo_root_cid").map_err(map_sqlite_error)?;
                Ok(RepoWithoutRev {
                    user_id,
                    repo_root_cid: column(repo_root_cid, col::REPOS_REPO_ROOT_CID)?,
                })
            })
            .collect()
    }

    async fn upsert_records(
        &self,
        repo_id: Uuid,
        collections: &[Nsid],
        rkeys: &[Rkey],
        record_cids: &[CidLink],
        repo_rev: &Tid,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;
        for ((collection, rkey), cid) in collections.iter().zip(rkeys).zip(record_cids) {
            sqlite_query!(
                "INSERT INTO records (repo_id, collection, rkey, record_cid, repo_rev) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (repo_id, collection, rkey) DO UPDATE SET record_cid = excluded.record_cid, repo_rev = excluded.repo_rev, created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
                repo_id,
                collection.as_str().to_owned(),
                rkey.as_str().to_owned(),
                cid.as_str().to_owned(),
                repo_rev.as_str().to_owned()
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        }
        tx.commit().await.map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn delete_records(
        &self,
        repo_id: Uuid,
        collections: &[Nsid],
        rkeys: &[Rkey],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;
        for (collection, rkey) in collections.iter().zip(rkeys) {
            sqlite_query!(
                "DELETE FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3",
                repo_id,
                collection.as_str().to_owned(),
                rkey.as_str().to_owned()
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        }
        tx.commit().await.map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn delete_all_records(&self, repo_id: Uuid) -> Result<(), DbError> {
        sqlite_query_unchecked!("DELETE FROM records WHERE repo_id = $1", repo_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn get_record_cid(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        rkey: &Rkey,
    ) -> Result<Option<CidLink>, DbError> {
        let result = sqlite_query_scalar_unchecked!(
            "SELECT record_cid FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3",
            repo_id,
            collection.as_str(),
            rkey.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        opt_column(result, col::RECORDS_RECORD_CID)
    }

    async fn list_records(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        cursor: Option<&Rkey>,
        limit: i64,
        reverse: bool,
        rkey_start: Option<&Rkey>,
        rkey_end: Option<&Rkey>,
    ) -> Result<Vec<RecordInfo>, DbError> {
        let to_record_info = |rows: Vec<RecordRow>| -> Result<Vec<RecordInfo>, DbError> {
            Ok(rows
                .into_iter()
                .filter_map(|r| {
                    Some(RecordInfo {
                        rkey: legacy_column(r.rkey, col::RECORDS_RKEY)?,
                        record_cid: legacy_column(r.record_cid, col::RECORDS_RECORD_CID)?,
                    })
                })
                .collect())
        };

        let collection_str = collection.as_str();

        if let Some(cursor_val) = cursor {
            let cursor_str = cursor_val.as_str();
            return match reverse {
                false => {
                    let rows = sqlite_query_as_unchecked!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey < $3
                           ORDER BY rkey DESC LIMIT $4"#,
                        repo_id,
                        collection_str,
                        cursor_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlite_error)?;
                    to_record_info(rows)
                }
                true => {
                    let rows = sqlite_query_as_unchecked!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey > $3
                           ORDER BY rkey ASC LIMIT $4"#,
                        repo_id,
                        collection_str,
                        cursor_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlite_error)?;
                    to_record_info(rows)
                }
            };
        }

        if let (Some(start), Some(end)) = (rkey_start, rkey_end) {
            let start_str = start.as_str();
            let end_str = end.as_str();
            return match reverse {
                false => {
                    let rows = sqlite_query_as_unchecked!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey >= $3 AND rkey <= $4
                           ORDER BY rkey DESC LIMIT $5"#,
                        repo_id,
                        collection_str,
                        start_str,
                        end_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlite_error)?;
                    to_record_info(rows)
                }
                true => {
                    let rows = sqlite_query_as_unchecked!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey >= $3 AND rkey <= $4
                           ORDER BY rkey ASC LIMIT $5"#,
                        repo_id,
                        collection_str,
                        start_str,
                        end_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlite_error)?;
                    to_record_info(rows)
                }
            };
        }

        if let Some(start) = rkey_start {
            let start_str = start.as_str();
            return match reverse {
                false => {
                    let rows = sqlite_query_as_unchecked!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey >= $3
                           ORDER BY rkey DESC LIMIT $4"#,
                        repo_id,
                        collection_str,
                        start_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlite_error)?;
                    to_record_info(rows)
                }
                true => {
                    let rows = sqlite_query_as_unchecked!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey >= $3
                           ORDER BY rkey ASC LIMIT $4"#,
                        repo_id,
                        collection_str,
                        start_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlite_error)?;
                    to_record_info(rows)
                }
            };
        }

        if let Some(end) = rkey_end {
            let end_str = end.as_str();
            return match reverse {
                false => {
                    let rows = sqlite_query_as_unchecked!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey <= $3
                           ORDER BY rkey DESC LIMIT $4"#,
                        repo_id,
                        collection_str,
                        end_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlite_error)?;
                    to_record_info(rows)
                }
                true => {
                    let rows = sqlite_query_as_unchecked!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey <= $3
                           ORDER BY rkey ASC LIMIT $4"#,
                        repo_id,
                        collection_str,
                        end_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlite_error)?;
                    to_record_info(rows)
                }
            };
        }

        match reverse {
            false => {
                let rows = sqlite_query_as_unchecked!(
                    RecordRow,
                    r#"SELECT rkey, record_cid FROM records
                       WHERE repo_id = $1 AND collection = $2
                       ORDER BY rkey DESC LIMIT $3"#,
                    repo_id,
                    collection_str,
                    limit
                )
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlite_error)?;
                to_record_info(rows)
            }
            true => {
                let rows = sqlite_query_as_unchecked!(
                    RecordRow,
                    r#"SELECT rkey, record_cid FROM records
                       WHERE repo_id = $1 AND collection = $2
                       ORDER BY rkey ASC LIMIT $3"#,
                    repo_id,
                    collection_str,
                    limit
                )
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlite_error)?;
                to_record_info(rows)
            }
        }
    }

    async fn get_all_records(&self, repo_id: Uuid) -> Result<Vec<FullRecordInfo>, DbError> {
        let rows = sqlite_query_unchecked!(
            "SELECT collection, rkey, record_cid FROM records WHERE repo_id = $1",
            repo_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                let collection: String = r.try_get("collection").map_err(map_sqlite_error)?;
                let rkey: String = r.try_get("rkey").map_err(map_sqlite_error)?;
                let record_cid: String = r.try_get("record_cid").map_err(map_sqlite_error)?;
                Ok(FullRecordInfo {
                    collection: legacy_column(collection, col::RECORDS_COLLECTION)
                        .ok_or(DbError::NotFound)?,
                    rkey: legacy_column(rkey, col::RECORDS_RKEY).ok_or(DbError::NotFound)?,
                    record_cid: legacy_column(record_cid, col::RECORDS_RECORD_CID)
                        .ok_or(DbError::NotFound)?,
                })
            })
            .collect()
    }

    async fn list_collections(&self, repo_id: Uuid) -> Result<Vec<Nsid>, DbError> {
        let rows = sqlite_query_scalar_unchecked!(
            "SELECT DISTINCT collection FROM records WHERE repo_id = $1",
            repo_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(rows
            .into_iter()
            .filter_map(|c| legacy_column(c, col::RECORDS_COLLECTION))
            .collect())
    }

    async fn count_records(&self, repo_id: Uuid) -> Result<i64, DbError> {
        let count = sqlite_query_scalar_unchecked!(
            r#"SELECT COUNT(*) as "count!" FROM records WHERE repo_id = $1"#,
            repo_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(count)
    }

    async fn count_all_records(&self) -> Result<i64, DbError> {
        let count = sqlite_query_scalar_unchecked!(r#"SELECT COUNT(*) as "count!" FROM records"#)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(count)
    }

    async fn get_record_by_cid(
        &self,
        cid: &CidLink,
    ) -> Result<Option<RecordWithTakedown>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT id, takedown_ref FROM records WHERE record_cid = $1",
            cid.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            let id = r.try_get::<Vec<u8>, _>("id").map_err(map_sqlite_error)?;
            let id = Uuid::from_slice(&id).map_err(|error| DbError::Other(error.to_string()))?;
            let takedown_ref = r.try_get("takedown_ref").map_err(map_sqlite_error)?;
            Ok(RecordWithTakedown { id, takedown_ref })
        })
        .transpose()
    }

    async fn referenced_record_cids(
        &self,
        repo_id: Uuid,
        cids: &[CidLink],
        excluded_keys: &[(&Nsid, &Rkey)],
    ) -> Result<Vec<CidLink>, DbError> {
        if cids.is_empty() {
            return Ok(Vec::new());
        }

        let cid_marks = std::iter::repeat_n("?", cids.len())
            .collect::<Vec<_>>()
            .join(", ");
        let mut sql = format!(
            "SELECT DISTINCT record_cid FROM records WHERE repo_id = ? AND record_cid IN ({cid_marks})"
        );
        if !excluded_keys.is_empty() {
            let exclusions =
                std::iter::repeat_n("(collection = ? AND rkey = ?)", excluded_keys.len())
                    .collect::<Vec<_>>()
                    .join(" OR ");
            sql.push_str(" AND NOT (");
            sql.push_str(&exclusions);
            sql.push(')');
        }
        let mut query = sqlx::query_scalar::<_, String>(&sql).bind(repo_id);
        for cid in cids {
            query = query.bind(cid.as_str().to_owned());
        }
        for (collection, rkey) in excluded_keys {
            query = query
                .bind(collection.as_str().to_owned())
                .bind(rkey.as_str().to_owned());
        }
        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        column_vec(rows, col::RECORDS_RECORD_CID)
    }

    async fn set_record_takedown(
        &self,
        cid: &CidLink,
        takedown_ref: Option<&str>,
    ) -> Result<(), DbError> {
        sqlite_query_unchecked!(
            "UPDATE records SET takedown_ref = $1 WHERE record_cid = $2",
            takedown_ref,
            cid.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn insert_user_blocks(
        &self,
        user_id: Uuid,
        block_cids: &[Vec<u8>],
        repo_rev: &Tid,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;
        for block_cid in block_cids {
            sqlite_query!(
                "INSERT INTO user_blocks (user_id, block_cid, repo_rev) VALUES ($1, $2, $3) ON CONFLICT (user_id, block_cid) DO NOTHING",
                user_id,
                block_cid,
                repo_rev.as_str().to_owned()
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        }
        tx.commit().await.map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn delete_user_blocks(
        &self,
        user_id: Uuid,
        block_cids: &[Vec<u8>],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;
        for block_cid in block_cids {
            sqlite_query!(
                "DELETE FROM user_blocks WHERE user_id = $1 AND block_cid = $2",
                user_id,
                block_cid
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        }
        tx.commit().await.map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn count_user_blocks(&self, user_id: Uuid) -> Result<i64, DbError> {
        let count = sqlite_query_scalar_unchecked!(
            r#"SELECT COUNT(*) as "count!" FROM user_blocks WHERE user_id = $1"#,
            user_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(count)
    }

    async fn get_user_block_cids_since_rev(
        &self,
        user_id: Uuid,
        since_rev: Option<&Tid>,
    ) -> Result<Vec<Vec<u8>>, DbError> {
        let rows = match since_rev {
            None => {
                sqlite_query_scalar_unchecked!(
                    r#"
                    SELECT block_cid AS "block_cid!" FROM user_blocks
                    WHERE user_id = $1
                    ORDER BY repo_rev ASC
                    "#,
                    user_id
                )
                .fetch_all(&self.pool)
                .await
            }
            Some(rev) => {
                sqlite_query_scalar_unchecked!(
                    r#"
                    SELECT block_cid AS "block_cid!" FROM user_blocks
                    WHERE user_id = $1 AND repo_rev > $2
                    ORDER BY repo_rev ASC
                    "#,
                    user_id,
                    rev.as_str()
                )
                .fetch_all(&self.pool)
                .await
            }
        };

        rows.map_err(map_sqlite_error)
    }

    async fn insert_commit_event(&self, data: &CommitEventData) -> Result<(), DbError> {
        let (block_cids, block_data) = inline_to_paired_blocks(data.blocks.as_deref());
        let blob_strs: Option<Vec<String>> = data
            .blobs
            .as_ref()
            .map(|blobs| blobs.iter().map(|c| c.to_string()).collect());
        let ops_json = data.ops.as_ref().map(encode_json).transpose()?;
        let blobs_json = blob_strs.as_ref().map(encode_json).transpose()?;
        let block_cids_json = encode_block_pairs(&block_cids)?;
        let block_data_json = encode_block_pairs(&block_data)?;
        sqlite_query_unchecked!(
            r#"
            INSERT INTO repo_seq (did, event_type, commit_cid, prev_cid, ops, blobs, block_cids, block_data, prev_data_cid, rev)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            data.did.as_str(),
            data.event_type.as_str(),
            data.commit_cid.as_ref().map(|c| c.as_str()),
            data.prev_cid.as_ref().map(|c| c.as_str()),
            ops_json,
            blobs_json,
            block_cids_json,
            block_data_json,
            data.prev_data_cid.as_ref().map(|c| c.as_str()),
            data.rev.as_deref()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        notify_repo_pending(&self.pool).await;
        Ok(())
    }

    async fn insert_identity_event(
        &self,
        did: &Did,
        handle: Option<&Handle>,
    ) -> Result<(), DbError> {
        let handle_str = handle.map(|h| h.as_str());
        sqlite_query_unchecked!(
            r#"
            INSERT INTO repo_seq (did, event_type, handle)
            VALUES ($1, 'identity', $2)
            "#,
            did.as_str(),
            handle_str
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        notify_repo_pending(&self.pool).await;
        Ok(())
    }

    async fn insert_account_event(&self, did: &Did, status: AccountStatus) -> Result<(), DbError> {
        let active = status.is_active();
        let status_str = status.for_firehose().map(|s| s.as_str());
        sqlite_query_unchecked!(
            r#"
            INSERT INTO repo_seq (did, event_type, active, status)
            VALUES ($1, 'account', $2, $3)
            "#,
            did.as_str(),
            active,
            status_str
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        notify_repo_pending(&self.pool).await;
        Ok(())
    }

    async fn insert_sync_event(
        &self,
        did: &Did,
        commit_cid: &CidLink,
        rev: Option<&Tid>,
        commit_bytes: &[u8],
    ) -> Result<(), DbError> {
        let cid_bytes = commit_cid
            .to_cid()
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        let block_cids: Vec<Vec<u8>> = vec![cid_bytes];
        let block_data: Vec<Vec<u8>> = vec![commit_bytes.to_vec()];
        let block_cids_json = encode_block_pairs(&block_cids)?;
        let block_data_json = encode_block_pairs(&block_data)?;
        sqlite_query_unchecked!(
            r#"
            INSERT INTO repo_seq (did, event_type, commit_cid, rev, block_cids, block_data)
            VALUES ($1, 'sync', $2, $3, $4, $5)
            "#,
            did.as_str(),
            commit_cid.as_str(),
            rev.map(|r| r.as_str()),
            block_cids_json,
            block_data_json
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        notify_repo_pending(&self.pool).await;
        Ok(())
    }

    async fn insert_genesis_commit_event(
        &self,
        did: &Did,
        commit_cid: &CidLink,
        mst_root_cid: &CidLink,
        rev: &Tid,
        commit_bytes: &[u8],
        mst_root_bytes: &[u8],
    ) -> Result<(), DbError> {
        let ops = serde_json::json!([]);
        let blobs: Vec<String> = vec![];
        let commit_cid_bytes = commit_cid
            .to_cid()
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        let mst_cid_bytes = mst_root_cid
            .to_cid()
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        let block_cids: Vec<Vec<u8>> = vec![commit_cid_bytes, mst_cid_bytes];
        let block_data: Vec<Vec<u8>> = vec![commit_bytes.to_vec(), mst_root_bytes.to_vec()];
        let block_cids_json = encode_block_pairs(&block_cids)?;
        let block_data_json = encode_block_pairs(&block_data)?;
        let blobs_json = encode_json(&blobs)?;
        let ops_json = encode_json(&ops)?;
        let prev_cid: Option<&str> = None;

        sqlite_query_unchecked!(
            r#"
            INSERT INTO repo_seq (did, event_type, commit_cid, prev_cid, ops, blobs, block_cids, block_data, rev)
            VALUES ($1, 'commit', $2, $3, $4, $5, $6, $7, $8)
            "#,
            did.as_str(),
            commit_cid.as_str(),
            prev_cid,
            ops_json,
            blobs_json,
            block_cids_json,
            block_data_json,
            rev.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        notify_repo_pending(&self.pool).await;
        Ok(())
    }

    async fn purge_did_events_keeping_latest(&self, did: &Did) -> Result<(), DbError> {
        sqlite_query_unchecked!(
            r#"
            DELETE FROM repo_seq
            WHERE did = $1
              AND id <> (SELECT id FROM repo_seq WHERE did = $1 ORDER BY id DESC LIMIT 1)
            "#,
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn assign_pending_sequences(&self) -> Result<u64, DbError> {
        let mut total: u64 = 0;
        loop {
            let tx = self.pool.begin().await.map_err(map_sqlite_error)?;
            let count = assign_one_batch(tx, &self.pool).await?;
            total += count as u64;
            if count < SEQUENCER_BATCH_SIZE {
                return Ok(total);
            }
        }
    }

    async fn flush_pending_sequences(&self) -> Result<(), DbError> {
        loop {
            let tx = self.pool.begin().await.map_err(map_sqlite_error)?;
            let count = assign_one_batch(tx, &self.pool).await?;
            if count < SEQUENCER_BATCH_SIZE {
                return Ok(());
            }
        }
    }

    async fn prune_events_older_than(&self, cutoff: DateTime<Utc>) -> Result<PruneCount, DbError> {
        let result = sqlite_query_unchecked!("DELETE FROM repo_seq WHERE created_at < $1", cutoff)
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(PruneCount::Rows(result.rows_affected()))
    }

    async fn get_max_seq(&self) -> Result<SequenceNumber, DbError> {
        let seq: i64 =
            sqlite_query_scalar_unchecked!(r#"SELECT COALESCE(MAX(seq), 0) FROM repo_seq"#)
                .fetch_one(&self.pool)
                .await
                .map_err(map_sqlite_error)?;

        Ok(seq.into())
    }

    async fn get_min_seq_since(
        &self,
        since: DateTime<Utc>,
    ) -> Result<Option<SequenceNumber>, DbError> {
        let seq: Option<i64> = sqlite_query_scalar_unchecked!(
            "SELECT MIN(seq) FROM repo_seq WHERE created_at >= $1",
            since
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(seq.map(SequenceNumber::from))
    }

    async fn get_account_with_repo(&self, did: &Did) -> Result<Option<RepoAccountInfo>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT u.id, u.did, u.deactivated_at, u.takedown_ref, r.repo_root_cid as "repo_root_cid?"
               FROM users u
               LEFT JOIN repos r ON r.user_id = u.id
               WHERE u.did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            let id = r.try_get::<Vec<u8>, _>("id").map_err(map_sqlite_error)?;
            let id = Uuid::from_slice(&id).map_err(|error| DbError::Other(error.to_string()))?;
            let did: String = r.try_get("did").map_err(map_sqlite_error)?;
            let deactivated_at =
                parse_optional_timestamp(r.try_get("deactivated_at").map_err(map_sqlite_error)?)?;
            let takedown_ref = r.try_get("takedown_ref").map_err(map_sqlite_error)?;
            let repo_root_cid = r.try_get("repo_root_cid").map_err(map_sqlite_error)?;
            Ok(RepoAccountInfo {
                user_id: id,
                did: column(did, col::USERS_DID)?,
                deactivated_at,
                takedown_ref,
                repo_root_cid: opt_column(repo_root_cid, col::REPOS_REPO_ROOT_CID)?,
            })
        })
        .transpose()
    }

    async fn get_events_since_seq(
        &self,
        since_seq: SequenceNumber,
        limit: Option<i64>,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        match limit {
            Some(lim) => {
                let rows = sqlite_query_as_unchecked!(
                    SequencedEventRow,
                    r#"SELECT seq, did, created_at, event_type, commit_cid, prev_cid, prev_data_cid,
                              ops, blobs, block_cids, block_data, blocks_cids, handle, active, status, rev
                       FROM repo_seq
                       WHERE seq > $1
                       ORDER BY seq ASC
                       LIMIT $2"#,
                    since_seq.as_i64(),
                    lim
                )
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlite_error)?;
                Ok(collect_sequenced_rows(rows))
            }
            None => {
                let rows = sqlite_query_as_unchecked!(
                    SequencedEventRow,
                    r#"SELECT seq, did, created_at, event_type, commit_cid, prev_cid, prev_data_cid,
                              ops, blobs, block_cids, block_data, blocks_cids, handle, active, status, rev
                       FROM repo_seq
                       WHERE seq > $1
                       ORDER BY seq ASC"#,
                    since_seq.as_i64()
                )
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlite_error)?;
                Ok(collect_sequenced_rows(rows))
            }
        }
    }

    async fn get_events_in_seq_range(
        &self,
        start_seq: SequenceNumber,
        end_seq: SequenceNumber,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let rows = sqlite_query_as_unchecked!(
            SequencedEventRow,
            r#"SELECT seq, did, created_at, event_type, commit_cid, prev_cid, prev_data_cid,
                      ops, blobs, block_cids, block_data, blocks_cids, handle, active, status, rev
               FROM repo_seq
               WHERE seq > $1 AND seq < $2
               ORDER BY seq ASC"#,
            start_seq.as_i64(),
            end_seq.as_i64()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(collect_sequenced_rows(rows))
    }

    async fn get_event_by_seq(
        &self,
        seq: SequenceNumber,
    ) -> Result<Option<SequencedEvent>, DbError> {
        let row = sqlite_query_as_unchecked!(
            SequencedEventRow,
            r#"SELECT seq, did, created_at, event_type, commit_cid, prev_cid, prev_data_cid,
                      ops, blobs, block_cids, block_data, blocks_cids, handle, active, status, rev
               FROM repo_seq
               WHERE seq = $1"#,
            seq.as_i64()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(map_sequenced_row).transpose()
    }

    async fn get_events_since_cursor(
        &self,
        cursor: SequenceNumber,
        limit: i64,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let rows = sqlite_query_as_unchecked!(
            SequencedEventRow,
            r#"SELECT seq, did, created_at, event_type, commit_cid, prev_cid, prev_data_cid,
                      ops, blobs, block_cids, block_data, blocks_cids, handle, active, status, rev
               FROM repo_seq
               WHERE seq > $1
               ORDER BY seq ASC
               LIMIT $2"#,
            cursor.as_i64(),
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(collect_sequenced_rows(rows))
    }

    async fn list_repos_paginated(
        &self,
        cursor_did: Option<&Did>,
        limit: i64,
    ) -> Result<Vec<RepoListItem>, DbError> {
        let cursor_str = cursor_did.map(|d| d.as_str()).unwrap_or("");
        let rows = sqlite_query_unchecked!(
            r#"SELECT u.did, u.deactivated_at, u.takedown_ref, r.repo_root_cid, r.repo_rev
               FROM repos r
               JOIN users u ON r.user_id = u.id
               WHERE u.did > $1
               ORDER BY u.did ASC
               LIMIT $2"#,
            cursor_str,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                let did: String = r.try_get("did").map_err(map_sqlite_error)?;
                let deactivated_at = parse_optional_timestamp(
                    r.try_get("deactivated_at").map_err(map_sqlite_error)?,
                )?;
                let takedown_ref = r.try_get("takedown_ref").map_err(map_sqlite_error)?;
                let repo_root_cid: String = r.try_get("repo_root_cid").map_err(map_sqlite_error)?;
                let repo_rev: Option<String> = r.try_get("repo_rev").map_err(map_sqlite_error)?;
                Ok(RepoListItem {
                    did: column(did, col::USERS_DID)?,
                    deactivated_at,
                    takedown_ref,
                    repo_root_cid: column(repo_root_cid, col::REPOS_REPO_ROOT_CID)?,
                    repo_rev: opt_column(repo_rev, col::REPOS_REPO_REV)?,
                })
            })
            .collect()
    }

    async fn get_repo_root_cid_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<CidLink>, DbError> {
        let cid = sqlite_query_scalar_unchecked!(
            "SELECT repo_root_cid FROM repos WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        opt_column(cid, col::REPOS_REPO_ROOT_CID)
    }

    async fn import_repo_data(
        &self,
        user_id: Uuid,
        blocks: &[ImportBlock],
        records: &[ImportRecord],
        expected_root_cid: Option<&CidLink>,
    ) -> Result<(), ImportRepoError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ImportRepoError::Database(e.to_string()))?;

        let repo = sqlite_query_unchecked!(
            "SELECT repo_root_cid FROM repos WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e
                && db_err.code().as_deref() == Some("55P03")
            {
                return ImportRepoError::ConcurrentModification;
            }
            ImportRepoError::Database(e.to_string())
        })?;

        let repo = match repo {
            Some(r) => r,
            None => return Err(ImportRepoError::RepoNotFound),
        };

        let repo_root_cid: String = repo
            .try_get("repo_root_cid")
            .map_err(|e| ImportRepoError::Database(e.to_string()))?;
        if let Some(expected) = expected_root_cid
            && repo_root_cid != expected.as_str()
        {
            return Err(ImportRepoError::ConcurrentModification);
        }

        let block_chunks: Vec<Vec<&ImportBlock>> = blocks
            .iter()
            .collect::<Vec<_>>()
            .chunks(100)
            .map(|c| c.to_vec())
            .collect();

        for chunk in block_chunks {
            for block in chunk {
                sqlite_query_unchecked!(
                    "INSERT INTO blocks (cid, data) VALUES ($1, $2) ON CONFLICT (cid) DO NOTHING",
                    &block.cid_bytes,
                    &block.data
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| ImportRepoError::Database(e.to_string()))?;
            }
        }

        sqlite_query_unchecked!("DELETE FROM records WHERE repo_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ImportRepoError::Database(e.to_string()))?;

        for record in records {
            sqlite_query_unchecked!(
                r#"
                INSERT INTO records (repo_id, collection, rkey, record_cid)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (repo_id, collection, rkey) DO UPDATE SET record_cid = $4
                "#,
                user_id,
                record.collection.as_str(),
                record.rkey.as_str(),
                record.record_cid.as_str()
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| ImportRepoError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| ImportRepoError::Database(e.to_string()))?;

        Ok(())
    }

    async fn apply_commit(
        &self,
        input: tranquil_db_traits::ApplyCommitInput,
    ) -> Result<tranquil_db_traits::ApplyCommitResult, tranquil_db_traits::ApplyCommitError> {
        use tranquil_db_traits::ApplyCommitError;

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        let lock_result: Result<Option<_>, sqlx::Error> = sqlite_query_unchecked!(
            "SELECT repo_root_cid FROM repos WHERE user_id = $1",
            input.user_id
        )
        .fetch_optional(&mut *tx)
        .await;

        match lock_result {
            Err(e) => {
                if let Some(db_err) = e.as_database_error()
                    && db_err.code().as_deref() == Some("55P03")
                {
                    return Err(ApplyCommitError::ConcurrentModification);
                }
                return Err(ApplyCommitError::Database(format!(
                    "Failed to acquire repo lock: {}",
                    e
                )));
            }
            Ok(Some(row)) => {
                let repo_root_cid: String = row
                    .try_get("repo_root_cid")
                    .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
                if let Some(expected_root) = &input.expected_root_cid
                    && repo_root_cid != expected_root.as_str()
                {
                    return Err(ApplyCommitError::ConcurrentModification);
                }
            }
            Ok(None) => {
                return Err(ApplyCommitError::RepoNotFound);
            }
        }

        let is_account_active: bool =
            sqlx::query_scalar::<_, i64>("SELECT deactivated_at IS NULL FROM users WHERE id = $1")
                .bind(input.user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| ApplyCommitError::Database(e.to_string()))?
                .map(|value| value != 0)
                .unwrap_or(false);

        sqlite_query!("UPDATE repos SET repo_root_cid = $1, repo_rev = $2 WHERE user_id = $3")
            .bind(&input.new_root_cid)
            .bind(&input.new_rev)
            .bind(input.user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        if !input.new_block_cids.is_empty() {
            for block_cid in &input.new_block_cids {
                sqlite_query!(
                    "INSERT INTO user_blocks (user_id, block_cid, repo_rev) VALUES ($1, $2, $3) ON CONFLICT (user_id, block_cid) DO NOTHING",
                    input.user_id,
                    block_cid,
                    input.new_rev.as_str().to_owned()
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
            }
        }

        if !input.obsolete_block_cids.is_empty() {
            for block_cid in &input.obsolete_block_cids {
                sqlite_query!(
                    "DELETE FROM user_blocks WHERE user_id = $1 AND block_cid = $2",
                    input.user_id,
                    block_cid
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
            }
        }

        if !input.record_upserts.is_empty() {
            for record in &input.record_upserts {
                sqlite_query!(
                    "INSERT INTO records (repo_id, collection, rkey, record_cid, repo_rev) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (repo_id, collection, rkey) DO UPDATE SET record_cid = excluded.record_cid, repo_rev = excluded.repo_rev",
                    input.user_id,
                    record.collection.as_str().to_owned(),
                    record.rkey.as_str().to_owned(),
                    record.cid.as_str().to_owned(),
                    input.new_rev.as_str().to_owned()
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
            }
        }

        if !input.record_deletes.is_empty() {
            for record in &input.record_deletes {
                sqlite_query!(
                    "DELETE FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3",
                    input.user_id,
                    record.collection.as_str().to_owned(),
                    record.rkey.as_str().to_owned()
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
            }
        }

        if !input.backlinks_to_remove.is_empty() {
            for uri in &input.backlinks_to_remove {
                sqlite_query!(
                    "DELETE FROM backlinks WHERE uri = $1",
                    uri.as_str().to_owned()
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
            }
        }

        if !input.backlinks_to_add.is_empty() {
            for backlink in &input.backlinks_to_add {
                sqlite_query!(
                    "INSERT INTO backlinks (uri, path, link_to, repo_id) VALUES ($1, $2, $3, $4) ON CONFLICT (uri, path) DO NOTHING",
                    backlink.uri.as_str().to_owned(),
                    backlink.path.as_str().to_owned(),
                    backlink.link_to.as_str().to_owned(),
                    input.user_id
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
            }
        }

        let event = input.commit_event;
        let (event_block_cids, event_block_data) = inline_into_paired_blocks(event.blocks);
        let event_blob_strs: Option<Vec<String>> = event
            .blobs
            .as_ref()
            .map(|blobs| blobs.iter().map(|c| c.to_string()).collect());
        let event_ops_json = event
            .ops
            .as_ref()
            .map(encode_json)
            .transpose()
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
        let event_blobs_json = event_blob_strs
            .as_ref()
            .map(encode_json)
            .transpose()
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
        let event_block_cids_json = encode_block_pairs(&event_block_cids)
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
        let event_block_data_json = encode_block_pairs(&event_block_data)
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
        sqlite_query_unchecked!(
            r#"
            INSERT INTO repo_seq (did, event_type, commit_cid, prev_cid, ops, blobs, block_cids, block_data, prev_data_cid, rev)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            event.did.as_str(),
            event.event_type.as_str(),
            event.commit_cid.as_ref().map(|c| c.as_str()),
            event.prev_cid.as_ref().map(|c| c.as_str()),
            event_ops_json,
            event_blobs_json,
            event_block_cids_json,
            event_block_data_json,
            event.prev_data_cid.as_ref().map(|c| c.as_str()),
            event.rev.as_deref()
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        Ok(tranquil_db_traits::ApplyCommitResult { is_account_active })
    }

    async fn get_users_without_blocks(&self) -> Result<Vec<UserWithoutBlocks>, DbError> {
        let rows: Vec<(Vec<u8>, String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT u.id as user_id, r.repo_root_cid, r.repo_rev
            FROM users u
            JOIN repos r ON r.user_id = u.id
            WHERE NOT EXISTS (SELECT 1 FROM user_blocks ub WHERE ub.user_id = u.id)
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|(user_id, repo_root_cid, repo_rev)| {
                let user_id = Uuid::from_slice(&user_id)
                    .map_err(|error| DbError::Other(error.to_string()))?;
                Ok(UserWithoutBlocks {
                    user_id,
                    repo_root_cid: column(repo_root_cid, col::REPOS_REPO_ROOT_CID)?,
                    repo_rev: opt_column(repo_rev, col::REPOS_REPO_REV)?,
                })
            })
            .collect()
    }

    async fn get_users_needing_record_blobs_backfill(
        &self,
        limit: i64,
    ) -> Result<Vec<tranquil_db_traits::UserNeedingRecordBlobsBackfill>, DbError> {
        let rows = sqlite_query_unchecked!(
            r#"
            SELECT DISTINCT u.id as user_id, u.did
            FROM users u
            JOIN records r ON r.repo_id = u.id
            WHERE NOT EXISTS (SELECT 1 FROM record_blobs rb WHERE rb.repo_id = u.id)
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                let user_id = r
                    .try_get::<Vec<u8>, _>("user_id")
                    .map_err(map_sqlite_error)?;
                let user_id = Uuid::from_slice(&user_id)
                    .map_err(|error| DbError::Other(error.to_string()))?;
                let did: String = r.try_get("did").map_err(map_sqlite_error)?;
                Ok(UserNeedingRecordBlobsBackfill {
                    user_id,
                    did: column(did, col::USERS_DID)?,
                })
            })
            .collect()
    }

    async fn insert_record_blobs(
        &self,
        repo_id: Uuid,
        record_uris: &[AtUri],
        blob_cids: &[CidLink],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;
        for (record_uri, blob_cid) in record_uris.iter().zip(blob_cids) {
            sqlite_query!(
                "INSERT INTO record_blobs (repo_id, record_uri, blob_cid) VALUES ($1, $2, $3) ON CONFLICT (repo_id, record_uri, blob_cid) DO NOTHING",
                repo_id,
                record_uri.as_str().to_owned(),
                blob_cid.as_str().to_owned()
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        }
        tx.commit().await.map_err(map_sqlite_error)?;

        Ok(())
    }
}
