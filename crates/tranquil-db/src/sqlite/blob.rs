use async_trait::async_trait;
use sqlx::SqlitePool;
use tranquil_db_traits::{
    BlobForExport, BlobMetadata, BlobRepository, BlobWithTakedown, DbError, MissingBlobInfo,
};
use tranquil_types::{AtUri, CidLink, Did, Tid};
use uuid::Uuid;

use super::col;
use super::map_sqlite_error;
use super::{column, column_vec, opt_column};

pub struct SqliteBlobRepository {
    pool: SqlitePool,
}

impl SqliteBlobRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BlobRepository for SqliteBlobRepository {
    async fn insert_blob(
        &self,
        cid: &CidLink,
        mime_type: &str,
        size_bytes: i64,
        created_by_user: Uuid,
        storage_key: &str,
    ) -> Result<Option<CidLink>, DbError> {
        let cid_value = cid.as_str().to_owned();
        let result = sqlx::query_scalar!(
            r#"INSERT INTO blobs (cid, mime_type, size_bytes, created_by_user, storage_key)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (cid) DO NOTHING RETURNING CAST(cid AS TEXT) as "cid!: String""#,
            cid_value,
            mime_type,
            size_bytes,
            created_by_user,
            storage_key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        opt_column(result, col::BLOBS_CID)
    }

    async fn get_blob_metadata(&self, cid: &CidLink) -> Result<Option<BlobMetadata>, DbError> {
        let cid_value = cid.as_str().to_owned();
        let result = sqlx::query!(
            "SELECT storage_key, mime_type, size_bytes FROM blobs WHERE cid = $1",
            cid_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.map(|r| BlobMetadata {
            storage_key: r.storage_key,
            mime_type: r.mime_type,
            size_bytes: r.size_bytes,
        }))
    }

    async fn get_blob_with_takedown(
        &self,
        cid: &CidLink,
    ) -> Result<Option<BlobWithTakedown>, DbError> {
        let cid_value = cid.as_str().to_owned();
        let result = sqlx::query!(
            "SELECT CAST(cid AS TEXT) as \"cid!: String\", takedown_ref FROM blobs WHERE cid = $1",
            cid_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        result
            .map(|r| {
                Ok(BlobWithTakedown {
                    cid: column(r.cid, col::BLOBS_CID)?,
                    takedown_ref: r.takedown_ref,
                })
            })
            .transpose()
    }

    async fn get_blob_storage_key(&self, cid: &CidLink) -> Result<Option<String>, DbError> {
        let cid_value = cid.as_str().to_owned();
        let result = sqlx::query_scalar!("SELECT storage_key FROM blobs WHERE cid = $1", cid_value)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(result)
    }

    async fn list_blobs_by_user(
        &self,
        user_id: Uuid,
        cursor: Option<&str>,
        limit: i64,
    ) -> Result<Vec<CidLink>, DbError> {
        let cursor_val = cursor.unwrap_or("");
        let results = sqlx::query_scalar!(
            r#"SELECT CAST(cid AS TEXT) as "cid!: String" FROM blobs
               WHERE created_by_user = $1 AND cid > $2
               ORDER BY cid ASC
               LIMIT $3"#,
            user_id,
            cursor_val,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        column_vec(results, col::BLOBS_CID)
    }

    async fn list_blobs_since_rev(&self, did: &Did, since: &Tid) -> Result<Vec<CidLink>, DbError> {
        let did_value = did.as_str().to_owned();
        let since_value = since.as_str().to_owned();
        let results = sqlx::query_scalar!(
            r#"SELECT DISTINCT CAST(COALESCE(je.value, '') AS TEXT) as "cid!: String"
               FROM repo_seq, json_each(repo_seq.blobs) AS je
               WHERE did = $1 AND rev > $2 AND blobs IS NOT NULL"#,
            did_value,
            since_value
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        column_vec(results, col::REPO_SEQ_BLOBS)
    }

    async fn count_blobs_by_user(&self, user_id: Uuid) -> Result<i64, DbError> {
        let result = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!" FROM blobs WHERE created_by_user = $1"#,
            user_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result)
    }

    async fn sum_blob_storage(&self) -> Result<i64, DbError> {
        let result =
            sqlx::query_scalar!(r#"SELECT COALESCE(SUM(size_bytes), 0) as "total!" FROM blobs"#)
                .fetch_one(&self.pool)
                .await
                .map_err(map_sqlite_error)?;

        Ok(result)
    }

    async fn update_blob_takedown(
        &self,
        cid: &CidLink,
        takedown_ref: Option<&str>,
    ) -> Result<bool, DbError> {
        let cid_value = cid.as_str().to_owned();
        let result = sqlx::query!(
            "UPDATE blobs SET takedown_ref = $1 WHERE cid = $2",
            takedown_ref,
            cid_value
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete_blob_by_cid(&self, cid: &CidLink) -> Result<bool, DbError> {
        let cid_value = cid.as_str().to_owned();
        let result = sqlx::query!("DELETE FROM blobs WHERE cid = $1", cid_value)
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete_blobs_by_user(&self, user_id: Uuid) -> Result<u64, DbError> {
        let result = sqlx::query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(result.rows_affected())
    }

    async fn get_blob_storage_keys_by_user(&self, user_id: Uuid) -> Result<Vec<String>, DbError> {
        let results = sqlx::query_scalar!(
            r#"SELECT storage_key as "storage_key!" FROM blobs WHERE created_by_user = $1"#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(results)
    }

    async fn insert_record_blobs(
        &self,
        repo_id: Uuid,
        record_uris: &[AtUri],
        blob_cids: &[CidLink],
    ) -> Result<(), DbError> {
        for (record_uri, blob_cid) in record_uris.iter().zip(blob_cids) {
            let record_uri_value = record_uri.as_str().to_owned();
            let blob_cid_value = blob_cid.as_str().to_owned();
            sqlx::query!(
                r#"INSERT INTO record_blobs (repo_id, record_uri, blob_cid)
                   VALUES ($1, $2, $3) ON CONFLICT (repo_id, record_uri, blob_cid) DO NOTHING"#,
                repo_id,
                record_uri_value,
                blob_cid_value
            )
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;
        }

        Ok(())
    }

    async fn list_missing_blobs(
        &self,
        repo_id: Uuid,
        cursor: Option<&str>,
        limit: i64,
    ) -> Result<Vec<MissingBlobInfo>, DbError> {
        let cursor_val = cursor.unwrap_or("");
        let results = sqlx::query!(
            r#"SELECT rb.blob_cid, rb.record_uri
               FROM record_blobs rb
               LEFT JOIN blobs b ON rb.blob_cid = b.cid
               WHERE rb.repo_id = $1 AND b.cid IS NULL AND rb.blob_cid > $2
               ORDER BY rb.blob_cid
               LIMIT $3"#,
            repo_id,
            cursor_val,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        results
            .into_iter()
            .map(|r| {
                Ok(MissingBlobInfo {
                    blob_cid: column(r.blob_cid, col::RECORD_BLOBS_BLOB_CID)?,
                    record_uri: column(r.record_uri, col::RECORD_BLOBS_RECORD_URI)?,
                })
            })
            .collect()
    }

    async fn count_distinct_record_blobs(&self, repo_id: Uuid) -> Result<i64, DbError> {
        let result = sqlx::query_scalar!(
            r#"SELECT COUNT(DISTINCT blob_cid) as "count!" FROM record_blobs WHERE repo_id = $1"#,
            repo_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result)
    }

    async fn get_blobs_for_export(&self, repo_id: Uuid) -> Result<Vec<BlobForExport>, DbError> {
        let results = sqlx::query!(
            r#"SELECT DISTINCT CAST(b.cid AS TEXT) as "cid!: String", b.storage_key, b.mime_type
               FROM blobs b
               JOIN record_blobs rb ON rb.blob_cid = b.cid
               WHERE rb.repo_id = $1"#,
            repo_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        results
            .into_iter()
            .map(|r| {
                Ok(BlobForExport {
                    cid: column(r.cid, col::BLOBS_CID)?,
                    storage_key: r.storage_key,
                    mime_type: r.mime_type,
                })
            })
            .collect()
    }
}
