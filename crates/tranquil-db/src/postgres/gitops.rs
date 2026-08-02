use async_trait::async_trait;
use sqlx::{PgPool, Row};
use tranquil_db_traits::{
    DbError, GitOpsRecord, GitOpsRecordClaim, GitOpsRepository, GitOpsSource,
};
use tranquil_types::{Did, Nsid, Rkey};
use uuid::Uuid;

use super::user::map_sqlx_error;

pub struct PostgresGitOpsRepository {
    pool: PgPool,
}

impl PostgresGitOpsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_did(value: String) -> Result<Did, DbError> {
    Did::new(value).map_err(|_| DbError::CorruptData("gitops DID"))
}

fn parse_nsid(value: String) -> Result<Nsid, DbError> {
    Nsid::new(value).map_err(|_| DbError::CorruptData("gitops collection"))
}

fn parse_rkey(value: String) -> Result<Rkey, DbError> {
    Rkey::new(value).map_err(|_| DbError::CorruptData("gitops rkey"))
}

#[async_trait]
impl GitOpsRepository for PostgresGitOpsRepository {
    async fn ensure_source(
        &self,
        name: &str,
        path: &str,
        did: &Did,
    ) -> Result<GitOpsSource, DbError> {
        let row = sqlx::query(
            "INSERT INTO gitops_sources (name, path, did) VALUES ($1, $2, $3) \
             ON CONFLICT(name) DO UPDATE SET path = EXCLUDED.path, did = EXCLUDED.did, \
             updated_at = NOW() \
             RETURNING id, name, path, did",
        )
        .bind(name)
        .bind(path)
        .bind(did.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(GitOpsSource {
            id: row.try_get("id").map_err(map_sqlx_error)?,
            name: row.try_get("name").map_err(map_sqlx_error)?,
            path: row.try_get("path").map_err(map_sqlx_error)?,
            did: parse_did(row.try_get("did").map_err(map_sqlx_error)?)?,
        })
    }

    async fn list_records(&self, source_id: Uuid) -> Result<Vec<GitOpsRecord>, DbError> {
        let rows = sqlx::query(
            "SELECT source_id, path, did, collection, rkey, content_hash, record_cid \
             FROM gitops_records WHERE source_id = $1 ORDER BY path",
        )
        .bind(source_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        rows.into_iter()
            .map(|row| {
                Ok(GitOpsRecord {
                    source_id: row.try_get("source_id").map_err(map_sqlx_error)?,
                    path: row.try_get("path").map_err(map_sqlx_error)?,
                    did: parse_did(row.try_get("did").map_err(map_sqlx_error)?)?,
                    collection: parse_nsid(row.try_get("collection").map_err(map_sqlx_error)?)?,
                    rkey: parse_rkey(row.try_get("rkey").map_err(map_sqlx_error)?)?,
                    content_hash: row.try_get("content_hash").map_err(map_sqlx_error)?,
                    record_cid: row.try_get("record_cid").map_err(map_sqlx_error)?,
                })
            })
            .collect()
    }

    async fn find_claim(
        &self,
        did: &Did,
        collection: &Nsid,
        rkey: &Rkey,
    ) -> Result<Option<GitOpsRecordClaim>, DbError> {
        let row = sqlx::query(
            "SELECT source_id, path FROM gitops_records \
             WHERE did = $1 AND collection = $2 AND rkey = $3",
        )
        .bind(did.as_str())
        .bind(collection.as_str())
        .bind(rkey.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        row.map(|row| {
            Ok(GitOpsRecordClaim {
                source_id: row.try_get("source_id").map_err(map_sqlx_error)?,
                path: row.try_get("path").map_err(map_sqlx_error)?,
            })
        })
        .transpose()
    }

    async fn upsert_record(&self, record: &GitOpsRecord) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO gitops_records \
             (source_id, path, did, collection, rkey, content_hash, record_cid) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT(source_id, path) DO UPDATE SET \
             did = EXCLUDED.did, collection = EXCLUDED.collection, rkey = EXCLUDED.rkey, \
             content_hash = EXCLUDED.content_hash, record_cid = EXCLUDED.record_cid, \
             updated_at = NOW()",
        )
        .bind(record.source_id)
        .bind(&record.path)
        .bind(record.did.as_str())
        .bind(record.collection.as_str())
        .bind(record.rkey.as_str())
        .bind(&record.content_hash)
        .bind(&record.record_cid)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn delete_record(&self, source_id: Uuid, path: &str) -> Result<(), DbError> {
        sqlx::query("DELETE FROM gitops_records WHERE source_id = $1 AND path = $2")
            .bind(source_id)
            .bind(path)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn mark_scan(&self, source_id: Uuid, error: Option<&str>) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE gitops_sources SET last_scan_at = NOW(), last_error = $1, \
             updated_at = NOW() WHERE id = $2",
        )
        .bind(error)
        .bind(source_id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }
}
