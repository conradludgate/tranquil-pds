use async_trait::async_trait;
use sqlx::{Row, SqlitePool};
use tranquil_db_traits::{
    DbError, GitOpsRecord, GitOpsRecordClaim, GitOpsRepository, GitOpsSource,
};
use tranquil_types::{Did, Nsid, Rkey};
use uuid::Uuid;

use super::map_sqlite_error;

pub struct SqliteGitOpsRepository {
    pool: SqlitePool,
}

impl SqliteGitOpsRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn parse_uuid(value: Vec<u8>) -> Result<Uuid, DbError> {
    Uuid::from_slice(&value).map_err(|_| DbError::CorruptData("gitops UUID"))
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
impl GitOpsRepository for SqliteGitOpsRepository {
    async fn ensure_source(
        &self,
        name: &str,
        path: &str,
        did: &Did,
    ) -> Result<GitOpsSource, DbError> {
        sqlx::query(
            "INSERT INTO gitops_sources (name, path, did) VALUES (?, ?, ?) \
             ON CONFLICT(name) DO UPDATE SET path = excluded.path, did = excluded.did, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(name)
        .bind(path)
        .bind(did.as_str())
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        let row = sqlx::query("SELECT id, name, path, did FROM gitops_sources WHERE name = ?")
            .bind(name)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(GitOpsSource {
            id: parse_uuid(row.try_get("id").map_err(map_sqlite_error)?)?,
            name: row.try_get("name").map_err(map_sqlite_error)?,
            path: row.try_get("path").map_err(map_sqlite_error)?,
            did: parse_did(row.try_get("did").map_err(map_sqlite_error)?)?,
        })
    }

    async fn list_records(&self, source_id: Uuid) -> Result<Vec<GitOpsRecord>, DbError> {
        let rows = sqlx::query(
            "SELECT source_id, path, did, collection, rkey, content_hash, record_cid \
             FROM gitops_records WHERE source_id = ? ORDER BY path",
        )
        .bind(source_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|row| {
                Ok(GitOpsRecord {
                    source_id: parse_uuid(row.try_get("source_id").map_err(map_sqlite_error)?)?,
                    path: row.try_get("path").map_err(map_sqlite_error)?,
                    did: parse_did(row.try_get("did").map_err(map_sqlite_error)?)?,
                    collection: parse_nsid(row.try_get("collection").map_err(map_sqlite_error)?)?,
                    rkey: parse_rkey(row.try_get("rkey").map_err(map_sqlite_error)?)?,
                    content_hash: row.try_get("content_hash").map_err(map_sqlite_error)?,
                    record_cid: row.try_get("record_cid").map_err(map_sqlite_error)?,
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
             WHERE did = ? AND collection = ? AND rkey = ?",
        )
        .bind(did.as_str())
        .bind(collection.as_str())
        .bind(rkey.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|row| {
            Ok(GitOpsRecordClaim {
                source_id: parse_uuid(row.try_get("source_id").map_err(map_sqlite_error)?)?,
                path: row.try_get("path").map_err(map_sqlite_error)?,
            })
        })
        .transpose()
    }

    async fn upsert_record(&self, record: &GitOpsRecord) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO gitops_records \
             (source_id, path, did, collection, rkey, content_hash, record_cid) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(source_id, path) DO UPDATE SET \
             did = excluded.did, collection = excluded.collection, rkey = excluded.rkey, \
             content_hash = excluded.content_hash, record_cid = excluded.record_cid, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
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
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn delete_record(&self, source_id: Uuid, path: &str) -> Result<(), DbError> {
        sqlx::query("DELETE FROM gitops_records WHERE source_id = ? AND path = ?")
            .bind(source_id)
            .bind(path)
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn mark_scan(&self, source_id: Uuid, error: Option<&str>) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE gitops_sources SET last_scan_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), \
             last_error = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
        )
        .bind(error)
        .bind(source_id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn ownership_round_trip_uses_sqlite_uuid_storage() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations-sqlite")
            .run(&pool)
            .await
            .unwrap();

        let repository = SqliteGitOpsRepository::new(pool);
        let did = Did::new("did:plc:s2zz2lewy34hvwxxyt7ivm4o").unwrap();
        let collection = Nsid::new("app.example.record").unwrap();
        let rkey = Rkey::new("test").unwrap();
        let source = repository
            .ensure_source("blog", "/sources/blog", &did)
            .await
            .unwrap();

        repository
            .upsert_record(&GitOpsRecord {
                source_id: source.id,
                path: "app.example.record/test.json".to_string(),
                did: did.clone(),
                collection: collection.clone(),
                rkey: rkey.clone(),
                content_hash: "hash".to_string(),
                record_cid: None,
            })
            .await
            .unwrap();

        let records = repository.list_records(source.id).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].path, "app.example.record/test.json");

        let claim = repository
            .find_claim(&did, &collection, &rkey)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.source_id, source.id);
        assert_eq!(claim.path, records[0].path);

        repository
            .delete_record(source.id, &records[0].path)
            .await
            .unwrap();
        assert!(repository.list_records(source.id).await.unwrap().is_empty());
    }
}
