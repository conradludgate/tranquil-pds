use async_trait::async_trait;
use uuid::Uuid;

use crate::DbError;
use tranquil_types::{Did, Nsid, Rkey};

#[derive(Debug, Clone)]
pub struct GitOpsSource {
    pub id: Uuid,
    pub name: String,
    pub path: String,
    pub did: Did,
}

#[derive(Debug, Clone)]
pub struct GitOpsRecord {
    pub source_id: Uuid,
    pub path: String,
    pub did: Did,
    pub collection: Nsid,
    pub rkey: Rkey,
    pub content_hash: String,
    pub record_cid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GitOpsRecordClaim {
    pub source_id: Uuid,
    pub path: String,
}

#[async_trait]
pub trait GitOpsRepository: Send + Sync {
    async fn ensure_source(
        &self,
        name: &str,
        path: &str,
        did: &Did,
    ) -> Result<GitOpsSource, DbError>;

    async fn list_records(&self, source_id: Uuid) -> Result<Vec<GitOpsRecord>, DbError>;

    async fn find_claim(
        &self,
        did: &Did,
        collection: &Nsid,
        rkey: &Rkey,
    ) -> Result<Option<GitOpsRecordClaim>, DbError>;

    async fn upsert_record(&self, record: &GitOpsRecord) -> Result<(), DbError>;

    async fn delete_record(&self, source_id: Uuid, path: &str) -> Result<(), DbError>;

    async fn mark_scan(&self, source_id: Uuid, error: Option<&str>) -> Result<(), DbError>;
}
