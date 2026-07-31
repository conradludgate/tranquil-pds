use async_trait::async_trait;
use sqlx::SqlitePool;
use tranquil_db_traits::{Backlink, BacklinkRepository, DbError};
use tranquil_types::{AtUri, Nsid};
use uuid::Uuid;

use super::col;
use super::column_vec;
use super::map_sqlite_error;

pub struct SqliteBacklinkRepository {
    pool: SqlitePool,
}

impl SqliteBacklinkRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BacklinkRepository for SqliteBacklinkRepository {
    async fn get_backlink_conflicts(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        backlinks: &[Backlink],
    ) -> Result<Vec<AtUri>, DbError> {
        if backlinks.is_empty() {
            return Ok(Vec::new());
        }

        let collection_pattern = format!("%/{}/%", collection.as_str());
        let mut results = Vec::new();
        for backlink in backlinks {
            let path = backlink.path.as_str().to_owned();
            let link_to = backlink.link_to.as_str().to_owned();
            let pattern = collection_pattern.clone();
            let rows = sqlx::query_scalar!(
                r#"SELECT DISTINCT CAST(uri AS TEXT) as "uri!: String"
                   FROM backlinks
                   WHERE repo_id = $1 AND uri LIKE $2 AND path = $3 AND link_to = $4"#,
                repo_id,
                pattern,
                path,
                link_to
            )
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlite_error)?;
            results.extend(rows);
        }

        column_vec(results, col::BACKLINKS_URI)
    }

    async fn add_backlinks(&self, repo_id: Uuid, backlinks: &[Backlink]) -> Result<(), DbError> {
        if backlinks.is_empty() {
            return Ok(());
        }

        for backlink in backlinks {
            let uri = backlink.uri.as_str().to_owned();
            let path = backlink.path.as_str().to_owned();
            let link_to = backlink.link_to.as_str().to_owned();
            sqlx::query!(
                r#"INSERT INTO backlinks (uri, path, link_to, repo_id)
                   VALUES ($1, $2, $3, $4) ON CONFLICT (uri, path) DO NOTHING"#,
                uri,
                path,
                link_to,
                repo_id
            )
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;
        }

        Ok(())
    }

    async fn remove_backlinks_by_uri(&self, uri: &AtUri) -> Result<(), DbError> {
        let uri_value = uri.as_str().to_owned();
        sqlx::query!("DELETE FROM backlinks WHERE uri = $1", uri_value)
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn remove_backlinks_by_repo(&self, repo_id: Uuid) -> Result<(), DbError> {
        sqlx::query!("DELETE FROM backlinks WHERE repo_id = $1", repo_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(())
    }
}
