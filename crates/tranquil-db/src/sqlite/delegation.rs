use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use tranquil_db_traits::{
    AuditLogEntry, ControllerInfo, DbError, DbScope, DelegatedAccountInfo, DelegationActionType,
    DelegationGrant, DelegationRepository,
};
use tranquil_types::Did;
use uuid::Uuid;

use super::col;
use super::map_sqlite_error;
use super::{column, legacy_column, opt_column};

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "delegation_action_type", rename_all = "snake_case")]
pub enum PgDelegationActionType {
    GrantCreated,
    GrantRevoked,
    ScopesModified,
    TokenIssued,
    RepoWrite,
    BlobUpload,
    AccountAction,
}

impl From<DelegationActionType> for PgDelegationActionType {
    fn from(t: DelegationActionType) -> Self {
        match t {
            DelegationActionType::GrantCreated => Self::GrantCreated,
            DelegationActionType::GrantRevoked => Self::GrantRevoked,
            DelegationActionType::ScopesModified => Self::ScopesModified,
            DelegationActionType::TokenIssued => Self::TokenIssued,
            DelegationActionType::RepoWrite => Self::RepoWrite,
            DelegationActionType::BlobUpload => Self::BlobUpload,
            DelegationActionType::AccountAction => Self::AccountAction,
        }
    }
}

impl From<PgDelegationActionType> for DelegationActionType {
    fn from(t: PgDelegationActionType) -> Self {
        match t {
            PgDelegationActionType::GrantCreated => Self::GrantCreated,
            PgDelegationActionType::GrantRevoked => Self::GrantRevoked,
            PgDelegationActionType::ScopesModified => Self::ScopesModified,
            PgDelegationActionType::TokenIssued => Self::TokenIssued,
            PgDelegationActionType::RepoWrite => Self::RepoWrite,
            PgDelegationActionType::BlobUpload => Self::BlobUpload,
            PgDelegationActionType::AccountAction => Self::AccountAction,
        }
    }
}

pub struct SqliteDelegationRepository {
    pool: SqlitePool,
}

fn timestamp(value: String) -> Result<DateTime<Utc>, DbError> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| DbError::Query(format!("invalid timestamp: {value}")))
}

fn optional_timestamp(value: Option<String>) -> Result<Option<DateTime<Utc>>, DbError> {
    value.map(timestamp).transpose()
}

fn uuid(value: Vec<u8>) -> Result<Uuid, DbError> {
    Uuid::from_slice(&value).map_err(|error| DbError::Query(error.to_string()))
}

impl SqliteDelegationRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DelegationRepository for SqliteDelegationRepository {
    async fn is_delegated_account(&self, did: &Did) -> Result<bool, DbError> {
        let did_value = did.as_str().to_owned();
        let exists = sqlx::query_scalar!(
            r#"SELECT EXISTS(
                SELECT 1 FROM account_delegations
                WHERE delegated_did = $1 AND revoked_at IS NULL
            ) as "exists!""#,
            did_value
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(exists != 0)
    }

    async fn create_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        granted_scopes: &DbScope,
        granted_by: &Did,
    ) -> Result<Uuid, DbError> {
        let delegated_did_value = delegated_did.as_str().to_owned();
        let controller_did_value = controller_did.as_str().to_owned();
        let granted_scopes_value = granted_scopes.as_str().to_owned();
        let granted_by_value = granted_by.as_str().to_owned();
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO account_delegations (delegated_did, controller_did, granted_scopes, granted_by)
            VALUES ($1, $2, $3, $4)
            RETURNING id as "id!: Vec<u8>"
            "#,
            delegated_did_value,
            controller_did_value,
            granted_scopes_value,
            granted_by_value
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        uuid(id)
    }

    async fn revoke_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        revoked_by: &Did,
    ) -> Result<bool, DbError> {
        let revoked_by_value = revoked_by.as_str().to_owned();
        let delegated_did_value = delegated_did.as_str().to_owned();
        let controller_did_value = controller_did.as_str().to_owned();
        let result = sqlx::query!(
            r#"
            UPDATE account_delegations
            SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), revoked_by = $1
            WHERE delegated_did = $2 AND controller_did = $3 AND revoked_at IS NULL
            "#,
            revoked_by_value,
            delegated_did_value,
            controller_did_value
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn update_delegation_scopes(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        new_scopes: &DbScope,
    ) -> Result<bool, DbError> {
        let new_scopes_value = new_scopes.as_str().to_owned();
        let delegated_did_value = delegated_did.as_str().to_owned();
        let controller_did_value = controller_did.as_str().to_owned();
        let result = sqlx::query!(
            r#"
            UPDATE account_delegations
            SET granted_scopes = $1
            WHERE delegated_did = $2 AND controller_did = $3 AND revoked_at IS NULL
            "#,
            new_scopes_value,
            delegated_did_value,
            controller_did_value
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn get_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
    ) -> Result<Option<DelegationGrant>, DbError> {
        let delegated_did_value = delegated_did.as_str().to_owned();
        let controller_did_value = controller_did.as_str().to_owned();
        let row = sqlx::query!(
            r#"
            SELECT id as "id!: Vec<u8>", delegated_did, controller_did, granted_scopes,
                   CAST(granted_at AS TEXT) as "granted_at!: String", granted_by,
                   CAST(revoked_at AS TEXT) as "revoked_at: String", revoked_by
            FROM account_delegations
            WHERE delegated_did = $1 AND controller_did = $2 AND revoked_at IS NULL
            "#,
            delegated_did_value,
            controller_did_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(DelegationGrant {
                id: uuid(r.id)?,
                delegated_did: column(r.delegated_did, col::ACCOUNT_DELEGATIONS_DELEGATED_DID)?,
                controller_did: column(r.controller_did, col::ACCOUNT_DELEGATIONS_CONTROLLER_DID)?,
                granted_scopes: DbScope::from_db(r.granted_scopes),
                granted_at: timestamp(r.granted_at)?,
                granted_by: column(r.granted_by, col::ACCOUNT_DELEGATIONS_GRANTED_BY)?,
                revoked_at: optional_timestamp(r.revoked_at)?,
                revoked_by: opt_column(r.revoked_by, col::ACCOUNT_DELEGATIONS_REVOKED_BY)?,
            })
        })
        .transpose()
    }

    async fn get_delegations_for_account(
        &self,
        delegated_did: &Did,
    ) -> Result<Vec<ControllerInfo>, DbError> {
        let delegated_did_value = delegated_did.as_str().to_owned();
        let rows = sqlx::query!(
            r#"
            SELECT
                d.controller_did,
                u.handle as "handle?",
                d.granted_scopes,
                CAST(d.granted_at AS TEXT) as "granted_at!: String",
                CAST(CASE WHEN u.did IS NOT NULL
                     THEN u.deactivated_at IS NULL AND u.takedown_ref IS NULL
                     ELSE true
                END AS INTEGER) as "is_active!: i64",
                CAST(u.did IS NOT NULL AS INTEGER) as "is_local!: i64"
            FROM account_delegations d
            LEFT JOIN users u ON u.did = d.controller_did
            WHERE d.delegated_did = $1 AND d.revoked_at IS NULL
            ORDER BY d.granted_at DESC
            "#,
            delegated_did_value
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(ControllerInfo {
                    did: column(r.controller_did, col::ACCOUNT_DELEGATIONS_CONTROLLER_DID)?,
                    handle: r.handle.and_then(|h| legacy_column(h, col::USERS_HANDLE)),
                    granted_scopes: DbScope::from_db(r.granted_scopes),
                    granted_at: timestamp(r.granted_at)?,
                    is_active: r.is_active != 0,
                    is_local: r.is_local != 0,
                })
            })
            .collect()
    }

    async fn get_accounts_controlled_by(
        &self,
        controller_did: &Did,
    ) -> Result<Vec<DelegatedAccountInfo>, DbError> {
        let controller_did_value = controller_did.as_str().to_owned();
        let rows = sqlx::query!(
            r#"
            SELECT
                u.did,
                u.handle,
                d.granted_scopes,
                CAST(d.granted_at AS TEXT) as "granted_at!: String"
            FROM account_delegations d
            JOIN users u ON u.did = d.delegated_did
            WHERE d.controller_did = $1
              AND d.revoked_at IS NULL
              AND u.deactivated_at IS NULL
              AND u.takedown_ref IS NULL
            ORDER BY d.granted_at DESC
            "#,
            controller_did_value
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(DelegatedAccountInfo {
                    did: column(r.did, col::USERS_DID)?,
                    handle: legacy_column(r.handle, col::USERS_HANDLE),
                    granted_scopes: DbScope::from_db(r.granted_scopes),
                    granted_at: timestamp(r.granted_at)?,
                })
            })
            .collect()
    }

    async fn count_active_controllers(&self, delegated_did: &Did) -> Result<i64, DbError> {
        let delegated_did_value = delegated_did.as_str().to_owned();
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM account_delegations d
            LEFT JOIN users u ON u.did = d.controller_did
            WHERE d.delegated_did = $1
              AND d.revoked_at IS NULL
              AND (u.did IS NULL OR (u.deactivated_at IS NULL AND u.takedown_ref IS NULL))
            "#,
            delegated_did_value
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(count)
    }

    async fn controls_any_accounts(&self, did: &Did) -> Result<bool, DbError> {
        let did_value = did.as_str().to_owned();
        let exists = sqlx::query_scalar!(
            r#"SELECT EXISTS(
                SELECT 1 FROM account_delegations
                WHERE controller_did = $1 AND revoked_at IS NULL
            ) as "exists!""#,
            did_value
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(exists != 0)
    }

    async fn log_delegation_action(
        &self,
        delegated_did: &Did,
        actor_did: &Did,
        controller_did: Option<&Did>,
        action_type: DelegationActionType,
        action_details: Option<serde_json::Value>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let action_type = match action_type {
            DelegationActionType::GrantCreated => "grant_created",
            DelegationActionType::GrantRevoked => "grant_revoked",
            DelegationActionType::ScopesModified => "scopes_modified",
            DelegationActionType::TokenIssued => "token_issued",
            DelegationActionType::RepoWrite => "repo_write",
            DelegationActionType::BlobUpload => "blob_upload",
            DelegationActionType::AccountAction => "account_action",
        };
        let delegated_did_value = delegated_did.as_str().to_owned();
        let actor_did_value = actor_did.as_str().to_owned();
        let controller_did_str = controller_did.map(|d| d.as_str().to_owned());
        let action_details_value = action_details.map(|value| value.to_string());
        let ip_address_value = ip_address.map(str::to_owned);
        let user_agent_value = user_agent.map(str::to_owned);
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO delegation_audit_log
                (delegated_did, actor_did, controller_did, action_type, action_details, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id as "id!: Vec<u8>"
            "#,
            delegated_did_value,
            actor_did_value,
            controller_did_str,
            action_type,
            action_details_value,
            ip_address_value,
            user_agent_value
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        uuid(id)
    }

    async fn get_audit_log_for_account(
        &self,
        delegated_did: &Did,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLogEntry>, DbError> {
        let delegated_did_value = delegated_did.as_str().to_owned();
        let rows = sqlx::query!(
            r#"
            SELECT
                id as "id!: Vec<u8>",
                delegated_did,
                actor_did,
                controller_did,
                CAST(action_type AS TEXT) as "action_type!: String",
                CAST(action_details AS TEXT) as "action_details: String",
                ip_address,
                user_agent,
                CAST(created_at AS TEXT) as "created_at!: String"
            FROM delegation_audit_log
            WHERE delegated_did = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            delegated_did_value,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(AuditLogEntry {
                    id: uuid(r.id)?,
                    delegated_did: column(
                        r.delegated_did,
                        col::DELEGATION_AUDIT_LOG_DELEGATED_DID,
                    )?,
                    actor_did: column(r.actor_did, col::DELEGATION_AUDIT_LOG_ACTOR_DID)?,
                    controller_did: opt_column(
                        r.controller_did,
                        col::DELEGATION_AUDIT_LOG_CONTROLLER_DID,
                    )?,
                    action_type: match r.action_type.as_str() {
                        "grant_created" => DelegationActionType::GrantCreated,
                        "grant_revoked" => DelegationActionType::GrantRevoked,
                        "scopes_modified" => DelegationActionType::ScopesModified,
                        "token_issued" => DelegationActionType::TokenIssued,
                        "repo_write" => DelegationActionType::RepoWrite,
                        "blob_upload" => DelegationActionType::BlobUpload,
                        "account_action" => DelegationActionType::AccountAction,
                        _ => return Err(DbError::Query("invalid delegation action type".into())),
                    },
                    action_details: r
                        .action_details
                        .and_then(|value| serde_json::from_str(&value).ok()),
                    ip_address: r.ip_address,
                    user_agent: r.user_agent,
                    created_at: timestamp(r.created_at)?,
                })
            })
            .collect()
    }

    async fn count_audit_log_entries(&self, delegated_did: &Did) -> Result<i64, DbError> {
        let delegated_did_value = delegated_did.as_str().to_owned();
        let count = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!" FROM delegation_audit_log WHERE delegated_did = $1"#,
            delegated_did_value
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(count)
    }
}
