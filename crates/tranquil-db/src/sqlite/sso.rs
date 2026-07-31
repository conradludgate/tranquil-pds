use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use tranquil_db_traits::{
    DbError, ExternalEmail, ExternalIdentity, ExternalUserId, ExternalUsername, SsoAction,
    SsoAuthState, SsoPendingRegistration, SsoProviderType, SsoRepository,
};
use tranquil_types::Did;
use uuid::Uuid;

use super::map_sqlite_error;

fn parse_timestamp(value: String) -> Result<DateTime<Utc>, DbError> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| DbError::CorruptData("timestamp"))
}

fn parse_optional_timestamp(value: Option<String>) -> Result<Option<DateTime<Utc>>, DbError> {
    value.map(parse_timestamp).transpose()
}

fn parse_uuid(value: Vec<u8>) -> Result<Uuid, DbError> {
    Uuid::from_slice(&value).map_err(|_| DbError::CorruptData("uuid"))
}

pub struct SqliteSsoRepository {
    pool: SqlitePool,
}

impl SqliteSsoRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SsoRepository for SqliteSsoRepository {
    async fn create_external_identity(
        &self,
        did: &Did,
        provider: SsoProviderType,
        provider_user_id: &str,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let did_value = did.as_str().to_owned();
        let provider_value = provider;
        let provider_db = provider_value as SsoProviderType;
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO external_identities (did, provider, provider_user_id, provider_username, provider_email)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id as "id!: Vec<u8>"
            "#,
            did_value,
            provider_db,
            provider_user_id,
            provider_username,
            provider_email,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        parse_uuid(id)
    }

    async fn get_external_identity_by_provider(
        &self,
        provider: SsoProviderType,
        provider_user_id: &str,
    ) -> Result<Option<ExternalIdentity>, DbError> {
        let provider_value = provider;
        let provider_db = provider_value as SsoProviderType;
        let row = sqlx::query!(
            r#"
            SELECT id as "id!: Vec<u8>", did, provider as "provider: SsoProviderType", provider_user_id,
                   provider_username, provider_email,
                   CAST(created_at AS TEXT) as "created_at!: String",
                   CAST(updated_at AS TEXT) as "updated_at!: String",
                   CAST(last_login_at AS TEXT) as "last_login_at: String"
            FROM external_identities
            WHERE provider = $1 AND provider_user_id = $2
            "#,
            provider_db,
            provider_user_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(ExternalIdentity {
                id: parse_uuid(r.id)?,
                did: r.did.parse().map_err(|_| DbError::CorruptData("DID"))?,
                provider: r.provider,
                provider_user_id: ExternalUserId::from(r.provider_user_id),
                provider_username: r.provider_username.map(ExternalUsername::from),
                provider_email: r.provider_email.map(ExternalEmail::from),
                created_at: parse_timestamp(r.created_at)?,
                updated_at: parse_timestamp(r.updated_at)?,
                last_login_at: parse_optional_timestamp(r.last_login_at)?,
            })
        })
        .transpose()
    }

    async fn get_external_identities_by_did(
        &self,
        did: &Did,
    ) -> Result<Vec<ExternalIdentity>, DbError> {
        let did_value = did.as_str().to_owned();
        let rows = sqlx::query!(
            r#"
            SELECT id as "id!: Vec<u8>", did, provider as "provider: SsoProviderType", provider_user_id,
                   provider_username, provider_email,
                   CAST(created_at AS TEXT) as "created_at!: String",
                   CAST(updated_at AS TEXT) as "updated_at!: String",
                   CAST(last_login_at AS TEXT) as "last_login_at: String"
            FROM external_identities
            WHERE did = $1
            ORDER BY created_at ASC
            "#,
            did_value,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(ExternalIdentity {
                    id: parse_uuid(r.id)?,
                    did: r.did.parse().map_err(|_| DbError::CorruptData("DID"))?,
                    provider: r.provider,
                    provider_user_id: ExternalUserId::from(r.provider_user_id),
                    provider_username: r.provider_username.map(ExternalUsername::from),
                    provider_email: r.provider_email.map(ExternalEmail::from),
                    created_at: parse_timestamp(r.created_at)?,
                    updated_at: parse_timestamp(r.updated_at)?,
                    last_login_at: parse_optional_timestamp(r.last_login_at)?,
                })
            })
            .collect()
    }

    async fn update_external_identity_login(
        &self,
        id: Uuid,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            UPDATE external_identities
            SET provider_username = COALESCE($2, provider_username),
                provider_email = COALESCE($3, provider_email),
                last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE id = $1
            "#,
            id,
            provider_username,
            provider_email,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn delete_external_identity(&self, id: Uuid, did: &Did) -> Result<bool, DbError> {
        let did_value = did.as_str().to_owned();
        let result = sqlx::query!(
            r#"
            DELETE FROM external_identities
            WHERE id = $1 AND did = $2
            "#,
            id,
            did_value,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn create_sso_auth_state(
        &self,
        state: &str,
        request_uri: &str,
        provider: SsoProviderType,
        action: SsoAction,
        nonce: Option<&str>,
        code_verifier: Option<&str>,
        did: Option<&Did>,
    ) -> Result<(), DbError> {
        let action_value = action.as_str().to_owned();
        let did_value = did.map(|value| value.as_str().to_owned());
        let provider_value = provider;
        let provider_db = provider_value as SsoProviderType;
        sqlx::query!(
            r#"
            INSERT INTO sso_auth_state (state, request_uri, provider, action, nonce, code_verifier, did)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            state,
            request_uri,
            provider_db,
            action_value,
            nonce,
            code_verifier,
            did_value,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn consume_sso_auth_state(&self, state: &str) -> Result<Option<SsoAuthState>, DbError> {
        let row = sqlx::query!(
            r#"
            DELETE FROM sso_auth_state
            WHERE state = $1 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            RETURNING state, request_uri, provider as "provider: SsoProviderType", action,
                      nonce, code_verifier, did,
                      CAST(created_at AS TEXT) as "created_at!: String",
                      CAST(expires_at AS TEXT) as "expires_at!: String"
            "#,
            state,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            let action: SsoAction = r
                .action
                .parse()
                .map_err(|_| DbError::CorruptData("sso_action"))?;
            Ok(SsoAuthState {
                state: r.state.unwrap_or_default(),
                request_uri: r.request_uri,
                provider: r.provider,
                action,
                nonce: r.nonce,
                code_verifier: r.code_verifier,
                did: r
                    .did
                    .map(|d| d.parse::<Did>())
                    .transpose()
                    .map_err(|_| DbError::CorruptData("DID"))?,
                created_at: parse_timestamp(r.created_at)?,
                expires_at: parse_timestamp(r.expires_at)?,
            })
        })
        .transpose()
    }

    async fn cleanup_expired_sso_auth_states(&self) -> Result<u64, DbError> {
        let now = Utc::now();
        let result = sqlx::query!(
            r#"
            DELETE FROM sso_auth_state
            WHERE expires_at < $1
            "#,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected())
    }

    async fn create_pending_registration(
        &self,
        token: &str,
        request_uri: &str,
        provider: SsoProviderType,
        provider_user_id: &str,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
        provider_email_verified: bool,
    ) -> Result<(), DbError> {
        let provider_value = provider;
        let provider_db = provider_value as SsoProviderType;
        sqlx::query!(
            r#"
            INSERT INTO sso_pending_registration (token, request_uri, provider, provider_user_id, provider_username, provider_email, provider_email_verified)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            token,
            request_uri,
            provider_db,
            provider_user_id,
            provider_username,
            provider_email,
            provider_email_verified,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn get_pending_registration(
        &self,
        token: &str,
    ) -> Result<Option<SsoPendingRegistration>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT token, request_uri, provider as "provider: SsoProviderType",
                   provider_user_id, provider_username, provider_email, provider_email_verified,
                   CAST(created_at AS TEXT) as "created_at!: String",
                   CAST(expires_at AS TEXT) as "expires_at!: String"
            FROM sso_pending_registration
            WHERE token = $1 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            "#,
            token,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(row.map(|r| SsoPendingRegistration {
            token: r.token.unwrap_or_default(),
            request_uri: r.request_uri,
            provider: r.provider,
            provider_user_id: ExternalUserId::from(r.provider_user_id),
            provider_username: r.provider_username.map(ExternalUsername::from),
            provider_email: r.provider_email.map(ExternalEmail::from),
            provider_email_verified: r.provider_email_verified != 0,
            created_at: parse_timestamp(r.created_at).unwrap_or_else(|_| Utc::now()),
            expires_at: parse_timestamp(r.expires_at).unwrap_or_else(|_| Utc::now()),
        }))
    }

    async fn consume_pending_registration(
        &self,
        token: &str,
    ) -> Result<Option<SsoPendingRegistration>, DbError> {
        let row = sqlx::query!(
            r#"
            DELETE FROM sso_pending_registration
            WHERE token = $1 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            RETURNING token, request_uri, provider as "provider: SsoProviderType",
                      provider_user_id, provider_username, provider_email, provider_email_verified,
                      CAST(created_at AS TEXT) as "created_at!: String",
                      CAST(expires_at AS TEXT) as "expires_at!: String"
            "#,
            token,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(row.map(|r| SsoPendingRegistration {
            token: r.token.unwrap_or_default(),
            request_uri: r.request_uri,
            provider: r.provider,
            provider_user_id: ExternalUserId::from(r.provider_user_id),
            provider_username: r.provider_username.map(ExternalUsername::from),
            provider_email: r.provider_email.map(ExternalEmail::from),
            provider_email_verified: r.provider_email_verified != 0,
            created_at: parse_timestamp(r.created_at).unwrap_or_else(|_| Utc::now()),
            expires_at: parse_timestamp(r.expires_at).unwrap_or_else(|_| Utc::now()),
        }))
    }

    async fn cleanup_expired_pending_registrations(&self) -> Result<u64, DbError> {
        let now = Utc::now();
        let result = sqlx::query!(
            r#"
            DELETE FROM sso_pending_registration
            WHERE expires_at < $1
            "#,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected())
    }
}
