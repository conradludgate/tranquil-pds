use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use sqlx::SqlitePool;
use tranquil_db_traits::{
    DbError, DeviceAccountRow, DeviceTrustInfo, OAuthRepository, OAuthSessionListItem,
    ScopePreference, TokenFamilyId, TrustedDeviceRow, TwoFactorChallenge,
};
use tranquil_oauth::{
    AuthorizationRequestParameters, AuthorizedClientData, ClientAuth, DeviceData, RequestData,
    SessionId as OAuthSessionId, TokenData,
};
use tranquil_types::{
    AuthorizationCode, ClientId, DPoPProofId, DeviceId, Did, RefreshToken, RequestId, TokenId,
};
use uuid::Uuid;

use super::col;
use super::column;
use super::map_sqlite_error;

macro_rules! sqlite_query {
    ($sql:expr $(,)?) => { sqlx::query($sql) };
    ($sql:expr, $($arg:expr),+ $(,)?) => {{
        let mut query = sqlx::query($sql);
        $(query = query.bind($arg);)*
        query
    }};
}

const REGISTRATION_FLOW_EXTENDED_EXPIRY_SECS: i64 = 600;

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, DbError> {
    serde_json::to_string(value).map_err(|e| {
        tracing::error!("JSON serialization error: {}", e);
        DbError::Serialization("Internal serialization error".to_string())
    })
}

fn from_json<T: serde::de::DeserializeOwned>(value: String) -> Result<T, DbError> {
    serde_json::from_str(&value).map_err(|e| {
        tracing::error!("JSON deserialization error: {}", e);
        DbError::Serialization("Internal data corruption".to_string())
    })
}

pub struct SqliteOAuthRepository {
    pool: SqlitePool,
}

impl SqliteOAuthRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn parse_timestamp(value: String) -> Result<DateTime<Utc>, DbError> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| DbError::Other(format!("invalid SQLite timestamp: {error}")))
}

fn parse_optional_timestamp(value: Option<String>) -> Result<Option<DateTime<Utc>>, DbError> {
    value.map(parse_timestamp).transpose()
}

fn parse_i32(value: i64) -> Result<i32, DbError> {
    value
        .try_into()
        .map_err(|error| DbError::Other(format!("SQLite integer out of range: {error}")))
}

fn query_arg<T>(value: T) -> T {
    value
}

fn query_str(value: &str) -> String {
    value.to_owned()
}

fn parse_uuid(value: Vec<u8>) -> Result<Uuid, DbError> {
    Uuid::from_slice(&value)
        .map_err(|error| DbError::Other(format!("invalid SQLite UUID: {error}")))
}

const REFRESH_GRACE_PERIOD_SECS: i64 = 60;

#[async_trait]
impl OAuthRepository for SqliteOAuthRepository {
    async fn create_token(&self, data: &TokenData) -> Result<TokenFamilyId, DbError> {
        let client_auth_json = to_json(&data.client_auth)?;
        let parameters_json = to_json(&data.parameters)?;
        let did = data.did.to_string();
        let token_id = data.token_id.to_string();
        let client_id = data.client_id.to_string();
        let device_id = data.device_id.as_ref().map(|value| value.to_string());
        let code = data.code.as_ref().map(|value| value.to_string());
        let current_refresh_token = data
            .current_refresh_token
            .as_ref()
            .map(|value| value.to_string());
        let controller_did = data.controller_did.as_ref().map(|value| value.to_string());
        let device_id_ref = device_id.as_deref();
        let code_ref = code.as_deref();
        let current_refresh_token_ref = current_refresh_token.as_deref();
        let controller_did_ref = controller_did.as_deref();
        let row = sqlx::query_unchecked!(
            r#"
            INSERT INTO oauth_token
                (did, token_id, created_at, updated_at, expires_at, client_id, client_auth,
                 device_id, parameters, details, code, current_refresh_token, scope, controller_did)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING id
            "#,
            did,
            token_id,
            data.created_at,
            data.updated_at,
            data.expires_at,
            client_id,
            client_auth_json,
            device_id_ref,
            parameters_json,
            data.details,
            code_ref,
            current_refresh_token_ref,
            data.scope,
            controller_did_ref,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(TokenFamilyId::new(parse_i32(row.id.unwrap_or_default())?))
    }

    async fn get_token_by_id(&self, token_id: &TokenId) -> Result<Option<TokenData>, DbError> {
        let token_id_value = token_id.to_string();
        let row = sqlx::query_unchecked!(
            r#"
            SELECT did, token_id,
                   created_at as "created_at!: DateTime<Utc>",
                   updated_at as "updated_at!: DateTime<Utc>",
                   expires_at as "expires_at!: DateTime<Utc>", client_id, client_auth,
                   device_id, parameters, details, code, current_refresh_token, scope, controller_did
            FROM oauth_token
            WHERE token_id = $1
            "#,
            token_id_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        match row {
            Some(r) => Ok(Some(TokenData {
                did: r
                    .did
                    .parse()
                    .map_err(|_| DbError::InvalidColumn(col::OAUTH_TOKEN_DID))?,
                token_id: TokenId::from(r.token_id),
                created_at: r.created_at,
                updated_at: r.updated_at,
                expires_at: r.expires_at,
                client_id: ClientId::from(r.client_id),
                client_auth: from_json(r.client_auth)?,
                device_id: r.device_id.map(DeviceId::from),
                parameters: from_json(r.parameters)?,
                details: r.details.map(from_json).transpose()?,
                code: r.code.map(AuthorizationCode::from),
                current_refresh_token: r.current_refresh_token.map(RefreshToken::from),
                scope: r.scope,
                controller_did: r
                    .controller_did
                    .map(|s| s.parse())
                    .transpose()
                    .map_err(|_| DbError::InvalidColumn(col::OAUTH_TOKEN_CONTROLLER_DID))?,
            })),
            None => Ok(None),
        }
    }

    async fn get_token_by_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<(TokenFamilyId, TokenData)>, DbError> {
        let refresh_token_value = refresh_token.to_string();
        let row = sqlx::query_unchecked!(
            r#"
            SELECT id, did, token_id,
                   created_at as "created_at!: DateTime<Utc>",
                   updated_at as "updated_at!: DateTime<Utc>",
                   expires_at as "expires_at!: DateTime<Utc>", client_id, client_auth,
                   device_id, parameters, details, code, current_refresh_token, scope, controller_did
            FROM oauth_token
            WHERE current_refresh_token = $1
            "#,
            refresh_token_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        match row {
            Some(r) => Ok(Some((
                TokenFamilyId::new(parse_i32(r.id.unwrap_or_default())?),
                TokenData {
                    did: r
                        .did
                        .parse()
                        .map_err(|_| DbError::InvalidColumn(col::OAUTH_TOKEN_DID))?,
                    token_id: TokenId::from(r.token_id),
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                    expires_at: r.expires_at,
                    client_id: ClientId::from(r.client_id),
                    client_auth: from_json(r.client_auth)?,
                    device_id: r.device_id.map(DeviceId::from),
                    parameters: from_json(r.parameters)?,
                    details: r.details.map(from_json).transpose()?,
                    code: r.code.map(AuthorizationCode::from),
                    current_refresh_token: r.current_refresh_token.map(RefreshToken::from),
                    scope: r.scope,
                    controller_did: r
                        .controller_did
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|_| DbError::InvalidColumn(col::OAUTH_TOKEN_CONTROLLER_DID))?,
                },
            ))),
            None => Ok(None),
        }
    }

    async fn get_token_by_previous_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<(TokenFamilyId, TokenData)>, DbError> {
        let grace_cutoff = Utc::now() - Duration::seconds(REFRESH_GRACE_PERIOD_SECS);
        let refresh_token_value = refresh_token.to_string();
        let row = sqlx::query_unchecked!(
            r#"
            SELECT id, did, token_id,
                   created_at as "created_at!: DateTime<Utc>",
                   updated_at as "updated_at!: DateTime<Utc>",
                   expires_at as "expires_at!: DateTime<Utc>", client_id, client_auth,
                   device_id, parameters, details, code, current_refresh_token, scope, controller_did
            FROM oauth_token
            WHERE previous_refresh_token = $1 AND rotated_at > $2
            "#,
            refresh_token_value,
            grace_cutoff
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        match row {
            Some(r) => Ok(Some((
                TokenFamilyId::new(parse_i32(r.id)?),
                TokenData {
                    did: r
                        .did
                        .parse()
                        .map_err(|_| DbError::InvalidColumn(col::OAUTH_TOKEN_DID))?,
                    token_id: TokenId::from(r.token_id),
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                    expires_at: r.expires_at,
                    client_id: ClientId::from(r.client_id),
                    client_auth: from_json(r.client_auth)?,
                    device_id: r.device_id.map(DeviceId::from),
                    parameters: from_json(r.parameters)?,
                    details: r.details.map(from_json).transpose()?,
                    code: r.code.map(AuthorizationCode::from),
                    current_refresh_token: r.current_refresh_token.map(RefreshToken::from),
                    scope: r.scope,
                    controller_did: r
                        .controller_did
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|_| DbError::InvalidColumn(col::OAUTH_TOKEN_CONTROLLER_DID))?,
                },
            ))),
            None => Ok(None),
        }
    }

    async fn rotate_token(
        &self,
        old_db_id: TokenFamilyId,
        new_refresh_token: &RefreshToken,
        new_expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;
        let old_id = old_db_id.as_i32();
        let old_refresh = sqlx::query_scalar_unchecked!(
            r#"
            SELECT current_refresh_token FROM oauth_token WHERE id = $1
            "#,
            old_id
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;
        if let Some(ref old_rt) = old_refresh {
            sqlite_query!(
                r#"
                INSERT INTO oauth_used_refresh_token (refresh_token, token_id)
                VALUES ($1, $2)
                "#,
                old_rt,
                query_arg(old_db_id.as_i32())
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        }
        sqlite_query!(
            r#"
            UPDATE oauth_token
            SET current_refresh_token = $2, expires_at = $3, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                previous_refresh_token = $4, rotated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE id = $1
            "#,
            query_arg(old_db_id.as_i32()),
            query_str(new_refresh_token.as_str()),
            new_expires_at,
            old_refresh
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;
        tx.commit().await.map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn check_refresh_token_used(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<TokenFamilyId>, DbError> {
        let refresh_token_value = refresh_token.to_string();
        let row = sqlx::query_scalar_unchecked!(
            r#"
            SELECT token_id FROM oauth_used_refresh_token WHERE refresh_token = $1
            "#,
            refresh_token_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(row.map(parse_i32).transpose()?.map(TokenFamilyId::new))
    }

    async fn delete_token(&self, token_id: &TokenId) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            DELETE FROM oauth_token WHERE token_id = $1
            "#,
            query_str(token_id.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn delete_token_family(&self, db_id: TokenFamilyId) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            DELETE FROM oauth_token WHERE id = $1
            "#,
            query_arg(db_id.as_i32())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn list_tokens_for_user(&self, did: &Did) -> Result<Vec<TokenData>, DbError> {
        let did_value = did.to_string();
        let rows = sqlx::query_unchecked!(
            r#"
            SELECT did, token_id,
                   created_at as "created_at!: DateTime<Utc>",
                   updated_at as "updated_at!: DateTime<Utc>",
                   expires_at as "expires_at!: DateTime<Utc>", client_id, client_auth,
                   device_id, parameters, details, code, current_refresh_token, scope, controller_did
            FROM oauth_token
            WHERE did = $1
            "#,
            did_value
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        rows.into_iter()
            .map(|r| {
                Ok(TokenData {
                    did: r
                        .did
                        .parse()
                        .map_err(|_| DbError::InvalidColumn(col::OAUTH_TOKEN_DID))?,
                    token_id: TokenId::from(r.token_id),
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                    expires_at: r.expires_at,
                    client_id: ClientId::from(r.client_id),
                    client_auth: from_json(r.client_auth)?,
                    device_id: r.device_id.map(DeviceId::from),
                    parameters: from_json(r.parameters)?,
                    details: r.details.map(from_json).transpose()?,
                    code: r.code.map(AuthorizationCode::from),
                    current_refresh_token: r.current_refresh_token.map(RefreshToken::from),
                    scope: r.scope,
                    controller_did: r
                        .controller_did
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|_| DbError::InvalidColumn(col::OAUTH_TOKEN_CONTROLLER_DID))?,
                })
            })
            .collect()
    }

    async fn count_tokens_for_user(&self, did: &Did) -> Result<i64, DbError> {
        let did_value = did.to_string();
        let count = sqlx::query_scalar_unchecked!(
            r#"
            SELECT COUNT(*) as "count!" FROM oauth_token WHERE did = $1
            "#,
            did_value
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(count)
    }

    async fn delete_oldest_tokens_for_user(
        &self,
        did: &Did,
        keep_count: i64,
    ) -> Result<u64, DbError> {
        let result = sqlite_query!(
            r#"
            DELETE FROM oauth_token
            WHERE id IN (
                SELECT id FROM oauth_token
                WHERE did = $1
                ORDER BY created_at DESC
                LIMIT -1 OFFSET $2
            )
            "#,
            query_str(did.as_str()),
            keep_count
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected())
    }

    async fn revoke_tokens_for_client(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<u64, DbError> {
        let result = sqlite_query!(
            "DELETE FROM oauth_token WHERE did = $1 AND client_id = $2",
            query_str(did.as_str()),
            query_str(client_id.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected())
    }

    async fn revoke_tokens_for_controller(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
    ) -> Result<u64, DbError> {
        let result = sqlite_query!(
            "DELETE FROM oauth_token WHERE did = $1 AND controller_did = $2",
            query_str(delegated_did.as_str()),
            query_str(controller_did.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected())
    }

    async fn create_authorization_request(
        &self,
        request_id: &RequestId,
        data: &RequestData,
    ) -> Result<(), DbError> {
        let client_auth_json = match &data.client_auth {
            Some(ca) => Some(to_json(ca)?),
            None => None,
        };
        let parameters_json = to_json(&data.parameters)?;
        sqlite_query!(
            r#"
            INSERT INTO oauth_authorization_request
                (id, did, device_id, client_id, client_auth, parameters, expires_at, code)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            query_str(request_id.as_str()),
            data.did.as_ref().map(|d| d.as_str()),
            data.device_id.as_ref().map(|v| query_str(v)),
            data.client_id.as_str(),
            client_auth_json,
            parameters_json,
            data.expires_at,
            data.code.as_ref().map(|v| query_str(v)),
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_authorization_request(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<RequestData>, DbError> {
        let request_id_value = request_id.to_string();
        let row = sqlx::query_unchecked!(
            r#"
            SELECT did, device_id, client_id, client_auth, parameters, expires_at, code, controller_did
            FROM oauth_authorization_request
            WHERE id = $1
            "#,
            request_id_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        match row {
            Some(r) => {
                let client_auth: Option<ClientAuth> = match r.client_auth {
                    Some(v) => Some(from_json(v)?),
                    None => None,
                };
                let parameters: AuthorizationRequestParameters = from_json(r.parameters)?;
                Ok(Some(RequestData {
                    client_id: ClientId::from(r.client_id),
                    client_auth,
                    parameters,
                    expires_at: parse_timestamp(r.expires_at)?,
                    did: r.did.map(|s| s.parse()).transpose().map_err(|_| {
                        DbError::InvalidColumn(col::OAUTH_AUTHORIZATION_REQUEST_DID)
                    })?,
                    device_id: r.device_id.map(DeviceId::from),
                    code: r.code.map(AuthorizationCode::from),
                    controller_did: r.controller_did.map(|s| s.parse()).transpose().map_err(
                        |_| DbError::InvalidColumn(col::OAUTH_AUTHORIZATION_REQUEST_CONTROLLER_DID),
                    )?,
                }))
            }
            None => Ok(None),
        }
    }

    async fn set_authorization_did(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
    ) -> Result<(), DbError> {
        let extended_expiry =
            chrono::Utc::now() + chrono::Duration::seconds(REGISTRATION_FLOW_EXTENDED_EXPIRY_SECS);
        sqlite_query!(
            r#"
            UPDATE oauth_authorization_request
            SET did = $2, device_id = $3, expires_at = $4
            WHERE id = $1
            "#,
            query_str(request_id.as_str()),
            query_str(did.as_str()),
            device_id.map(|d| d.as_str()),
            extended_expiry
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn update_authorization_request(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
        code: &AuthorizationCode,
    ) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            UPDATE oauth_authorization_request
            SET did = $2, device_id = $3, code = $4
            WHERE id = $1
            "#,
            query_str(request_id.as_str()),
            query_str(did.as_str()),
            device_id.map(|d| d.as_str()),
            query_str(code)
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn consume_authorization_request_by_code(
        &self,
        code: &AuthorizationCode,
    ) -> Result<Option<RequestData>, DbError> {
        let code_value = code.to_string();
        let row = sqlx::query_unchecked!(
            r#"
            DELETE FROM oauth_authorization_request
            WHERE code = $1
            RETURNING did, device_id, client_id, client_auth, parameters, expires_at, code, controller_did
            "#,
            code_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        match row {
            Some(r) => {
                let client_auth: Option<ClientAuth> = match r.client_auth {
                    Some(v) => Some(from_json(v)?),
                    None => None,
                };
                let parameters: AuthorizationRequestParameters = from_json(r.parameters)?;
                Ok(Some(RequestData {
                    client_id: ClientId::from(r.client_id),
                    client_auth,
                    parameters,
                    expires_at: parse_timestamp(r.expires_at)?,
                    did: r.did.map(|s| s.parse()).transpose().map_err(|_| {
                        DbError::InvalidColumn(col::OAUTH_AUTHORIZATION_REQUEST_DID)
                    })?,
                    device_id: r.device_id.map(DeviceId::from),
                    code: r.code.map(AuthorizationCode::from),
                    controller_did: r.controller_did.map(|s| s.parse()).transpose().map_err(
                        |_| DbError::InvalidColumn(col::OAUTH_AUTHORIZATION_REQUEST_CONTROLLER_DID),
                    )?,
                }))
            }
            None => Ok(None),
        }
    }

    async fn delete_authorization_request(&self, request_id: &RequestId) -> Result<(), DbError> {
        let request_id_value = request_id.to_string();
        sqlite_query!(
            r#"
            DELETE FROM oauth_authorization_request WHERE id = $1
            "#,
            request_id_value
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn delete_expired_authorization_requests(&self) -> Result<u64, DbError> {
        let result = sqlite_query!(
            r#"
            DELETE FROM oauth_authorization_request
            WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            "#
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected())
    }

    async fn extend_authorization_request_expiry(
        &self,
        request_id: &RequestId,
        new_expires_at: DateTime<Utc>,
    ) -> Result<bool, DbError> {
        let result = sqlite_query!(
            r#"
            UPDATE oauth_authorization_request
            SET expires_at = $2
            WHERE id = $1 AND did IS NOT NULL AND code IS NULL
            "#,
            query_str(request_id.as_str()),
            new_expires_at
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn mark_request_authenticated(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
    ) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            UPDATE oauth_authorization_request
            SET did = $2, device_id = $3
            WHERE id = $1
            "#,
            query_str(request_id.as_str()),
            query_str(did.as_str()),
            device_id.map(|d| d.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn update_request_scope(
        &self,
        request_id: &RequestId,
        scope: &str,
    ) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            UPDATE oauth_authorization_request
            SET parameters = json_set(parameters, '$.scope', $2)
            WHERE id = $1
            "#,
            query_str(request_id.as_str()),
            scope
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn set_controller_did(
        &self,
        request_id: &RequestId,
        controller_did: &Did,
    ) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            UPDATE oauth_authorization_request
            SET controller_did = $2
            WHERE id = $1
            "#,
            query_str(request_id.as_str()),
            query_str(controller_did.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn set_request_did(&self, request_id: &RequestId, did: &Did) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            UPDATE oauth_authorization_request
            SET did = $2
            WHERE id = $1
            "#,
            query_str(request_id.as_str()),
            query_str(did.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn create_device(&self, device_id: &DeviceId, data: &DeviceData) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            INSERT INTO oauth_device (id, session_id, user_agent, ip_address, last_seen_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            query_str(device_id.as_str()),
            query_str(data.session_id.as_str()),
            data.user_agent.clone(),
            data.ip_address.clone(),
            data.last_seen_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_device(&self, device_id: &DeviceId) -> Result<Option<DeviceData>, DbError> {
        let device_id_value = device_id.to_string();
        let row = sqlx::query_unchecked!(
            r#"
            SELECT session_id, user_agent, ip_address, last_seen_at
            FROM oauth_device
            WHERE id = $1
            "#,
            device_id_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(DeviceData {
                session_id: OAuthSessionId::from(r.session_id),
                user_agent: r.user_agent,
                ip_address: r.ip_address,
                last_seen_at: parse_timestamp(r.last_seen_at)?,
            })
        })
        .transpose()
    }

    async fn update_device_last_seen(&self, device_id: &DeviceId) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            UPDATE oauth_device
            SET last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE id = $1
            "#,
            query_str(device_id.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn delete_device(&self, device_id: &DeviceId) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            DELETE FROM oauth_device WHERE id = $1
            "#,
            query_str(device_id.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn upsert_account_device(&self, did: &Did, device_id: &DeviceId) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            INSERT INTO oauth_account_device (did, device_id, created_at, updated_at)
            VALUES ($1, $2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            ON CONFLICT (did, device_id) DO UPDATE SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            "#,
            query_str(did.as_str()),
            query_str(device_id.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_device_accounts(
        &self,
        device_id: &DeviceId,
    ) -> Result<Vec<DeviceAccountRow>, DbError> {
        let device_id_value = device_id.to_string();
        let rows = sqlx::query_unchecked!(
            r#"
            SELECT u.did, u.handle, u.email, ad.updated_at as last_used_at
            FROM oauth_account_device ad
            JOIN users u ON u.did = ad.did
            WHERE ad.device_id = $1
              AND u.deactivated_at IS NULL
              AND u.takedown_ref IS NULL
            ORDER BY ad.updated_at DESC
            "#,
            device_id_value
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        rows.into_iter()
            .map(|r| {
                Ok(DeviceAccountRow {
                    did: column(r.did, col::USERS_DID)?,
                    handle: column(r.handle, col::USERS_HANDLE)?,
                    email: r.email,
                    last_used_at: parse_timestamp(r.last_used_at)?,
                })
            })
            .collect()
    }

    async fn verify_account_on_device(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<bool, DbError> {
        let device_id_value = device_id.to_string();
        let did_value = did.to_string();
        let row = sqlx::query_unchecked!(
            r#"
            SELECT 1 as "exists!: i64"
            FROM oauth_account_device ad
            JOIN users u ON u.did = ad.did
            WHERE ad.device_id = $1
              AND ad.did = $2
              AND u.deactivated_at IS NULL
              AND u.takedown_ref IS NULL
            "#,
            device_id_value,
            did_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(row.is_some())
    }

    async fn check_and_record_dpop_jti(&self, jti: &DPoPProofId) -> Result<bool, DbError> {
        let result = sqlite_query!(
            r#"
            INSERT INTO oauth_dpop_jti (jti)
            VALUES ($1)
            ON CONFLICT (jti) DO NOTHING
            "#,
            query_str(jti.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn cleanup_expired_dpop_jtis(&self, max_age_secs: i64) -> Result<u64, DbError> {
        let result = sqlite_query!(
            r#"
            DELETE FROM oauth_dpop_jti
            WHERE created_at < datetime('now', printf('-%d seconds', $1))
            "#,
            query_arg(max_age_secs as f64)
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected())
    }

    async fn create_2fa_challenge(
        &self,
        did: &Did,
        request_uri: &RequestId,
    ) -> Result<TwoFactorChallenge, DbError> {
        let code = {
            let mut rng = rand::thread_rng();
            let code_num: u32 = rng.gen_range(0..1_000_000);
            format!("{:06}", code_num)
        };
        let expires_at = Utc::now() + Duration::minutes(10);
        let did_value = did.to_string();
        let request_uri_value = request_uri.to_string();
        let row = sqlx::query_unchecked!(
            r#"
            INSERT INTO oauth_2fa_challenge (did, request_uri, code, expires_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, did, request_uri, code, attempts, created_at, expires_at
            "#,
            did_value,
            request_uri_value,
            code,
            expires_at,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(TwoFactorChallenge {
            id: parse_uuid(row.id.unwrap_or_default())?,
            did: column(row.did, col::OAUTH_2FA_CHALLENGE_DID)?,
            request_uri: RequestId::from(row.request_uri),
            code: row.code,
            attempts: parse_i32(row.attempts)?,
            created_at: parse_timestamp(row.created_at)?,
            expires_at: parse_timestamp(row.expires_at)?,
        })
    }

    async fn get_2fa_challenge(
        &self,
        request_uri: &RequestId,
    ) -> Result<Option<TwoFactorChallenge>, DbError> {
        let request_uri_value = request_uri.to_string();
        let row = sqlx::query_unchecked!(
            r#"
            SELECT id, did, request_uri, code, attempts, created_at, expires_at
            FROM oauth_2fa_challenge
            WHERE request_uri = $1
            "#,
            request_uri_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(TwoFactorChallenge {
                id: parse_uuid(r.id.unwrap_or_default())?,
                did: column(r.did, col::OAUTH_2FA_CHALLENGE_DID)?,
                request_uri: RequestId::from(r.request_uri),
                code: r.code,
                attempts: parse_i32(r.attempts)?,
                created_at: parse_timestamp(r.created_at)?,
                expires_at: parse_timestamp(r.expires_at)?,
            })
        })
        .transpose()
    }

    async fn increment_2fa_attempts(&self, id: Uuid) -> Result<i32, DbError> {
        let row = sqlx::query_unchecked!(
            r#"
            UPDATE oauth_2fa_challenge
            SET attempts = attempts + 1
            WHERE id = $1
            RETURNING attempts
            "#,
            id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(parse_i32(row.attempts)?)
    }

    async fn delete_2fa_challenge(&self, id: Uuid) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            DELETE FROM oauth_2fa_challenge WHERE id = $1
            "#,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn delete_2fa_challenge_by_request_uri(
        &self,
        request_uri: &RequestId,
    ) -> Result<(), DbError> {
        let request_uri_value = request_uri.to_string();
        sqlite_query!(
            r#"
            DELETE FROM oauth_2fa_challenge WHERE request_uri = $1
            "#,
            request_uri_value
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn cleanup_expired_2fa_challenges(&self) -> Result<u64, DbError> {
        let result = sqlite_query!(
            r#"
            DELETE FROM oauth_2fa_challenge WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            "#
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected())
    }

    async fn check_user_2fa_enabled(&self, did: &Did) -> Result<bool, DbError> {
        let did_value = did.to_string();
        let row = sqlx::query_unchecked!(
            r#"
            SELECT two_factor_enabled
            FROM users
            WHERE did = $1
            "#,
            did_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(row.map(|r| r.two_factor_enabled != 0).unwrap_or(false))
    }

    async fn get_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<Vec<ScopePreference>, DbError> {
        let did_value = did.to_string();
        let client_id_value = client_id.to_string();
        let rows = sqlx::query_unchecked!(
            r#"
            SELECT scope, granted FROM oauth_scope_preference
            WHERE did = $1 AND client_id = $2
            "#,
            did_value,
            client_id_value
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(rows
            .into_iter()
            .map(|r| ScopePreference {
                scope: r.scope,
                granted: r.granted != 0,
            })
            .collect())
    }

    async fn upsert_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
        prefs: &[ScopePreference],
    ) -> Result<(), DbError> {
        for pref in prefs {
            sqlite_query!(
                r#"
                INSERT INTO oauth_scope_preference (did, client_id, scope, granted, created_at, updated_at)
                VALUES ($1, $2, $3, $4, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                ON CONFLICT (did, client_id, scope) DO UPDATE SET granted = $4, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                "#,
                query_str(did.as_str()),
                query_str(client_id.as_str()),
                pref.scope.clone(),
                pref.granted
            )
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;
        }
        Ok(())
    }

    async fn delete_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<(), DbError> {
        sqlite_query!(
            r#"
            DELETE FROM oauth_scope_preference
            WHERE did = $1 AND client_id = $2
            "#,
            query_str(did.as_str()),
            query_str(client_id.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn upsert_authorized_client(
        &self,
        did: &Did,
        client_id: &ClientId,
        data: &AuthorizedClientData,
    ) -> Result<(), DbError> {
        let data_json = to_json(data)?;
        sqlite_query!(
            r#"
            INSERT INTO oauth_authorized_client (did, client_id, created_at, updated_at, data)
            VALUES ($1, $2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), $3)
            ON CONFLICT (did, client_id) DO UPDATE SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), data = $3
            "#,
            query_str(did.as_str()),
            query_str(client_id.as_str()),
            data_json
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_authorized_client(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<Option<AuthorizedClientData>, DbError> {
        let did_value = did.to_string();
        let client_id_value = client_id.to_string();
        let row = sqlx::query_scalar_unchecked!(
            r#"
            SELECT data FROM oauth_authorized_client
            WHERE did = $1 AND client_id = $2
            "#,
            did_value,
            client_id_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        match row {
            Some(v) => Ok(Some(from_json(v)?)),
            None => Ok(None),
        }
    }

    async fn list_trusted_devices(&self, did: &Did) -> Result<Vec<TrustedDeviceRow>, DbError> {
        let did_value = did.to_string();
        let rows = sqlx::query_unchecked!(
            r#"SELECT od.id, od.user_agent, od.friendly_name, od.trusted_at, od.trusted_until, od.last_seen_at
               FROM oauth_device od
               JOIN oauth_account_device oad ON od.id = oad.device_id
               WHERE oad.did = $1 AND od.trusted_until IS NOT NULL AND od.trusted_until > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
               ORDER BY od.last_seen_at DESC"#,
            did_value
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(TrustedDeviceRow {
                    id: DeviceId::from(r.id.unwrap_or_default()),
                    user_agent: r.user_agent,
                    friendly_name: r.friendly_name,
                    trusted_at: parse_optional_timestamp(r.trusted_at)?,
                    trusted_until: parse_optional_timestamp(r.trusted_until)?,
                    last_seen_at: parse_timestamp(r.last_seen_at)?,
                })
            })
            .collect()
    }

    async fn get_device_trust_info(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<Option<DeviceTrustInfo>, DbError> {
        let device_id_value = device_id.to_string();
        let did_value = did.to_string();
        let row = sqlx::query_unchecked!(
            r#"SELECT trusted_at, trusted_until FROM oauth_device od
               JOIN oauth_account_device oad ON od.id = oad.device_id
               WHERE od.id = $1 AND oad.did = $2"#,
            device_id_value,
            did_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(DeviceTrustInfo {
                trusted_at: parse_optional_timestamp(r.trusted_at)?,
                trusted_until: parse_optional_timestamp(r.trusted_until)?,
            })
        })
        .transpose()
    }

    async fn device_belongs_to_user(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<bool, DbError> {
        let did_value = did.to_string();
        let device_id_value = device_id.to_string();
        let exists = sqlx::query_scalar_unchecked!(
            r#"SELECT 1 as "one!: i64" FROM oauth_device od
               JOIN oauth_account_device oad ON od.id = oad.device_id
               WHERE oad.did = $1 AND od.id = $2"#,
            did_value,
            device_id_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(exists.is_some())
    }

    async fn revoke_device_trust(&self, device_id: &DeviceId, _did: &Did) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE oauth_device SET trusted_at = NULL, trusted_until = NULL WHERE id = $1",
            query_str(device_id.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn update_device_friendly_name(
        &self,
        device_id: &DeviceId,
        _did: &Did,
        friendly_name: Option<&str>,
    ) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE oauth_device SET friendly_name = $1 WHERE id = $2",
            friendly_name,
            query_str(device_id.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn trust_device(
        &self,
        device_id: &DeviceId,
        _did: &Did,
        trusted_at: DateTime<Utc>,
        trusted_until: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE oauth_device SET trusted_at = $1, trusted_until = $2 WHERE id = $3",
            trusted_at,
            trusted_until,
            query_str(device_id.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn extend_device_trust(
        &self,
        device_id: &DeviceId,
        _did: &Did,
        trusted_until: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE oauth_device SET trusted_until = $1 WHERE id = $2 AND trusted_until IS NOT NULL",
            trusted_until,
            query_str(device_id.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn list_sessions_by_did(&self, did: &Did) -> Result<Vec<OAuthSessionListItem>, DbError> {
        let did_value = did.to_string();
        let rows = sqlx::query_unchecked!(
            r#"
            SELECT id, token_id, created_at, expires_at, client_id
            FROM oauth_token
            WHERE did = $1 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            ORDER BY created_at DESC
            "#,
            did_value
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(OAuthSessionListItem {
                    id: TokenFamilyId::new(parse_i32(r.id.unwrap_or_default())?),
                    token_id: TokenId::from(r.token_id),
                    created_at: parse_timestamp(r.created_at)?,
                    expires_at: parse_timestamp(r.expires_at)?,
                    client_id: ClientId::from(r.client_id),
                })
            })
            .collect()
    }

    async fn delete_session_by_id(
        &self,
        session_id: TokenFamilyId,
        did: &Did,
    ) -> Result<u64, DbError> {
        let result = sqlite_query!(
            "DELETE FROM oauth_token WHERE id = $1 AND did = $2",
            query_arg(session_id.as_i32()),
            query_str(did.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected())
    }

    async fn delete_sessions_by_did(&self, did: &Did) -> Result<u64, DbError> {
        let result = sqlite_query!(
            "DELETE FROM oauth_token WHERE did = $1",
            query_str(did.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected())
    }

    async fn delete_sessions_by_did_except(
        &self,
        did: &Did,
        except_token_id: &TokenId,
    ) -> Result<u64, DbError> {
        let result = sqlite_query!(
            "DELETE FROM oauth_token WHERE did = $1 AND token_id != $2",
            query_str(did.as_str()),
            query_str(except_token_id.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected())
    }

    async fn get_2fa_challenge_code(
        &self,
        request_uri: &RequestId,
    ) -> Result<Option<String>, DbError> {
        let request_uri_value = request_uri.to_string();
        let code = sqlx::query_scalar_unchecked!(
            "SELECT code FROM oauth_2fa_challenge WHERE request_uri = $1",
            request_uri_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(code)
    }
}
