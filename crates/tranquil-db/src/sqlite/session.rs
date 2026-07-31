use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sqlx::SqlitePool;
use tranquil_db_traits::{
    AppPasswordCreate, AppPasswordPrivilege, AppPasswordRecord, DbError, LoginType,
    REFRESH_GRACE_PERIOD_SECS, RefreshGraceLookup, RefreshGraceReplay, RefreshSessionResult,
    SessionForRefresh, SessionId, SessionListItem, SessionMfaStatus, SessionRefreshData,
    SessionRepository, SessionToken, SessionTokenCreate,
};
use tranquil_types::{Did, Jti, PasswordHash};
use uuid::Uuid;

use super::col;
use super::map_sqlite_error;
use super::{column, opt_column};

fn timestamp(value: String) -> Result<DateTime<Utc>, DbError> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| DbError::CorruptData("timestamp"))
}

fn optional_timestamp(value: Option<String>) -> Result<Option<DateTime<Utc>>, DbError> {
    value.map(timestamp).transpose()
}

fn uuid(value: Vec<u8>) -> Result<Uuid, DbError> {
    Uuid::from_slice(&value).map_err(|_| DbError::CorruptData("uuid"))
}

fn session_id(value: i64) -> Result<SessionId, DbError> {
    i32::try_from(value)
        .map(SessionId::new)
        .map_err(|_| DbError::CorruptData("session id"))
}

pub struct SqliteSessionRepository {
    pool: SqlitePool,
}

impl SqliteSessionRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for SqliteSessionRepository {
    async fn create_session(&self, data: &SessionTokenCreate) -> Result<SessionId, DbError> {
        let did = data.did.as_str().to_owned();
        let access_jti = data.access_jti.as_str().to_owned();
        let refresh_jti = data.refresh_jti.as_str().to_owned();
        let legacy_login = data.login_type.is_legacy();
        let controller_did = data
            .controller_did
            .as_ref()
            .map(|did| did.as_str().to_owned());
        let row = sqlx::query!(
            r#"
            INSERT INTO session_tokens
                (did, access_jti, refresh_jti, access_expires_at, refresh_expires_at,
                 legacy_login, mfa_verified, scope, controller_did, app_password_name)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id as "id!: i64"
            "#,
            did,
            access_jti,
            refresh_jti,
            data.access_expires_at,
            data.refresh_expires_at,
            legacy_login,
            data.mfa_verified,
            data.scope,
            controller_did,
            data.app_password_name
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        session_id(row.id)
    }

    async fn get_session_by_access_jti(
        &self,
        access_jti: &Jti,
    ) -> Result<Option<SessionToken>, DbError> {
        let access_jti_value = access_jti.as_str().to_owned();
        let row = sqlx::query!(
            r#"
            SELECT id as "id!: i64", did, access_jti, refresh_jti,
                   CAST(access_expires_at AS TEXT) as "access_expires_at!: String",
                   CAST(refresh_expires_at AS TEXT) as "refresh_expires_at!: String",
                   legacy_login, mfa_verified, scope, controller_did, app_password_name,
                   CAST(created_at AS TEXT) as "created_at!: String",
                   CAST(updated_at AS TEXT) as "updated_at!: String"
            FROM session_tokens
            WHERE access_jti = $1
            "#,
            access_jti_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(SessionToken {
                id: session_id(r.id)?,
                did: column(r.did, col::SESSION_TOKENS_DID)?,
                access_jti: Jti::from(r.access_jti),
                refresh_jti: Jti::from(r.refresh_jti),
                access_expires_at: timestamp(r.access_expires_at)?,
                refresh_expires_at: timestamp(r.refresh_expires_at)?,
                login_type: LoginType::from_legacy_flag(r.legacy_login != 0),
                mfa_verified: r.mfa_verified != 0,
                scope: r.scope,
                controller_did: opt_column(r.controller_did, col::SESSION_TOKENS_CONTROLLER_DID)?,
                app_password_name: r.app_password_name,
                created_at: timestamp(r.created_at)?,
                updated_at: timestamp(r.updated_at)?,
            })
        })
        .transpose()
    }

    async fn get_session_for_refresh(
        &self,
        refresh_jti: &Jti,
    ) -> Result<Option<SessionForRefresh>, DbError> {
        let refresh_jti_value = refresh_jti.as_str().to_owned();
        let row = sqlx::query!(
            r#"
            SELECT st.id as "id!: i64", st.did, st.scope, st.controller_did, k.key_bytes, k.encryption_version
            FROM session_tokens st
            JOIN users u ON st.did = u.did
            JOIN user_keys k ON u.id = k.user_id
            WHERE st.refresh_jti = $1 AND st.refresh_expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            "#,
            refresh_jti_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(SessionForRefresh {
                id: session_id(r.id)?,
                did: column(r.did, col::SESSION_TOKENS_DID)?,
                scope: r.scope,
                controller_did: opt_column(r.controller_did, col::SESSION_TOKENS_CONTROLLER_DID)?,
                key_bytes: r.key_bytes,
                encryption_version: i32::try_from(r.encryption_version.unwrap_or(0)).unwrap_or(0),
            })
        })
        .transpose()
    }

    async fn delete_session_by_access_jti(
        &self,
        access_jti: &Jti,
        did: &Did,
    ) -> Result<u64, DbError> {
        let access_jti_value = access_jti.as_str().to_owned();
        let did_value = did.as_str().to_owned();
        let result = sqlx::query!(
            "DELETE FROM session_tokens WHERE access_jti = $1 AND did = $2",
            access_jti_value,
            did_value
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected())
    }

    async fn delete_session_by_id(&self, session_id: SessionId, did: &Did) -> Result<u64, DbError> {
        let session_id_value = session_id.as_i32();
        let did_value = did.as_str().to_owned();
        let result = sqlx::query!(
            "DELETE FROM session_tokens WHERE id = $1 AND did = $2",
            session_id_value,
            did_value
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected())
    }

    async fn delete_sessions_by_did(&self, did: &Did) -> Result<u64, DbError> {
        let did_value = did.as_str().to_owned();
        let result = sqlx::query!("DELETE FROM session_tokens WHERE did = $1", did_value)
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(result.rows_affected())
    }

    async fn delete_sessions_by_did_except_jti(
        &self,
        did: &Did,
        except_jti: &Jti,
    ) -> Result<u64, DbError> {
        let did_value = did.as_str().to_owned();
        let except_jti_value = except_jti.as_str().to_owned();
        let result = sqlx::query!(
            "DELETE FROM session_tokens WHERE did = $1 AND access_jti != $2",
            did_value,
            except_jti_value
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected())
    }

    async fn list_sessions_by_did(&self, did: &Did) -> Result<Vec<SessionListItem>, DbError> {
        let did_value = did.as_str().to_owned();
        let rows = sqlx::query!(
            r#"
            SELECT id as "id!: i64", access_jti,
                   CAST(created_at AS TEXT) as "created_at!: String",
                   CAST(refresh_expires_at AS TEXT) as "refresh_expires_at!: String"
            FROM session_tokens
            WHERE did = $1 AND refresh_expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            ORDER BY created_at DESC
            "#,
            did_value
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                Ok(SessionListItem {
                    id: session_id(r.id)?,
                    access_jti: Jti::from(r.access_jti),
                    created_at: timestamp(r.created_at)?,
                    refresh_expires_at: timestamp(r.refresh_expires_at)?,
                })
            })
            .collect::<Result<Vec<_>, DbError>>()?)
    }

    async fn get_session_access_jti_by_id(
        &self,
        session_id: SessionId,
        did: &Did,
    ) -> Result<Option<Jti>, DbError> {
        let session_id_value = session_id.as_i32();
        let did_value = did.as_str().to_owned();
        let row = sqlx::query_scalar!(
            "SELECT access_jti FROM session_tokens WHERE id = $1 AND did = $2",
            session_id_value,
            did_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(row.map(Jti::from))
    }

    async fn delete_sessions_by_app_password(
        &self,
        did: &Did,
        app_password_name: &str,
    ) -> Result<u64, DbError> {
        let did_value = did.as_str().to_owned();
        let result = sqlx::query!(
            "DELETE FROM session_tokens WHERE did = $1 AND app_password_name = $2",
            did_value,
            app_password_name
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected())
    }

    async fn get_session_jtis_by_app_password(
        &self,
        did: &Did,
        app_password_name: &str,
    ) -> Result<Vec<Jti>, DbError> {
        let did_value = did.as_str().to_owned();
        let rows = sqlx::query_scalar!(
            "SELECT access_jti FROM session_tokens WHERE did = $1 AND app_password_name = $2",
            did_value,
            app_password_name
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(rows.into_iter().map(Jti::from).collect())
    }

    async fn lookup_refresh_grace(&self, refresh_jti: &Jti) -> Result<RefreshGraceLookup, DbError> {
        let refresh_jti_value = refresh_jti.as_str().to_owned();
        let row = sqlx::query!(
            r#"
            SELECT CAST(u.used_at AS TEXT) as "used_at!: String",
                   st.id AS "session_id!: i64", st.did, st.scope, st.controller_did,
                   st.access_jti, st.refresh_jti,
                   CAST(st.access_expires_at AS TEXT) as "access_expires_at!: String",
                   CAST(st.refresh_expires_at AS TEXT) as "refresh_expires_at!: String",
                   k.key_bytes, k.encryption_version
            FROM used_refresh_tokens u
            JOIN session_tokens st ON st.id = u.session_id
            JOIN users us ON st.did = us.did
            JOIN user_keys k ON us.id = k.user_id
            WHERE u.refresh_jti = $1
            "#,
            refresh_jti_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        // No marker (or a missing users/user_keys join row) degrades to NotUsed.
        // That is safe: the normal refresh path then fails closed with "Invalid
        // refresh token" without mutating any state.
        let Some(r) = row else {
            return Ok(RefreshGraceLookup::NotUsed);
        };

        let grace_cutoff = Utc::now() - Duration::seconds(REFRESH_GRACE_PERIOD_SECS);
        if timestamp(r.used_at)? > grace_cutoff {
            Ok(RefreshGraceLookup::Replay(RefreshGraceReplay {
                did: column(r.did, col::SESSION_TOKENS_DID)?,
                scope: r.scope,
                controller_did: opt_column(r.controller_did, col::SESSION_TOKENS_CONTROLLER_DID)?,
                access_jti: Jti::from(r.access_jti),
                refresh_jti: Jti::from(r.refresh_jti),
                access_expires_at: timestamp(r.access_expires_at)?,
                refresh_expires_at: timestamp(r.refresh_expires_at)?,
                key_bytes: r.key_bytes,
                encryption_version: i32::try_from(r.encryption_version.unwrap_or(0)).unwrap_or(0),
            }))
        } else {
            Ok(RefreshGraceLookup::Compromised {
                did: column(r.did, col::SESSION_TOKENS_DID)?,
                session_id: session_id(r.session_id)?,
                key_bytes: r.key_bytes,
                encryption_version: i32::try_from(r.encryption_version.unwrap_or(0)).unwrap_or(0),
            })
        }
    }

    async fn list_app_passwords(&self, user_id: Uuid) -> Result<Vec<AppPasswordRecord>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id as "id!: Vec<u8>", user_id as "user_id!: Vec<u8>", name, password_hash,
                   CAST(created_at AS TEXT) as "created_at!: String", privileged, scopes, created_by_controller_did
            FROM app_passwords
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(AppPasswordRecord {
                    id: uuid(r.id)?,
                    user_id: uuid(r.user_id)?,
                    name: r.name,
                    password_hash: PasswordHash::new(r.password_hash),
                    created_at: timestamp(r.created_at)?,
                    privilege: AppPasswordPrivilege::from_privileged_flag(r.privileged != 0),
                    scopes: r.scopes,
                    created_by_controller_did: opt_column(
                        r.created_by_controller_did,
                        col::APP_PASSWORDS_CREATED_BY_CONTROLLER_DID,
                    )?,
                })
            })
            .collect()
    }

    async fn get_app_passwords_for_login(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AppPasswordRecord>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id as "id!: Vec<u8>", user_id as "user_id!: Vec<u8>", name, password_hash,
                   CAST(created_at AS TEXT) as "created_at!: String", privileged, scopes, created_by_controller_did
            FROM app_passwords
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 20
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(AppPasswordRecord {
                    id: uuid(r.id)?,
                    user_id: uuid(r.user_id)?,
                    name: r.name,
                    password_hash: PasswordHash::new(r.password_hash),
                    created_at: timestamp(r.created_at)?,
                    privilege: AppPasswordPrivilege::from_privileged_flag(r.privileged != 0),
                    scopes: r.scopes,
                    created_by_controller_did: opt_column(
                        r.created_by_controller_did,
                        col::APP_PASSWORDS_CREATED_BY_CONTROLLER_DID,
                    )?,
                })
            })
            .collect()
    }

    async fn get_app_password_by_name(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<Option<AppPasswordRecord>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id as "id!: Vec<u8>", user_id as "user_id!: Vec<u8>", name, password_hash,
                   CAST(created_at AS TEXT) as "created_at!: String", privileged, scopes, created_by_controller_did
            FROM app_passwords
            WHERE user_id = $1 AND name = $2
            "#,
            user_id,
            name
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(AppPasswordRecord {
                id: uuid(r.id)?,
                user_id: uuid(r.user_id)?,
                name: r.name,
                password_hash: PasswordHash::new(r.password_hash),
                created_at: timestamp(r.created_at)?,
                privilege: AppPasswordPrivilege::from_privileged_flag(r.privileged != 0),
                scopes: r.scopes,
                created_by_controller_did: opt_column(
                    r.created_by_controller_did,
                    col::APP_PASSWORDS_CREATED_BY_CONTROLLER_DID,
                )?,
            })
        })
        .transpose()
    }

    async fn create_app_password(&self, data: &AppPasswordCreate) -> Result<Uuid, DbError> {
        let password_hash = data.password_hash.as_str().to_owned();
        let privileged = data.privilege.is_privileged();
        let controller_did = data
            .created_by_controller_did
            .as_ref()
            .map(|did| did.as_str().to_owned());
        let row = sqlx::query!(
            r#"
            INSERT INTO app_passwords (user_id, name, password_hash, privileged, scopes, created_by_controller_did)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id as "id!: Vec<u8>"
            "#,
            data.user_id,
            data.name,
            password_hash,
            privileged,
            data.scopes,
            controller_did
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        uuid(row.id)
    }

    async fn delete_app_password(&self, user_id: Uuid, name: &str) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "DELETE FROM app_passwords WHERE user_id = $1 AND name = $2",
            user_id,
            name
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected())
    }

    async fn delete_app_passwords_by_controller(
        &self,
        did: &Did,
        controller_did: &Did,
    ) -> Result<u64, DbError> {
        let did_value = did.as_str().to_owned();
        let controller_did_value = controller_did.as_str().to_owned();
        let result = sqlx::query!(
            r#"DELETE FROM app_passwords
               WHERE user_id = (SELECT id FROM users WHERE did = $1)
               AND created_by_controller_did = $2"#,
            did_value,
            controller_did_value
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected())
    }

    async fn get_last_reauth_at(&self, did: &Did) -> Result<Option<DateTime<Utc>>, DbError> {
        let did_value = did.as_str().to_owned();
        let row = sqlx::query_scalar!(
            r#"SELECT last_reauth_at FROM session_tokens
               WHERE did = $1 ORDER BY created_at DESC LIMIT 1"#,
            did_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.flatten().map(timestamp).transpose()
    }

    async fn update_last_reauth(&self, did: &Did) -> Result<DateTime<Utc>, DbError> {
        let now = Utc::now();
        let did_value = did.as_str().to_owned();
        sqlx::query!(
            "UPDATE session_tokens SET last_reauth_at = $1, mfa_verified = TRUE WHERE did = $2",
            now,
            did_value
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(now)
    }

    async fn get_session_mfa_status(&self, did: &Did) -> Result<Option<SessionMfaStatus>, DbError> {
        let did_value = did.as_str().to_owned();
        let row = sqlx::query!(
            r#"SELECT legacy_login, mfa_verified, last_reauth_at FROM session_tokens
               WHERE did = $1 ORDER BY created_at DESC LIMIT 1"#,
            did_value
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(SessionMfaStatus {
                login_type: LoginType::from_legacy_flag(r.legacy_login != 0),
                mfa_verified: r.mfa_verified != 0,
                last_reauth_at: optional_timestamp(r.last_reauth_at)?,
            })
        })
        .transpose()
    }

    async fn update_mfa_verified(&self, did: &Did) -> Result<(), DbError> {
        let did_value = did.as_str().to_owned();
        sqlx::query!(
            "UPDATE session_tokens SET mfa_verified = TRUE, last_reauth_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE did = $1",
            did_value
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn get_app_password_hashes_by_did(
        &self,
        did: &Did,
    ) -> Result<Vec<PasswordHash>, DbError> {
        let did_value = did.as_str().to_owned();
        let rows = sqlx::query_scalar!(
            r#"SELECT ap.password_hash FROM app_passwords ap
               JOIN users u ON ap.user_id = u.id
               WHERE u.did = $1"#,
            did_value
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(rows.into_iter().map(PasswordHash::new).collect())
    }

    async fn refresh_session_atomic(
        &self,
        data: &SessionRefreshData,
    ) -> Result<RefreshSessionResult, DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;
        let old_refresh_jti = data.old_refresh_jti.as_str().to_owned();
        let session_id_value = data.session_id.as_i32();

        // Atomically claim the old refresh jti. The INSERT serializes concurrent
        // rotations of the same token: exactly one request inserts the row, the
        // rest see `rows_affected == 0`.
        let claimed = sqlx::query!(
            "INSERT INTO used_refresh_tokens (refresh_jti, session_id) VALUES ($1, $2) ON CONFLICT (refresh_jti) DO NOTHING",
            old_refresh_jti,
            session_id_value
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        if claimed.rows_affected() == 0 {
            // Another request already rotated this token. Nothing to write, so
            // end our transaction before reading the winner's committed row.
            tx.rollback().await.map_err(map_sqlite_error)?;

            // Within the grace window (measured from this token's own rotation
            // time) we replay the session's current tokens so a benignly-racing
            // client keeps a working session instead of being revoked.
            match self.lookup_refresh_grace(&data.old_refresh_jti).await? {
                RefreshGraceLookup::Replay(replay) => {
                    return Ok(RefreshSessionResult::GraceReplay(replay));
                }
                RefreshGraceLookup::Compromised { .. } | RefreshGraceLookup::NotUsed => {
                    // Outside the grace window, or the marker/session vanished
                    // concurrently: genuine reuse. Revoke the session (delete is
                    // idempotent).
                    sqlx::query!("DELETE FROM session_tokens WHERE id = $1", session_id_value)
                        .execute(&self.pool)
                        .await
                        .map_err(map_sqlite_error)?;
                    return Ok(RefreshSessionResult::Compromise);
                }
            }
        }

        // We won the rotation.
        let new_access_jti = data.new_access_jti.as_str().to_owned();
        let new_refresh_jti = data.new_refresh_jti.as_str().to_owned();
        sqlx::query!(
            r#"
            UPDATE session_tokens
            SET access_jti = $1, refresh_jti = $2, access_expires_at = $3,
                refresh_expires_at = $4, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE id = $5
            "#,
            new_access_jti,
            new_refresh_jti,
            data.new_access_expires_at,
            data.new_refresh_expires_at,
            session_id_value
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        tx.commit().await.map_err(map_sqlite_error)?;
        Ok(RefreshSessionResult::Success)
    }
}
