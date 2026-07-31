CREATE TABLE IF NOT EXISTS users (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    handle TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    did TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    deactivated_at TEXT,
    invites_disabled INTEGER DEFAULT FALSE,
    takedown_ref TEXT,
    preferred_comms_channel comms_channel NOT NULL DEFAULT 'email',
    password_reset_code TEXT,
    password_reset_code_expires_at TEXT,
    email_verified INTEGER NOT NULL DEFAULT FALSE,
    two_factor_enabled INTEGER NOT NULL DEFAULT FALSE,
    discord_id TEXT,
    discord_verified INTEGER NOT NULL DEFAULT FALSE,
    telegram_username TEXT,
    telegram_verified INTEGER NOT NULL DEFAULT FALSE,
    signal_number TEXT,
    signal_verified INTEGER NOT NULL DEFAULT FALSE,
    is_admin INTEGER NOT NULL DEFAULT FALSE,
    migrated_to_pds TEXT,
    migrated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_password_reset_code ON users(password_reset_code) WHERE password_reset_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_discord_id ON users(discord_id) WHERE discord_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_telegram_username ON users(telegram_username) WHERE telegram_username IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_signal_number ON users(signal_number) WHERE signal_number IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE TABLE IF NOT EXISTS invite_codes (
    code TEXT PRIMARY KEY,
    available_uses INT NOT NULL DEFAULT 1,
    created_by_user BLOB NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    disabled INTEGER DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_invite_codes_created_by ON invite_codes(created_by_user);
CREATE TABLE IF NOT EXISTS invite_code_uses (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    code TEXT NOT NULL REFERENCES invite_codes(code),
    used_by_user BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    used_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(code, used_by_user)
);
CREATE TABLE IF NOT EXISTS user_keys (
    user_id BLOB PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    key_bytes BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    encrypted_at TEXT,
    encryption_version INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS repos (
    user_id BLOB PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    repo_root_cid TEXT NOT NULL,
    repo_rev TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS blocks (
    cid BLOB PRIMARY KEY,
    data BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS records (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    repo_id BLOB NOT NULL REFERENCES repos(user_id) ON DELETE CASCADE,
    collection TEXT NOT NULL,
    rkey TEXT NOT NULL,
    record_cid TEXT NOT NULL,
    takedown_ref TEXT,
    repo_rev TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(repo_id, collection, rkey)
);
CREATE INDEX idx_records_repo_rev ON records(repo_rev);
CREATE INDEX IF NOT EXISTS idx_records_repo_collection ON records(repo_id, collection);
CREATE INDEX IF NOT EXISTS idx_records_repo_collection_created ON records(repo_id, collection, created_at DESC);
CREATE TABLE IF NOT EXISTS blobs (
    cid TEXT PRIMARY KEY,
    mime_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_by_user BLOB NOT NULL REFERENCES users(id),
    storage_key TEXT NOT NULL,
    takedown_ref TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_blobs_created_by_user ON blobs(created_by_user, created_at DESC);
CREATE TABLE IF NOT EXISTS app_passwords (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    privileged INTEGER NOT NULL DEFAULT FALSE,
    UNIQUE(user_id, name)
);
CREATE INDEX IF NOT EXISTS idx_app_passwords_user_id ON app_passwords(user_id);
CREATE TABLE reports (
    id BIGINT PRIMARY KEY,
    reason_type TEXT NOT NULL,
    reason TEXT,
    subject_json TEXT NOT NULL,
    reported_by_did TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS account_deletion_requests (
    token TEXT PRIMARY KEY,
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS comms_queue (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel comms_channel NOT NULL DEFAULT 'email',
    comms_type comms_type NOT NULL,
    status comms_status NOT NULL DEFAULT 'pending',
    recipient TEXT NOT NULL,
    subject TEXT,
    body TEXT NOT NULL,
    metadata TEXT,
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    scheduled_for TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    processed_at TEXT
);
CREATE INDEX idx_comms_queue_status_scheduled
    ON comms_queue(status, scheduled_for)
    WHERE status = 'pending';
CREATE INDEX idx_comms_queue_user_id ON comms_queue(user_id);
CREATE TABLE IF NOT EXISTS reserved_signing_keys (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    did TEXT,
    public_key_did_key TEXT NOT NULL,
    private_key_bytes BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now','+24 hours')),
    used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_reserved_signing_keys_did ON reserved_signing_keys(did) WHERE did IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_reserved_signing_keys_expires ON reserved_signing_keys(expires_at) WHERE used_at IS NULL;
CREATE TABLE repo_seq (
    seq INTEGER PRIMARY KEY,
    did TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    event_type TEXT NOT NULL,
    commit_cid TEXT,
    prev_cid TEXT,
    ops TEXT,
    blobs TEXT,
    blocks_cids TEXT,
    prev_data_cid TEXT,
    handle TEXT,
    active INTEGER,
    status TEXT
);
CREATE INDEX idx_repo_seq_seq ON repo_seq(seq);
CREATE INDEX idx_repo_seq_did ON repo_seq(did);
CREATE INDEX IF NOT EXISTS idx_repo_seq_did_seq ON repo_seq(did, seq DESC);
CREATE TABLE IF NOT EXISTS session_tokens (
    id INTEGER PRIMARY KEY,
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    access_jti TEXT NOT NULL UNIQUE,
    refresh_jti TEXT NOT NULL UNIQUE,
    access_expires_at TEXT NOT NULL,
    refresh_expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_session_tokens_did ON session_tokens(did);
CREATE INDEX idx_session_tokens_access_jti ON session_tokens(access_jti);
CREATE INDEX idx_session_tokens_refresh_jti ON session_tokens(refresh_jti);
CREATE TABLE IF NOT EXISTS used_refresh_tokens (
    refresh_jti TEXT PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES session_tokens(id) ON DELETE CASCADE,
    used_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_used_refresh_tokens_session_id ON used_refresh_tokens(session_id);
CREATE TABLE IF NOT EXISTS oauth_device (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL UNIQUE,
    user_agent TEXT,
    ip_address TEXT NOT NULL,
    last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS oauth_authorization_request (
    id TEXT PRIMARY KEY,
    did TEXT REFERENCES users(did) ON DELETE CASCADE,
    device_id TEXT REFERENCES oauth_device(id) ON DELETE SET NULL,
    client_id TEXT NOT NULL,
    client_auth TEXT,
    parameters TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    code TEXT UNIQUE
);
CREATE INDEX idx_oauth_auth_request_expires ON oauth_authorization_request(expires_at);
CREATE INDEX idx_oauth_auth_request_code ON oauth_authorization_request(code) WHERE code IS NOT NULL;
CREATE TABLE IF NOT EXISTS oauth_token (
    id INTEGER PRIMARY KEY,
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    token_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_auth TEXT NOT NULL,
    device_id TEXT REFERENCES oauth_device(id) ON DELETE SET NULL,
    parameters TEXT NOT NULL,
    details TEXT,
    code TEXT UNIQUE,
    current_refresh_token TEXT UNIQUE,
    scope TEXT
);
CREATE INDEX idx_oauth_token_did ON oauth_token(did);
CREATE INDEX idx_oauth_token_code ON oauth_token(code) WHERE code IS NOT NULL;
CREATE TABLE IF NOT EXISTS oauth_account_device (
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES oauth_device(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (did, device_id)
);
CREATE TABLE IF NOT EXISTS oauth_authorized_client (
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    data TEXT NOT NULL,
    PRIMARY KEY (did, client_id)
);
CREATE TABLE IF NOT EXISTS oauth_used_refresh_token (
    refresh_token TEXT PRIMARY KEY,
    token_id INTEGER NOT NULL REFERENCES oauth_token(id) ON DELETE CASCADE
);
CREATE TABLE oauth_dpop_jti (
    jti TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_oauth_dpop_jti_created_at ON oauth_dpop_jti(created_at);
CREATE TABLE plc_operation_tokens (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_plc_op_tokens_user ON plc_operation_tokens(user_id);
CREATE INDEX idx_plc_op_tokens_expires ON plc_operation_tokens(expires_at);
CREATE TABLE IF NOT EXISTS account_preferences (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    value_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(user_id, name)
);
CREATE INDEX IF NOT EXISTS idx_account_preferences_user_id ON account_preferences(user_id);
CREATE INDEX IF NOT EXISTS idx_account_preferences_name ON account_preferences(name);
CREATE TABLE oauth_2fa_challenge (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    request_uri TEXT NOT NULL,
    code TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now','+10 minutes'))
);
CREATE INDEX idx_oauth_2fa_challenge_request_uri ON oauth_2fa_challenge(request_uri);
CREATE INDEX idx_oauth_2fa_challenge_expires ON oauth_2fa_challenge(expires_at);
CREATE TABLE IF NOT EXISTS channel_verifications (
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel comms_channel NOT NULL,
    code TEXT NOT NULL,
    pending_identifier TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (user_id, channel)
);
CREATE INDEX IF NOT EXISTS idx_channel_verifications_expires ON channel_verifications(expires_at);
CREATE TABLE oauth_scope_preference (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    granted INTEGER NOT NULL DEFAULT TRUE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(did, client_id, scope)
);
CREATE INDEX idx_oauth_scope_pref_lookup ON oauth_scope_preference(did, client_id);
CREATE TABLE user_totp (
    did TEXT PRIMARY KEY REFERENCES users(did) ON DELETE CASCADE,
    secret_encrypted BLOB NOT NULL,
    encryption_version INTEGER NOT NULL DEFAULT 1,
    verified INTEGER NOT NULL DEFAULT FALSE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_used TEXT
);
CREATE TABLE backup_codes (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_backup_codes_did ON backup_codes(did);
CREATE TABLE passkeys (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_used TEXT,
    friendly_name TEXT,
    aaguid BLOB,
    transports TEXT
);
CREATE INDEX idx_passkeys_did ON passkeys(did);
CREATE TABLE webauthn_challenges (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    did TEXT NOT NULL,
    challenge BLOB NOT NULL,
    challenge_type TEXT NOT NULL,
    state_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at TEXT NOT NULL
);
CREATE INDEX idx_webauthn_challenges_did ON webauthn_challenges(did);
