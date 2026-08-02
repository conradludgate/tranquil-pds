CREATE TABLE users_new (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    handle TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    did TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    deactivated_at TEXT,
    invites_disabled INTEGER DEFAULT FALSE,
    takedown_ref TEXT,
    preferred_comms_channel TEXT NOT NULL DEFAULT 'email',
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
    migrated_at TEXT,
    password_required INTEGER NOT NULL DEFAULT TRUE,
    recovery_token TEXT,
    recovery_token_expires_at TEXT
);
INSERT INTO users_new SELECT *, TRUE, NULL, NULL FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
CREATE INDEX idx_users_password_reset_code ON users(password_reset_code) WHERE password_reset_code IS NOT NULL;
CREATE INDEX idx_users_discord_id ON users(discord_id) WHERE discord_id IS NOT NULL;
CREATE INDEX idx_users_telegram_username ON users(telegram_username) WHERE telegram_username IS NOT NULL;
CREATE INDEX idx_users_signal_number ON users(signal_number) WHERE signal_number IS NOT NULL;
CREATE INDEX idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE INDEX idx_users_recovery_token ON users(recovery_token) WHERE recovery_token IS NOT NULL;