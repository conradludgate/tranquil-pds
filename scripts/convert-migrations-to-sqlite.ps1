$targetDir = "crates/tranquil-db/migrations-sqlite"
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
Get-ChildItem -LiteralPath $targetDir -Filter *.sql | Remove-Item -Force

foreach ($file in Get-ChildItem migrations -Filter *.sql | Sort-Object Name) {
    $sql = Get-Content -Raw -LiteralPath $file.FullName
    $sql = [regex]::Replace($sql, 'CREATE TYPE[\s\S]*?;\s*', '')
    $sql = $sql -replace 'DEFAULT gen_random_uuid\(\)', 'DEFAULT (randomblob(16))'
    $sql = $sql -replace "DEFAULT NOW\(\) \+ INTERVAL '24 hours'", "DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now','+24 hours'))"
    $sql = $sql -replace "DEFAULT NOW\(\) \+ INTERVAL '10 minutes'", "DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now','+10 minutes'))"
    $sql = $sql -replace "DEFAULT NOW\(\) \+ INTERVAL '5 minutes'", "DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now','+5 minutes'))"
    # Keep replacements case-sensitive so identifiers such as `uuid` are not
    # accidentally rewritten along with PostgreSQL type names.
    $sql = $sql -creplace '\bUUID\b', 'BLOB'
    $sql = $sql -creplace '\bTIMESTAMPTZ\b', 'TEXT'
    $sql = $sql -creplace '\bBYTEA\[\]', 'BLOB'
    $sql = $sql -creplace '\bBYTEA\b', 'BLOB'
    $sql = $sql -creplace '\bJSONB\b', 'TEXT'
    $sql = $sql -creplace '\bBIGSERIAL\b', 'INTEGER'
    $sql = $sql -creplace '\bSERIAL\b', 'INTEGER'
    $sql = $sql -creplace '\bTEXT\[\]', 'TEXT'
    $sql = $sql -creplace '\bBOOLEAN\b', 'INTEGER'
    $sql = $sql -replace 'DEFAULT NOW\(\)', "DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))"
    $sql = $sql -replace 'CREATE INDEX CONCURRENTLY', 'CREATE INDEX'
    $sql = $sql -replace 'DROP INDEX CONCURRENTLY', 'DROP INDEX'
    $sql = $sql -replace 'ADD COLUMN IF NOT EXISTS', 'ADD COLUMN'
    $sql = $sql -replace '(?im)^\s*TRUNCATE TABLE\s+([^;]+);', 'DELETE FROM $1;'
    $sql = $sql -replace 'DROP COLUMN IF EXISTS', 'DROP COLUMN'

    # PostgreSQL-only schema operations have no SQLite equivalent. Enum values
    # are represented as TEXT plus CHECK constraints in the SQLite schema, and
    # foreign-key/unique constraints are defined when tables are created.
    $sql = [regex]::Replace($sql, '(?im)^\s*ALTER TYPE .*?;\s*$', '')
    $sql = [regex]::Replace($sql, '(?im)^\s*ALTER TABLE .*? DROP CONSTRAINT .*?;\s*$', '')
    $sql = [regex]::Replace($sql, '(?im)^\s*ALTER TABLE .*? ALTER COLUMN .*?;\s*$', '')
    $sql = [regex]::Replace($sql, '(?im)^\s*CREATE SEQUENCE .*?;\s*$', '')
    $sql = [regex]::Replace($sql, '(?im)^\s*SELECT setval\(.*?;\s*$', '')

    if ($file.Name -eq '20260407_inline_event_blocks.sql') {
        $sql = "ALTER TABLE repo_seq ADD COLUMN block_cids BLOB;`nALTER TABLE repo_seq ADD COLUMN block_data BLOB;`n"
    }

    if ($file.Name -eq '20260107_add_repo_rev_to_user_blocks.sql') {
        $sql = @"
ALTER TABLE user_blocks ADD COLUMN repo_rev TEXT;
UPDATE user_blocks
SET repo_rev = (SELECT r.repo_rev FROM repos r WHERE r.user_id = user_blocks.user_id)
WHERE repo_rev IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_blocks_repo_rev ON user_blocks(user_id, repo_rev);
"@
    }

    if ($file.Name -eq '20251225_passwordless_accounts.sql') {
        # SQLite cannot drop NOT NULL from an existing column. Rebuild this
        # small table so passwordless accounts have the same nullable field as
        # the PostgreSQL schema.
        $sql = @"
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
"@
    }

    if ($file.Name -eq '20260721_backfill_invite_code_for_account.sql') {
        $sql = @"
UPDATE invite_codes
SET for_account = (SELECT u.did FROM users u WHERE LOWER(u.handle) = LOWER(invite_codes.for_account))
WHERE for_account NOT LIKE 'did:%'
  AND EXISTS (SELECT 1 FROM users u WHERE LOWER(u.handle) = LOWER(invite_codes.for_account));
UPDATE invite_codes
SET for_account = (SELECT u.did FROM users u WHERE u.id = invite_codes.created_by_user)
WHERE for_account = 'admin';
"@
    }

    if ($file.Name -eq '20260122_backup_storage_key_unique.sql') {
        $sql = @"
DELETE FROM account_backups
WHERE EXISTS (
    SELECT 1 FROM account_backups b
    WHERE account_backups.storage_key = b.storage_key
      AND account_backups.created_at < b.created_at
);
CREATE UNIQUE INDEX idx_account_backups_storage_key ON account_backups(storage_key);
"@
    }

    if ($file.Name -eq '20260529_firehose_outbox_sequencing.sql') {
        $sql = @"
CREATE TABLE repo_seq_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER UNIQUE,
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
    status TEXT,
    rev TEXT,
    block_cids BLOB,
    block_data BLOB
);
INSERT INTO repo_seq_new (
    seq, did, created_at, event_type, commit_cid, prev_cid, ops, blobs,
    blocks_cids, prev_data_cid, handle, active, status, rev, block_cids, block_data
)
SELECT seq, did, created_at, event_type, commit_cid, prev_cid, ops, blobs,
       blocks_cids, prev_data_cid, handle, active, status, rev, block_cids, block_data
FROM repo_seq;
DROP TABLE repo_seq;
ALTER TABLE repo_seq_new RENAME TO repo_seq;
CREATE INDEX idx_repo_seq_seq ON repo_seq(seq);
CREATE INDEX idx_repo_seq_did ON repo_seq(did);
CREATE INDEX idx_repo_seq_did_seq ON repo_seq(did, seq DESC);
CREATE INDEX idx_repo_seq_unsequenced ON repo_seq(id) WHERE seq IS NULL;
"@
    }

    Set-Content -LiteralPath (Join-Path $targetDir $file.Name) -Value $sql -NoNewline
}
