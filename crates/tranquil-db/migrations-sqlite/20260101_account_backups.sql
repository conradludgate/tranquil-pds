ALTER TABLE users ADD COLUMN backup_enabled INTEGER NOT NULL DEFAULT TRUE;

CREATE TABLE account_backups (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    storage_key TEXT NOT NULL,
    repo_root_cid TEXT NOT NULL,
    repo_rev TEXT NOT NULL,
    block_count INT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX idx_account_backups_user_id ON account_backups(user_id);
CREATE INDEX idx_account_backups_created_at ON account_backups(created_at);
