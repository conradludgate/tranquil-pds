CREATE TABLE IF NOT EXISTS did_web_overrides (
    user_id BLOB PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    verification_methods TEXT NOT NULL DEFAULT '[]',
    also_known_as TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
