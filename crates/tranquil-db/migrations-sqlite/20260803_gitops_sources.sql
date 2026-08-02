CREATE TABLE gitops_sources (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    name TEXT NOT NULL UNIQUE,
    path TEXT NOT NULL,
    did TEXT NOT NULL,
    last_scan_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE gitops_records (
    source_id BLOB NOT NULL REFERENCES gitops_sources(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    did TEXT NOT NULL,
    collection TEXT NOT NULL,
    rkey TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    record_cid TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (source_id, path),
    UNIQUE (did, collection, rkey)
);

CREATE INDEX idx_gitops_records_source ON gitops_records(source_id);
CREATE INDEX idx_gitops_records_identity ON gitops_records(did, collection, rkey);
