CREATE TABLE record_blobs (
    id BLOB PRIMARY KEY DEFAULT (randomblob(16)),
    repo_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    record_uri TEXT NOT NULL,
    blob_cid TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(repo_id, record_uri, blob_cid)
);

CREATE INDEX idx_record_blobs_repo_id ON record_blobs(repo_id);
CREATE INDEX idx_record_blobs_blob_cid ON record_blobs(blob_cid);
