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