CREATE TABLE gitops_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    path TEXT NOT NULL,
    did TEXT NOT NULL,
    last_scan_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE gitops_records (
    source_id UUID NOT NULL REFERENCES gitops_sources(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    did TEXT NOT NULL,
    collection TEXT NOT NULL,
    rkey TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    record_cid TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (source_id, path),
    UNIQUE (did, collection, rkey)
);

CREATE INDEX idx_gitops_records_source ON gitops_records(source_id);
CREATE INDEX idx_gitops_records_identity ON gitops_records(did, collection, rkey);
