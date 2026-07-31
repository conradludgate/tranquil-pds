CREATE TABLE handle_reservations (
    handle TEXT PRIMARY KEY,
    reserved_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now','+5 minutes'))
);

CREATE INDEX idx_handle_reservations_expires ON handle_reservations(expires_at);
