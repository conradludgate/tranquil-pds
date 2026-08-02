CREATE TABLE signal_kv (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE signal_sessions (
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL CHECK (device_id BETWEEN 0 AND 127),
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    record BLOB NOT NULL,
    PRIMARY KEY (address, device_id, identity)
);

CREATE TABLE signal_identities (
    address TEXT NOT NULL,
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    record BLOB NOT NULL,
    PRIMARY KEY (address, identity)
);

CREATE TABLE signal_pre_keys (
    id INTEGER NOT NULL CHECK (id >= 0),
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    record BLOB NOT NULL,
    PRIMARY KEY (id, identity)
);

CREATE TABLE signal_signed_pre_keys (
    id INTEGER NOT NULL CHECK (id >= 0),
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    record BLOB NOT NULL,
    PRIMARY KEY (id, identity)
);

CREATE TABLE signal_kyber_pre_keys (
    id INTEGER NOT NULL CHECK (id >= 0),
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    record BLOB NOT NULL,
    is_last_resort INTEGER NOT NULL DEFAULT FALSE,
    stale_at TEXT,
    PRIMARY KEY (id, identity)
);

CREATE TABLE signal_sender_keys (
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL CHECK (device_id BETWEEN 0 AND 127),
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    distribution_id BLOB NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (address, device_id, identity, distribution_id)
);

CREATE TABLE signal_base_keys_seen (
    kyber_pre_key_id INTEGER NOT NULL CHECK (kyber_pre_key_id >= 0),
    signed_pre_key_id INTEGER NOT NULL CHECK (signed_pre_key_id >= 0),
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    base_key BLOB NOT NULL,
    PRIMARY KEY (identity, kyber_pre_key_id, signed_pre_key_id, base_key)
);

CREATE TABLE signal_profile_keys (
    uuid BLOB PRIMARY KEY,
    key BLOB NOT NULL
);
