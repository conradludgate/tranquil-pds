ALTER TABLE users ADD COLUMN allow_legacy_login INTEGER NOT NULL DEFAULT TRUE;

ALTER TABLE session_tokens ADD COLUMN mfa_verified INTEGER NOT NULL DEFAULT FALSE;
ALTER TABLE session_tokens ADD COLUMN legacy_login INTEGER NOT NULL DEFAULT FALSE;

CREATE INDEX idx_session_tokens_legacy ON session_tokens(did, legacy_login) WHERE legacy_login = TRUE;
