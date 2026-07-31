use tranquil_db_traits::ColumnRef;

pub const ACCOUNT_DELEGATIONS_CONTROLLER_DID: ColumnRef =
    ColumnRef::new("account_delegations", "controller_did");
pub const ACCOUNT_DELEGATIONS_DELEGATED_DID: ColumnRef =
    ColumnRef::new("account_delegations", "delegated_did");
pub const ACCOUNT_DELEGATIONS_GRANTED_BY: ColumnRef =
    ColumnRef::new("account_delegations", "granted_by");
pub const ACCOUNT_DELEGATIONS_REVOKED_BY: ColumnRef =
    ColumnRef::new("account_delegations", "revoked_by");
pub const ACCOUNT_DELETION_REQUESTS_DID: ColumnRef =
    ColumnRef::new("account_deletion_requests", "did");
pub const APP_PASSWORDS_CREATED_BY_CONTROLLER_DID: ColumnRef =
    ColumnRef::new("app_passwords", "created_by_controller_did");
pub const BACKLINKS_URI: ColumnRef = ColumnRef::new("backlinks", "uri");
pub const BLOBS_CID: ColumnRef = ColumnRef::new("blobs", "cid");
pub const DELEGATION_AUDIT_LOG_ACTOR_DID: ColumnRef =
    ColumnRef::new("delegation_audit_log", "actor_did");
pub const DELEGATION_AUDIT_LOG_CONTROLLER_DID: ColumnRef =
    ColumnRef::new("delegation_audit_log", "controller_did");
pub const DELEGATION_AUDIT_LOG_DELEGATED_DID: ColumnRef =
    ColumnRef::new("delegation_audit_log", "delegated_did");
pub const INVITE_CODES_FOR_ACCOUNT: ColumnRef = ColumnRef::new("invite_codes", "for_account");
pub const OAUTH_2FA_CHALLENGE_DID: ColumnRef = ColumnRef::new("oauth_2fa_challenge", "did");
pub const OAUTH_AUTHORIZATION_REQUEST_CONTROLLER_DID: ColumnRef =
    ColumnRef::new("oauth_authorization_request", "controller_did");
pub const OAUTH_AUTHORIZATION_REQUEST_DID: ColumnRef =
    ColumnRef::new("oauth_authorization_request", "did");
pub const OAUTH_TOKEN_CONTROLLER_DID: ColumnRef = ColumnRef::new("oauth_token", "controller_did");
pub const OAUTH_TOKEN_DID: ColumnRef = ColumnRef::new("oauth_token", "did");
pub const PASSKEYS_DID: ColumnRef = ColumnRef::new("passkeys", "did");
pub const RECORD_BLOBS_BLOB_CID: ColumnRef = ColumnRef::new("record_blobs", "blob_cid");
pub const RECORD_BLOBS_RECORD_URI: ColumnRef = ColumnRef::new("record_blobs", "record_uri");
pub const RECORDS_COLLECTION: ColumnRef = ColumnRef::new("records", "collection");
pub const RECORDS_RECORD_CID: ColumnRef = ColumnRef::new("records", "record_cid");
pub const RECORDS_RKEY: ColumnRef = ColumnRef::new("records", "rkey");
pub const REPO_SEQ_BLOBS: ColumnRef = ColumnRef::new("repo_seq", "blobs");
pub const REPO_SEQ_BLOCKS_CIDS: ColumnRef = ColumnRef::new("repo_seq", "blocks_cids");
pub const REPO_SEQ_COMMIT_CID: ColumnRef = ColumnRef::new("repo_seq", "commit_cid");
pub const REPO_SEQ_DID: ColumnRef = ColumnRef::new("repo_seq", "did");
pub const REPO_SEQ_HANDLE: ColumnRef = ColumnRef::new("repo_seq", "handle");
pub const REPO_SEQ_PREV_CID: ColumnRef = ColumnRef::new("repo_seq", "prev_cid");
pub const REPO_SEQ_PREV_DATA_CID: ColumnRef = ColumnRef::new("repo_seq", "prev_data_cid");
pub const REPO_SEQ_REV: ColumnRef = ColumnRef::new("repo_seq", "rev");
pub const REPOS_REPO_REV: ColumnRef = ColumnRef::new("repos", "repo_rev");
pub const REPOS_REPO_ROOT_CID: ColumnRef = ColumnRef::new("repos", "repo_root_cid");
pub const RESERVED_SIGNING_KEYS_DID: ColumnRef = ColumnRef::new("reserved_signing_keys", "did");
pub const RESERVED_SIGNING_KEYS_PUBLIC_KEY_DID_KEY: ColumnRef =
    ColumnRef::new("reserved_signing_keys", "public_key_did_key");
pub const SESSION_TOKENS_CONTROLLER_DID: ColumnRef =
    ColumnRef::new("session_tokens", "controller_did");
pub const SESSION_TOKENS_DID: ColumnRef = ColumnRef::new("session_tokens", "did");
pub const USERS_DID: ColumnRef = ColumnRef::new("users", "did");
pub const USERS_HANDLE: ColumnRef = ColumnRef::new("users", "handle");
