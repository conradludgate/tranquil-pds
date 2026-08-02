DELETE FROM account_backups
WHERE EXISTS (
    SELECT 1 FROM account_backups b
    WHERE account_backups.storage_key = b.storage_key
      AND account_backups.created_at < b.created_at
);
CREATE UNIQUE INDEX idx_account_backups_storage_key ON account_backups(storage_key);