ALTER TABLE user_blocks ADD COLUMN repo_rev TEXT;
UPDATE user_blocks
SET repo_rev = (SELECT r.repo_rev FROM repos r WHERE r.user_id = user_blocks.user_id)
WHERE repo_rev IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_blocks_repo_rev ON user_blocks(user_id, repo_rev);