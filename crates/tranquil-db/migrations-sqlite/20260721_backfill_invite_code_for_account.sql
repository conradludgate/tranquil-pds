UPDATE invite_codes
SET for_account = (SELECT u.did FROM users u WHERE LOWER(u.handle) = LOWER(invite_codes.for_account))
WHERE for_account NOT LIKE 'did:%'
  AND EXISTS (SELECT 1 FROM users u WHERE LOWER(u.handle) = LOWER(invite_codes.for_account));
UPDATE invite_codes
SET for_account = (SELECT u.did FROM users u WHERE u.id = invite_codes.created_by_user)
WHERE for_account = 'admin';