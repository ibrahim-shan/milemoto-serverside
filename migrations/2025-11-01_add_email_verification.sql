-- This table is almost identical to password_resets
CREATE TABLE IF NOT EXISTS email_verifications (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,     -- sha256(raw_token)
  expires_at DATETIME NOT NULL,            -- e.g., 24h window
  used_at DATETIME NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  CONSTRAINT fk_email_verif_user 
    FOREIGN KEY (user_id) 
    REFERENCES users(id) 
    ON DELETE CASCADE,

  KEY idx_email_verif_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- We also need to add the verified_at column to the users table
-- This column already exists from your '0001_AUTH.sql' file,
-- but we run this 'ADD COLUMN IF NOT EXISTS' just to be safe.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMP NULL DEFAULT NULL AFTER status;