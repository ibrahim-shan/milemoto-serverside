-- Users: store encrypted TOTP secret + flag
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS mfa_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER status,
  ADD COLUMN IF NOT EXISTS mfa_secret_enc VARBINARY(128) NULL AFTER mfa_enabled;

-- One-shot setup challenges (secret kept here until verified)
CREATE TABLE IF NOT EXISTS mfa_challenges (
  id CHAR(26) PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  secret_enc VARBINARY(128) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  consumed_at DATETIME NULL DEFAULT NULL,
  CONSTRAINT fk_mfa_ch_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Backup codes (hashed)
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  code_hash CHAR(64) NOT NULL,
  used_at DATETIME NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_user_code (user_id, code_hash),
  CONSTRAINT fk_mfa_codes_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_mfa_ch_exp ON mfa_challenges (expires_at);
CREATE INDEX IF NOT EXISTS idx_mfa_codes_used ON mfa_backup_codes (used_at);