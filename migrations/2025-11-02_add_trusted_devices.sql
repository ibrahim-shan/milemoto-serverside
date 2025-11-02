-- Trusted devices: allow MFA bypass on known devices for a limited TTL
-- Stores a per-device opaque token (hashed), plus metadata for auditing and management.

CREATE TABLE IF NOT EXISTS trusted_devices (
  id CHAR(26) PRIMARY KEY,                 -- ULID
  user_id BIGINT UNSIGNED NOT NULL,
  token_hash CHAR(64) NOT NULL,            -- sha256(raw token)
  user_agent VARCHAR(255) NULL,
  ip VARCHAR(64) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME NULL DEFAULT NULL,
  expires_at DATETIME NOT NULL,
  revoked_at DATETIME NULL DEFAULT NULL,

  UNIQUE KEY uniq_user_token (user_id, token_hash),
  CONSTRAINT fk_trusted_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Helpful indexes for pruning and listing
CREATE INDEX IF NOT EXISTS idx_trusted_user_expires ON trusted_devices (user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_trusted_expires ON trusted_devices (expires_at);
CREATE INDEX IF NOT EXISTS idx_trusted_revoked ON trusted_devices (revoked_at);

