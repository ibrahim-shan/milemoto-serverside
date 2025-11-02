-- Pending MFA login (created after password OK, before issuing session)
CREATE TABLE IF NOT EXISTS mfa_login_challenges (
  id CHAR(26) PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  remember TINYINT(1) NOT NULL DEFAULT 0,
  user_agent VARCHAR(255) NULL,
  ip VARCHAR(64) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  consumed_at DATETIME NULL DEFAULT NULL,
  CONSTRAINT fk_mfa_login_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX IF NOT EXISTS idx_mfa_login_exp ON mfa_login_challenges (expires_at);