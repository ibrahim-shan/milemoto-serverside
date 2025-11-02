-- ==== AUTH-ONLY SCHEMA (MySQL 8+) ===========================================
-- DANGER: Drops unused catalog tables if they exist
DROP TABLE IF EXISTS product_categories;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS categories;

-- ==== USERS =================================================================
CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  full_name VARCHAR(191) NOT NULL,
  email VARCHAR(191) NOT NULL UNIQUE,
  phone VARCHAR(32) NULL,
  password_hash VARCHAR(191) NOT NULL,
  role ENUM('user','admin') NOT NULL DEFAULT 'user',
  status ENUM('active','disabled') NOT NULL DEFAULT 'active',
  email_verified_at TIMESTAMP NULL,
  google_sub VARCHAR(64) UNIQUE NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_users_phone (phone)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ==== SESSIONS (ULID 26 chars, httpOnly refresh cookies) ====================
CREATE TABLE IF NOT EXISTS sessions (
  id CHAR(26) PRIMARY KEY,                 -- ULID SID
  user_id BIGINT UNSIGNED NOT NULL,
  refresh_hash CHAR(64) NOT NULL,          -- sha256(refresh_jwt)
  user_agent VARCHAR(255) NULL,
  ip VARCHAR(64) NULL,
  remember TINYINT(1) NOT NULL DEFAULT 0,  -- 0=session cookie, 1=persistent
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  revoked_at DATETIME NULL DEFAULT NULL,
  replaced_by CHAR(26) NULL,               -- ULID of the new session on rotation
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  KEY idx_sessions_user_expires (user_id, expires_at),
  KEY idx_sessions_revoked (revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ==== PASSWORD RESETS =======================================================
CREATE TABLE IF NOT EXISTS password_resets (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,     -- sha256(raw_token)
  expires_at DATETIME NOT NULL,            -- 1h window per your code
  used_at DATETIME NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_pw_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  KEY idx_pw_user (user_id),
  KEY idx_pw_active (user_id, expires_at, used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;