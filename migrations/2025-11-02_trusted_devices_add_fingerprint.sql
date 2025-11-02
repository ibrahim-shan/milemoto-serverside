-- Add fingerprint column for soft device binding (UA + IP prefix hash)
ALTER TABLE trusted_devices
  ADD COLUMN IF NOT EXISTS fingerprint CHAR(64) NULL AFTER token_hash;

-- Optional helpful index if you later query by fingerprint
-- CREATE INDEX IF NOT EXISTS idx_trusted_fingerprint ON trusted_devices (fingerprint);

