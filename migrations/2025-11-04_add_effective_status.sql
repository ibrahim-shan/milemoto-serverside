-- Add effective_status columns to preserve admin intent while tracking availability

ALTER TABLE `states`
  ADD COLUMN `status_effective` ENUM('active', 'inactive') NOT NULL DEFAULT 'active' AFTER `status`;

ALTER TABLE `cities`
  ADD COLUMN `status_effective` ENUM('active', 'inactive') NOT NULL DEFAULT 'active' AFTER `status`;

-- Initialize effective status to match current status
UPDATE `states` SET `status_effective` = `status`;
UPDATE `cities` SET `status_effective` = `status`;
