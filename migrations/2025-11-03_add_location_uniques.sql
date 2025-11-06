-- migrations/2025-11-03_add_location_uniques.sql
-- Ensure location tables prevent duplicate names within their parent scope

ALTER TABLE `states`
  ADD CONSTRAINT `uniq_states_country_name` UNIQUE (`country_id`, `name`);

ALTER TABLE `cities`
  ADD CONSTRAINT `uniq_cities_state_name` UNIQUE (`state_id`, `name`);
