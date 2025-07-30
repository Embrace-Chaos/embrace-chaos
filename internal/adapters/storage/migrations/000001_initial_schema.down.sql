-- Rollback initial schema

-- Drop triggers first
DROP TRIGGER IF EXISTS update_experiments_updated_at ON experiments;
DROP TRIGGER IF EXISTS update_executions_updated_at ON executions;
DROP TRIGGER IF EXISTS update_targets_updated_at ON targets;
DROP TRIGGER IF EXISTS update_results_updated_at ON results;
DROP TRIGGER IF EXISTS update_provider_configs_updated_at ON provider_configs;
DROP TRIGGER IF EXISTS update_scheduled_experiments_updated_at ON scheduled_experiments;
DROP TRIGGER IF EXISTS update_experiment_templates_updated_at ON experiment_templates;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop tables in reverse order of dependencies
DROP TABLE IF EXISTS safety_metrics;
DROP TABLE IF EXISTS experiment_templates;
DROP TABLE IF EXISTS scheduled_experiments;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS domain_events;
DROP TABLE IF EXISTS provider_configs;
DROP TABLE IF EXISTS results;
DROP TABLE IF EXISTS targets;
DROP TABLE IF EXISTS executions;
DROP TABLE IF EXISTS experiments;

-- Drop extensions
DROP EXTENSION IF EXISTS "uuid-ossp";