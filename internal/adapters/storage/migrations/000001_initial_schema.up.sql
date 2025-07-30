-- Initial schema for Embrace Chaos platform
-- All tables use UUID for primary keys and include audit fields

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Experiments table
CREATE TABLE experiments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    status VARCHAR(50) NOT NULL,
    config JSONB NOT NULL,
    targets JSONB NOT NULL,
    safety JSONB NOT NULL,
    labels JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    deleted_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT chk_status CHECK (status IN ('draft', 'ready', 'scheduled', 'running', 'completed', 'failed', 'archived'))
);

-- Create indexes for experiments
CREATE INDEX idx_experiments_name ON experiments(name) WHERE deleted_at IS NULL;
CREATE INDEX idx_experiments_status ON experiments(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_experiments_created_at ON experiments(created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX idx_experiments_labels ON experiments USING GIN(labels) WHERE deleted_at IS NULL;

-- Executions table
CREATE TABLE executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    experiment_id UUID NOT NULL REFERENCES experiments(id),
    status VARCHAR(50) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration BIGINT, -- in milliseconds
    trigger_type VARCHAR(50) NOT NULL,
    trigger_by VARCHAR(255) NOT NULL,
    parameters JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    version INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT chk_execution_status CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled', 'timeout'))
);

-- Create indexes for executions
CREATE INDEX idx_executions_experiment_id ON executions(experiment_id);
CREATE INDEX idx_executions_status ON executions(status);
CREATE INDEX idx_executions_started_at ON executions(started_at DESC);

-- Targets table
CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    resource_id VARCHAR(500) NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    region VARCHAR(100),
    tags JSONB,
    status VARCHAR(50) NOT NULL,
    metadata JSONB,
    last_discovered TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT chk_target_provider CHECK (provider IN ('aws', 'gcp', 'azure', 'kubernetes', 'vmware'))
);

-- Create indexes for targets
CREATE INDEX idx_targets_resource_id ON targets(resource_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_targets_type_provider ON targets(type, provider) WHERE deleted_at IS NULL;
CREATE INDEX idx_targets_tags ON targets USING GIN(tags) WHERE deleted_at IS NULL;
CREATE INDEX idx_targets_status ON targets(status) WHERE deleted_at IS NULL;

-- Results table
CREATE TABLE results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id UUID NOT NULL REFERENCES executions(id),
    experiment_id UUID NOT NULL REFERENCES experiments(id),
    status VARCHAR(50) NOT NULL,
    summary TEXT,
    metrics JSONB,
    errors JSONB,
    target_results JSONB,
    duration BIGINT, -- in milliseconds
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_result_status CHECK (status IN ('success', 'partial_success', 'failure', 'error'))
);

-- Create indexes for results
CREATE INDEX idx_results_execution_id ON results(execution_id);
CREATE INDEX idx_results_experiment_id ON results(experiment_id);
CREATE INDEX idx_results_status ON results(status);
CREATE INDEX idx_results_created_at ON results(created_at DESC);

-- Provider configurations table
CREATE TABLE provider_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    provider VARCHAR(50) NOT NULL,
    config JSONB NOT NULL, -- encrypted sensitive data
    capabilities JSONB,
    status VARCHAR(50) NOT NULL,
    last_health_check TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255) NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT chk_provider CHECK (provider IN ('aws', 'gcp', 'azure', 'kubernetes', 'vmware'))
);

-- Create indexes for provider configs
CREATE INDEX idx_provider_configs_name ON provider_configs(name) WHERE deleted_at IS NULL;
CREATE INDEX idx_provider_configs_provider ON provider_configs(provider) WHERE deleted_at IS NULL;

-- Domain events table (for event sourcing)
CREATE TABLE domain_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    aggregate_id VARCHAR(500) NOT NULL,
    aggregate_type VARCHAR(100) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    event_version INTEGER NOT NULL,
    payload JSONB NOT NULL,
    metadata JSONB,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for domain events
CREATE INDEX idx_domain_events_aggregate ON domain_events(aggregate_id, event_version);
CREATE INDEX idx_domain_events_type ON domain_events(event_type);
CREATE INDEX idx_domain_events_occurred_at ON domain_events(occurred_at DESC);

-- Audit log table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_type VARCHAR(100) NOT NULL,
    entity_id VARCHAR(500) NOT NULL,
    action VARCHAR(50) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    changes JSONB,
    metadata JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for audit logs
CREATE INDEX idx_audit_logs_entity ON audit_logs(entity_type, entity_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Scheduled experiments table
CREATE TABLE scheduled_experiments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    experiment_id UUID NOT NULL REFERENCES experiments(id),
    schedule_expression VARCHAR(255) NOT NULL, -- cron expression
    next_run_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_run_at TIMESTAMP WITH TIME ZONE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    time_zone VARCHAR(100) NOT NULL DEFAULT 'UTC',
    parameters JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255) NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Create indexes for scheduled experiments
CREATE INDEX idx_scheduled_experiments_next_run ON scheduled_experiments(next_run_at) WHERE enabled = true AND deleted_at IS NULL;
CREATE INDEX idx_scheduled_experiments_experiment_id ON scheduled_experiments(experiment_id) WHERE deleted_at IS NULL;

-- Experiment templates table (for GitHub integration)
CREATE TABLE experiment_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    repository VARCHAR(500) NOT NULL,
    path VARCHAR(1000) NOT NULL,
    branch VARCHAR(255) NOT NULL DEFAULT 'main',
    commit_sha VARCHAR(64),
    content TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    labels JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255) NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT unq_template_repo_path UNIQUE (repository, path, branch)
);

-- Create indexes for experiment templates
CREATE INDEX idx_experiment_templates_name ON experiment_templates(name) WHERE deleted_at IS NULL;
CREATE INDEX idx_experiment_templates_repository ON experiment_templates(repository) WHERE deleted_at IS NULL;
CREATE INDEX idx_experiment_templates_labels ON experiment_templates USING GIN(labels) WHERE deleted_at IS NULL;

-- Safety metrics table
CREATE TABLE safety_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id UUID NOT NULL REFERENCES executions(id),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    failure_rate NUMERIC(5,2),
    total_failures INTEGER,
    success_rate NUMERIC(5,2),
    response_time_ms BIGINT,
    cpu_usage NUMERIC(5,2),
    memory_usage NUMERIC(5,2),
    disk_usage NUMERIC(5,2),
    network_io NUMERIC(10,2),
    custom_metrics JSONB,
    health_status VARCHAR(50),
    active_targets INTEGER,
    completed_actions INTEGER,
    failed_actions INTEGER,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for safety metrics
CREATE INDEX idx_safety_metrics_execution_id ON safety_metrics(execution_id);
CREATE INDEX idx_safety_metrics_timestamp ON safety_metrics(execution_id, timestamp DESC);

-- Functions for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at columns
CREATE TRIGGER update_experiments_updated_at BEFORE UPDATE ON experiments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_executions_updated_at BEFORE UPDATE ON executions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_targets_updated_at BEFORE UPDATE ON targets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_results_updated_at BEFORE UPDATE ON results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_provider_configs_updated_at BEFORE UPDATE ON provider_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scheduled_experiments_updated_at BEFORE UPDATE ON scheduled_experiments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_experiment_templates_updated_at BEFORE UPDATE ON experiment_templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE experiments IS 'Stores chaos experiment definitions';
COMMENT ON TABLE executions IS 'Stores experiment execution instances';
COMMENT ON TABLE targets IS 'Stores infrastructure targets for chaos experiments';
COMMENT ON TABLE results IS 'Stores experiment execution results';
COMMENT ON TABLE provider_configs IS 'Stores cloud provider configurations';
COMMENT ON TABLE domain_events IS 'Event sourcing table for domain events';
COMMENT ON TABLE audit_logs IS 'Audit trail for all system changes';
COMMENT ON TABLE scheduled_experiments IS 'Stores scheduled experiment configurations';
COMMENT ON TABLE experiment_templates IS 'Stores experiment templates from GitHub repositories';
COMMENT ON TABLE safety_metrics IS 'Stores real-time safety metrics during experiment execution';