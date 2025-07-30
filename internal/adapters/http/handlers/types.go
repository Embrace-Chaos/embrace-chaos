package handlers

import (
	"time"
)

// Request types

type CreateExperimentRequest struct {
	Name        string                 `json:"name" validate:"required,max=255"`
	Description string                 `json:"description"`
	Config      ExperimentConfig       `json:"config" validate:"required"`
	Safety      SafetyConfig           `json:"safety" validate:"required"`
	Targets     []Target               `json:"targets" validate:"required,min=1"`
	Labels      map[string]string      `json:"labels"`
}

type UpdateExperimentRequest struct {
	Name        string                 `json:"name,omitempty" validate:"omitempty,max=255"`
	Description *string                `json:"description,omitempty"`
	Config      *ExperimentConfig      `json:"config,omitempty"`
	Safety      *SafetyConfig          `json:"safety,omitempty"`
	Targets     *[]Target              `json:"targets,omitempty" validate:"omitempty,min=1"`
	Labels      *map[string]string     `json:"labels,omitempty"`
}

type ExecuteExperimentRequest struct {
	DryRun     bool                   `json:"dry_run"`
	Parameters map[string]interface{} `json:"parameters"`
	TriggerBy  string                 `json:"trigger_by"`
}

type DiscoverTargetsRequest struct {
	Provider string            `json:"provider" validate:"required"`
	Region   string            `json:"region"`
	Filters  map[string]string `json:"filters"`
}

// Response types

type ExperimentListResponse struct {
	Experiments []interface{}    `json:"experiments"`
	Pagination  PaginationInfo   `json:"pagination"`
}

type ExecutionListResponse struct {
	Executions []interface{}    `json:"executions"`
	Pagination PaginationInfo   `json:"pagination"`
}

type TargetListResponse struct {
	Targets    []Target         `json:"targets"`
	Pagination PaginationInfo   `json:"pagination"`
}

type DiscoverTargetsResponse struct {
	Targets []Target `json:"targets"`
	Total   int      `json:"total"`
}

type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Message  string   `json:"message"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type LogResponse struct {
	Logs  []LogEntry `json:"logs"`
	Total int        `json:"total"`
}

type HealthResponse struct {
	Status    string                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Version   string                 `json:"version"`
	Checks    map[string]HealthCheck `json:"checks"`
}

type ReadinessResponse struct {
	Ready     bool      `json:"ready"`
	Timestamp time.Time `json:"timestamp"`
}

// Common types

type PaginationInfo struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

type ExperimentConfig struct {
	Duration        string       `json:"duration" validate:"required"`
	Parallelism     int          `json:"parallelism" validate:"required,min=1,max=100"`
	ConcurrencyMode string       `json:"concurrency_mode"`
	Timeout         string       `json:"timeout"`
	RetryPolicy     *RetryPolicy `json:"retry_policy,omitempty"`
}

type RetryPolicy struct {
	MaxRetries      int    `json:"max_retries" validate:"min=0,max=10"`
	BackoffStrategy string `json:"backoff_strategy"`
	InitialDelay    string `json:"initial_delay"`
	MaxDelay        string `json:"max_delay"`
}

type SafetyConfig struct {
	MaxFailures        int                    `json:"max_failures" validate:"min=0"`
	FailureThreshold   float64                `json:"failure_threshold" validate:"min=0,max=100"`
	AutoRollback       bool                   `json:"auto_rollback"`
	RollbackTimeout    string                 `json:"rollback_timeout"`
	PreflightChecks    []string               `json:"preflight_checks"`
	HealthChecks       []string               `json:"health_checks"`
	MonitoringPeriod   string                 `json:"monitoring_period"`
	AlertThresholds    map[string]float64     `json:"alert_thresholds"`
}

type Target struct {
	ID         string                 `json:"id"`
	ResourceID string                 `json:"resource_id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Provider   string                 `json:"provider"`
	Region     string                 `json:"region"`
	Tags       map[string]string      `json:"tags"`
	Status     string                 `json:"status"`
	Metadata   map[string]interface{} `json:"metadata"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type HealthCheck struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	Duration string `json:"duration"`
}