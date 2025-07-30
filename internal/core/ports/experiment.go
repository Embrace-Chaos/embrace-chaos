package ports

import (
	"context"

	"github.com/embrace-chaos/internal/core/domain"
)

// ExperimentService defines the primary port for experiment operations
type ExperimentService interface {
	// Experiment CRUD operations
	CreateExperiment(ctx context.Context, req CreateExperimentRequest) (*domain.Experiment, error)
	GetExperiment(ctx context.Context, id domain.ExperimentID) (*domain.Experiment, error)
	GetExperimentByName(ctx context.Context, name string) (*domain.Experiment, error)
	UpdateExperiment(ctx context.Context, id domain.ExperimentID, req UpdateExperimentRequest) (*domain.Experiment, error)
	DeleteExperiment(ctx context.Context, id domain.ExperimentID) error
	
	// Experiment querying
	ListExperiments(ctx context.Context, req ListExperimentsRequest) (*ListExperimentsResponse, error)
	SearchExperiments(ctx context.Context, req SearchExperimentsRequest) (*SearchExperimentsResponse, error)
	
	// Experiment lifecycle operations
	ActivateExperiment(ctx context.Context, id domain.ExperimentID) error
	DeactivateExperiment(ctx context.Context, id domain.ExperimentID) error
	CloneExperiment(ctx context.Context, id domain.ExperimentID, newName string) (*domain.Experiment, error)
	
	// Experiment execution
	ExecuteExperiment(ctx context.Context, id domain.ExperimentID, req ExecuteExperimentRequest) (*domain.Execution, error)
	ScheduleExperiment(ctx context.Context, id domain.ExperimentID, req ScheduleExperimentRequest) error
	CancelExperiment(ctx context.Context, id domain.ExperimentID) error
	
	// Experiment validation
	ValidateExperiment(ctx context.Context, experiment *domain.Experiment) error
	ValidateExperimentConfig(ctx context.Context, config domain.ExperimentConfig) error
	
	// Experiment statistics and analytics
	GetExperimentStats(ctx context.Context, id domain.ExperimentID) (*ExperimentStats, error)
	GetExperimentHistory(ctx context.Context, id domain.ExperimentID, req HistoryRequest) (*HistoryResponse, error)
	
	// Experiment templates and marketplace
	SaveAsTemplate(ctx context.Context, id domain.ExperimentID, req SaveTemplateRequest) (*ExperimentTemplate, error)
	ListTemplates(ctx context.Context, req ListTemplatesRequest) (*ListTemplatesResponse, error)
	CreateFromTemplate(ctx context.Context, templateID string, req CreateFromTemplateRequest) (*domain.Experiment, error)
}

// CreateExperimentRequest represents the request to create an experiment
type CreateExperimentRequest struct {
	Name        string                    `json:"name" validate:"required,min=1,max=255"`
	Description string                    `json:"description" validate:"max=1000"`
	Type        domain.ExperimentType     `json:"type" validate:"required"`
	Config      domain.ExperimentConfig   `json:"config" validate:"required"`
	Targets     []domain.Target           `json:"targets" validate:"required,min=1"`
	Safety      domain.SafetyConfig       `json:"safety"`
	Schedule    *domain.Schedule          `json:"schedule,omitempty"`
	Tags        []string                  `json:"tags" validate:"dive,max=50"`
	CreatedBy   string                    `json:"created_by" validate:"required"`
}

// UpdateExperimentRequest represents the request to update an experiment
type UpdateExperimentRequest struct {
	Name        *string                   `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Description *string                   `json:"description,omitempty" validate:"omitempty,max=1000"`
	Config      *domain.ExperimentConfig  `json:"config,omitempty"`
	Targets     []domain.Target           `json:"targets,omitempty" validate:"omitempty,min=1"`
	Safety      *domain.SafetyConfig      `json:"safety,omitempty"`
	Schedule    *domain.Schedule          `json:"schedule,omitempty"`
	Tags        []string                  `json:"tags,omitempty" validate:"dive,max=50"`
	UpdatedBy   string                    `json:"updated_by" validate:"required"`
}

// ListExperimentsRequest represents the request to list experiments
type ListExperimentsRequest struct {
	Pagination PaginationRequest         `json:"pagination"`
	Filters    ExperimentFilters         `json:"filters"`
	Sort       SortRequest               `json:"sort"`
}

// ListExperimentsResponse represents the response for listing experiments
type ListExperimentsResponse struct {
	Experiments []domain.Experiment       `json:"experiments"`
	Pagination  PaginationResponse        `json:"pagination"`
	Total       int64                     `json:"total"`
}

// SearchExperimentsRequest represents the request to search experiments
type SearchExperimentsRequest struct {
	Query      string                    `json:"query" validate:"required,min=1"`
	Filters    ExperimentFilters         `json:"filters"`
	Pagination PaginationRequest         `json:"pagination"`
	Sort       SortRequest               `json:"sort"`
}

// SearchExperimentsResponse represents the response for searching experiments
type SearchExperimentsResponse struct {
	Experiments []ExperimentSearchResult  `json:"experiments"`
	Pagination  PaginationResponse        `json:"pagination"`
	Total       int64                     `json:"total"`
	Suggestions []string                  `json:"suggestions"`
}

// ExperimentSearchResult represents a search result with highlighting
type ExperimentSearchResult struct {
	Experiment  domain.Experiment         `json:"experiment"`
	Score       float64                   `json:"score"`
	Highlights  map[string][]string       `json:"highlights"`
	MatchedFields []string                `json:"matched_fields"`
}

// ExperimentFilters represents filters for experiment queries
type ExperimentFilters struct {
	Status      []domain.ExperimentStatus `json:"status,omitempty"`
	Type        []domain.ExperimentType   `json:"type,omitempty"`
	Tags        []string                  `json:"tags,omitempty"`
	CreatedBy   []string                  `json:"created_by,omitempty"`
	CreatedFrom *string                   `json:"created_from,omitempty"`
	CreatedTo   *string                   `json:"created_to,omitempty"`
	UpdatedFrom *string                   `json:"updated_from,omitempty"`
	UpdatedTo   *string                   `json:"updated_to,omitempty"`
	Provider    []string                  `json:"provider,omitempty"`
	HasSchedule *bool                     `json:"has_schedule,omitempty"`
}

// ExecuteExperimentRequest represents the request to execute an experiment
type ExecuteExperimentRequest struct {
	TriggerType string                    `json:"trigger_type" validate:"required"`
	TriggeredBy string                    `json:"triggered_by" validate:"required"`
	DryRun      bool                      `json:"dry_run"`
	Overrides   *ExecutionOverrides       `json:"overrides,omitempty"`
	Context     map[string]string         `json:"context,omitempty"`
}

// ExecutionOverrides allows overriding experiment configuration for a single execution
type ExecutionOverrides struct {
	Duration    *domain.Duration          `json:"duration,omitempty"`
	Intensity   *domain.Percentage        `json:"intensity,omitempty"`
	Parameters  map[string]interface{}    `json:"parameters,omitempty"`
	Safety      *domain.SafetyConfig      `json:"safety,omitempty"`
	Targets     []string                  `json:"targets,omitempty"` // Target IDs to override
}

// ScheduleExperimentRequest represents the request to schedule an experiment
type ScheduleExperimentRequest struct {
	Schedule    domain.Schedule           `json:"schedule" validate:"required"`
	ScheduledBy string                    `json:"scheduled_by" validate:"required"`
	Context     map[string]string         `json:"context,omitempty"`
}

// ExperimentStats represents experiment statistics
type ExperimentStats struct {
	TotalExecutions    int64                 `json:"total_executions"`
	SuccessfulExecutions int64               `json:"successful_executions"`
	FailedExecutions   int64                 `json:"failed_executions"`
	SuccessRate        float64               `json:"success_rate"`
	
	AverageExecutionTime domain.Duration     `json:"average_execution_time"`
	LastExecutionTime    *string             `json:"last_execution_time,omitempty"`
	
	TargetStats        map[string]TargetStats `json:"target_stats"`
	ProviderStats      map[string]ProviderStats `json:"provider_stats"`
	
	SafetyViolations   int64                 `json:"safety_violations"`
	AutoRollbacks      int64                 `json:"auto_rollbacks"`
	
	CreatedAt          string                `json:"created_at"`
	LastUpdated        string                `json:"last_updated"`
}

// TargetStats represents statistics for a specific target
type TargetStats struct {
	TotalExecutions    int64   `json:"total_executions"`
	SuccessfulExecutions int64 `json:"successful_executions"`
	FailedExecutions   int64   `json:"failed_executions"`
	SuccessRate        float64 `json:"success_rate"`
	AverageResponseTime domain.Duration `json:"average_response_time"`
}

// ProviderStats represents statistics for a specific provider
type ProviderStats struct {
	TotalExecutions    int64   `json:"total_executions"`
	SuccessfulExecutions int64 `json:"successful_executions"`
	FailedExecutions   int64   `json:"failed_executions"`
	SuccessRate        float64 `json:"success_rate"`
	AverageLatency     domain.Duration `json:"average_latency"`
}

// HistoryRequest represents a request for experiment history
type HistoryRequest struct {
	Pagination PaginationRequest         `json:"pagination"`
	EventTypes []string                  `json:"event_types,omitempty"`
	From       *string                   `json:"from,omitempty"`
	To         *string                   `json:"to,omitempty"`
	UserID     *string                   `json:"user_id,omitempty"`
}

// HistoryResponse represents the response for experiment history
type HistoryResponse struct {
	Events     []ExperimentHistoryEvent  `json:"events"`
	Pagination PaginationResponse        `json:"pagination"`
	Total      int64                     `json:"total"`
}

// ExperimentHistoryEvent represents a historical event for an experiment
type ExperimentHistoryEvent struct {
	ID          string                    `json:"id"`
	Type        string                    `json:"type"`
	Timestamp   string                    `json:"timestamp"`
	UserID      string                    `json:"user_id"`
	UserName    string                    `json:"user_name"`
	Description string                    `json:"description"`
	Changes     map[string]interface{}    `json:"changes,omitempty"`
	Context     map[string]string         `json:"context,omitempty"`
}

// ExperimentTemplate represents an experiment template
type ExperimentTemplate struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Category    string                    `json:"category"`
	Version     string                    `json:"version"`
	Author      string                    `json:"author"`
	
	Template    ExperimentTemplateData    `json:"template"`
	
	Metadata    TemplateMetadata          `json:"metadata"`
	
	CreatedAt   string                    `json:"created_at"`
	UpdatedAt   string                    `json:"updated_at"`
}

// ExperimentTemplateData represents the template data
type ExperimentTemplateData struct {
	Type        domain.ExperimentType     `json:"type"`
	Config      domain.ExperimentConfig   `json:"config"`
	Safety      domain.SafetyConfig       `json:"safety"`
	
	// Template variables
	Variables   []TemplateVariable        `json:"variables"`
	
	// Default targets (can be overridden)
	DefaultTargets []domain.Target        `json:"default_targets"`
}

// TemplateVariable represents a template variable
type TemplateVariable struct {
	Name        string                    `json:"name"`
	Type        string                    `json:"type"`
	Required    bool                      `json:"required"`
	Default     interface{}               `json:"default,omitempty"`
	Description string                    `json:"description"`
	Validation  map[string]interface{}    `json:"validation,omitempty"`
}

// TemplateMetadata represents template metadata
type TemplateMetadata struct {
	Tags        []string                  `json:"tags"`
	Difficulty  string                    `json:"difficulty"`
	Duration    domain.Duration           `json:"duration"`
	Provider    string                    `json:"provider"`
	Rating      float64                   `json:"rating"`
	UsageCount  int64                     `json:"usage_count"`
	Public      bool                      `json:"public"`
}

// SaveTemplateRequest represents the request to save an experiment as template
type SaveTemplateRequest struct {
	Name        string                    `json:"name" validate:"required,min=1,max=255"`
	Description string                    `json:"description" validate:"max=1000"`
	Category    string                    `json:"category" validate:"required"`
	Public      bool                      `json:"public"`
	Tags        []string                  `json:"tags" validate:"dive,max=50"`
	Variables   []TemplateVariable        `json:"variables"`
}

// ListTemplatesRequest represents the request to list templates
type ListTemplatesRequest struct {
	Pagination PaginationRequest         `json:"pagination"`
	Filters    TemplateFilters           `json:"filters"`
	Sort       SortRequest               `json:"sort"`
}

// ListTemplatesResponse represents the response for listing templates
type ListTemplatesResponse struct {
	Templates  []ExperimentTemplate      `json:"templates"`
	Pagination PaginationResponse        `json:"pagination"`
	Total      int64                     `json:"total"`
}

// TemplateFilters represents filters for template queries
type TemplateFilters struct {
	Category    []string                  `json:"category,omitempty"`
	Tags        []string                  `json:"tags,omitempty"`
	Author      []string                  `json:"author,omitempty"`
	Difficulty  []string                  `json:"difficulty,omitempty"`
	Provider    []string                  `json:"provider,omitempty"`
	Public      *bool                     `json:"public,omitempty"`
	MinRating   *float64                  `json:"min_rating,omitempty"`
}

// CreateFromTemplateRequest represents the request to create experiment from template
type CreateFromTemplateRequest struct {
	Name        string                    `json:"name" validate:"required,min=1,max=255"`
	Description string                    `json:"description" validate:"max=1000"`
	Variables   map[string]interface{}    `json:"variables"`
	Targets     []domain.Target           `json:"targets,omitempty"`
	Tags        []string                  `json:"tags" validate:"dive,max=50"`
	CreatedBy   string                    `json:"created_by" validate:"required"`
}

// Common request/response types

// PaginationRequest represents pagination parameters
type PaginationRequest struct {
	Page     int `json:"page" validate:"min=1"`
	PageSize int `json:"page_size" validate:"min=1,max=1000"`
}

// PaginationResponse represents pagination information in response
type PaginationResponse struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalPages int   `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// SortRequest represents sorting parameters
type SortRequest struct {
	Field     string `json:"field"`
	Direction string `json:"direction" validate:"oneof=asc desc"`
}