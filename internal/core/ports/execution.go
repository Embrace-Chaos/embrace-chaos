package ports

import (
	"context"

	"github.com/embrace-chaos/internal/core/domain"
)

// ExecutionService defines the primary port for execution operations
type ExecutionService interface {
	// Execution lifecycle operations
	StartExecution(ctx context.Context, req StartExecutionRequest) (*domain.Execution, error)
	GetExecution(ctx context.Context, id domain.ExecutionID) (*domain.Execution, error)
	UpdateExecution(ctx context.Context, id domain.ExecutionID, req UpdateExecutionRequest) (*domain.Execution, error)
	CancelExecution(ctx context.Context, id domain.ExecutionID, reason string) error
	PauseExecution(ctx context.Context, id domain.ExecutionID, reason string) error
	ResumeExecution(ctx context.Context, id domain.ExecutionID) error
	
	// Execution querying
	ListExecutions(ctx context.Context, req ListExecutionsRequest) (*ListExecutionsResponse, error)
	ListExecutionsByExperiment(ctx context.Context, experimentID domain.ExperimentID, req ListExecutionsRequest) (*ListExecutionsResponse, error)
	SearchExecutions(ctx context.Context, req SearchExecutionsRequest) (*SearchExecutionsResponse, error)
	
	// Execution monitoring
	GetExecutionStatus(ctx context.Context, id domain.ExecutionID) (*ExecutionStatusResponse, error)
	GetExecutionProgress(ctx context.Context, id domain.ExecutionID) (*ExecutionProgressResponse, error)
	GetExecutionLogs(ctx context.Context, id domain.ExecutionID, req LogsRequest) (*LogsResponse, error)
	StreamExecutionLogs(ctx context.Context, id domain.ExecutionID, req StreamLogsRequest) (<-chan LogEvent, error)
	
	// Execution results
	GetExecutionResults(ctx context.Context, id domain.ExecutionID) (*domain.Result, error)
	GetExecutionMetrics(ctx context.Context, id domain.ExecutionID, req MetricsRequest) (*MetricsResponse, error)
	ExportExecutionData(ctx context.Context, id domain.ExecutionID, format string) (*ExportResponse, error)
	
	// Execution rollback and recovery
	RollbackExecution(ctx context.Context, id domain.ExecutionID, req RollbackRequest) error
	GetRollbackStatus(ctx context.Context, id domain.ExecutionID) (*RollbackStatusResponse, error)
	
	// Batch operations
	BulkCancelExecutions(ctx context.Context, req BulkCancelRequest) (*BulkOperationResponse, error)
	BulkPauseExecutions(ctx context.Context, req BulkPauseRequest) (*BulkOperationResponse, error)
	
	// Execution analytics
	GetExecutionStatistics(ctx context.Context, req ExecutionStatsRequest) (*ExecutionStatisticsResponse, error)
	GetExecutionTrends(ctx context.Context, req TrendsRequest) (*TrendsResponse, error)
}

// StartExecutionRequest represents the request to start an execution
type StartExecutionRequest struct {
	ExperimentID domain.ExperimentID      `json:"experiment_id" validate:"required"`
	TriggerType  string                   `json:"trigger_type" validate:"required"`
	TriggeredBy  string                   `json:"triggered_by" validate:"required"`
	DryRun       bool                     `json:"dry_run"`
	Config       domain.ExecutionConfig   `json:"config" validate:"required"`
	Context      map[string]string        `json:"context,omitempty"`
	Metadata     map[string]interface{}   `json:"metadata,omitempty"`
}

// UpdateExecutionRequest represents the request to update an execution
type UpdateExecutionRequest struct {
	Status    *domain.ExecutionStatus   `json:"status,omitempty"`
	Phase     *domain.ExecutionPhase    `json:"phase,omitempty"`
	Progress  *domain.ExecutionProgress `json:"progress,omitempty"`
	Error     *domain.ExecutionError    `json:"error,omitempty"`
	Metadata  map[string]interface{}    `json:"metadata,omitempty"`
	UpdatedBy string                    `json:"updated_by" validate:"required"`
}

// ListExecutionsRequest represents the request to list executions
type ListExecutionsRequest struct {
	Pagination PaginationRequest         `json:"pagination"`
	Filters    ExecutionFilters          `json:"filters"`
	Sort       SortRequest               `json:"sort"`
}

// ListExecutionsResponse represents the response for listing executions
type ListExecutionsResponse struct {
	Executions []domain.Execution        `json:"executions"`
	Pagination PaginationResponse        `json:"pagination"`
	Total      int64                     `json:"total"`
}

// SearchExecutionsRequest represents the request to search executions
type SearchExecutionsRequest struct {
	Query      string                    `json:"query" validate:"required,min=1"`
	Filters    ExecutionFilters          `json:"filters"`
	Pagination PaginationRequest         `json:"pagination"`
	Sort       SortRequest               `json:"sort"`
}

// SearchExecutionsResponse represents the response for searching executions
type SearchExecutionsResponse struct {
	Executions []ExecutionSearchResult   `json:"executions"`
	Pagination PaginationResponse        `json:"pagination"`
	Total      int64                     `json:"total"`
	Suggestions []string                 `json:"suggestions"`
}

// ExecutionSearchResult represents a search result with highlighting
type ExecutionSearchResult struct {
	Execution   domain.Execution          `json:"execution"`
	Score       float64                   `json:"score"`
	Highlights  map[string][]string       `json:"highlights"`
	MatchedFields []string                `json:"matched_fields"`
}

// ExecutionFilters represents filters for execution queries
type ExecutionFilters struct {
	Status        []domain.ExecutionStatus `json:"status,omitempty"`
	Phase         []domain.ExecutionPhase  `json:"phase,omitempty"`
	ExperimentID  []domain.ExperimentID    `json:"experiment_id,omitempty"`
	TriggeredBy   []string                 `json:"triggered_by,omitempty"`
	TriggerType   []string                 `json:"trigger_type,omitempty"`
	StartedFrom   *string                  `json:"started_from,omitempty"`
	StartedTo     *string                  `json:"started_to,omitempty"`
	CompletedFrom *string                  `json:"completed_from,omitempty"`
	CompletedTo   *string                  `json:"completed_to,omitempty"`
	MinDuration   *domain.Duration         `json:"min_duration,omitempty"`
	MaxDuration   *domain.Duration         `json:"max_duration,omitempty"`
	HasErrors     *bool                    `json:"has_errors,omitempty"`
	HasSafetyViolations *bool              `json:"has_safety_violations,omitempty"`
	Provider      []string                 `json:"provider,omitempty"`
	DryRun        *bool                    `json:"dry_run,omitempty"`
}

// ExecutionStatusResponse represents the current status of an execution
type ExecutionStatusResponse struct {
	ID                domain.ExecutionID     `json:"id"`
	Status            domain.ExecutionStatus `json:"status"`
	Phase             domain.ExecutionPhase  `json:"phase"`
	StartTime         *string                `json:"start_time,omitempty"`
	EndTime           *string                `json:"end_time,omitempty"`
	Duration          *domain.Duration       `json:"duration,omitempty"`
	IsRunning         bool                   `json:"is_running"`
	IsCompleted       bool                   `json:"is_completed"`
	CanCancel         bool                   `json:"can_cancel"`
	CanPause          bool                   `json:"can_pause"`
	CanResume         bool                   `json:"can_resume"`
	CanRollback       bool                   `json:"can_rollback"`
	LastUpdated       string                 `json:"last_updated"`
}

// ExecutionProgressResponse represents the progress of an execution
type ExecutionProgressResponse struct {
	ID               domain.ExecutionID     `json:"id"`
	Progress         domain.ExecutionProgress `json:"progress"`
	CurrentStep      string                 `json:"current_step"`
	EstimatedTimeRemaining *domain.Duration `json:"estimated_time_remaining,omitempty"`
	TargetProgress   []TargetProgress       `json:"target_progress"`
	PhaseProgress    []PhaseProgress        `json:"phase_progress"`
	RecentEvents     []ProgressEvent        `json:"recent_events"`
}

// TargetProgress represents progress for a specific target
type TargetProgress struct {
	TargetID    string  `json:"target_id"`
	TargetName  string  `json:"target_name"`
	Status      string  `json:"status"`
	Progress    float64 `json:"progress"`
	CurrentStep string  `json:"current_step"`
	Error       string  `json:"error,omitempty"`
}

// PhaseProgress represents progress for a specific phase
type PhaseProgress struct {
	Phase       domain.ExecutionPhase `json:"phase"`
	Status      string                `json:"status"`
	Progress    float64               `json:"progress"`
	StartTime   *string               `json:"start_time,omitempty"`
	EndTime     *string               `json:"end_time,omitempty"`
	Duration    *domain.Duration      `json:"duration,omitempty"`
}

// ProgressEvent represents a progress event
type ProgressEvent struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Message   string `json:"message"`
	Level     string `json:"level"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

// LogsRequest represents a request for execution logs
type LogsRequest struct {
	Pagination PaginationRequest `json:"pagination"`
	Level      []string          `json:"level,omitempty"`
	From       *string           `json:"from,omitempty"`
	To         *string           `json:"to,omitempty"`
	Query      string            `json:"query,omitempty"`
	TargetID   string            `json:"target_id,omitempty"`
	Phase      string            `json:"phase,omitempty"`
}

// LogsResponse represents the response for execution logs
type LogsResponse struct {
	Logs       []LogEntry        `json:"logs"`
	Pagination PaginationResponse `json:"pagination"`
	Total      int64             `json:"total"`
}

// LogEntry represents a single log entry
type LogEntry struct {
	ID        string                 `json:"id"`
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Phase     string                 `json:"phase,omitempty"`
	TargetID  string                 `json:"target_id,omitempty"`
	Provider  string                 `json:"provider,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// StreamLogsRequest represents a request for streaming logs
type StreamLogsRequest struct {
	Follow    bool     `json:"follow"`
	TailLines int      `json:"tail_lines"`
	Level     []string `json:"level,omitempty"`
	Query     string   `json:"query,omitempty"`
	TargetID  string   `json:"target_id,omitempty"`
	Phase     string   `json:"phase,omitempty"`
}

// LogEvent represents a streaming log event
type LogEvent struct {
	Type      string    `json:"type"`
	LogEntry  *LogEntry `json:"log_entry,omitempty"`
	Error     error     `json:"error,omitempty"`
	Completed bool      `json:"completed"`
}

// MetricsRequest represents a request for execution metrics
type MetricsRequest struct {
	MetricTypes []string `json:"metric_types,omitempty"`
	From        *string  `json:"from,omitempty"`
	To          *string  `json:"to,omitempty"`
	Granularity string   `json:"granularity,omitempty"`
	TargetID    string   `json:"target_id,omitempty"`
}

// MetricsResponse represents the response for execution metrics
type MetricsResponse struct {
	Metrics       map[string]MetricSeries `json:"metrics"`
	Summary       MetricsSummary          `json:"summary"`
	CollectedAt   string                  `json:"collected_at"`
	CollectionDuration domain.Duration    `json:"collection_duration"`
}

// MetricSeries represents a time series of metric values
type MetricSeries struct {
	Name        string              `json:"name"`
	Unit        string              `json:"unit"`
	Type        string              `json:"type"`
	Description string              `json:"description"`
	DataPoints  []MetricDataPoint   `json:"data_points"`
	Aggregation MetricAggregation   `json:"aggregation"`
}

// MetricDataPoint represents a single metric data point
type MetricDataPoint struct {
	Timestamp string  `json:"timestamp"`
	Value     float64 `json:"value"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// MetricAggregation represents aggregated metric values
type MetricAggregation struct {
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Avg    float64 `json:"avg"`
	Sum    float64 `json:"sum"`
	Count  int64   `json:"count"`
	Median float64 `json:"median"`
	P95    float64 `json:"p95"`
	P99    float64 `json:"p99"`
}

// MetricsSummary represents a summary of metrics
type MetricsSummary struct {
	TotalDataPoints int64                  `json:"total_data_points"`
	TimeRange       TimeRange              `json:"time_range"`
	Targets         []string               `json:"targets"`
	Providers       []string               `json:"providers"`
	Anomalies       []MetricAnomaly        `json:"anomalies"`
}

// TimeRange represents a time range
type TimeRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// MetricAnomaly represents a detected anomaly in metrics
type MetricAnomaly struct {
	MetricName  string  `json:"metric_name"`
	Timestamp   string  `json:"timestamp"`
	Value       float64 `json:"value"`
	Expected    float64 `json:"expected"`
	Deviation   float64 `json:"deviation"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
}

// ExportResponse represents the response for data export
type ExportResponse struct {
	Format      string `json:"format"`
	Size        int64  `json:"size"`
	URL         string `json:"url,omitempty"`
	Data        []byte `json:"data,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Checksum    string `json:"checksum"`
}

// RollbackRequest represents a request to rollback an execution
type RollbackRequest struct {
	Reason      string            `json:"reason" validate:"required"`
	RequestedBy string            `json:"requested_by" validate:"required"`
	Targets     []string          `json:"targets,omitempty"`
	Context     map[string]string `json:"context,omitempty"`
}

// RollbackStatusResponse represents the status of a rollback operation
type RollbackStatusResponse struct {
	ExecutionID   domain.ExecutionID `json:"execution_id"`
	Status        string             `json:"status"`
	Progress      float64            `json:"progress"`
	StartTime     *string            `json:"start_time,omitempty"`
	EndTime       *string            `json:"end_time,omitempty"`
	Duration      *domain.Duration   `json:"duration,omitempty"`
	TargetResults []RollbackTargetResult `json:"target_results"`
	Error         string             `json:"error,omitempty"`
}

// RollbackTargetResult represents the rollback result for a specific target
type RollbackTargetResult struct {
	TargetID  string `json:"target_id"`
	Status    string `json:"status"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	Actions   []RollbackAction `json:"actions"`
}

// RollbackAction represents a rollback action
type RollbackAction struct {
	ActionType  string                 `json:"action_type"`
	Status      string                 `json:"status"`
	Success     bool                   `json:"success"`
	StartTime   string                 `json:"start_time"`
	EndTime     *string                `json:"end_time,omitempty"`
	Duration    *domain.Duration       `json:"duration,omitempty"`
	Output      string                 `json:"output,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// BulkCancelRequest represents a request to cancel multiple executions
type BulkCancelRequest struct {
	ExecutionIDs []domain.ExecutionID `json:"execution_ids" validate:"required,min=1"`
	Reason       string               `json:"reason" validate:"required"`
	RequestedBy  string               `json:"requested_by" validate:"required"`
	Context      map[string]string    `json:"context,omitempty"`
}

// BulkPauseRequest represents a request to pause multiple executions
type BulkPauseRequest struct {
	ExecutionIDs []domain.ExecutionID `json:"execution_ids" validate:"required,min=1"`
	Reason       string               `json:"reason" validate:"required"`
	RequestedBy  string               `json:"requested_by" validate:"required"`
	Context      map[string]string    `json:"context,omitempty"`
}

// BulkOperationResponse represents the response for bulk operations
type BulkOperationResponse struct {
	TotalRequested int64                    `json:"total_requested"`
	Successful     int64                    `json:"successful"`
	Failed         int64                    `json:"failed"`
	Results        []BulkOperationResult    `json:"results"`
	Errors         []BulkOperationError     `json:"errors"`
	Duration       domain.Duration          `json:"duration"`
}

// BulkOperationResult represents the result of a single operation in a bulk request
type BulkOperationResult struct {
	ExecutionID domain.ExecutionID `json:"execution_id"`
	Success     bool               `json:"success"`
	Error       string             `json:"error,omitempty"`
}

// BulkOperationError represents an error in bulk operations
type BulkOperationError struct {
	ExecutionID domain.ExecutionID `json:"execution_id"`
	ErrorCode   string             `json:"error_code"`
	ErrorMessage string            `json:"error_message"`
}

// ExecutionStatsRequest represents a request for execution statistics
type ExecutionStatsRequest struct {
	TimeRange     TimeRange         `json:"time_range"`
	ExperimentIDs []domain.ExperimentID `json:"experiment_ids,omitempty"`
	Granularity   string            `json:"granularity,omitempty"`
	GroupBy       []string          `json:"group_by,omitempty"`
}

// ExecutionStatisticsResponse represents the response for execution statistics
type ExecutionStatisticsResponse struct {
	Overview     ExecutionOverview         `json:"overview"`
	TimeSeries   []ExecutionTimeSeriesData `json:"time_series"`
	Breakdown    map[string]ExecutionBreakdown `json:"breakdown"`
	Trends       ExecutionTrends           `json:"trends"`
	GeneratedAt  string                    `json:"generated_at"`
}

// ExecutionOverview represents overall execution statistics
type ExecutionOverview struct {
	TotalExecutions      int64   `json:"total_executions"`
	SuccessfulExecutions int64   `json:"successful_executions"`
	FailedExecutions     int64   `json:"failed_executions"`
	CancelledExecutions  int64   `json:"cancelled_executions"`
	SuccessRate          float64 `json:"success_rate"`
	AverageExecutionTime domain.Duration `json:"average_execution_time"`
	TotalExecutionTime   domain.Duration `json:"total_execution_time"`
	SafetyViolations     int64   `json:"safety_violations"`
	AutoRollbacks        int64   `json:"auto_rollbacks"`
}

// ExecutionTimeSeriesData represents time series data for executions
type ExecutionTimeSeriesData struct {
	Timestamp        string `json:"timestamp"`
	TotalExecutions  int64  `json:"total_executions"`
	SuccessfulExecutions int64 `json:"successful_executions"`
	FailedExecutions int64  `json:"failed_executions"`
	AverageExecutionTime domain.Duration `json:"average_execution_time"`
	SafetyViolations int64  `json:"safety_violations"`
}

// ExecutionBreakdown represents execution statistics broken down by a dimension
type ExecutionBreakdown struct {
	Dimension string                        `json:"dimension"`
	Values    map[string]ExecutionOverview  `json:"values"`
}

// ExecutionTrends represents execution trends
type ExecutionTrends struct {
	ExecutionCountTrend    TrendData `json:"execution_count_trend"`
	SuccessRateTrend       TrendData `json:"success_rate_trend"`
	ExecutionTimeTrend     TrendData `json:"execution_time_trend"`
	SafetyViolationsTrend  TrendData `json:"safety_violations_trend"`
}

// TrendData represents trend data
type TrendData struct {
	Direction   string  `json:"direction"` // "up", "down", "stable"
	Percentage  float64 `json:"percentage"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// TrendsRequest represents a request for trend analysis
type TrendsRequest struct {
	TimeRange     TimeRange `json:"time_range"`
	CompareWith   TimeRange `json:"compare_with"`
	Metrics       []string  `json:"metrics,omitempty"`
	ExperimentIDs []domain.ExperimentID `json:"experiment_ids,omitempty"`
}

// TrendsResponse represents the response for trend analysis
type TrendsResponse struct {
	Trends      map[string]TrendAnalysis `json:"trends"`
	Comparison  ComparisonData           `json:"comparison"`
	Insights    []TrendInsight           `json:"insights"`
	GeneratedAt string                   `json:"generated_at"`
}

// TrendAnalysis represents analysis of a specific trend
type TrendAnalysis struct {
	Metric      string    `json:"metric"`
	Trend       TrendData `json:"trend"`
	Forecast    []ForecastPoint `json:"forecast,omitempty"`
	Anomalies   []TrendAnomaly  `json:"anomalies"`
}

// ForecastPoint represents a forecasted data point
type ForecastPoint struct {
	Timestamp    string  `json:"timestamp"`
	Value        float64 `json:"value"`
	Confidence   float64 `json:"confidence"`
	LowerBound   float64 `json:"lower_bound"`
	UpperBound   float64 `json:"upper_bound"`
}

// TrendAnomaly represents an anomaly in trend data
type TrendAnomaly struct {
	Timestamp   string  `json:"timestamp"`
	Value       float64 `json:"value"`
	Expected    float64 `json:"expected"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
}

// ComparisonData represents comparison between time periods
type ComparisonData struct {
	BaselinePeriod TimeRange                    `json:"baseline_period"`
	ComparisonPeriod TimeRange                  `json:"comparison_period"`
	Changes        map[string]float64           `json:"changes"`
	Significances  map[string]bool              `json:"significances"`
}

// TrendInsight represents an insight from trend analysis
type TrendInsight struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Metric      string  `json:"metric,omitempty"`
	Value       float64 `json:"value,omitempty"`
	Threshold   float64 `json:"threshold,omitempty"`
	Confidence  float64 `json:"confidence"`
}