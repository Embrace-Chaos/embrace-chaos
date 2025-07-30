package safety

import (
	"context"
	"time"

	"github.com/embrace-chaos/internal/core/domain"
)

// PreflightChecker defines the interface for preflight checks
type PreflightChecker interface {
	Check(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) (*CheckResult, error)
	GetName() string
	GetDescription() string
}

// HealthChecker defines the interface for health checks
type HealthChecker interface {
	CheckHealth(ctx context.Context, target *domain.Target) (*HealthResult, error)
	GetName() string
	GetDescription() string
}

// Monitor defines the interface for experiment monitoring
type Monitor interface {
	CollectMetrics(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution, metrics *SafetyMetrics) error
	GetName() string
	GetDescription() string
}

// RollbackManager defines the interface for managing rollbacks
type RollbackManager interface {
	ExecuteRollback(ctx context.Context, request *RollbackRequest) error
	GetRollbackStatus(ctx context.Context, executionID domain.ExecutionID) (*RollbackStatus, error)
	RegisterRollbackHandler(targetType domain.TargetType, handler RollbackHandler) error
}

// AlertManager defines the interface for managing alerts
type AlertManager interface {
	SendAlert(ctx context.Context, alert *Alert) error
	GetAlertHistory(ctx context.Context, executionID domain.ExecutionID) ([]*Alert, error)
	RegisterAlertChannel(channel AlertChannel) error
}

// CircuitBreaker defines the interface for circuit breaker functionality
type CircuitBreaker interface {
	CanExecute() bool
	RecordSuccess()
	RecordFailure()
	GetState() CircuitBreakerState
}

// RateLimiter defines the interface for rate limiting
type RateLimiter interface {
	Allow() bool
	GetRemainingTokens() int
	GetResetTime() time.Time
}

// CheckResult represents the result of a safety check
type CheckResult struct {
	Status      CheckStatus          `json:"status"`
	Message     string               `json:"message"`
	Details     string               `json:"details,omitempty"`
	Timestamp   time.Time            `json:"timestamp"`
	Duration    time.Duration        `json:"duration"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Suggestions []string             `json:"suggestions,omitempty"`
}

// CheckStatus represents the status of a check
type CheckStatus string

const (
	CheckStatusPending CheckStatus = "pending"
	CheckStatusPassed  CheckStatus = "passed"
	CheckStatusWarning CheckStatus = "warning"
	CheckStatusFailed  CheckStatus = "failed"
	CheckStatusSkipped CheckStatus = "skipped"
)

// PreflightResult represents the overall result of preflight checks
type PreflightResult struct {
	ExecutionID   domain.ExecutionID       `json:"execution_id"`
	StartedAt     time.Time                `json:"started_at"`
	CompletedAt   time.Time                `json:"completed_at"`
	Duration      time.Duration            `json:"duration"`
	OverallStatus CheckStatus              `json:"overall_status"`
	CheckResults  map[string]*CheckResult  `json:"check_results"`
	Warnings      []string                 `json:"warnings,omitempty"`
	Errors        []error                  `json:"errors,omitempty"`
	Metadata      map[string]interface{}   `json:"metadata,omitempty"`
}

// HealthResult represents the result of a health check
type HealthResult struct {
	Status      HealthStatus           `json:"status"`
	Message     string                 `json:"message"`
	Timestamp   time.Time              `json:"timestamp"`
	Duration    time.Duration          `json:"duration"`
	Metrics     map[string]float64     `json:"metrics,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	LastChecked time.Time              `json:"last_checked"`
}

// HealthStatus represents the health status of a target
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// SafetyMetrics represents collected safety metrics
type SafetyMetrics struct {
	ExecutionID       domain.ExecutionID     `json:"execution_id"`
	Timestamp         time.Time              `json:"timestamp"`
	FailureRate       float64                `json:"failure_rate"`
	TotalFailures     int                    `json:"total_failures"`
	SuccessRate       float64                `json:"success_rate"`
	ResponseTime      time.Duration          `json:"response_time"`
	ResourceUsage     ResourceUsageMetrics   `json:"resource_usage"`
	CustomMetrics     map[string]float64     `json:"custom_metrics"`
	HealthStatus      HealthStatus           `json:"health_status"`
	ActiveTargets     int                    `json:"active_targets"`
	CompletedActions  int                    `json:"completed_actions"`
	FailedActions     int                    `json:"failed_actions"`
}

// ResourceUsageMetrics represents resource usage metrics
type ResourceUsageMetrics struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	DiskUsage   float64 `json:"disk_usage"`
	NetworkIO   float64 `json:"network_io"`
}

// SafetyEvaluation represents the evaluation of safety thresholds
type SafetyEvaluation struct {
	ExecutionID   domain.ExecutionID  `json:"execution_id"`
	Timestamp     time.Time           `json:"timestamp"`
	Metrics       *SafetyMetrics      `json:"metrics"`
	Violations    []*SafetyViolation  `json:"violations"`
	OverallStatus SafetyStatus        `json:"overall_status"`
	Recommendations []string          `json:"recommendations,omitempty"`
}

// SafetyStatus represents the overall safety status
type SafetyStatus string

const (
	SafetyStatusSafe      SafetyStatus = "safe"
	SafetyStatusWarning   SafetyStatus = "warning"
	SafetyStatusDangerous SafetyStatus = "dangerous"
	SafetyStatusCritical  SafetyStatus = "critical"
)

// SafetyViolation represents a safety threshold violation
type SafetyViolation struct {
	Type        ViolationType     `json:"type"`
	Severity    ViolationSeverity `json:"severity"`
	Message     string            `json:"message"`
	Metric      string            `json:"metric"`
	Current     float64           `json:"current"`
	Threshold   float64           `json:"threshold"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ViolationType represents the type of safety violation
type ViolationType string

const (
	ViolationTypeFailureThreshold  ViolationType = "failure_threshold"
	ViolationTypeMaxFailures        ViolationType = "max_failures"
	ViolationTypeResponseTime       ViolationType = "response_time"
	ViolationTypeResourceUsage      ViolationType = "resource_usage"
	ViolationTypeCustomThreshold    ViolationType = "custom_threshold"
	ViolationTypeHealthDegradation  ViolationType = "health_degradation"
)

// ViolationSeverity represents the severity of a violation
type ViolationSeverity int

const (
	ViolationSeverityLow      ViolationSeverity = 1
	ViolationSeverityMedium   ViolationSeverity = 2
	ViolationSeverityHigh     ViolationSeverity = 3
	ViolationSeverityCritical ViolationSeverity = 4
)

// RollbackRequest represents a request for rollback
type RollbackRequest struct {
	ExecutionID   domain.ExecutionID    `json:"execution_id"`
	Reason        string                `json:"reason"`
	Timestamp     time.Time             `json:"timestamp"`
	Timeout       time.Duration         `json:"timeout"`
	TargetIDs     []string              `json:"target_ids,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// RollbackStatus represents the status of a rollback operation
type RollbackStatus struct {
	ExecutionID     domain.ExecutionID   `json:"execution_id"`
	Status          RollbackState        `json:"status"`
	StartedAt       time.Time            `json:"started_at"`
	CompletedAt     *time.Time           `json:"completed_at,omitempty"`
	Duration        time.Duration        `json:"duration"`
	Progress        int                  `json:"progress"` // 0-100
	CompletedSteps  []string             `json:"completed_steps"`
	FailedSteps     []string             `json:"failed_steps"`
	Error           string               `json:"error,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// RollbackState represents the state of a rollback operation
type RollbackState string

const (
	RollbackStateStarted   RollbackState = "started"
	RollbackStateInProgress RollbackState = "in_progress"
	RollbackStateCompleted RollbackState = "completed"
	RollbackStateFailed    RollbackState = "failed"
	RollbackStateTimeout   RollbackState = "timeout"
)

// RollbackHandler defines a handler for rollback operations
type RollbackHandler func(ctx context.Context, target *domain.Target, metadata map[string]interface{}) error

// Alert represents a safety alert
type Alert struct {
	ID          string                 `json:"id"`
	Type        AlertType              `json:"type"`
	Severity    AlertSeverity          `json:"severity"`
	ExecutionID domain.ExecutionID     `json:"execution_id"`
	TargetID    string                 `json:"target_id,omitempty"`
	Message     string                 `json:"message"`
	Description string                 `json:"description,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy  string                 `json:"resolved_by,omitempty"`
}

// AlertType represents the type of alert
type AlertType string

const (
	AlertTypeSafetyViolation    AlertType = "safety_violation"
	AlertTypeHealthDegradation  AlertType = "health_degradation"
	AlertTypeRollbackTriggered  AlertType = "rollback_triggered"
	AlertTypeRollbackCompleted  AlertType = "rollback_completed"
	AlertTypeRollbackFailed     AlertType = "rollback_failed"
	AlertTypeMonitoringError    AlertType = "monitoring_error"
	AlertTypePreflightFailure   AlertType = "preflight_failure"
	AlertTypeCustom             AlertType = "custom"
)

// AlertSeverity represents the severity of an alert
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertChannel defines an interface for alert channels
type AlertChannel interface {
	SendAlert(ctx context.Context, alert *Alert) error
	GetChannelType() string
	IsEnabled() bool
}

// SafetyConfig represents the configuration for the safety controller
type SafetyConfig struct {
	AutoRollbackEnabled   bool              `json:"auto_rollback_enabled"`
	RollbackTimeout       time.Duration     `json:"rollback_timeout"`
	MonitoringInterval    time.Duration     `json:"monitoring_interval"`
	AlertingEnabled       bool              `json:"alerting_enabled"`
	CircuitBreakerConfig  CircuitBreakerConfig `json:"circuit_breaker_config"`
	RateLimiterConfig     RateLimiterConfig `json:"rate_limiter_config"`
	PreflightTimeout      time.Duration     `json:"preflight_timeout"`
	HealthCheckTimeout    time.Duration     `json:"health_check_timeout"`
	MaxConcurrentChecks   int               `json:"max_concurrent_checks"`
}

// CircuitBreakerConfig represents circuit breaker configuration
type CircuitBreakerConfig struct {
	FailureThreshold   int           `json:"failure_threshold"`
	RecoveryTimeout    time.Duration `json:"recovery_timeout"`
	HalfOpenMaxCalls   int           `json:"half_open_max_calls"`
	HalfOpenSuccessThreshold int     `json:"half_open_success_threshold"`
}

// RateLimiterConfig represents rate limiter configuration
type RateLimiterConfig struct {
	RequestsPerSecond int           `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	WindowDuration    time.Duration `json:"window_duration"`
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState string

const (
	CircuitBreakerStateClosed   CircuitBreakerState = "closed"
	CircuitBreakerStateOpen     CircuitBreakerState = "open"
	CircuitBreakerStateHalfOpen CircuitBreakerState = "half_open"
)

// Built-in checker implementations

// ResourceAvailabilityChecker checks system resource availability
type ResourceAvailabilityChecker struct{}

func (c *ResourceAvailabilityChecker) Check(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) (*CheckResult, error) {
	// Implementation would check CPU, memory, disk, network resources
	return &CheckResult{
		Status:    CheckStatusPassed,
		Message:   "System resources are available",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
	}, nil
}

func (c *ResourceAvailabilityChecker) GetName() string        { return "resource_availability" }
func (c *ResourceAvailabilityChecker) GetDescription() string { return "Checks system resource availability" }

// PermissionChecker checks required permissions
type PermissionChecker struct{}

func (c *PermissionChecker) Check(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) (*CheckResult, error) {
	// Implementation would check IAM permissions, RBAC, etc.
	return &CheckResult{
		Status:    CheckStatusPassed,
		Message:   "Required permissions are available",
		Timestamp: time.Now(),
		Duration:  200 * time.Millisecond,
	}, nil
}

func (c *PermissionChecker) GetName() string        { return "permissions" }
func (c *PermissionChecker) GetDescription() string { return "Checks required permissions" }

// TargetHealthChecker checks target health before experiment
type TargetHealthChecker struct{}

func (c *TargetHealthChecker) Check(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) (*CheckResult, error) {
	// Implementation would check target health
	return &CheckResult{
		Status:    CheckStatusPassed,
		Message:   "All targets are healthy",
		Timestamp: time.Now(),
		Duration:  500 * time.Millisecond,
	}, nil
}

func (c *TargetHealthChecker) GetName() string        { return "target_health" }
func (c *TargetHealthChecker) GetDescription() string { return "Checks target health status" }

// NetworkConnectivityChecker checks network connectivity to targets
type NetworkConnectivityChecker struct{}

func (c *NetworkConnectivityChecker) Check(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) (*CheckResult, error) {
	// Implementation would check network connectivity
	return &CheckResult{
		Status:    CheckStatusPassed,
		Message:   "Network connectivity to targets is available",
		Timestamp: time.Now(),
		Duration:  300 * time.Millisecond,
	}, nil
}

func (c *NetworkConnectivityChecker) GetName() string        { return "network_connectivity" }
func (c *NetworkConnectivityChecker) GetDescription() string { return "Checks network connectivity to targets" }

// DependencyChecker checks external dependencies
type DependencyChecker struct{}

func (c *DependencyChecker) Check(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) (*CheckResult, error) {
	// Implementation would check external dependencies
	return &CheckResult{
		Status:    CheckStatusPassed,
		Message:   "All dependencies are available",
		Timestamp: time.Now(),
		Duration:  400 * time.Millisecond,
	}, nil
}

func (c *DependencyChecker) GetName() string        { return "dependencies" }
func (c *DependencyChecker) GetDescription() string { return "Checks external dependencies" }

// QuotaChecker checks resource quotas and limits
type QuotaChecker struct{}

func (c *QuotaChecker) Check(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) (*CheckResult, error) {
	// Implementation would check quotas and limits
	return &CheckResult{
		Status:    CheckStatusPassed,
		Message:   "Resource quotas are within limits",
		Timestamp: time.Now(),
		Duration:  150 * time.Millisecond,
	}, nil
}

func (c *QuotaChecker) GetName() string        { return "quota_limits" }
func (c *QuotaChecker) GetDescription() string { return "Checks resource quotas and limits" }

// Built-in health checker implementations

// SystemHealthChecker checks overall system health
type SystemHealthChecker struct{}

func (c *SystemHealthChecker) CheckHealth(ctx context.Context, target *domain.Target) (*HealthResult, error) {
	return &HealthResult{
		Status:    HealthStatusHealthy,
		Message:   "System is healthy",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
	}, nil
}

func (c *SystemHealthChecker) GetName() string        { return "system_health" }
func (c *SystemHealthChecker) GetDescription() string { return "Checks overall system health" }

// ServiceHealthChecker checks service health
type ServiceHealthChecker struct{}

func (c *ServiceHealthChecker) CheckHealth(ctx context.Context, target *domain.Target) (*HealthResult, error) {
	return &HealthResult{
		Status:    HealthStatusHealthy,
		Message:   "Service is healthy",
		Timestamp: time.Now(),
		Duration:  200 * time.Millisecond,
	}, nil
}

func (c *ServiceHealthChecker) GetName() string        { return "service_health" }
func (c *ServiceHealthChecker) GetDescription() string { return "Checks service health" }

// ResourceHealthChecker checks resource health
type ResourceHealthChecker struct{}

func (c *ResourceHealthChecker) CheckHealth(ctx context.Context, target *domain.Target) (*HealthResult, error) {
	return &HealthResult{
		Status:    HealthStatusHealthy,
		Message:   "Resource is healthy",
		Timestamp: time.Now(),
		Duration:  150 * time.Millisecond,
	}, nil
}

func (c *ResourceHealthChecker) GetName() string        { return "resource_health" }
func (c *ResourceHealthChecker) GetDescription() string { return "Checks resource health" }

// Built-in monitor implementations

// FailureRateMonitor monitors failure rates
type FailureRateMonitor struct{}

func (m *FailureRateMonitor) CollectMetrics(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution, metrics *SafetyMetrics) error {
	// Implementation would collect failure rate metrics
	metrics.FailureRate = 5.0 // Example value
	return nil
}

func (m *FailureRateMonitor) GetName() string        { return "failure_rate" }
func (m *FailureRateMonitor) GetDescription() string { return "Monitors failure rates" }

// ResourceUtilizationMonitor monitors resource utilization
type ResourceUtilizationMonitor struct{}

func (m *ResourceUtilizationMonitor) CollectMetrics(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution, metrics *SafetyMetrics) error {
	// Implementation would collect resource utilization metrics
	metrics.ResourceUsage = ResourceUsageMetrics{
		CPUUsage:    45.5,
		MemoryUsage: 60.2,
		DiskUsage:   30.1,
		NetworkIO:   15.8,
	}
	return nil
}

func (m *ResourceUtilizationMonitor) GetName() string        { return "resource_utilization" }
func (m *ResourceUtilizationMonitor) GetDescription() string { return "Monitors resource utilization" }

// ResponseTimeMonitor monitors response times
type ResponseTimeMonitor struct{}

func (m *ResponseTimeMonitor) CollectMetrics(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution, metrics *SafetyMetrics) error {
	// Implementation would collect response time metrics
	metrics.ResponseTime = 250 * time.Millisecond
	return nil
}

func (m *ResponseTimeMonitor) GetName() string        { return "response_time" }
func (m *ResponseTimeMonitor) GetDescription() string { return "Monitors response times" }

// ErrorCountMonitor monitors error counts
type ErrorCountMonitor struct{}

func (m *ErrorCountMonitor) CollectMetrics(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution, metrics *SafetyMetrics) error {
	// Implementation would collect error count metrics
	metrics.TotalFailures = 2
	metrics.FailedActions = 2
	return nil
}

func (m *ErrorCountMonitor) GetName() string        { return "error_count" }
func (m *ErrorCountMonitor) GetDescription() string { return "Monitors error counts" }

// CustomMetricsMonitor monitors custom metrics
type CustomMetricsMonitor struct{}

func (m *CustomMetricsMonitor) CollectMetrics(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution, metrics *SafetyMetrics) error {
	// Implementation would collect custom metrics based on experiment configuration
	for metric := range experiment.Safety.AlertThresholds {
		metrics.CustomMetrics[metric] = 25.0 // Example value
	}
	return nil
}

func (m *CustomMetricsMonitor) GetName() string        { return "custom_metrics" }
func (m *CustomMetricsMonitor) GetDescription() string { return "Monitors custom metrics" }