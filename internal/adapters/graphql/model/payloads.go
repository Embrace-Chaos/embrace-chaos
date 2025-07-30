package model

// Payload types for GraphQL mutations and responses

// ExperimentPayload is returned from experiment mutations
type ExperimentPayload struct {
	Experiment *Experiment  `json:"experiment"`
	Errors     []*Error     `json:"errors"`
	UserErrors []*UserError `json:"userErrors"`
}

// ExecutionPayload is returned from execution mutations
type ExecutionPayload struct {
	Execution  *Execution   `json:"execution"`
	Errors     []*Error     `json:"errors"`
	UserErrors []*UserError `json:"userErrors"`
}

// TargetPayload is returned from target mutations
type TargetPayload struct {
	Target     *Target      `json:"target"`
	Errors     []*Error     `json:"errors"`
	UserErrors []*UserError `json:"userErrors"`
}

// DeletePayload is returned from delete mutations
type DeletePayload struct {
	Success    bool         `json:"success"`
	Errors     []*Error     `json:"errors"`
	UserErrors []*UserError `json:"userErrors"`
}

// ValidationPayload is returned from validation operations
type ValidationPayload struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// SyncPayload is returned from GitOps sync operations
type SyncPayload struct {
	SyncedExperiments []*Experiment `json:"syncedExperiments"`
	Errors            []*Error      `json:"errors"`
	TotalProcessed    int           `json:"totalProcessed"`
	Created           int           `json:"created"`
	Updated           int           `json:"updated"`
	Failed            int           `json:"failed"`
}

// PullRequestPayload is returned from PR creation
type PullRequestPayload struct {
	PullRequestURL *string  `json:"pullRequestUrl"`
	Number         int      `json:"number"`
	Errors         []*Error `json:"errors"`
}

// SchedulePayload is returned from schedule mutations
type SchedulePayload struct {
	Schedule   *Schedule    `json:"schedule"`
	Errors     []*Error     `json:"errors"`
	UserErrors []*UserError `json:"userErrors"`
}

// Error represents a GraphQL error
type Error struct {
	Message string   `json:"message"`
	Code    string   `json:"code"`
	Path    []string `json:"path"`
}

// UserError represents a user-facing error with field information
type UserError struct {
	Message string   `json:"message"`
	Field   []string `json:"field"`
	Code    string   `json:"code"`
}

// Real-time update types for subscriptions

// ExecutionUpdate provides real-time execution status updates
type ExecutionUpdate struct {
	ID           string            `json:"id"`
	Status       ExecutionStatus   `json:"status"`
	Progress     float64           `json:"progress"`
	CurrentPhase string            `json:"currentPhase"`
	Message      *string           `json:"message"`
	Metrics      *ExecutionMetrics `json:"metrics"`
	Timestamp    string            `json:"timestamp"`
}

// ExperimentUpdate provides real-time experiment change notifications
type ExperimentUpdate struct {
	ID         string     `json:"id"`
	ChangeType ChangeType `json:"changeType"`
	Field      string     `json:"field"`
	OldValue   *string    `json:"oldValue"`
	NewValue   *string    `json:"newValue"`
	ChangedBy  *User      `json:"changedBy"`
	Timestamp  string     `json:"timestamp"`
}

// SafetyAlert provides real-time safety violation alerts
type SafetyAlert struct {
	ID           string        `json:"id"`
	Severity     AlertSeverity `json:"severity"`
	ExperimentID string        `json:"experimentId"`
	ExecutionID  string        `json:"executionId"`
	Metric       string        `json:"metric"`
	Threshold    float64       `json:"threshold"`
	ActualValue  float64       `json:"actualValue"`
	Message      string        `json:"message"`
	Timestamp    string        `json:"timestamp"`
}

// LogEntry represents a log entry from execution logs
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// OrganizationEvent represents organization-wide events
type OrganizationEvent struct {
	ID         string                 `json:"id"`
	Type       EventType              `json:"type"`
	Actor      *User                  `json:"actor"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resourceId"`
	Action     string                 `json:"action"`
	Metadata   map[string]interface{} `json:"metadata"`
	Timestamp  string                 `json:"timestamp"`
}

// Health and monitoring types

// HealthStatus represents overall system health
type HealthStatus struct {
	Status    ServiceStatus   `json:"status"`
	Version   string          `json:"version"`
	Uptime    string          `json:"uptime"`
	Checks    []*HealthCheck  `json:"checks"`
}

// HealthCheck represents a single health check result
type HealthCheck struct {
	Name        string         `json:"name"`
	Status      ServiceStatus  `json:"status"`
	Message     *string        `json:"message"`
	Duration    string         `json:"duration"`
	LastChecked string         `json:"lastChecked"`
}

// ReadinessResponse for readiness checks
type ReadinessResponse struct {
	Ready     bool   `json:"ready"`
	Timestamp string `json:"timestamp"`
}

// Search results

// SearchResults contains search results across different entity types
type SearchResults struct {
	Experiments []*Experiment `json:"experiments"`
	Executions  []*Execution  `json:"executions"`
	Targets     []*Target     `json:"targets"`
	Users       []*User       `json:"users"`
	TotalCount  int           `json:"totalCount"`
}

// Advanced features

// Schedule represents experiment scheduling configuration
type Schedule struct {
	ID             string                 `json:"id"`
	Experiment     *Experiment            `json:"experiment"`
	CronExpression string                 `json:"cronExpression"`
	Timezone       string                 `json:"timezone"`
	Enabled        bool                   `json:"enabled"`
	NextRun        string                 `json:"nextRun"`
	LastRun        *string                `json:"lastRun"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// ValidationStatus for experiment validation
type ValidationStatus struct {
	Valid         bool                 `json:"valid"`
	LastValidated *string              `json:"lastValidated"`
	Errors        []*ValidationError   `json:"errors"`
	Warnings      []*ValidationWarning `json:"warnings"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// SafetyStatus represents current safety state
type SafetyStatus struct {
	PreflightPassed    bool               `json:"preflightPassed"`
	MonitoringActive   bool               `json:"monitoringActive"`
	ThresholdsExceeded bool               `json:"thresholdsExceeded"`
	Violations         []*SafetyViolation `json:"violations"`
}

// SafetyViolation represents a safety threshold violation
type SafetyViolation struct {
	Metric       string        `json:"metric"`
	Threshold    float64       `json:"threshold"`
	ActualValue  float64       `json:"actualValue"`
	Timestamp    string        `json:"timestamp"`
	Severity     AlertSeverity `json:"severity"`
}

// RollbackStatus represents rollback state
type RollbackStatus struct {
	Required    bool              `json:"required"`
	Initiated   bool              `json:"initiated"`
	Completed   bool              `json:"completed"`
	StartedAt   *string           `json:"startedAt"`
	CompletedAt *string           `json:"completedAt"`
	Reason      *string           `json:"reason"`
	Results     []*RollbackResult `json:"results"`
}

// RollbackResult represents the result of rolling back a single target
type RollbackResult struct {
	Target      *Target      `json:"target"`
	Status      ResultStatus `json:"status"`
	Message     *string      `json:"message"`
	CompletedAt string       `json:"completedAt"`
}

// ExecutionEvent represents events during execution
type ExecutionEvent struct {
	ID        string                 `json:"id"`
	Type      ExecutionEventType     `json:"type"`
	Phase     string                 `json:"phase"`
	Message   string                 `json:"message"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp string                 `json:"timestamp"`
}

// Organization and user management

// OrganizationQuotas represents resource quotas for an organization
type OrganizationQuotas struct {
	MaxExperiments         int          `json:"maxExperiments"`
	MaxExecutionsPerMonth  int          `json:"maxExecutionsPerMonth"`
	MaxTargets             int          `json:"maxTargets"`
	MaxUsers               int          `json:"maxUsers"`
	CurrentUsage           *QuotaUsage  `json:"currentUsage"`
}

// QuotaUsage represents current quota usage
type QuotaUsage struct {
	Experiments          int `json:"experiments"`
	ExecutionsThisMonth  int `json:"executionsThisMonth"`
	Targets              int `json:"targets"`
	Users                int `json:"users"`
}

// OrganizationSettings represents organization configuration
type OrganizationSettings struct {
	RequireApproval       bool            `json:"requireApproval"`
	AllowedProviders      []Provider      `json:"allowedProviders"`
	DefaultSafetyConfig   *SafetyConfig   `json:"defaultSafetyConfig"`
	WebhookURL            *string         `json:"webhookUrl"`
	SlackChannel          *string         `json:"slackChannel"`
}

// UserPreferences represents user preferences
type UserPreferences struct {
	Theme                 Theme                    `json:"theme"`
	Notifications         *NotificationPreferences `json:"notifications"`
	DefaultView           DefaultView              `json:"defaultView"`
}

// NotificationPreferences represents notification settings
type NotificationPreferences struct {
	Email            bool `json:"email"`
	Slack            bool `json:"slack"`
	Webhook          bool `json:"webhook"`
	ExecutionUpdates bool `json:"executionUpdates"`
	SafetyAlerts     bool `json:"safetyAlerts"`
}

// GitOps input types

// GitHubSyncInput for syncing experiments from GitHub
type GitHubSyncInput struct {
	Repository string  `json:"repository"`
	Branch     string  `json:"branch"`
	Path       *string `json:"path"`
	DryRun     *bool   `json:"dryRun"`
}

// CreatePRInput for creating pull requests
type CreatePRInput struct {
	Repository   string  `json:"repository"`
	Title        string  `json:"title"`
	Body         string  `json:"body"`
	ExperimentID string  `json:"experimentId"`
	BaseBranch   *string `json:"baseBranch"`
}

// Additional input types

// CloneExperimentInput for cloning experiments
type CloneExperimentInput struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

// ScheduleInput for scheduling experiments
type ScheduleInput struct {
	CronExpression string                 `json:"cronExpression"`
	Timezone       *string                `json:"timezone"`
	Enabled        *bool                  `json:"enabled"`
	Parameters     map[string]interface{} `json:"parameters"`
}

// DiscoverTargetsInput for target discovery
type DiscoverTargetsInput struct {
	Provider Provider               `json:"provider"`
	Region   *string                `json:"region"`
	Filters  map[string]interface{} `json:"filters"`
}

// Advanced experiment configuration

// SteadyStateHypothesis defines expected system behavior
type SteadyStateHypothesis struct {
	Metrics []*MetricCheck `json:"metrics"`
	Probes  []*Probe       `json:"probes"`
}

// MetricCheck defines a metric-based check
type MetricCheck struct {
	Name      string             `json:"name"`
	Query     string             `json:"query"`
	Threshold float64            `json:"threshold"`
	Operator  ComparisonOperator `json:"operator"`
}

// Probe defines a probe-based check
type Probe struct {
	Name           string    `json:"name"`
	Type           ProbeType `json:"type"`
	Endpoint       string    `json:"endpoint"`
	ExpectedStatus *int      `json:"expectedStatus"`
	Timeout        string    `json:"timeout"`
}

// Result represents execution results for individual targets
type Result struct {
	ID          string                 `json:"id"`
	Target      *Target                `json:"target"`
	Status      ResultStatus           `json:"status"`
	StartedAt   string                 `json:"startedAt"`
	CompletedAt *string                `json:"completedAt"`
	Error       *string                `json:"error"`
	Output      map[string]interface{} `json:"output"`
	Metrics     map[string]interface{} `json:"metrics"`
}