package model

// GraphQL enum types that correspond to domain enums

// ExperimentStatus represents the current state of an experiment
type ExperimentStatus string

const (
	ExperimentStatusDraft     ExperimentStatus = "DRAFT"
	ExperimentStatusReady     ExperimentStatus = "READY"
	ExperimentStatusScheduled ExperimentStatus = "SCHEDULED"
	ExperimentStatusRunning   ExperimentStatus = "RUNNING"
	ExperimentStatusCompleted ExperimentStatus = "COMPLETED"
	ExperimentStatusFailed    ExperimentStatus = "FAILED"
	ExperimentStatusArchived  ExperimentStatus = "ARCHIVED"
)

// ExecutionStatus represents the current state of an execution
type ExecutionStatus string

const (
	ExecutionStatusPending   ExecutionStatus = "PENDING"
	ExecutionStatusRunning   ExecutionStatus = "RUNNING"
	ExecutionStatusSucceeded ExecutionStatus = "SUCCEEDED"
	ExecutionStatusFailed    ExecutionStatus = "FAILED"
	ExecutionStatusCancelled ExecutionStatus = "CANCELLED"
	ExecutionStatusTimeout   ExecutionStatus = "TIMEOUT"
)

// TargetStatus represents the current state of a target
type TargetStatus string

const (
	TargetStatusActive   TargetStatus = "ACTIVE"
	TargetStatusInactive TargetStatus = "INACTIVE"
	TargetStatusUnknown  TargetStatus = "UNKNOWN"
)

// ResultStatus represents the state of an execution result
type ResultStatus string

const (
	ResultStatusPending  ResultStatus = "PENDING"
	ResultStatusRunning  ResultStatus = "RUNNING"
	ResultStatusSuccess  ResultStatus = "SUCCESS"
	ResultStatusFailed   ResultStatus = "FAILED"
	ResultStatusSkipped  ResultStatus = "SKIPPED"
	ResultStatusRollback ResultStatus = "ROLLBACK"
)

// Provider represents infrastructure providers
type Provider string

const (
	ProviderAWS        Provider = "AWS"
	ProviderGCP        Provider = "GCP"
	ProviderAzure      Provider = "AZURE"
	ProviderKubernetes Provider = "KUBERNETES"
	ProviderVMware     Provider = "VMWARE"
)

// TargetType represents different types of infrastructure targets
type TargetType string

const (
	TargetTypeEC2Instance      TargetType = "EC2_INSTANCE"
	TargetTypeECSService       TargetType = "ECS_SERVICE"
	TargetTypeRDSInstance      TargetType = "RDS_INSTANCE"
	TargetTypeLambdaFunction   TargetType = "LAMBDA_FUNCTION"
	TargetTypeGCEInstance      TargetType = "GCE_INSTANCE"
	TargetTypeCloudSQLInstance TargetType = "CLOUDSQL_INSTANCE"
	TargetTypeGKENode          TargetType = "GKE_NODE"
	TargetTypeAzureVM          TargetType = "AZURE_VM"
	TargetTypeAKSNode          TargetType = "AKS_NODE"
)

// TriggerType represents how an execution was triggered
type TriggerType string

const (
	TriggerTypeManual    TriggerType = "MANUAL"
	TriggerTypeScheduled TriggerType = "SCHEDULED"
	TriggerTypeAPI       TriggerType = "API"
	TriggerTypeWebhook   TriggerType = "WEBHOOK"
	TriggerTypeGitops    TriggerType = "GITOPS"
)

// ConcurrencyMode represents how targets are executed
type ConcurrencyMode string

const (
	ConcurrencyModeSequential ConcurrencyMode = "SEQUENTIAL"
	ConcurrencyModeParallel   ConcurrencyMode = "PARALLEL"
	ConcurrencyModePipeline   ConcurrencyMode = "PIPELINE"
)

// UserRole represents user permissions level
type UserRole string

const (
	UserRoleAdmin    UserRole = "ADMIN"
	UserRoleOperator UserRole = "OPERATOR"
	UserRoleViewer   UserRole = "VIEWER"
)

// OrderDirection for sorting
type OrderDirection string

const (
	OrderDirectionAsc  OrderDirection = "ASC"
	OrderDirectionDesc OrderDirection = "DESC"
)

// SearchType for global search
type SearchType string

const (
	SearchTypeExperiment SearchType = "EXPERIMENT"
	SearchTypeExecution  SearchType = "EXECUTION"
	SearchTypeTarget     SearchType = "TARGET"
	SearchTypeUser       SearchType = "USER"
)

// ProbeType for health checks
type ProbeType string

const (
	ProbeTypeHTTP       ProbeType = "HTTP"
	ProbeTypeTCP        ProbeType = "TCP"
	ProbeTypeCommand    ProbeType = "COMMAND"
	ProbeTypePrometheus ProbeType = "PROMETHEUS"
)

// ComparisonOperator for metric checks
type ComparisonOperator string

const (
	ComparisonOperatorEquals              ComparisonOperator = "EQUALS"
	ComparisonOperatorNotEquals           ComparisonOperator = "NOT_EQUALS"
	ComparisonOperatorGreaterThan         ComparisonOperator = "GREATER_THAN"
	ComparisonOperatorLessThan            ComparisonOperator = "LESS_THAN"
	ComparisonOperatorGreaterThanOrEqual  ComparisonOperator = "GREATER_THAN_OR_EQUAL"
	ComparisonOperatorLessThanOrEqual     ComparisonOperator = "LESS_THAN_OR_EQUAL"
)

// ChangeType for real-time updates
type ChangeType string

const (
	ChangeTypeCreated      ChangeType = "CREATED"
	ChangeTypeUpdated      ChangeType = "UPDATED"
	ChangeTypeDeleted      ChangeType = "DELETED"
	ChangeTypeExecuted     ChangeType = "EXECUTED"
	ChangeTypeScheduled    ChangeType = "SCHEDULED"
	ChangeTypeUnscheduled  ChangeType = "UNSCHEDULED"
)

// AlertSeverity for safety alerts
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "INFO"
	AlertSeverityWarning  AlertSeverity = "WARNING"
	AlertSeverityError    AlertSeverity = "ERROR"
	AlertSeverityCritical AlertSeverity = "CRITICAL"
)

// LogLevel for log entries
type LogLevel string

const (
	LogLevelDebug LogLevel = "DEBUG"
	LogLevelInfo  LogLevel = "INFO"
	LogLevelWarn  LogLevel = "WARN"
	LogLevelError LogLevel = "ERROR"
)

// BackoffStrategy for retry policies
type BackoffStrategy string

const (
	BackoffStrategyFixed       BackoffStrategy = "FIXED"
	BackoffStrategyExponential BackoffStrategy = "EXPONENTIAL"
	BackoffStrategyLinear      BackoffStrategy = "LINEAR"
)

// ParameterType for experiment parameters
type ParameterType string

const (
	ParameterTypeString   ParameterType = "STRING"
	ParameterTypeInteger  ParameterType = "INTEGER"
	ParameterTypeFloat    ParameterType = "FLOAT"
	ParameterTypeBoolean  ParameterType = "BOOLEAN"
	ParameterTypeDuration ParameterType = "DURATION"
	ParameterTypeJSON     ParameterType = "JSON"
)

// ServiceStatus for health checks
type ServiceStatus string

const (
	ServiceStatusHealthy   ServiceStatus = "HEALTHY"
	ServiceStatusDegraded  ServiceStatus = "DEGRADED"
	ServiceStatusUnhealthy ServiceStatus = "UNHEALTHY"
)

// EventType for organization events
type EventType string

const (
	EventTypeAudit  EventType = "AUDIT"
	EventTypeSafety EventType = "SAFETY"
	EventTypeQuota  EventType = "QUOTA"
	EventTypeSystem EventType = "SYSTEM"
)

// Theme for user preferences
type Theme string

const (
	ThemeLight Theme = "LIGHT"
	ThemeDark  Theme = "DARK"
	ThemeAuto  Theme = "AUTO"
)

// DefaultView for user preferences
type DefaultView string

const (
	DefaultViewExperiments DefaultView = "EXPERIMENTS"
	DefaultViewExecutions  DefaultView = "EXECUTIONS"
	DefaultViewTargets     DefaultView = "TARGETS"
	DefaultViewDashboard   DefaultView = "DASHBOARD"
)

// ExecutionEventType for execution events
type ExecutionEventType string

const (
	ExecutionEventTypeStarted         ExecutionEventType = "STARTED"
	ExecutionEventTypePhaseStarted    ExecutionEventType = "PHASE_STARTED"
	ExecutionEventTypePhaseCompleted  ExecutionEventType = "PHASE_COMPLETED"
	ExecutionEventTypeTargetStarted   ExecutionEventType = "TARGET_STARTED"
	ExecutionEventTypeTargetCompleted ExecutionEventType = "TARGET_COMPLETED"
	ExecutionEventTypeSafetyCheck     ExecutionEventType = "SAFETY_CHECK"
	ExecutionEventTypeRollbackInitiated ExecutionEventType = "ROLLBACK_INITIATED"
	ExecutionEventTypeCompleted       ExecutionEventType = "COMPLETED"
	ExecutionEventTypeFailed          ExecutionEventType = "FAILED"
	ExecutionEventTypeCancelled       ExecutionEventType = "CANCELLED"
)

// Validation methods for enums (optional, for runtime validation)

func (e ExperimentStatus) IsValid() bool {
	switch e {
	case ExperimentStatusDraft, ExperimentStatusReady, ExperimentStatusScheduled,
		 ExperimentStatusRunning, ExperimentStatusCompleted, ExperimentStatusFailed,
		 ExperimentStatusArchived:
		return true
	}
	return false
}

func (e ExecutionStatus) IsValid() bool {
	switch e {
	case ExecutionStatusPending, ExecutionStatusRunning, ExecutionStatusSucceeded,
		 ExecutionStatusFailed, ExecutionStatusCancelled, ExecutionStatusTimeout:
		return true
	}
	return false
}

func (p Provider) IsValid() bool {
	switch p {
	case ProviderAWS, ProviderGCP, ProviderAzure, ProviderKubernetes, ProviderVMware:
		return true
	}
	return false
}

func (t TargetType) IsValid() bool {
	switch t {
	case TargetTypeEC2Instance, TargetTypeECSService, TargetTypeRDSInstance,
		 TargetTypeLambdaFunction, TargetTypeGCEInstance, TargetTypeCloudSQLInstance,
		 TargetTypeGKENode, TargetTypeAzureVM, TargetTypeAKSNode:
		return true
	}
	return false
}

func (u UserRole) IsValid() bool {
	switch u {
	case UserRoleAdmin, UserRoleOperator, UserRoleViewer:
		return true
	}
	return false
}