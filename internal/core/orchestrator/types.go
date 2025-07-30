package orchestrator

import (
	"context"
	"time"

	"github.com/embrace-chaos/internal/core/domain"
)

// Saga represents a saga orchestrating an experiment execution
type Saga struct {
	ID           string               `json:"id"`
	ExecutionID  domain.ExecutionID   `json:"execution_id"`
	ExperimentID domain.ExperimentID  `json:"experiment_id"`
	State        SagaState            `json:"state"`
	Steps        []*SagaStep          `json:"steps"`
	CreatedAt    time.Time            `json:"created_at"`
	UpdatedAt    time.Time            `json:"updated_at"`
	CompletedAt  *time.Time           `json:"completed_at,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// SagaState represents the state of a saga
type SagaState string

const (
	SagaStateStarted              SagaState = "started"
	SagaStateInProgress          SagaState = "in_progress"
	SagaStateCompleted           SagaState = "completed"
	SagaStateFailed              SagaState = "failed"
	SagaStateCompensating        SagaState = "compensating"
	SagaStateCompensated         SagaState = "compensated"
	SagaStateCompensationFailed  SagaState = "compensation_failed"
)

// SagaStep represents a step in the saga execution
type SagaStep struct {
	ID            string               `json:"id"`
	Name          string               `json:"name"`
	Type          StepType             `json:"type"`
	State         StepState            `json:"state"`
	StartedAt     time.Time            `json:"started_at"`
	CompletedAt   time.Time            `json:"completed_at,omitempty"`
	Duration      time.Duration        `json:"duration"`
	Error         string               `json:"error,omitempty"`
	Warnings      []string             `json:"warnings,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	RetryCount    int                  `json:"retry_count"`
	MaxRetries    int                  `json:"max_retries"`
}

// StepType represents the type of saga step
type StepType string

const (
	StepTypePreflight            StepType = "preflight"
	StepTypeResourcePreparation  StepType = "resource_preparation"
	StepTypeChaosInjection      StepType = "chaos_injection"
	StepTypeMonitoring          StepType = "monitoring"
	StepTypeCleanup             StepType = "cleanup"
	StepTypeRollback            StepType = "rollback"
)

// StepState represents the state of a saga step
type StepState string

const (
	StepStatePending    StepState = "pending"
	StepStateStarted    StepState = "started"
	StepStateInProgress StepState = "in_progress"
	StepStateCompleted  StepState = "completed"
	StepStateFailed     StepState = "failed"
	StepStateSkipped    StepState = "skipped"
)

// CompensationAction represents an action to be performed during compensation
type CompensationAction struct {
	Type        CompensationType `json:"type"`
	Description string           `json:"description"`
	TargetID    string           `json:"target_id,omitempty"`
	Action      func(ctx context.Context) error `json:"-"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CompensationType represents the type of compensation action
type CompensationType string

const (
	CompensationTypeCleanup         CompensationType = "cleanup"
	CompensationTypeResourceCleanup CompensationType = "resource_cleanup"
	CompensationTypeRollback        CompensationType = "rollback"
	CompensationTypeNotification    CompensationType = "notification"
)

// EventBus defines the interface for publishing saga events
type EventBus interface {
	PublishEvent(ctx context.Context, event SagaEvent) error
	SubscribeToEvents(ctx context.Context, eventType string, handler EventHandler) error
}

// SagaEvent represents an event in the saga lifecycle
type SagaEvent interface {
	GetEventType() string
	GetSagaID() string
	GetTimestamp() time.Time
}

// EventHandler handles saga events
type EventHandler func(ctx context.Context, event SagaEvent) error

// Saga event implementations

// SagaStartedEvent represents a saga started event
type SagaStartedEvent struct {
	SagaID       string               `json:"saga_id"`
	ExecutionID  domain.ExecutionID   `json:"execution_id"`
	ExperimentID domain.ExperimentID  `json:"experiment_id"`
	Timestamp    time.Time            `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

func (e *SagaStartedEvent) GetEventType() string { return "saga.started" }
func (e *SagaStartedEvent) GetSagaID() string    { return e.SagaID }
func (e *SagaStartedEvent) GetTimestamp() time.Time { return e.Timestamp }

// SagaCompletedEvent represents a saga completed event
type SagaCompletedEvent struct {
	SagaID       string               `json:"saga_id"`
	ExecutionID  domain.ExecutionID   `json:"execution_id"`
	ExperimentID domain.ExperimentID  `json:"experiment_id"`
	Timestamp    time.Time            `json:"timestamp"`
	Duration     time.Duration        `json:"duration"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

func (e *SagaCompletedEvent) GetEventType() string { return "saga.completed" }
func (e *SagaCompletedEvent) GetSagaID() string    { return e.SagaID }
func (e *SagaCompletedEvent) GetTimestamp() time.Time { return e.Timestamp }

// SagaFailedEvent represents a saga failed event
type SagaFailedEvent struct {
	SagaID       string               `json:"saga_id"`
	ExecutionID  domain.ExecutionID   `json:"execution_id"`
	ExperimentID domain.ExperimentID  `json:"experiment_id"`
	Timestamp    time.Time            `json:"timestamp"`
	Error        string               `json:"error"`
	FailedStep   string               `json:"failed_step,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

func (e *SagaFailedEvent) GetEventType() string { return "saga.failed" }
func (e *SagaFailedEvent) GetSagaID() string    { return e.SagaID }
func (e *SagaFailedEvent) GetTimestamp() time.Time { return e.Timestamp }

// SagaCompensationStartedEvent represents a saga compensation started event
type SagaCompensationStartedEvent struct {
	SagaID      string            `json:"saga_id"`
	ExecutionID domain.ExecutionID `json:"execution_id"`
	Timestamp   time.Time         `json:"timestamp"`
	Reason      string            `json:"reason,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func (e *SagaCompensationStartedEvent) GetEventType() string { return "saga.compensation.started" }
func (e *SagaCompensationStartedEvent) GetSagaID() string    { return e.SagaID }
func (e *SagaCompensationStartedEvent) GetTimestamp() time.Time { return e.Timestamp }

// SagaCompensationCompletedEvent represents a saga compensation completed event
type SagaCompensationCompletedEvent struct {
	SagaID      string            `json:"saga_id"`
	ExecutionID domain.ExecutionID `json:"execution_id"`
	Timestamp   time.Time         `json:"timestamp"`
	Duration    time.Duration     `json:"duration"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func (e *SagaCompensationCompletedEvent) GetEventType() string { return "saga.compensation.completed" }
func (e *SagaCompensationCompletedEvent) GetSagaID() string    { return e.SagaID }
func (e *SagaCompensationCompletedEvent) GetTimestamp() time.Time { return e.Timestamp }

// StepStartedEvent represents a step started event
type StepStartedEvent struct {
	SagaID      string            `json:"saga_id"`
	ExecutionID domain.ExecutionID `json:"execution_id"`
	StepID      string            `json:"step_id"`
	StepName    string            `json:"step_name"`
	StepType    StepType          `json:"step_type"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func (e *StepStartedEvent) GetEventType() string { return "saga.step.started" }
func (e *StepStartedEvent) GetSagaID() string    { return e.SagaID }
func (e *StepStartedEvent) GetTimestamp() time.Time { return e.Timestamp }

// StepCompletedEvent represents a step completed event
type StepCompletedEvent struct {
	SagaID      string            `json:"saga_id"`
	ExecutionID domain.ExecutionID `json:"execution_id"`
	StepID      string            `json:"step_id"`
	StepName    string            `json:"step_name"`
	StepType    StepType          `json:"step_type"`
	Timestamp   time.Time         `json:"timestamp"`
	Duration    time.Duration     `json:"duration"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func (e *StepCompletedEvent) GetEventType() string { return "saga.step.completed" }
func (e *StepCompletedEvent) GetSagaID() string    { return e.SagaID }
func (e *StepCompletedEvent) GetTimestamp() time.Time { return e.Timestamp }

// StateManager defines the interface for managing saga state
type StateManager interface {
	SaveSagaState(ctx context.Context, saga *Saga) error
	LoadSagaState(ctx context.Context, sagaID string) (*Saga, error)
	UpdateSagaState(ctx context.Context, sagaID string, state SagaState) error
	DeleteSagaState(ctx context.Context, sagaID string) error
	ListSagas(ctx context.Context, filters SagaFilters) ([]*Saga, error)
}

// SagaFilters represents filters for querying sagas
type SagaFilters struct {
	ExecutionID  *domain.ExecutionID  `json:"execution_id,omitempty"`
	ExperimentID *domain.ExperimentID `json:"experiment_id,omitempty"`
	State        *SagaState           `json:"state,omitempty"`
	CreatedFrom  *time.Time           `json:"created_from,omitempty"`
	CreatedTo    *time.Time           `json:"created_to,omitempty"`
}

// ProgressTracker defines the interface for tracking experiment progress
type ProgressTracker interface {
	UpdateProgress(ctx context.Context, executionID domain.ExecutionID, update ProgressUpdate) error
	GetProgress(ctx context.Context, executionID domain.ExecutionID) (*ProgressStatus, error)
	SubscribeToProgress(ctx context.Context, executionID domain.ExecutionID, handler ProgressHandler) error
}

// ProgressUpdate represents a progress update
type ProgressUpdate struct {
	Step        string               `json:"step"`
	Progress    int                  `json:"progress"` // 0-100
	Message     string               `json:"message"`
	Timestamp   time.Time            `json:"timestamp"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// ProgressStatus represents the current progress status
type ProgressStatus struct {
	ExecutionID   domain.ExecutionID `json:"execution_id"`
	CurrentStep   string             `json:"current_step"`
	Progress      int                `json:"progress"` // 0-100
	Message       string             `json:"message"`
	StartedAt     time.Time          `json:"started_at"`
	LastUpdated   time.Time          `json:"last_updated"`
	EstimatedETA  *time.Time         `json:"estimated_eta,omitempty"`
	StepHistory   []ProgressUpdate   `json:"step_history"`
}

// ProgressHandler handles progress updates
type ProgressHandler func(ctx context.Context, update ProgressUpdate) error

// ExecutionHooks defines hooks that can be executed at various points in the saga
type ExecutionHooks interface {
	BeforeExecution(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) error
	AfterExecution(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution, result *domain.Result) error
	OnStepStart(ctx context.Context, step *SagaStep, experiment *domain.Experiment, execution *domain.Execution) error
	OnStepComplete(ctx context.Context, step *SagaStep, experiment *domain.Experiment, execution *domain.Execution) error
	OnStepFail(ctx context.Context, step *SagaStep, experiment *domain.Experiment, execution *domain.Execution, err error) error
	OnCompensation(ctx context.Context, saga *Saga, reason string) error
}

// RetryStrategy defines different retry strategies for saga steps
type RetryStrategy interface {
	ShouldRetry(ctx context.Context, step *SagaStep, err error) bool
	GetRetryDelay(ctx context.Context, step *SagaStep, attempt int) time.Duration
	GetMaxRetries() int
}

// ConcurrencyController manages concurrent execution of saga steps
type ConcurrencyController interface {
	AcquireLock(ctx context.Context, resource string) error
	ReleaseLock(ctx context.Context, resource string) error
	GetConcurrencyLimit(stepType StepType) int
	IsResourceLocked(ctx context.Context, resource string) (bool, error)
}

// SafetyChecker performs safety checks during saga execution
type SafetyChecker interface {
	CheckSafetyConstraints(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) error
	ShouldAbortExecution(ctx context.Context, saga *Saga, experiment *domain.Experiment) (bool, string, error)
	ValidateTargetHealth(ctx context.Context, target *domain.Target) error
	CheckResourceLimits(ctx context.Context, experiment *domain.Experiment) error
}