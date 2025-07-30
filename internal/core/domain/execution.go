package domain

import (
	"time"
)

// ExecutionID is a unique identifier for an execution
type ExecutionID string

// ExecutionStatus represents the current status of an execution
type ExecutionStatus string

const (
	ExecutionStatusPending    ExecutionStatus = "pending"
	ExecutionStatusRunning    ExecutionStatus = "running"
	ExecutionStatusCompleted  ExecutionStatus = "completed"
	ExecutionStatusFailed     ExecutionStatus = "failed"
	ExecutionStatusCancelled  ExecutionStatus = "cancelled"
	ExecutionStatusRolledBack ExecutionStatus = "rolled_back"
)

// ExecutionPhase represents the current phase of execution
type ExecutionPhase string

const (
	ExecutionPhasePreFlight ExecutionPhase = "pre_flight"
	ExecutionPhaseSetup     ExecutionPhase = "setup"
	ExecutionPhaseExecution ExecutionPhase = "execution"
	ExecutionPhaseCleanup   ExecutionPhase = "cleanup"
	ExecutionPhaseRollback  ExecutionPhase = "rollback"
)

// Execution represents a single execution of an experiment
type Execution struct {
	ID           ExecutionID     `json:"id"`
	ExperimentID ExperimentID    `json:"experiment_id"`
	Status       ExecutionStatus `json:"status"`
	Phase        ExecutionPhase  `json:"phase"`
	
	// Timing
	StartTime    *time.Time      `json:"start_time,omitempty"`
	EndTime      *time.Time      `json:"end_time,omitempty"`
	Duration     *Duration       `json:"duration,omitempty"`
	
	// Configuration snapshot
	Config       ExecutionConfig `json:"config"`
	
	// Progress tracking
	Progress     ExecutionProgress `json:"progress"`
	
	// Results
	Results      []ExecutionResult `json:"results"`
	
	// Safety monitoring
	SafetyEvents []SafetyEvent     `json:"safety_events"`
	
	// Metadata
	TriggeredBy  string            `json:"triggered_by"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	
	// Error information
	Error        *ExecutionError   `json:"error,omitempty"`
	
	// Metrics
	Metrics      ExecutionMetrics  `json:"metrics"`
}

// ExecutionConfig holds the configuration snapshot for an execution
type ExecutionConfig struct {
	ExperimentName string                 `json:"experiment_name"`
	Targets        []Target               `json:"targets"`
	Duration       Duration               `json:"duration"`
	Intensity      Percentage             `json:"intensity"`
	Parameters     map[string]any         `json:"parameters"`
	Safety         SafetyConfig           `json:"safety"`
	Providers      []ProviderConfig       `json:"providers"`
}

// ExecutionProgress tracks the progress of an execution
type ExecutionProgress struct {
	CurrentPhase    ExecutionPhase `json:"current_phase"`
	CompletedPhases []ExecutionPhase `json:"completed_phases"`
	TotalSteps      int            `json:"total_steps"`
	CompletedSteps  int            `json:"completed_steps"`
	Percentage      float64        `json:"percentage"`
	Message         string         `json:"message"`
}

// ExecutionResult holds the result of an execution step
type ExecutionResult struct {
	ID          string                 `json:"id"`
	TargetID    string                 `json:"target_id"`
	ProviderID  string                 `json:"provider_id"`
	Action      string                 `json:"action"`
	Status      string                 `json:"status"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     *time.Time             `json:"end_time,omitempty"`
	Duration    *Duration              `json:"duration,omitempty"`
	Output      string                 `json:"output"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]any         `json:"metadata"`
}

// ExecutionError holds detailed error information
type ExecutionError struct {
	Code        string                 `json:"code"`
	Message     string                 `json:"message"`
	Details     map[string]any         `json:"details"`
	Phase       ExecutionPhase         `json:"phase"`
	Step        string                 `json:"step"`
	Timestamp   time.Time              `json:"timestamp"`
	Recoverable bool                   `json:"recoverable"`
	StackTrace  string                 `json:"stack_trace,omitempty"`
}

// SafetyEvent represents a safety-related event during execution
type SafetyEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Message     string                 `json:"message"`
	Timestamp   time.Time              `json:"timestamp"`
	CheckName   string                 `json:"check_name"`
	Value       float64                `json:"value"`
	Threshold   Threshold              `json:"threshold"`
	Action      string                 `json:"action"`
	Metadata    map[string]any         `json:"metadata"`
}

// ExecutionMetrics holds metrics collected during execution
type ExecutionMetrics struct {
	ResourcesAffected   int                    `json:"resources_affected"`
	ActionsExecuted     int                    `json:"actions_executed"`
	SafetyChecksRun     int                    `json:"safety_checks_run"`
	SafetyViolations    int                    `json:"safety_violations"`
	AverageResponseTime Duration               `json:"average_response_time"`
	Throughput          float64                `json:"throughput"`
	ErrorRate           float64                `json:"error_rate"`
	CustomMetrics       map[string]interface{} `json:"custom_metrics"`
}

// NewExecution creates a new execution
func NewExecution(experimentID ExperimentID, config ExecutionConfig, triggeredBy string) *Execution {
	now := time.Now()
	return &Execution{
		ID:           ExecutionID(generateID()),
		ExperimentID: experimentID,
		Status:       ExecutionStatusPending,
		Phase:        ExecutionPhasePreFlight,
		Config:       config,
		Progress: ExecutionProgress{
			CurrentPhase:    ExecutionPhasePreFlight,
			CompletedPhases: make([]ExecutionPhase, 0),
			TotalSteps:      calculateTotalSteps(config),
			CompletedSteps:  0,
			Percentage:      0.0,
			Message:         "Execution created",
		},
		Results:      make([]ExecutionResult, 0),
		SafetyEvents: make([]SafetyEvent, 0),
		TriggeredBy:  triggeredBy,
		CreatedAt:    now,
		UpdatedAt:    now,
		Metrics: ExecutionMetrics{
			CustomMetrics: make(map[string]interface{}),
		},
	}
}

// Start starts the execution
func (e *Execution) Start() error {
	if e.Status != ExecutionStatusPending {
		return NewValidationError("execution can only be started from pending status")
	}
	
	now := time.Now()
	e.Status = ExecutionStatusRunning
	e.StartTime = &now
	e.UpdatedAt = now
	e.Progress.Message = "Execution started"
	
	return nil
}

// Complete completes the execution successfully
func (e *Execution) Complete() error {
	if e.Status != ExecutionStatusRunning {
		return NewValidationError("execution can only be completed from running status")
	}
	
	now := time.Now()
	e.Status = ExecutionStatusCompleted
	e.EndTime = &now
	e.UpdatedAt = now
	
	if e.StartTime != nil {
		duration := Duration(now.Sub(*e.StartTime))
		e.Duration = &duration
	}
	
	e.Progress.Percentage = 100.0
	e.Progress.Message = "Execution completed successfully"
	
	return nil
}

// Fail marks the execution as failed
func (e *Execution) Fail(err ExecutionError) error {
	now := time.Now()
	e.Status = ExecutionStatusFailed
	e.EndTime = &now
	e.UpdatedAt = now
	e.Error = &err
	
	if e.StartTime != nil {
		duration := Duration(now.Sub(*e.StartTime))
		e.Duration = &duration
	}
	
	e.Progress.Message = "Execution failed: " + err.Message
	
	return nil
}

// Cancel cancels the execution
func (e *Execution) Cancel() error {
	if e.Status != ExecutionStatusRunning && e.Status != ExecutionStatusPending {
		return NewValidationError("execution can only be cancelled from running or pending status")
	}
	
	now := time.Now()
	e.Status = ExecutionStatusCancelled
	e.EndTime = &now
	e.UpdatedAt = now
	
	if e.StartTime != nil {
		duration := Duration(now.Sub(*e.StartTime))
		e.Duration = &duration
	}
	
	e.Progress.Message = "Execution cancelled"
	
	return nil
}

// UpdatePhase updates the current execution phase
func (e *Execution) UpdatePhase(phase ExecutionPhase) error {
	if !e.isValidPhaseTransition(e.Phase, phase) {
		return NewValidationError("invalid phase transition from %s to %s", e.Phase, phase)
	}
	
	// Mark current phase as completed
	if e.Phase != phase {
		e.Progress.CompletedPhases = append(e.Progress.CompletedPhases, e.Phase)
	}
	
	e.Phase = phase
	e.Progress.CurrentPhase = phase
	e.UpdatedAt = time.Now()
	
	return nil
}

// UpdateProgress updates the execution progress
func (e *Execution) UpdateProgress(completedSteps int, message string) {
	e.Progress.CompletedSteps = completedSteps
	if e.Progress.TotalSteps > 0 {
		e.Progress.Percentage = float64(completedSteps) / float64(e.Progress.TotalSteps) * 100.0
	}
	e.Progress.Message = message
	e.UpdatedAt = time.Now()
}

// AddResult adds an execution result
func (e *Execution) AddResult(result ExecutionResult) {
	e.Results = append(e.Results, result)
	e.UpdatedAt = time.Now()
}

// AddSafetyEvent adds a safety event
func (e *Execution) AddSafetyEvent(event SafetyEvent) {
	e.SafetyEvents = append(e.SafetyEvents, event)
	e.Metrics.SafetyChecksRun++
	
	if event.Severity == "high" || event.Severity == "critical" {
		e.Metrics.SafetyViolations++
	}
	
	e.UpdatedAt = time.Now()
}

// IsRunning checks if execution is currently running
func (e *Execution) IsRunning() bool {
	return e.Status == ExecutionStatusRunning
}

// IsCompleted checks if execution is completed (successfully or not)
func (e *Execution) IsCompleted() bool {
	return e.Status == ExecutionStatusCompleted ||
		   e.Status == ExecutionStatusFailed ||
		   e.Status == ExecutionStatusCancelled ||
		   e.Status == ExecutionStatusRolledBack
}

// CanRollback checks if execution can be rolled back
func (e *Execution) CanRollback() bool {
	return e.Status == ExecutionStatusFailed && e.Error != nil && e.Error.Recoverable
}

// isValidPhaseTransition checks if phase transition is valid
func (e *Execution) isValidPhaseTransition(from, to ExecutionPhase) bool {
	validTransitions := map[ExecutionPhase][]ExecutionPhase{
		ExecutionPhasePreFlight: {ExecutionPhaseSetup, ExecutionPhaseRollback},
		ExecutionPhaseSetup:     {ExecutionPhaseExecution, ExecutionPhaseRollback},
		ExecutionPhaseExecution: {ExecutionPhaseCleanup, ExecutionPhaseRollback},
		ExecutionPhaseCleanup:   {ExecutionPhaseRollback},
		ExecutionPhaseRollback:  {},
	}
	
	allowed, exists := validTransitions[from]
	if !exists {
		return false
	}
	
	for _, phase := range allowed {
		if phase == to {
			return true
		}
	}
	
	return false
}

// calculateTotalSteps calculates the total number of steps for progress tracking
func calculateTotalSteps(config ExecutionConfig) int {
	// Basic calculation: pre-flight + setup + execution per target + cleanup
	totalSteps := 3 // pre-flight, setup, cleanup
	totalSteps += len(config.Targets) // one execution step per target
	
	// Add safety check steps if enabled
	if config.Safety.Enabled {
		totalSteps += len(config.Safety.Checks)
	}
	
	return totalSteps
}