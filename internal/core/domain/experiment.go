package domain

import (
	"context"
	"time"
)

// ExperimentID is a unique identifier for an experiment
type ExperimentID string

// ExperimentStatus represents the current status of an experiment
type ExperimentStatus string

const (
	ExperimentStatusDraft      ExperimentStatus = "draft"
	ExperimentStatusActive     ExperimentStatus = "active"
	ExperimentStatusRunning    ExperimentStatus = "running"
	ExperimentStatusCompleted  ExperimentStatus = "completed"
	ExperimentStatusFailed     ExperimentStatus = "failed"
	ExperimentStatusCancelled  ExperimentStatus = "cancelled"
	ExperimentStatusPaused     ExperimentStatus = "paused"
)

// ExperimentType defines different types of chaos experiments
type ExperimentType string

const (
	ExperimentTypeInfrastructure ExperimentType = "infrastructure"
	ExperimentTypeApplication    ExperimentType = "application"
	ExperimentTypeNetwork        ExperimentType = "network"
	ExperimentTypeSecurity       ExperimentType = "security"
)

// Experiment is the root aggregate for chaos experiments
type Experiment struct {
	ID          ExperimentID     `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Type        ExperimentType   `json:"type"`
	Status      ExperimentStatus `json:"status"`
	
	// Configuration
	Config      ExperimentConfig `json:"config"`
	
	// Targets
	Targets     []Target         `json:"targets"`
	
	// Safety configuration
	Safety      SafetyConfig     `json:"safety"`
	
	// Scheduling
	Schedule    *Schedule        `json:"schedule,omitempty"`
	
	// Metadata
	CreatedBy   string           `json:"created_by"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	Version     int              `json:"version"`
	
	// Tags for organization
	Tags        []string         `json:"tags"`
	
	// Execution history
	Executions  []ExecutionID    `json:"executions"`
}

// ExperimentConfig holds the configuration for an experiment
type ExperimentConfig struct {
	Duration    Duration         `json:"duration"`
	Intensity   Percentage       `json:"intensity"`
	Parameters  map[string]any   `json:"parameters"`
	
	// Rollback configuration
	AutoRollback    bool         `json:"auto_rollback"`
	RollbackTimeout Duration     `json:"rollback_timeout"`
}

// SafetyConfig defines safety constraints for experiments
type SafetyConfig struct {
	Enabled         bool                   `json:"enabled"`
	Checks          []SafetyCheck          `json:"checks"`
	Thresholds      map[string]Threshold   `json:"thresholds"`
	Actions         []SafetyAction         `json:"actions"`
}

// SafetyCheck defines a safety condition to monitor
type SafetyCheck struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Query       string            `json:"query"`
	Interval    Duration          `json:"interval"`
	Threshold   Threshold         `json:"threshold"`
	Enabled     bool              `json:"enabled"`
}

// SafetyAction defines what to do when safety is breached
type SafetyAction struct {
	Type        string            `json:"type"`
	Parameters  map[string]any    `json:"parameters"`
	Enabled     bool              `json:"enabled"`
}

// Threshold defines a safety threshold
type Threshold struct {
	Operator    string      `json:"operator"`
	Value       float64     `json:"value"`
	Unit        string      `json:"unit,omitempty"`
}

// Schedule defines when experiments should run
type Schedule struct {
	Type        string      `json:"type"`
	Cron        string      `json:"cron,omitempty"`
	Timezone    string      `json:"timezone"`
	StartDate   *time.Time  `json:"start_date,omitempty"`
	EndDate     *time.Time  `json:"end_date,omitempty"`
	Enabled     bool        `json:"enabled"`
}

// NewExperiment creates a new experiment with required fields
func NewExperiment(name, description string, experimentType ExperimentType, createdBy string) *Experiment {
	now := time.Now()
	return &Experiment{
		ID:          ExperimentID(generateID()),
		Name:        name,
		Description: description,
		Type:        experimentType,
		Status:      ExperimentStatusDraft,
		Config:      ExperimentConfig{
			Duration:        Duration(30 * time.Minute),
			Intensity:       Percentage(10),
			Parameters:      make(map[string]any),
			AutoRollback:    true,
			RollbackTimeout: Duration(5 * time.Minute),
		},
		Safety: SafetyConfig{
			Enabled:    true,
			Checks:     make([]SafetyCheck, 0),
			Thresholds: make(map[string]Threshold),
			Actions:    make([]SafetyAction, 0),
		},
		CreatedBy:  createdBy,
		CreatedAt:  now,
		UpdatedAt:  now,
		Version:    1,
		Tags:       make([]string, 0),
		Targets:    make([]Target, 0),
		Executions: make([]ExecutionID, 0),
	}
}

// Validate checks if the experiment is valid
func (e *Experiment) Validate() error {
	if e.Name == "" {
		return NewValidationError("experiment name is required")
	}
	
	if len(e.Name) > 255 {
		return NewValidationError("experiment name cannot exceed 255 characters")
	}
	
	if e.CreatedBy == "" {
		return NewValidationError("created_by is required")
	}
	
	if len(e.Targets) == 0 {
		return NewValidationError("at least one target is required")
	}
	
	if e.Config.Duration <= 0 {
		return NewValidationError("experiment duration must be positive")
	}
	
	if e.Config.Intensity < 0 || e.Config.Intensity > 100 {
		return NewValidationError("experiment intensity must be between 0 and 100")
	}
	
	return nil
}

// CanExecute checks if experiment can be executed
func (e *Experiment) CanExecute() bool {
	return e.Status == ExperimentStatusActive || e.Status == ExperimentStatusDraft
}

// CanPause checks if experiment can be paused
func (e *Experiment) CanPause() bool {
	return e.Status == ExperimentStatusRunning
}

// CanResume checks if experiment can be resumed
func (e *Experiment) CanResume() bool {
	return e.Status == ExperimentStatusPaused
}

// CanCancel checks if experiment can be cancelled
func (e *Experiment) CanCancel() bool {
	return e.Status == ExperimentStatusRunning || e.Status == ExperimentStatusPaused
}

// UpdateStatus updates the experiment status with validation
func (e *Experiment) UpdateStatus(status ExperimentStatus) error {
	if !e.isValidStatusTransition(e.Status, status) {
		return NewValidationError("invalid status transition from %s to %s", e.Status, status)
	}
	
	e.Status = status
	e.UpdatedAt = time.Now()
	e.Version++
	
	return nil
}

// AddTarget adds a target to the experiment
func (e *Experiment) AddTarget(target Target) error {
	if err := target.Validate(); err != nil {
		return err
	}
	
	e.Targets = append(e.Targets, target)
	e.UpdatedAt = time.Now()
	e.Version++
	
	return nil
}

// AddExecution records a new execution
func (e *Experiment) AddExecution(executionID ExecutionID) {
	e.Executions = append(e.Executions, executionID)
	e.UpdatedAt = time.Now()
	e.Version++
}

// isValidStatusTransition checks if status transition is valid
func (e *Experiment) isValidStatusTransition(from, to ExperimentStatus) bool {
	validTransitions := map[ExperimentStatus][]ExperimentStatus{
		ExperimentStatusDraft: {
			ExperimentStatusActive,
			ExperimentStatusCancelled,
		},
		ExperimentStatusActive: {
			ExperimentStatusRunning,
			ExperimentStatusCancelled,
		},
		ExperimentStatusRunning: {
			ExperimentStatusCompleted,
			ExperimentStatusFailed,
			ExperimentStatusCancelled,
			ExperimentStatusPaused,
		},
		ExperimentStatusPaused: {
			ExperimentStatusRunning,
			ExperimentStatusCancelled,
		},
		ExperimentStatusCompleted: {},
		ExperimentStatusFailed:    {},
		ExperimentStatusCancelled: {},
	}
	
	allowed, exists := validTransitions[from]
	if !exists {
		return false
	}
	
	for _, status := range allowed {
		if status == to {
			return true
		}
	}
	
	return false
}

// generateID generates a unique ID (simplified for now)
func generateID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

// randomString generates a random string of given length
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(result)
}