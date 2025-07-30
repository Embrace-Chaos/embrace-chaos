package domain

import (
	"encoding/json"
	"time"
)

// DomainEvent represents a domain event that occurred in the system
type DomainEvent interface {
	// Event identification
	ID() string
	Type() string
	Version() string
	
	// Event metadata
	AggregateID() string
	AggregateType() string
	AggregateVersion() int
	
	// Timing
	OccurredAt() time.Time
	
	// Serialization
	Data() map[string]interface{}
	Marshal() ([]byte, error)
}

// BaseDomainEvent provides common functionality for all domain events
type BaseDomainEvent struct {
	EventID          string                 `json:"event_id"`
	EventType        string                 `json:"event_type"`
	EventVersion     string                 `json:"event_version"`
	AggregateId      string                 `json:"aggregate_id"`
	AggregateType    string                 `json:"aggregate_type"`
	AggregateVersion int                    `json:"aggregate_version"`
	OccurredAtTime   time.Time              `json:"occurred_at"`
	EventData        map[string]interface{} `json:"event_data"`
}

// ID returns the event ID
func (e *BaseDomainEvent) ID() string {
	return e.EventID
}

// Type returns the event type
func (e *BaseDomainEvent) Type() string {
	return e.EventType
}

// Version returns the event version
func (e *BaseDomainEvent) Version() string {
	return e.EventVersion
}

// AggregateID returns the aggregate ID
func (e *BaseDomainEvent) AggregateID() string {
	return e.AggregateId
}

// AggregateType returns the aggregate type
func (e *BaseDomainEvent) AggregateType() string {
	return e.AggregateType
}

// AggregateVersion returns the aggregate version
func (e *BaseDomainEvent) AggregateVersion() int {
	return e.AggregateVersion
}

// OccurredAt returns when the event occurred
func (e *BaseDomainEvent) OccurredAt() time.Time {
	return e.OccurredAtTime
}

// Data returns the event data
func (e *BaseDomainEvent) Data() map[string]interface{} {
	return e.EventData
}

// Marshal serializes the event to JSON
func (e *BaseDomainEvent) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// newBaseDomainEvent creates a new base domain event
func newBaseDomainEvent(eventType, aggregateID, aggregateType string, aggregateVersion int, data map[string]interface{}) *BaseDomainEvent {
	return &BaseDomainEvent{
		EventID:          generateID(),
		EventType:        eventType,
		EventVersion:     "1.0",
		AggregateId:      aggregateID,
		AggregateType:    aggregateType,
		AggregateVersion: aggregateVersion,
		OccurredAtTime:   time.Now(),
		EventData:        data,
	}
}

// Experiment Events

// ExperimentCreated is fired when an experiment is created
type ExperimentCreated struct {
	*BaseDomainEvent
	ExperimentName string            `json:"experiment_name"`
	ExperimentType ExperimentType    `json:"experiment_type"`
	CreatedBy      string            `json:"created_by"`
	Tags           []string          `json:"tags"`
}

// NewExperimentCreated creates a new ExperimentCreated event
func NewExperimentCreated(experiment *Experiment) *ExperimentCreated {
	data := map[string]interface{}{
		"experiment_name": experiment.Name,
		"experiment_type": experiment.Type,
		"created_by":      experiment.CreatedBy,
		"tags":            experiment.Tags,
		"description":     experiment.Description,
	}
	
	return &ExperimentCreated{
		BaseDomainEvent: newBaseDomainEvent(
			"experiment.created",
			string(experiment.ID),
			"experiment",
			experiment.Version,
			data,
		),
		ExperimentName: experiment.Name,
		ExperimentType: experiment.Type,
		CreatedBy:      experiment.CreatedBy,
		Tags:           experiment.Tags,
	}
}

// ExperimentUpdated is fired when an experiment is updated
type ExperimentUpdated struct {
	*BaseDomainEvent
	Changes map[string]interface{} `json:"changes"`
}

// NewExperimentUpdated creates a new ExperimentUpdated event
func NewExperimentUpdated(experiment *Experiment, changes map[string]interface{}) *ExperimentUpdated {
	data := map[string]interface{}{
		"experiment_name": experiment.Name,
		"changes":         changes,
		"version":         experiment.Version,
	}
	
	return &ExperimentUpdated{
		BaseDomainEvent: newBaseDomainEvent(
			"experiment.updated",
			string(experiment.ID),
			"experiment",
			experiment.Version,
			data,
		),
		Changes: changes,
	}
}

// ExperimentStatusChanged is fired when an experiment's status changes
type ExperimentStatusChanged struct {
	*BaseDomainEvent
	OldStatus ExperimentStatus `json:"old_status"`
	NewStatus ExperimentStatus `json:"new_status"`
	Reason    string           `json:"reason"`
}

// NewExperimentStatusChanged creates a new ExperimentStatusChanged event
func NewExperimentStatusChanged(experiment *Experiment, oldStatus ExperimentStatus, reason string) *ExperimentStatusChanged {
	data := map[string]interface{}{
		"experiment_name": experiment.Name,
		"old_status":      oldStatus,
		"new_status":      experiment.Status,
		"reason":          reason,
	}
	
	return &ExperimentStatusChanged{
		BaseDomainEvent: newBaseDomainEvent(
			"experiment.status_changed",
			string(experiment.ID),
			"experiment",
			experiment.Version,
			data,
		),
		OldStatus: oldStatus,
		NewStatus: experiment.Status,
		Reason:    reason,
	}
}

// ExperimentDeleted is fired when an experiment is deleted
type ExperimentDeleted struct {
	*BaseDomainEvent
	ExperimentName string `json:"experiment_name"`
	DeletedBy      string `json:"deleted_by"`
}

// NewExperimentDeleted creates a new ExperimentDeleted event
func NewExperimentDeleted(experimentID ExperimentID, experimentName, deletedBy string) *ExperimentDeleted {
	data := map[string]interface{}{
		"experiment_name": experimentName,
		"deleted_by":      deletedBy,
	}
	
	return &ExperimentDeleted{
		BaseDomainEvent: newBaseDomainEvent(
			"experiment.deleted",
			string(experimentID),
			"experiment",
			0,
			data,
		),
		ExperimentName: experimentName,
		DeletedBy:      deletedBy,
	}
}

// Execution Events

// ExecutionStarted is fired when an execution starts
type ExecutionStarted struct {
	*BaseDomainEvent
	ExperimentID   ExperimentID `json:"experiment_id"`
	TriggeredBy    string       `json:"triggered_by"`
	TriggerType    string       `json:"trigger_type"`
	TargetCount    int          `json:"target_count"`
}

// NewExecutionStarted creates a new ExecutionStarted event
func NewExecutionStarted(execution *Execution, triggerType string) *ExecutionStarted {
	data := map[string]interface{}{
		"experiment_id": execution.ExperimentID,
		"triggered_by":  execution.TriggeredBy,
		"trigger_type":  triggerType,
		"target_count":  len(execution.Config.Targets),
		"duration":      execution.Config.Duration,
		"intensity":     execution.Config.Intensity,
	}
	
	return &ExecutionStarted{
		BaseDomainEvent: newBaseDomainEvent(
			"execution.started",
			string(execution.ID),
			"execution",
			1,
			data,
		),
		ExperimentID: execution.ExperimentID,
		TriggeredBy:  execution.TriggeredBy,
		TriggerType:  triggerType,
		TargetCount:  len(execution.Config.Targets),
	}
}

// ExecutionPhaseChanged is fired when an execution phase changes
type ExecutionPhaseChanged struct {
	*BaseDomainEvent
	OldPhase ExecutionPhase `json:"old_phase"`
	NewPhase ExecutionPhase `json:"new_phase"`
	Progress float64        `json:"progress"`
}

// NewExecutionPhaseChanged creates a new ExecutionPhaseChanged event
func NewExecutionPhaseChanged(execution *Execution, oldPhase ExecutionPhase) *ExecutionPhaseChanged {
	data := map[string]interface{}{
		"experiment_id": execution.ExperimentID,
		"old_phase":     oldPhase,
		"new_phase":     execution.Phase,
		"progress":      execution.Progress.Percentage,
		"message":       execution.Progress.Message,
	}
	
	return &ExecutionPhaseChanged{
		BaseDomainEvent: newBaseDomainEvent(
			"execution.phase_changed",
			string(execution.ID),
			"execution",
			1,
			data,
		),
		OldPhase: oldPhase,
		NewPhase: execution.Phase,
		Progress: execution.Progress.Percentage,
	}
}

// ExecutionCompleted is fired when an execution completes
type ExecutionCompleted struct {
	*BaseDomainEvent
	ExperimentID    ExperimentID  `json:"experiment_id"`
	FinalStatus     ExecutionStatus `json:"final_status"`
	Duration        Duration        `json:"duration"`
	SuccessfulTargets int           `json:"successful_targets"`
	FailedTargets     int           `json:"failed_targets"`
	SafetyViolations  int           `json:"safety_violations"`
}

// NewExecutionCompleted creates a new ExecutionCompleted event
func NewExecutionCompleted(execution *Execution) *ExecutionCompleted {
	successfulTargets := 0
	failedTargets := 0
	safetyViolations := len(execution.SafetyEvents)
	
	for _, result := range execution.Results {
		if result.Status == "success" {
			successfulTargets++
		} else {
			failedTargets++
		}
	}
	
	data := map[string]interface{}{
		"experiment_id":      execution.ExperimentID,
		"final_status":       execution.Status,
		"duration":           execution.Duration,
		"successful_targets": successfulTargets,
		"failed_targets":     failedTargets,
		"safety_violations":  safetyViolations,
		"total_actions":      len(execution.Results),
	}
	
	return &ExecutionCompleted{
		BaseDomainEvent: newBaseDomainEvent(
			"execution.completed",
			string(execution.ID),
			"execution",
			1,
			data,
		),
		ExperimentID:      execution.ExperimentID,
		FinalStatus:       execution.Status,
		Duration:          *execution.Duration,
		SuccessfulTargets: successfulTargets,
		FailedTargets:     failedTargets,
		SafetyViolations:  safetyViolations,
	}
}

// Safety Events

// SafetyViolationDetected is fired when a safety violation is detected
type SafetyViolationDetected struct {
	*BaseDomainEvent
	ExecutionID   ExecutionID `json:"execution_id"`
	ExperimentID  ExperimentID `json:"experiment_id"`
	CheckName     string      `json:"check_name"`
	Severity      string      `json:"severity"`
	Value         float64     `json:"value"`
	Threshold     Threshold   `json:"threshold"`
	ActionTaken   string      `json:"action_taken"`
}

// NewSafetyViolationDetected creates a new SafetyViolationDetected event
func NewSafetyViolationDetected(executionID ExecutionID, experimentID ExperimentID, event SafetyEvent) *SafetyViolationDetected {
	data := map[string]interface{}{
		"execution_id":  executionID,
		"experiment_id": experimentID,
		"check_name":    event.CheckName,
		"severity":      event.Severity,
		"value":         event.Value,
		"threshold":     event.Threshold,
		"action_taken":  event.Action,
		"message":       event.Message,
	}
	
	return &SafetyViolationDetected{
		BaseDomainEvent: newBaseDomainEvent(
			"safety.violation_detected",
			string(executionID),
			"execution",
			1,
			data,
		),
		ExecutionID:  executionID,
		ExperimentID: experimentID,
		CheckName:    event.CheckName,
		Severity:     event.Severity,
		Value:        event.Value,
		Threshold:    event.Threshold,
		ActionTaken:  event.Action,
	}
}

// Target Events

// TargetHealthChanged is fired when a target's health changes
type TargetHealthChanged struct {
	*BaseDomainEvent
	TargetID    string       `json:"target_id"`
	TargetName  string       `json:"target_name"`
	OldStatus   TargetStatus `json:"old_status"`
	NewStatus   TargetStatus `json:"new_status"`
	CheckResults []HealthCheck `json:"check_results"`
}

// NewTargetHealthChanged creates a new TargetHealthChanged event
func NewTargetHealthChanged(target *Target, oldStatus TargetStatus) *TargetHealthChanged {
	data := map[string]interface{}{
		"target_id":     target.ID,
		"target_name":   target.Name,
		"target_type":   target.Type,
		"old_status":    oldStatus,
		"new_status":    target.Status,
		"check_results": target.Health.CheckResults,
		"provider":      target.Provider,
	}
	
	return &TargetHealthChanged{
		BaseDomainEvent: newBaseDomainEvent(
			"target.health_changed",
			target.ID,
			"target",
			1,
			data,
		),
		TargetID:     target.ID,
		TargetName:   target.Name,
		OldStatus:    oldStatus,
		NewStatus:    target.Status,
		CheckResults: target.Health.CheckResults,
	}
}

// Provider Events

// ProviderRegistered is fired when a provider is registered
type ProviderRegistered struct {
	*BaseDomainEvent
	ProviderName string               `json:"provider_name"`
	ProviderType string               `json:"provider_type"`
	Version      string               `json:"version"`
	Capabilities ProviderCapabilities `json:"capabilities"`
}

// NewProviderRegistered creates a new ProviderRegistered event
func NewProviderRegistered(provider Provider) *ProviderRegistered {
	capabilities := provider.GetCapabilities()
	data := map[string]interface{}{
		"provider_name": provider.Name(),
		"provider_type": "chaos_provider",
		"version":       provider.Version(),
		"capabilities":  capabilities,
	}
	
	return &ProviderRegistered{
		BaseDomainEvent: newBaseDomainEvent(
			"provider.registered",
			provider.ID(),
			"provider",
			1,
			data,
		),
		ProviderName: provider.Name(),
		ProviderType: "chaos_provider",
		Version:      provider.Version(),
		Capabilities: capabilities,
	}
}

// ProviderHealthChanged is fired when a provider's health changes
type ProviderHealthChanged struct {
	*BaseDomainEvent
	ProviderName string `json:"provider_name"`
	OldHealthy   bool   `json:"old_healthy"`
	NewHealthy   bool   `json:"new_healthy"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// NewProviderHealthChanged creates a new ProviderHealthChanged event
func NewProviderHealthChanged(provider Provider, oldHealthy bool, errorMessage string) *ProviderHealthChanged {
	status := provider.GetStatus()
	data := map[string]interface{}{
		"provider_name":      provider.Name(),
		"provider_id":        provider.ID(),
		"old_healthy":        oldHealthy,
		"new_healthy":        status.Healthy,
		"status":             status.Status,
		"running_experiments": status.RunningExperiments,
	}
	
	if errorMessage != "" {
		data["error_message"] = errorMessage
	}
	
	return &ProviderHealthChanged{
		BaseDomainEvent: newBaseDomainEvent(
			"provider.health_changed",
			provider.ID(),
			"provider",
			1,
			data,
		),
		ProviderName: provider.Name(),
		OldHealthy:   oldHealthy,
		NewHealthy:   status.Healthy,
		ErrorMessage: errorMessage,
	}
}

// EventPublisher defines the interface for publishing domain events
type EventPublisher interface {
	Publish(ctx context.Context, events ...DomainEvent) error
}

// EventHandler defines the interface for handling domain events
type EventHandler interface {
	Handle(ctx context.Context, event DomainEvent) error
	CanHandle(eventType string) bool
}

// EventBus manages event publishing and subscription
type EventBus struct {
	handlers map[string][]EventHandler
	publisher EventPublisher
}

// NewEventBus creates a new event bus
func NewEventBus(publisher EventPublisher) *EventBus {
	return &EventBus{
		handlers:  make(map[string][]EventHandler),
		publisher: publisher,
	}
}

// Subscribe subscribes a handler to an event type
func (eb *EventBus) Subscribe(eventType string, handler EventHandler) {
	if eb.handlers[eventType] == nil {
		eb.handlers[eventType] = make([]EventHandler, 0)
	}
	eb.handlers[eventType] = append(eb.handlers[eventType], handler)
}

// Publish publishes events to both local handlers and external publisher
func (eb *EventBus) Publish(ctx context.Context, events ...DomainEvent) error {
	// Publish to external publisher first
	if eb.publisher != nil {
		if err := eb.publisher.Publish(ctx, events...); err != nil {
			return err
		}
	}
	
	// Handle locally
	for _, event := range events {
		if handlers, exists := eb.handlers[event.Type()]; exists {
			for _, handler := range handlers {
				if handler.CanHandle(event.Type()) {
					if err := handler.Handle(ctx, event); err != nil {
						// Log error but don't fail the entire publish
						// In a real implementation, you'd use proper logging
						continue
					}
				}
			}
		}
	}
	
	return nil
}