package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// SagaOrchestrator implements the saga pattern for experiment execution
type SagaOrchestrator struct {
	sagas          map[string]*Saga
	compensations  map[string][]CompensationAction
	eventBus       EventBus
	stateManager   StateManager
	progressTracker ProgressTracker
	mu             sync.RWMutex
}

// NewSagaOrchestrator creates a new saga orchestrator
func NewSagaOrchestrator(eventBus EventBus, stateManager StateManager, progressTracker ProgressTracker) *SagaOrchestrator {
	return &SagaOrchestrator{
		sagas:           make(map[string]*Saga),
		compensations:   make(map[string][]CompensationAction),
		eventBus:        eventBus,
		stateManager:    stateManager,
		progressTracker: progressTracker,
	}
}

// ExecuteExperiment orchestrates the execution of a chaos experiment using saga pattern
func (o *SagaOrchestrator) ExecuteExperiment(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) error {
	// Create saga for this execution
	saga := &Saga{
		ID:           fmt.Sprintf("saga-%s", execution.ID),
		ExecutionID:  execution.ID,
		ExperimentID: experiment.ID,
		State:        SagaStateStarted,
		Steps:        make([]*SagaStep, 0),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Register saga
	o.mu.Lock()
	o.sagas[saga.ID] = saga
	o.compensations[saga.ID] = make([]CompensationAction, 0)
	o.mu.Unlock()

	// Publish saga started event
	if err := o.eventBus.PublishEvent(ctx, &SagaStartedEvent{
		SagaID:       saga.ID,
		ExecutionID:  execution.ID,
		ExperimentID: experiment.ID,
		Timestamp:    time.Now(),
	}); err != nil {
		return errors.NewOrchestrationError("failed to publish saga started event: %w", err)
	}

	// Execute saga steps
	if err := o.executeSagaSteps(ctx, saga, experiment, execution); err != nil {
		// Compensate on failure
		if compensateErr := o.compensate(ctx, saga); compensateErr != nil {
			return errors.NewOrchestrationError("execution failed and compensation failed: %w", compensateErr)
		}
		return err
	}

	// Mark saga as completed
	saga.State = SagaStateCompleted
	saga.UpdatedAt = time.Now()

	// Publish saga completed event
	if err := o.eventBus.PublishEvent(ctx, &SagaCompletedEvent{
		SagaID:       saga.ID,
		ExecutionID:  execution.ID,
		ExperimentID: experiment.ID,
		Timestamp:    time.Now(),
	}); err != nil {
		return errors.NewOrchestrationError("failed to publish saga completed event: %w", err)
	}

	return nil
}

// CompensateExperiment performs compensation for a failed experiment
func (o *SagaOrchestrator) CompensateExperiment(ctx context.Context, executionID domain.ExecutionID) error {
	// Find saga by execution ID
	var saga *Saga
	o.mu.RLock()
	for _, s := range o.sagas {
		if s.ExecutionID == executionID {
			saga = s
			break
		}
	}
	o.mu.RUnlock()

	if saga == nil {
		return errors.NewNotFoundError("saga not found for execution: %s", executionID)
	}

	return o.compensate(ctx, saga)
}

// GetSagaState returns the current state of a saga
func (o *SagaOrchestrator) GetSagaState(sagaID string) (*Saga, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	saga, exists := o.sagas[sagaID]
	if !exists {
		return nil, errors.NewNotFoundError("saga not found: %s", sagaID)
	}

	return saga, nil
}

// Private methods

func (o *SagaOrchestrator) executeSagaSteps(ctx context.Context, saga *Saga, experiment *domain.Experiment, execution *domain.Execution) error {
	// Step 1: Pre-flight checks
	if err := o.executePreflightStep(ctx, saga, experiment, execution); err != nil {
		return err
	}

	// Step 2: Resource preparation
	if err := o.executeResourcePreparationStep(ctx, saga, experiment, execution); err != nil {
		return err
	}

	// Step 3: Chaos injection
	if err := o.executeChaosInjectionStep(ctx, saga, experiment, execution); err != nil {
		return err
	}

	// Step 4: Monitoring and validation
	if err := o.executeMonitoringStep(ctx, saga, experiment, execution); err != nil {
		return err
	}

	// Step 5: Cleanup
	if err := o.executeCleanupStep(ctx, saga, experiment, execution); err != nil {
		return err
	}

	return nil
}

func (o *SagaOrchestrator) executePreflightStep(ctx context.Context, saga *Saga, experiment *domain.Experiment, execution *domain.Execution) error {
	step := &SagaStep{
		ID:           fmt.Sprintf("%s-preflight", saga.ID),
		Name:         "Preflight Checks",
		Type:         StepTypePreflight,
		State:        StepStateStarted,
		StartedAt:    time.Now(),
	}

	saga.Steps = append(saga.Steps, step)

	// Update progress
	if err := o.progressTracker.UpdateProgress(ctx, execution.ID, ProgressUpdate{
		Step:        "Preflight Checks",
		Progress:    10,
		Message:     "Running preflight checks",
		Timestamp:   time.Now(),
	}); err != nil {
		return errors.NewOrchestrationError("failed to update progress: %w", err)
	}

	// Execute preflight checks
	for _, check := range experiment.Safety.PreflightChecks {
		if err := o.executePreflightCheck(ctx, check, experiment, execution); err != nil {
			step.State = StepStateFailed
			step.Error = err.Error()
			step.CompletedAt = time.Now()
			return errors.NewOrchestrationError("preflight check failed: %w", err)
		}
	}

	// Add compensation action for preflight step
	o.addCompensationAction(saga.ID, CompensationAction{
		Type:        CompensationTypeCleanup,
		Description: "Cleanup preflight resources",
		Action: func(ctx context.Context) error {
			// Cleanup any resources created during preflight
			return nil
		},
	})

	step.State = StepStateCompleted
	step.CompletedAt = time.Now()

	return nil
}

func (o *SagaOrchestrator) executeResourcePreparationStep(ctx context.Context, saga *Saga, experiment *domain.Experiment, execution *domain.Execution) error {
	step := &SagaStep{
		ID:           fmt.Sprintf("%s-resource-prep", saga.ID),
		Name:         "Resource Preparation",
		Type:         StepTypeResourcePreparation,
		State:        StepStateStarted,
		StartedAt:    time.Now(),
	}

	saga.Steps = append(saga.Steps, step)

	// Update progress
	if err := o.progressTracker.UpdateProgress(ctx, execution.ID, ProgressUpdate{
		Step:        "Resource Preparation",
		Progress:    25,
		Message:     "Preparing target resources",
		Timestamp:   time.Now(),
	}); err != nil {
		return errors.NewOrchestrationError("failed to update progress: %w", err)
	}

	// Prepare resources for each target
	for _, target := range experiment.Targets {
		if err := o.prepareTargetResources(ctx, &target, experiment, execution); err != nil {
			step.State = StepStateFailed
			step.Error = err.Error()
			step.CompletedAt = time.Now()
			return errors.NewOrchestrationError("resource preparation failed for target %s: %w", target.ID, err)
		}

		// Add compensation action for each prepared resource
		o.addCompensationAction(saga.ID, CompensationAction{
			Type:        CompensationTypeResourceCleanup,
			Description: fmt.Sprintf("Cleanup resources for target %s", target.ID),
			TargetID:    target.ID,
			Action: func(ctx context.Context) error {
				return o.cleanupTargetResources(ctx, &target)
			},
		})
	}

	step.State = StepStateCompleted
	step.CompletedAt = time.Now()

	return nil
}

func (o *SagaOrchestrator) executeChaosInjectionStep(ctx context.Context, saga *Saga, experiment *domain.Experiment, execution *domain.Execution) error {
	step := &SagaStep{
		ID:           fmt.Sprintf("%s-chaos-injection", saga.ID),
		Name:         "Chaos Injection",
		Type:         StepTypeChaosInjection,
		State:        StepStateStarted,
		StartedAt:    time.Now(),
	}

	saga.Steps = append(saga.Steps, step)

	// Update progress
	if err := o.progressTracker.UpdateProgress(ctx, execution.ID, ProgressUpdate{
		Step:        "Chaos Injection",
		Progress:    50,
		Message:     "Injecting chaos into targets",
		Timestamp:   time.Now(),
	}); err != nil {
		return errors.NewOrchestrationError("failed to update progress: %w", err)
	}

	// Execute chaos actions based on concurrency mode
	switch experiment.Config.ConcurrencyMode {
	case domain.ConcurrencyModeSequential:
		if err := o.executeChaosSequentially(ctx, saga, experiment, execution); err != nil {
			step.State = StepStateFailed
			step.Error = err.Error()
			step.CompletedAt = time.Now()
			return err
		}
	case domain.ConcurrencyModeParallel:
		if err := o.executeChaosParallel(ctx, saga, experiment, execution); err != nil {
			step.State = StepStateFailed
			step.Error = err.Error()
			step.CompletedAt = time.Now()
			return err
		}
	case domain.ConcurrencyModePipeline:
		if err := o.executeChaosPipeline(ctx, saga, experiment, execution); err != nil {
			step.State = StepStateFailed
			step.Error = err.Error()
			step.CompletedAt = time.Now()
			return err
		}
	default:
		return errors.NewValidationError("unsupported concurrency mode: %s", experiment.Config.ConcurrencyMode)
	}

	step.State = StepStateCompleted
	step.CompletedAt = time.Now()

	return nil
}

func (o *SagaOrchestrator) executeMonitoringStep(ctx context.Context, saga *Saga, experiment *domain.Experiment, execution *domain.Execution) error {
	step := &SagaStep{
		ID:           fmt.Sprintf("%s-monitoring", saga.ID),
		Name:         "Monitoring",
		Type:         StepTypeMonitoring,
		State:        StepStateStarted,
		StartedAt:    time.Now(),
	}

	saga.Steps = append(saga.Steps, step)

	// Update progress
	if err := o.progressTracker.UpdateProgress(ctx, execution.ID, ProgressUpdate{
		Step:        "Monitoring",
		Progress:    75,
		Message:     "Monitoring experiment progress",
		Timestamp:   time.Now(),
	}); err != nil {
		return errors.NewOrchestrationError("failed to update progress: %w", err)
	}

	// Start monitoring goroutine
	monitoringCtx, cancel := context.WithTimeout(ctx, time.Duration(experiment.Config.Duration))
	defer cancel()

	if err := o.monitorExperiment(monitoringCtx, saga, experiment, execution); err != nil {
		step.State = StepStateFailed
		step.Error = err.Error()
		step.CompletedAt = time.Now()
		return errors.NewOrchestrationError("monitoring failed: %w", err)
	}

	step.State = StepStateCompleted
	step.CompletedAt = time.Now()

	return nil
}

func (o *SagaOrchestrator) executeCleanupStep(ctx context.Context, saga *Saga, experiment *domain.Experiment, execution *domain.Execution) error {
	step := &SagaStep{
		ID:           fmt.Sprintf("%s-cleanup", saga.ID),
		Name:         "Cleanup",
		Type:         StepTypeCleanup,
		State:        StepStateStarted,
		StartedAt:    time.Now(),
	}

	saga.Steps = append(saga.Steps, step)

	// Update progress
	if err := o.progressTracker.UpdateProgress(ctx, execution.ID, ProgressUpdate{
		Step:        "Cleanup",
		Progress:    90,
		Message:     "Cleaning up experiment resources",
		Timestamp:   time.Now(),
	}); err != nil {
		return errors.NewOrchestrationError("failed to update progress: %w", err)
	}

	// Cleanup resources
	for _, target := range experiment.Targets {
		if err := o.cleanupTargetResources(ctx, &target); err != nil {
			// Log error but don't fail the entire cleanup
			step.Warnings = append(step.Warnings, fmt.Sprintf("Failed to cleanup target %s: %v", target.ID, err))
		}
	}

	// Update progress to complete
	if err := o.progressTracker.UpdateProgress(ctx, execution.ID, ProgressUpdate{
		Step:        "Completed",
		Progress:    100,
		Message:     "Experiment completed successfully",
		Timestamp:   time.Now(),
	}); err != nil {
		return errors.NewOrchestrationError("failed to update final progress: %w", err)
	}

	step.State = StepStateCompleted
	step.CompletedAt = time.Now()

	return nil
}

func (o *SagaOrchestrator) compensate(ctx context.Context, saga *Saga) error {
	saga.State = SagaStateCompensating
	saga.UpdatedAt = time.Now()

	// Publish compensation started event
	if err := o.eventBus.PublishEvent(ctx, &SagaCompensationStartedEvent{
		SagaID:      saga.ID,
		ExecutionID: saga.ExecutionID,
		Timestamp:   time.Now(),
	}); err != nil {
		return errors.NewOrchestrationError("failed to publish compensation started event: %w", err)
	}

	// Execute compensation actions in reverse order
	o.mu.RLock()
	compensations := o.compensations[saga.ID]
	o.mu.RUnlock()

	var compensationErrors []error
	for i := len(compensations) - 1; i >= 0; i-- {
		compensation := compensations[i]
		if err := compensation.Action(ctx); err != nil {
			compensationErrors = append(compensationErrors, fmt.Errorf("compensation %s failed: %w", compensation.Description, err))
		}
	}

	if len(compensationErrors) > 0 {
		saga.State = SagaStateCompensationFailed
		saga.UpdatedAt = time.Now()
		return errors.NewOrchestrationError("compensation failed: %v", compensationErrors)
	}

	saga.State = SagaStateCompensated
	saga.UpdatedAt = time.Now()

	// Publish compensation completed event
	if err := o.eventBus.PublishEvent(ctx, &SagaCompensationCompletedEvent{
		SagaID:      saga.ID,
		ExecutionID: saga.ExecutionID,
		Timestamp:   time.Now(),
	}); err != nil {
		return errors.NewOrchestrationError("failed to publish compensation completed event: %w", err)
	}

	return nil
}

func (o *SagaOrchestrator) addCompensationAction(sagaID string, action CompensationAction) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.compensations[sagaID] = append(o.compensations[sagaID], action)
}

// Placeholder implementations for specific execution modes
func (o *SagaOrchestrator) executeChaosSequentially(ctx context.Context, saga *Saga, experiment *domain.Experiment, execution *domain.Execution) error {
	// Execute targets one by one
	for _, target := range experiment.Targets {
		if err := o.executeChaosOnTarget(ctx, &target, experiment, execution); err != nil {
			return err
		}
	}
	return nil
}

func (o *SagaOrchestrator) executeChaosParallel(ctx context.Context, saga *Saga, experiment *domain.Experiment, execution *domain.Execution) error {
	// Execute all targets in parallel
	var wg sync.WaitGroup
	errChan := make(chan error, len(experiment.Targets))

	for _, target := range experiment.Targets {
		wg.Add(1)
		go func(t domain.Target) {
			defer wg.Done()
			if err := o.executeChaosOnTarget(ctx, &t, experiment, execution); err != nil {
				errChan <- err
			}
		}(target)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

func (o *SagaOrchestrator) executeChaosPipeline(ctx context.Context, saga *Saga, experiment *domain.Experiment, execution *domain.Execution) error {
	// Execute targets in pipeline mode (with dependencies)
	// This would implement a more complex dependency resolution
	return o.executeChaosSequentially(ctx, saga, experiment, execution)
}

// Placeholder implementations for specific operations
func (o *SagaOrchestrator) executePreflightCheck(ctx context.Context, check string, experiment *domain.Experiment, execution *domain.Execution) error {
	// Implementation would depend on the specific check type
	return nil
}

func (o *SagaOrchestrator) prepareTargetResources(ctx context.Context, target *domain.Target, experiment *domain.Experiment, execution *domain.Execution) error {
	// Implementation would prepare resources for the target
	return nil
}

func (o *SagaOrchestrator) cleanupTargetResources(ctx context.Context, target *domain.Target) error {
	// Implementation would cleanup resources for the target
	return nil
}

func (o *SagaOrchestrator) executeChaosOnTarget(ctx context.Context, target *domain.Target, experiment *domain.Experiment, execution *domain.Execution) error {
	// Implementation would execute chaos actions on the target
	return nil
}

func (o *SagaOrchestrator) monitorExperiment(ctx context.Context, saga *Saga, experiment *domain.Experiment, execution *domain.Execution) error {
	// Implementation would monitor the experiment for the specified duration
	ticker := time.NewTicker(time.Duration(experiment.Safety.MonitoringPeriod))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Perform monitoring checks
			// This would check health, metrics, etc.
		}
	}
}