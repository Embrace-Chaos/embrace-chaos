package graphql

import (
	"context"
	"time"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/adapters/graphql/generated"
	"github.com/embrace-chaos/internal/adapters/graphql/model"
)

type subscriptionResolver struct{ *Resolver }

// ExecutionUpdated provides real-time updates for execution status
func (r *subscriptionResolver) ExecutionUpdated(ctx context.Context, id string) (<-chan *model.ExecutionUpdate, error) {
	updateChan := make(chan *model.ExecutionUpdate, 10)
	
	go func() {
		defer close(updateChan)
		
		// Start monitoring execution
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		
		var lastStatus domain.ExecutionStatus
		var lastProgress float64
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Get current execution status
				execution, err := r.executionService.GetExecution(ctx, domain.ExecutionID(id))
				if err != nil {
					continue
				}
				
				// Calculate progress based on status and phases
				progress := calculateExecutionProgress(execution)
				
				// Send update if status or progress changed
				if execution.Status != lastStatus || progress != lastProgress {
					update := &model.ExecutionUpdate{
						ID:           id,
						Status:       model.ExecutionStatus(execution.Status),
						Progress:     progress,
						CurrentPhase: getCurrentPhase(execution),
						Message:      getStatusMessage(execution),
						Metrics:      convertExecutionMetrics(execution),
						Timestamp:    time.Now().Format(time.RFC3339),
					}
					
					select {
					case updateChan <- update:
					case <-ctx.Done():
						return
					}
					
					lastStatus = execution.Status
					lastProgress = progress
				}
				
				// Stop monitoring if execution is complete
				if isExecutionComplete(execution.Status) {
					return
				}
			}
		}
	}()
	
	return updateChan, nil
}

// ExecutionLogs provides real-time log streaming
func (r *subscriptionResolver) ExecutionLogs(ctx context.Context, id string, tail *int) (<-chan *model.LogEntry, error) {
	logChan := make(chan *model.LogEntry, 100)
	
	go func() {
		defer close(logChan)
		
		// Get initial logs
		tailCount := 10
		if tail != nil && *tail > 0 {
			tailCount = *tail
		}
		
		logs, err := r.executionService.GetExecutionLogs(ctx, domain.ExecutionID(id), tailCount)
		if err != nil {
			return
		}
		
		// Send initial logs
		for _, log := range logs {
			logEntry := &model.LogEntry{
				Timestamp: log.Timestamp.Format(time.RFC3339),
				Level:     model.LogLevel(log.Level),
				Message:   log.Message,
				Source:    log.Source,
				Metadata:  log.Metadata,
			}
			
			select {
			case logChan <- logEntry:
			case <-ctx.Done():
				return
			}
		}
		
		// Stream new logs
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		
		lastLogTime := time.Now()
		if len(logs) > 0 {
			lastLogTime = logs[len(logs)-1].Timestamp
		}
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Get new logs since last check
				newLogs, err := r.executionService.GetExecutionLogsSince(ctx, domain.ExecutionID(id), lastLogTime)
				if err != nil {
					continue
				}
				
				for _, log := range newLogs {
					logEntry := &model.LogEntry{
						Timestamp: log.Timestamp.Format(time.RFC3339),
						Level:     model.LogLevel(log.Level),
						Message:   log.Message,
						Source:    log.Source,
						Metadata:  log.Metadata,
					}
					
					select {
					case logChan <- logEntry:
						lastLogTime = log.Timestamp
					case <-ctx.Done():
						return
					}
				}
				
				// Check if execution is complete
				execution, err := r.executionService.GetExecution(ctx, domain.ExecutionID(id))
				if err == nil && isExecutionComplete(execution.Status) {
					return
				}
			}
		}
	}()
	
	return logChan, nil
}

// ExperimentChanged provides real-time updates for experiment changes
func (r *subscriptionResolver) ExperimentChanged(ctx context.Context, id string) (<-chan *model.ExperimentUpdate, error) {
	updateChan := make(chan *model.ExperimentUpdate, 10)
	
	go func() {
		defer close(updateChan)
		
		// Monitor experiment changes
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		
		var lastVersion int
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				experiment, err := r.experimentService.GetExperiment(ctx, domain.ExperimentID(id))
				if err != nil {
					continue
				}
				
				// Send update if version changed
				if experiment.Version != lastVersion && lastVersion != 0 {
					update := &model.ExperimentUpdate{
						ID:         id,
						ChangeType: model.ChangeTypeUpdated,
						Field:      "version",
						NewValue:   stringPtr(string(rune(experiment.Version))),
						Timestamp:  time.Now().Format(time.RFC3339),
					}
					
					select {
					case updateChan <- update:
					case <-ctx.Done():
						return
					}
				}
				
				lastVersion = experiment.Version
			}
		}
	}()
	
	return updateChan, nil
}

// SafetyAlert provides real-time safety alerts
func (r *subscriptionResolver) SafetyAlert(ctx context.Context, experimentID *string) (<-chan *model.SafetyAlert, error) {
	alertChan := make(chan *model.SafetyAlert, 10)
	
	go func() {
		defer close(alertChan)
		
		// Monitor safety alerts
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Check for safety violations in running executions
				filter := ports.ExecutionFilters{
					Status: []domain.ExecutionStatus{domain.ExecutionStatusRunning},
				}
				
				if experimentID != nil {
					filter.ExperimentID = domain.ExperimentID(*experimentID)
				}
				
				pagination := ports.PaginationRequest{Page: 1, PageSize: 100}
				executions, _, err := r.executionService.ListExecutions(ctx, filter, pagination)
				if err != nil {
					continue
				}
				
				for _, execution := range executions {
					// Check safety status
					safetyStatus, err := r.executionService.GetSafetyStatus(ctx, execution.ID)
					if err != nil {
						continue
					}
					
					// Generate alerts for violations
					for _, violation := range safetyStatus.Violations {
						alert := &model.SafetyAlert{
							ID:            generateAlertID(),
							Severity:      convertAlertSeverity(violation.Severity),
							ExperimentID:  string(execution.ExperimentID),
							ExecutionID:   string(execution.ID),
							Metric:        violation.Metric,
							Threshold:     violation.Threshold,
							ActualValue:   violation.ActualValue,
							Message:       generateAlertMessage(violation),
							Timestamp:     time.Now().Format(time.RFC3339),
						}
						
						select {
						case alertChan <- alert:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}
	}()
	
	return alertChan, nil
}

// OrganizationEvents provides real-time organization-wide events
func (r *subscriptionResolver) OrganizationEvents(ctx context.Context, organizationID string) (<-chan *model.OrganizationEvent, error) {
	eventChan := make(chan *model.OrganizationEvent, 50)
	
	go func() {
		defer close(eventChan)
		
		// Monitor organization events
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		
		lastEventTime := time.Now()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Get recent events for the organization
				events, err := r.organizationService.GetRecentEvents(ctx, organizationID, lastEventTime)
				if err != nil {
					continue
				}
				
				for _, event := range events {
					orgEvent := &model.OrganizationEvent{
						ID:         event.ID,
						Type:       convertEventType(event.Type),
						Resource:   event.Resource,
						ResourceID: event.ResourceID,
						Action:     event.Action,
						Metadata:   event.Metadata,
						Timestamp:  event.Timestamp.Format(time.RFC3339),
					}
					
					select {
					case eventChan <- orgEvent:
						lastEventTime = event.Timestamp
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	
	return eventChan, nil
}

// Helper functions for subscriptions

func calculateExecutionProgress(execution *domain.Execution) float64 {
	switch execution.Status {
	case domain.ExecutionStatusPending:
		return 0.0
	case domain.ExecutionStatusRunning:
		// Calculate based on completed targets
		if len(execution.Results) == 0 {
			return 0.1 // Started but no results yet
		}
		
		completed := 0
		for _, result := range execution.Results {
			if result.Status == domain.ResultStatusSuccess || result.Status == domain.ResultStatusFailed {
				completed++
			}
		}
		
		progress := float64(completed) / float64(len(execution.Results))
		return 0.1 + (progress * 0.8) // Scale to 10-90%
	case domain.ExecutionStatusSucceeded, domain.ExecutionStatusFailed, domain.ExecutionStatusCancelled:
		return 1.0
	default:
		return 0.0
	}
}

func getCurrentPhase(execution *domain.Execution) string {
	switch execution.Status {
	case domain.ExecutionStatusPending:
		return "Initializing"
	case domain.ExecutionStatusRunning:
		if len(execution.Results) == 0 {
			return "Starting chaos injection"
		}
		return "Executing chaos experiments"
	case domain.ExecutionStatusSucceeded:
		return "Completed successfully"
	case domain.ExecutionStatusFailed:
		return "Failed"
	case domain.ExecutionStatusCancelled:
		return "Cancelled"
	default:
		return "Unknown"
	}
}

func getStatusMessage(execution *domain.Execution) *string {
	var message string
	
	switch execution.Status {
	case domain.ExecutionStatusRunning:
		completed := 0
		total := len(execution.Results)
		for _, result := range execution.Results {
			if result.Status == domain.ResultStatusSuccess || result.Status == domain.ResultStatusFailed {
				completed++
			}
		}
		message = fmt.Sprintf("Progress: %d/%d targets completed", completed, total)
	case domain.ExecutionStatusFailed:
		message = "Execution failed - check logs for details"
	case domain.ExecutionStatusCancelled:
		message = "Execution was cancelled by user"
	default:
		return nil
	}
	
	return &message
}

func convertExecutionMetrics(execution *domain.Execution) *model.ExecutionMetrics {
	metrics := &model.ExecutionMetrics{
		TargetsAffected:    len(execution.Results),
		SuccessCount:       0,
		FailureCount:       0,
		RollbackCount:      0,
		TotalDuration:      execution.Duration.String(),
		AvgTargetDuration:  "0s",
	}
	
	var totalDuration time.Duration
	var completedTargets int
	
	for _, result := range execution.Results {
		switch result.Status {
		case domain.ResultStatusSuccess:
			metrics.SuccessCount++
		case domain.ResultStatusFailed:
			metrics.FailureCount++
		case domain.ResultStatusRollback:
			metrics.RollbackCount++
		}
		
		if !result.CompletedAt.IsZero() && !result.StartedAt.IsZero() {
			duration := result.CompletedAt.Sub(result.StartedAt)
			totalDuration += duration
			completedTargets++
		}
	}
	
	if completedTargets > 0 {
		avgDuration := totalDuration / time.Duration(completedTargets)
		metrics.AvgTargetDuration = avgDuration.String()
	}
	
	return metrics
}

func isExecutionComplete(status domain.ExecutionStatus) bool {
	return status == domain.ExecutionStatusSucceeded ||
		status == domain.ExecutionStatusFailed ||
		status == domain.ExecutionStatusCancelled ||
		status == domain.ExecutionStatusTimeout
}

func generateAlertID() string {
	// Generate unique alert ID
	return fmt.Sprintf("alert_%d", time.Now().UnixNano())
}

func convertAlertSeverity(severity domain.AlertSeverity) model.AlertSeverity {
	switch severity {
	case domain.AlertSeverityInfo:
		return model.AlertSeverityInfo
	case domain.AlertSeverityWarning:
		return model.AlertSeverityWarning
	case domain.AlertSeverityError:
		return model.AlertSeverityError
	case domain.AlertSeverityCritical:
		return model.AlertSeverityCritical
	default:
		return model.AlertSeverityInfo
	}
}

func generateAlertMessage(violation domain.SafetyViolation) string {
	return fmt.Sprintf("Safety threshold exceeded for %s: %.2f > %.2f", 
		violation.Metric, violation.ActualValue, violation.Threshold)
}

func convertEventType(eventType domain.EventType) model.EventType {
	switch eventType {
	case domain.EventTypeAudit:
		return model.EventTypeAudit
	case domain.EventTypeSafety:
		return model.EventTypeSafety
	case domain.EventTypeQuota:
		return model.EventTypeQuota
	case domain.EventTypeSystem:
		return model.EventTypeSystem
	default:
		return model.EventTypeSystem
	}
}

// Import fmt package for string formatting
import "fmt"