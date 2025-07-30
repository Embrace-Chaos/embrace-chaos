package safety

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// SafetyController manages safety mechanisms for chaos experiments
type SafetyController struct {
	preflightCheckers map[string]PreflightChecker
	healthCheckers    map[string]HealthChecker
	monitors          map[string]Monitor
	rollbackManager   RollbackManager
	alertManager      AlertManager
	circuitBreaker    CircuitBreaker
	rateLimiter       RateLimiter
	config            SafetyConfig
	mu                sync.RWMutex
	activeMonitors    map[domain.ExecutionID]context.CancelFunc
}

// NewSafetyController creates a new safety controller
func NewSafetyController(config SafetyConfig, rollbackManager RollbackManager, alertManager AlertManager) *SafetyController {
	controller := &SafetyController{
		preflightCheckers: make(map[string]PreflightChecker),
		healthCheckers:    make(map[string]HealthChecker),
		monitors:          make(map[string]Monitor),
		rollbackManager:   rollbackManager,
		alertManager:      alertManager,
		config:            config,
		activeMonitors:    make(map[domain.ExecutionID]context.CancelFunc),
	}

	// Initialize built-in checkers and monitors
	controller.initializeBuiltinCheckers()
	controller.initializeBuiltinMonitors()

	// Initialize circuit breaker and rate limiter
	controller.circuitBreaker = NewCircuitBreaker(config.CircuitBreakerConfig)
	controller.rateLimiter = NewRateLimiter(config.RateLimiterConfig)

	return controller
}

// RunPreflightChecks executes all preflight checks for an experiment
func (c *SafetyController) RunPreflightChecks(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) (*PreflightResult, error) {
	if !c.circuitBreaker.CanExecute() {
		return nil, errors.NewSafetyError("circuit breaker is open, cannot run preflight checks")
	}

	if !c.rateLimiter.Allow() {
		return nil, errors.NewSafetyError("rate limit exceeded for preflight checks")
	}

	result := &PreflightResult{
		ExecutionID:  execution.ID,
		StartedAt:    time.Now(),
		CheckResults: make(map[string]*CheckResult),
		OverallStatus: CheckStatusPending,
	}

	var checkErrors []error
	var warnings []string

	// Run system-level checks
	if err := c.runSystemChecks(ctx, experiment, execution, result); err != nil {
		checkErrors = append(checkErrors, err)
	}

	// Run target-specific checks
	for _, target := range experiment.Targets {
		if err := c.runTargetChecks(ctx, &target, experiment, execution, result); err != nil {
			checkErrors = append(checkErrors, err)
		}
	}

	// Run safety configuration checks
	if err := c.runSafetyConfigChecks(ctx, experiment, execution, result); err != nil {
		checkErrors = append(checkErrors, err)
	}

	// Run custom preflight checks
	for _, checkName := range experiment.Safety.PreflightChecks {
		if checker, exists := c.preflightCheckers[checkName]; exists {
			checkResult, err := checker.Check(ctx, experiment, execution)
			result.CheckResults[checkName] = checkResult
			
			if err != nil {
				checkErrors = append(checkErrors, fmt.Errorf("preflight check %s failed: %w", checkName, err))
			} else if checkResult.Status == CheckStatusWarning {
				warnings = append(warnings, fmt.Sprintf("preflight check %s returned warning: %s", checkName, checkResult.Message))
			}
		} else {
			checkErrors = append(checkErrors, fmt.Errorf("unknown preflight check: %s", checkName))
		}
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)
	result.Warnings = warnings

	// Determine overall status
	if len(checkErrors) > 0 {
		result.OverallStatus = CheckStatusFailed
		result.Errors = checkErrors
		c.circuitBreaker.RecordFailure()
		return result, errors.NewSafetyError("preflight checks failed: %v", checkErrors)
	}

	if len(warnings) > 0 {
		result.OverallStatus = CheckStatusWarning
	} else {
		result.OverallStatus = CheckStatusPassed
	}

	c.circuitBreaker.RecordSuccess()
	return result, nil
}

// StartMonitoring begins real-time monitoring of an experiment
func (c *SafetyController) StartMonitoring(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) error {
	monitoringCtx, cancel := context.WithCancel(ctx)
	
	c.mu.Lock()
	c.activeMonitors[execution.ID] = cancel
	c.mu.Unlock()

	// Start monitoring goroutine
	go func() {
		defer func() {
			c.mu.Lock()
			delete(c.activeMonitors, execution.ID)
			c.mu.Unlock()
		}()

		if err := c.monitorExperiment(monitoringCtx, experiment, execution); err != nil {
			// Log error and potentially trigger alerts
			c.alertManager.SendAlert(ctx, &Alert{
				Type:        AlertTypeMonitoringError,
				Severity:    AlertSeverityCritical,
				ExecutionID: execution.ID,
				Message:     fmt.Sprintf("Monitoring error: %v", err),
				Timestamp:   time.Now(),
			})
		}
	}()

	return nil
}

// StopMonitoring stops monitoring for an experiment
func (c *SafetyController) StopMonitoring(ctx context.Context, executionID domain.ExecutionID) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if cancel, exists := c.activeMonitors[executionID]; exists {
		cancel()
		delete(c.activeMonitors, executionID)
	}

	return nil
}

// CheckSafetyThresholds evaluates current safety thresholds
func (c *SafetyController) CheckSafetyThresholds(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution, metrics *SafetyMetrics) (*SafetyEvaluation, error) {
	evaluation := &SafetyEvaluation{
		ExecutionID:   execution.ID,
		Timestamp:     time.Now(),
		Metrics:       metrics,
		Violations:    make([]*SafetyViolation, 0),
		OverallStatus: SafetyStatusSafe,
	}

	// Check failure threshold
	if metrics.FailureRate > float64(experiment.Safety.FailureThreshold) {
		violation := &SafetyViolation{
			Type:        ViolationTypeFailureThreshold,
			Severity:    ViolationSeverityHigh,
			Message:     fmt.Sprintf("Failure rate %.2f%% exceeds threshold %.2f%%", metrics.FailureRate, float64(experiment.Safety.FailureThreshold)),
			Metric:      "failure_rate",
			Current:     metrics.FailureRate,
			Threshold:   float64(experiment.Safety.FailureThreshold),
			Timestamp:   time.Now(),
		}
		evaluation.Violations = append(evaluation.Violations, violation)
	}

	// Check max failures
	if metrics.TotalFailures > experiment.Safety.MaxFailures {
		violation := &SafetyViolation{
			Type:        ViolationTypeMaxFailures,
			Severity:    ViolationSeverityCritical,
			Message:     fmt.Sprintf("Total failures %d exceeds maximum %d", metrics.TotalFailures, experiment.Safety.MaxFailures),
			Metric:      "total_failures",
			Current:     float64(metrics.TotalFailures),
			Threshold:   float64(experiment.Safety.MaxFailures),
			Timestamp:   time.Now(),
		}
		evaluation.Violations = append(evaluation.Violations, violation)
	}

	// Check custom alert thresholds
	for metric, threshold := range experiment.Safety.AlertThresholds {
		if metricValue, exists := metrics.CustomMetrics[metric]; exists {
			if metricValue > float64(threshold) {
				violation := &SafetyViolation{
					Type:        ViolationTypeCustomThreshold,
					Severity:    ViolationSeverityMedium,
					Message:     fmt.Sprintf("Custom metric %s value %.2f exceeds threshold %.2f", metric, metricValue, float64(threshold)),
					Metric:      metric,
					Current:     metricValue,
					Threshold:   float64(threshold),
					Timestamp:   time.Now(),
				}
				evaluation.Violations = append(evaluation.Violations, violation)
			}
		}
	}

	// Determine overall status
	if len(evaluation.Violations) > 0 {
		// Find highest severity
		highestSeverity := ViolationSeverityLow
		for _, violation := range evaluation.Violations {
			if violation.Severity > highestSeverity {
				highestSeverity = violation.Severity
			}
		}

		if highestSeverity >= ViolationSeverityCritical {
			evaluation.OverallStatus = SafetyStatusCritical
		} else if highestSeverity >= ViolationSeverityHigh {
			evaluation.OverallStatus = SafetyStatusDangerous
		} else {
			evaluation.OverallStatus = SafetyStatusWarning
		}
	}

	return evaluation, nil
}

// TriggerRollback initiates automatic rollback of an experiment
func (c *SafetyController) TriggerRollback(ctx context.Context, executionID domain.ExecutionID, reason string) error {
	if !c.config.AutoRollbackEnabled {
		return errors.NewSafetyError("automatic rollback is disabled")
	}

	rollbackCtx, cancel := context.WithTimeout(ctx, c.config.RollbackTimeout)
	defer cancel()

	rollback := &RollbackRequest{
		ExecutionID: executionID,
		Reason:      reason,
		Timestamp:   time.Now(),
		Timeout:     c.config.RollbackTimeout,
	}

	if err := c.rollbackManager.ExecuteRollback(rollbackCtx, rollback); err != nil {
		// Send critical alert on rollback failure
		c.alertManager.SendAlert(ctx, &Alert{
			Type:        AlertTypeRollbackFailed,
			Severity:    AlertSeverityCritical,
			ExecutionID: executionID,
			Message:     fmt.Sprintf("Rollback failed: %v", err),
			Timestamp:   time.Now(),
		})
		return errors.NewSafetyError("rollback failed: %w", err)
	}

	// Send success notification
	c.alertManager.SendAlert(ctx, &Alert{
		Type:        AlertTypeRollbackCompleted,
		Severity:    AlertSeverityInfo,
		ExecutionID: executionID,
		Message:     fmt.Sprintf("Rollback completed successfully: %s", reason),
		Timestamp:   time.Now(),
	})

	return nil
}

// RegisterPreflightChecker registers a custom preflight checker
func (c *SafetyController) RegisterPreflightChecker(name string, checker PreflightChecker) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.preflightCheckers[name] = checker
}

// RegisterHealthChecker registers a custom health checker
func (c *SafetyController) RegisterHealthChecker(name string, checker HealthChecker) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.healthCheckers[name] = checker
}

// RegisterMonitor registers a custom monitor
func (c *SafetyController) RegisterMonitor(name string, monitor Monitor) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.monitors[name] = monitor
}

// Private methods

func (c *SafetyController) initializeBuiltinCheckers() {
	// Resource availability checker
	c.preflightCheckers["resource_availability"] = &ResourceAvailabilityChecker{}
	
	// Permission checker
	c.preflightCheckers["permissions"] = &PermissionChecker{}
	
	// Target health checker
	c.preflightCheckers["target_health"] = &TargetHealthChecker{}
	
	// Network connectivity checker
	c.preflightCheckers["network_connectivity"] = &NetworkConnectivityChecker{}
	
	// Dependency checker
	c.preflightCheckers["dependencies"] = &DependencyChecker{}
	
	// Quota checker
	c.preflightCheckers["quota_limits"] = &QuotaChecker{}

	// Health checkers
	c.healthCheckers["system_health"] = &SystemHealthChecker{}
	c.healthCheckers["service_health"] = &ServiceHealthChecker{}
	c.healthCheckers["resource_health"] = &ResourceHealthChecker{}
}

func (c *SafetyController) initializeBuiltinMonitors() {
	// Failure rate monitor
	c.monitors["failure_rate"] = &FailureRateMonitor{}
	
	// Resource utilization monitor
	c.monitors["resource_utilization"] = &ResourceUtilizationMonitor{}
	
	// Response time monitor
	c.monitors["response_time"] = &ResponseTimeMonitor{}
	
	// Error count monitor
	c.monitors["error_count"] = &ErrorCountMonitor{}
	
	// Custom metrics monitor
	c.monitors["custom_metrics"] = &CustomMetricsMonitor{}
}

func (c *SafetyController) runSystemChecks(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution, result *PreflightResult) error {
	// Check system resources
	if checker, exists := c.preflightCheckers["resource_availability"]; exists {
		checkResult, err := checker.Check(ctx, experiment, execution)
		result.CheckResults["system_resources"] = checkResult
		if err != nil {
			return fmt.Errorf("system resource check failed: %w", err)
		}
	}

	// Check permissions
	if checker, exists := c.preflightCheckers["permissions"]; exists {
		checkResult, err := checker.Check(ctx, experiment, execution)
		result.CheckResults["permissions"] = checkResult
		if err != nil {
			return fmt.Errorf("permission check failed: %w", err)
		}
	}

	// Check quota limits
	if checker, exists := c.preflightCheckers["quota_limits"]; exists {
		checkResult, err := checker.Check(ctx, experiment, execution)
		result.CheckResults["quota_limits"] = checkResult
		if err != nil {
			return fmt.Errorf("quota check failed: %w", err)
		}
	}

	return nil
}

func (c *SafetyController) runTargetChecks(ctx context.Context, target *domain.Target, experiment *domain.Experiment, execution *domain.Execution, result *PreflightResult) error {
	// Check target health
	if checker, exists := c.preflightCheckers["target_health"]; exists {
		checkResult, err := checker.Check(ctx, experiment, execution)
		result.CheckResults[fmt.Sprintf("target_health_%s", target.ID)] = checkResult
		if err != nil {
			return fmt.Errorf("target health check failed for %s: %w", target.ID, err)
		}
	}

	// Check network connectivity
	if checker, exists := c.preflightCheckers["network_connectivity"]; exists {
		checkResult, err := checker.Check(ctx, experiment, execution)
		result.CheckResults[fmt.Sprintf("network_connectivity_%s", target.ID)] = checkResult
		if err != nil {
			return fmt.Errorf("network connectivity check failed for %s: %w", target.ID, err)
		}
	}

	return nil
}

func (c *SafetyController) runSafetyConfigChecks(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution, result *PreflightResult) error {
	// Validate safety configuration
	checkResult := &CheckResult{
		Status:    CheckStatusPassed,
		Message:   "Safety configuration is valid",
		Timestamp: time.Now(),
	}

	// Check if auto-rollback is enabled but no rollback timeout is set
	if experiment.Safety.AutoRollback && experiment.Safety.RollbackTimeout == 0 {
		checkResult.Status = CheckStatusWarning
		checkResult.Message = "Auto-rollback is enabled but no rollback timeout is set"
	}

	// Check if monitoring period is too short
	if experiment.Safety.MonitoringPeriod < domain.Duration(5*time.Second) {
		checkResult.Status = CheckStatusWarning
		checkResult.Message = "Monitoring period is very short, may cause performance issues"
	}

	// Check if failure threshold is reasonable
	if experiment.Safety.FailureThreshold > 90 {
		checkResult.Status = CheckStatusWarning
		checkResult.Message = "Failure threshold is very high, may not provide adequate protection"
	}

	result.CheckResults["safety_config"] = checkResult
	return nil
}

func (c *SafetyController) monitorExperiment(ctx context.Context, experiment *domain.Experiment, execution *domain.Execution) error {
	ticker := time.NewTicker(time.Duration(experiment.Safety.MonitoringPeriod))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Collect metrics from all monitors
			metrics := &SafetyMetrics{
				ExecutionID:     execution.ID,
				Timestamp:       time.Now(),
				CustomMetrics:   make(map[string]float64),
			}

			// Run all registered monitors
			for name, monitor := range c.monitors {
				if err := monitor.CollectMetrics(ctx, experiment, execution, metrics); err != nil {
					// Log error but continue monitoring
					continue
				}
			}

			// Evaluate safety thresholds
			evaluation, err := c.CheckSafetyThresholds(ctx, experiment, execution, metrics)
			if err != nil {
				return fmt.Errorf("safety threshold evaluation failed: %w", err)
			}

			// Handle violations
			if len(evaluation.Violations) > 0 {
				if err := c.handleSafetyViolations(ctx, evaluation, experiment, execution); err != nil {
					return fmt.Errorf("failed to handle safety violations: %w", err)
				}
			}
		}
	}
}

func (c *SafetyController) handleSafetyViolations(ctx context.Context, evaluation *SafetyEvaluation, experiment *domain.Experiment, execution *domain.Execution) error {
	// Send alerts for all violations
	for _, violation := range evaluation.Violations {
		alert := &Alert{
			Type:        AlertTypeSafetyViolation,
			Severity:    c.mapViolationSeverityToAlertSeverity(violation.Severity),
			ExecutionID: execution.ID,
			Message:     violation.Message,
			Timestamp:   time.Now(),
			Metadata: map[string]interface{}{
				"violation_type": violation.Type,
				"metric":         violation.Metric,
				"current_value":  violation.Current,
				"threshold":      violation.Threshold,
			},
		}

		if err := c.alertManager.SendAlert(ctx, alert); err != nil {
			return fmt.Errorf("failed to send alert: %w", err)
		}
	}

	// Trigger automatic rollback if configured and violations are critical
	if experiment.Safety.AutoRollback && evaluation.OverallStatus == SafetyStatusCritical {
		reason := fmt.Sprintf("Critical safety violations detected: %d violations", len(evaluation.Violations))
		if err := c.TriggerRollback(ctx, execution.ID, reason); err != nil {
			return fmt.Errorf("failed to trigger automatic rollback: %w", err)
		}
	}

	return nil
}

func (c *SafetyController) mapViolationSeverityToAlertSeverity(severity ViolationSeverity) AlertSeverity {
	switch severity {
	case ViolationSeverityLow:
		return AlertSeverityInfo
	case ViolationSeverityMedium:
		return AlertSeverityWarning
	case ViolationSeverityHigh:
		return AlertSeverityHigh
	case ViolationSeverityCritical:
		return AlertSeverityCritical
	default:
		return AlertSeverityInfo
	}
}