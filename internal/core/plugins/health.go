package plugins

import (
	"context"
	"sync"
	"time"
)

// HealthChecker monitors the health of loaded plugins
type HealthChecker interface {
	StartMonitoring(ctx context.Context, plugin *PluginInfo) error
	StopMonitoring(ctx context.Context, pluginID string) error
	CheckHealth(ctx context.Context, pluginID string) (*HealthCheckResult, error)
	GetHealthHistory(pluginID string) []HealthCheckResult
}

// HealthCheckResult represents the result of a health check
type HealthCheckResult struct {
	PluginID     string                    `json:"plugin_id"`
	Timestamp    time.Time                 `json:"timestamp"`
	Status       HealthStatus              `json:"status"`
	ResponseTime time.Duration             `json:"response_time"`
	Score        float64                   `json:"score"`
	Issues       []HealthIssue             `json:"issues"`
	Metrics      map[string]interface{}    `json:"metrics"`
	Details      string                    `json:"details,omitempty"`
}

// HealthStatus represents the health status
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusError     HealthStatus = "error"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// DefaultHealthChecker implements the HealthChecker interface
type DefaultHealthChecker struct {
	mu           sync.RWMutex
	interval     time.Duration
	monitors     map[string]*healthMonitor
	history      map[string][]HealthCheckResult
	maxHistory   int
	logger       Logger
	stopChannels map[string]chan struct{}
}

type healthMonitor struct {
	pluginID      string
	plugin        *PluginInfo
	ticker        *time.Ticker
	lastCheck     time.Time
	consecutiveFails int
	isActive      bool
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(interval time.Duration, logger Logger) *DefaultHealthChecker {
	return &DefaultHealthChecker{
		interval:     interval,
		monitors:     make(map[string]*healthMonitor),
		history:      make(map[string][]HealthCheckResult),
		maxHistory:   100,
		logger:       logger,
		stopChannels: make(map[string]chan struct{}),
	}
}

// StartMonitoring starts health monitoring for a plugin
func (hc *DefaultHealthChecker) StartMonitoring(ctx context.Context, plugin *PluginInfo) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	// Stop existing monitor if any
	if stopCh, exists := hc.stopChannels[plugin.ID]; exists {
		close(stopCh)
	}
	
	monitor := &healthMonitor{
		pluginID:  plugin.ID,
		plugin:    plugin,
		ticker:    time.NewTicker(hc.interval),
		lastCheck: time.Now(),
		isActive:  true,
	}
	
	hc.monitors[plugin.ID] = monitor
	stopCh := make(chan struct{})
	hc.stopChannels[plugin.ID] = stopCh
	
	// Start monitoring goroutine
	go hc.monitorPlugin(ctx, monitor, stopCh)
	
	hc.logger.Info(ctx, "Started health monitoring", "plugin", plugin.ID, "interval", hc.interval)
	
	return nil
}

// StopMonitoring stops health monitoring for a plugin
func (hc *DefaultHealthChecker) StopMonitoring(ctx context.Context, pluginID string) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	if monitor, exists := hc.monitors[pluginID]; exists {
		monitor.ticker.Stop()
		monitor.isActive = false
		delete(hc.monitors, pluginID)
	}
	
	if stopCh, exists := hc.stopChannels[pluginID]; exists {
		close(stopCh)
		delete(hc.stopChannels, pluginID)
	}
	
	hc.logger.Info(ctx, "Stopped health monitoring", "plugin", pluginID)
	
	return nil
}

// CheckHealth performs a health check on a plugin
func (hc *DefaultHealthChecker) CheckHealth(ctx context.Context, pluginID string) (*HealthCheckResult, error) {
	hc.mu.RLock()
	monitor, exists := hc.monitors[pluginID]
	hc.mu.RUnlock()
	
	if !exists {
		return nil, &PluginError{
			Code:    "HEALTH_MONITOR_NOT_FOUND",
			Message: "Health monitor not found for plugin: " + pluginID,
		}
	}
	
	return hc.performHealthCheck(ctx, monitor)
}

// GetHealthHistory returns the health check history for a plugin
func (hc *DefaultHealthChecker) GetHealthHistory(pluginID string) []HealthCheckResult {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	history, exists := hc.history[pluginID]
	if !exists {
		return []HealthCheckResult{}
	}
	
	// Return a copy
	result := make([]HealthCheckResult, len(history))
	copy(result, history)
	return result
}

// monitorPlugin runs the health monitoring loop for a plugin
func (hc *DefaultHealthChecker) monitorPlugin(ctx context.Context, monitor *healthMonitor, stopCh chan struct{}) {
	defer monitor.ticker.Stop()
	
	for {
		select {
		case <-monitor.ticker.C:
			result, err := hc.performHealthCheck(ctx, monitor)
			if err != nil {
				hc.logger.Error(ctx, "Health check failed", "plugin", monitor.pluginID, "error", err)
				continue
			}
			
			// Update plugin health info
			hc.updatePluginHealth(monitor.plugin, result)
			
			// Store in history
			hc.addToHistory(monitor.pluginID, *result)
			
			// Check for alerts
			hc.checkHealthAlerts(ctx, monitor, result)
			
		case <-stopCh:
			hc.logger.Info(ctx, "Health monitoring stopped", "plugin", monitor.pluginID)
			return
		case <-ctx.Done():
			hc.logger.Info(ctx, "Health monitoring cancelled", "plugin", monitor.pluginID)
			return
		}
	}
}

// performHealthCheck performs the actual health check
func (hc *DefaultHealthChecker) performHealthCheck(ctx context.Context, monitor *healthMonitor) (*HealthCheckResult, error) {
	start := time.Now()
	
	result := &HealthCheckResult{
		PluginID:  monitor.pluginID,
		Timestamp: start,
		Status:    HealthStatusUnknown,
		Issues:    make([]HealthIssue, 0),
		Metrics:   make(map[string]interface{}),
	}
	
	// Check if provider implements health check interface
	if healthCheckable, ok := monitor.plugin.Provider.(HealthCheckable); ok {
		// Use provider's health check
		healthCtx, cancel := context.WithTimeout(ctx, monitor.plugin.Config.Timeout)
		defer cancel()
		
		err := healthCheckable.HealthCheck(healthCtx)
		result.ResponseTime = time.Since(start)
		
		if err != nil {
			result.Status = HealthStatusError
			result.Details = err.Error()
			result.Score = 0.0
			monitor.consecutiveFails++
		} else {
			result.Status = HealthStatusHealthy
			result.Score = 100.0
			monitor.consecutiveFails = 0
		}
	} else {
		// Basic health check - check if provider is responsive
		result.ResponseTime = time.Since(start)
		
		// Try to get provider status
		if statusProvider, ok := monitor.plugin.Provider.(StatusProvider); ok {
			status := statusProvider.GetStatus()
			if status.Healthy {
				result.Status = HealthStatusHealthy
				result.Score = 100.0
				monitor.consecutiveFails = 0
			} else {
				result.Status = HealthStatusDegraded
				result.Score = 50.0
				monitor.consecutiveFails++
			}
		} else {
			// Default to healthy if no specific health check
			result.Status = HealthStatusHealthy
			result.Score = 100.0
			monitor.consecutiveFails = 0
		}
	}
	
	// Adjust score based on consecutive failures
	if monitor.consecutiveFails > 0 {
		result.Score = result.Score * (1.0 - float64(monitor.consecutiveFails)*0.1)
		if result.Score < 0 {
			result.Score = 0
		}
	}
	
	// Add performance metrics
	result.Metrics["response_time_ms"] = result.ResponseTime.Milliseconds()
	result.Metrics["consecutive_fails"] = monitor.consecutiveFails
	result.Metrics["last_check"] = monitor.lastCheck
	
	monitor.lastCheck = result.Timestamp
	
	return result, nil
}

// updatePluginHealth updates the plugin's health information
func (hc *DefaultHealthChecker) updatePluginHealth(plugin *PluginInfo, result *HealthCheckResult) {
	plugin.Health.Status = string(result.Status)
	plugin.Health.LastCheck = result.Timestamp
	plugin.Health.HealthScore = result.Score
	plugin.Health.ResponseTime = result.ResponseTime
	
	// Update issues
	if result.Status != HealthStatusHealthy {
		issue := HealthIssue{
			Type:       "health_check_failed",
			Severity:   string(result.Status),
			Message:    result.Details,
			DetectedAt: result.Timestamp,
		}
		plugin.Health.Issues = append(plugin.Health.Issues, issue)
		
		// Keep only recent issues
		if len(plugin.Health.Issues) > 10 {
			plugin.Health.Issues = plugin.Health.Issues[len(plugin.Health.Issues)-10:]
		}
	}
}

// addToHistory adds a health check result to the history
func (hc *DefaultHealthChecker) addToHistory(pluginID string, result HealthCheckResult) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	if _, exists := hc.history[pluginID]; !exists {
		hc.history[pluginID] = make([]HealthCheckResult, 0, hc.maxHistory)
	}
	
	hc.history[pluginID] = append(hc.history[pluginID], result)
	
	// Keep only maxHistory results
	if len(hc.history[pluginID]) > hc.maxHistory {
		hc.history[pluginID] = hc.history[pluginID][len(hc.history[pluginID])-hc.maxHistory:]
	}
}

// checkHealthAlerts checks if any alerts should be triggered
func (hc *DefaultHealthChecker) checkHealthAlerts(ctx context.Context, monitor *healthMonitor, result *HealthCheckResult) {
	// Alert on consecutive failures
	if monitor.consecutiveFails >= 3 {
		hc.logger.Warn(ctx, "Plugin health degraded", 
			"plugin", monitor.pluginID,
			"consecutive_fails", monitor.consecutiveFails,
			"status", result.Status)
	}
	
	// Alert on critical status
	if result.Status == HealthStatusError {
		hc.logger.Error(ctx, "Plugin health critical",
			"plugin", monitor.pluginID,
			"error", result.Details)
	}
}

// Interfaces for providers that support health checking

// HealthCheckable interface for providers that support custom health checks
type HealthCheckable interface {
	HealthCheck(ctx context.Context) error
}

// StatusProvider interface for providers that expose status
type StatusProvider interface {
	GetStatus() ProviderStatus
}

// ProviderStatus represents provider status
type ProviderStatus struct {
	Healthy          bool                   `json:"healthy"`
	Status           string                 `json:"status"`
	LastHealthCheck  *time.Time             `json:"last_health_check,omitempty"`
	RunningExperiments int                  `json:"running_experiments"`
	TotalExperiments   int                  `json:"total_experiments"`
	Errors           []ProviderError        `json:"errors"`
	Metrics          map[string]interface{} `json:"metrics"`
}

// ProviderError represents a provider error
type ProviderError struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Context   map[string]interface{} `json:"context"`
}

// PluginError represents a plugin-specific error
type PluginError struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Context map[string]string `json:"context,omitempty"`
}

func (e *PluginError) Error() string {
	return e.Message
}