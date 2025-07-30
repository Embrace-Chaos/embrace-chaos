package plugins

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"
)

// RetryHandler interface for managing retry logic with exponential backoff
type RetryHandler interface {
	Execute(ctx context.Context, pluginID string, operation func() error) error
	ExecuteWithConfig(ctx context.Context, config RetryConfig, operation func() error) error
	GetStats(pluginID string) RetryStats
	Reset(pluginID string) error
}

// RetryConfig holds configuration for retry logic
type RetryConfig struct {
	MaxRetries    int           `json:"max_retries"`
	BaseDelay     time.Duration `json:"base_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	Multiplier    float64       `json:"multiplier"`
	Jitter        bool          `json:"jitter"`
	JitterFactor  float64       `json:"jitter_factor"`
	RetryOn       []string      `json:"retry_on"`       // Error types to retry on
	DoNotRetryOn  []string      `json:"do_not_retry_on"` // Error types to not retry on
	Timeout       time.Duration `json:"timeout"`        // Overall timeout
}

// RetryStats represents statistics for retry operations
type RetryStats struct {
	PluginID        string        `json:"plugin_id"`
	TotalAttempts   uint64        `json:"total_attempts"`
	TotalRetries    uint64        `json:"total_retries"`
	SuccessfulOps   uint64        `json:"successful_ops"`
	FailedOps       uint64        `json:"failed_ops"`
	AverageDelay    time.Duration `json:"average_delay"`
	MaxDelay        time.Duration `json:"max_delay"`
	LastAttempt     *time.Time    `json:"last_attempt,omitempty"`
	LastSuccess     *time.Time    `json:"last_success,omitempty"`
	LastFailure     *time.Time    `json:"last_failure,omitempty"`
}

// DefaultRetryHandler implements the RetryHandler interface
type DefaultRetryHandler struct {
	mu       sync.RWMutex
	configs  map[string]RetryConfig
	stats    map[string]*RetryStats
	logger   Logger
	rand     *rand.Rand
}

// NewRetryHandler creates a new retry handler
func NewRetryHandler(logger Logger) *DefaultRetryHandler {
	return &DefaultRetryHandler{
		configs: make(map[string]RetryConfig),
		stats:   make(map[string]*RetryStats),
		logger:  logger,
		rand:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Execute executes an operation with retry logic using plugin-specific configuration
func (rh *DefaultRetryHandler) Execute(ctx context.Context, pluginID string, operation func() error) error {
	config := rh.getConfig(pluginID)
	return rh.executeWithRetry(ctx, pluginID, config, operation)
}

// ExecuteWithConfig executes an operation with retry logic using provided configuration
func (rh *DefaultRetryHandler) ExecuteWithConfig(ctx context.Context, config RetryConfig, operation func() error) error {
	return rh.executeWithRetry(ctx, "", config, operation)
}

// GetStats returns retry statistics for a plugin
func (rh *DefaultRetryHandler) GetStats(pluginID string) RetryStats {
	rh.mu.RLock()
	defer rh.mu.RUnlock()
	
	if stats, exists := rh.stats[pluginID]; exists {
		return *stats
	}
	
	return RetryStats{
		PluginID: pluginID,
	}
}

// Reset resets retry statistics for a plugin
func (rh *DefaultRetryHandler) Reset(pluginID string) error {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	
	rh.stats[pluginID] = &RetryStats{
		PluginID: pluginID,
	}
	
	return nil
}

// SetConfig sets retry configuration for a plugin
func (rh *DefaultRetryHandler) SetConfig(pluginID string, config RetryConfig) {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	
	rh.configs[pluginID] = config
}

// getConfig gets retry configuration for a plugin (with defaults)
func (rh *DefaultRetryHandler) getConfig(pluginID string) RetryConfig {
	rh.mu.RLock()
	defer rh.mu.RUnlock()
	
	if config, exists := rh.configs[pluginID]; exists {
		return config
	}
	
	// Return default configuration
	return RetryConfig{
		MaxRetries:   3,
		BaseDelay:    100 * time.Millisecond,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		Jitter:       true,
		JitterFactor: 0.1,
		Timeout:      5 * time.Minute,
	}
}

// executeWithRetry executes the operation with retry logic
func (rh *DefaultRetryHandler) executeWithRetry(ctx context.Context, pluginID string, config RetryConfig, operation func() error) error {
	stats := rh.getOrCreateStats(pluginID)
	
	// Create timeout context if configured
	if config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, config.Timeout)
		defer cancel()
	}
	
	var lastErr error
	delay := config.BaseDelay
	
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		start := time.Now()
		
		// Update stats
		rh.updateStats(stats, func(s *RetryStats) {
			s.TotalAttempts++
			now := time.Now()
			s.LastAttempt = &now
		})
		
		// Execute the operation
		err := operation()
		
		if err == nil {
			// Success
			rh.updateStats(stats, func(s *RetryStats) {
				s.SuccessfulOps++
				now := time.Now()
				s.LastSuccess = &now
			})
			
			if pluginID != "" {
				rh.logger.Debug(ctx, "Operation succeeded", 
					"plugin", pluginID,
					"attempt", attempt+1,
					"duration", time.Since(start))
			}
			
			return nil
		}
		
		lastErr = err
		
		// Check if we should retry
		if !rh.shouldRetry(err, config) {
			rh.updateStats(stats, func(s *RetryStats) {
				s.FailedOps++
				now := time.Now()
				s.LastFailure = &now
			})
			
			if pluginID != "" {
				rh.logger.Debug(ctx, "Operation failed, not retrying", 
					"plugin", pluginID,
					"error", err,
					"attempt", attempt+1)
			}
			
			return err
		}
		
		// Check if we've reached max retries
		if attempt >= config.MaxRetries {
			rh.updateStats(stats, func(s *RetryStats) {
				s.FailedOps++
				now := time.Now()
				s.LastFailure = &now
			})
			
			if pluginID != "" {
				rh.logger.Warn(ctx, "Operation failed after max retries", 
					"plugin", pluginID,
					"error", err,
					"attempts", attempt+1,
					"max_retries", config.MaxRetries)
			}
			
			return &RetryExhaustedError{
				OriginalError: err,
				Attempts:      attempt + 1,
				MaxRetries:    config.MaxRetries,
			}
		}
		
		// Update retry stats
		rh.updateStats(stats, func(s *RetryStats) {
			s.TotalRetries++
		})
		
		// Calculate delay with exponential backoff
		actualDelay := rh.calculateDelay(delay, config)
		
		if pluginID != "" {
			rh.logger.Debug(ctx, "Operation failed, retrying", 
				"plugin", pluginID,
				"error", err,
				"attempt", attempt+1,
				"delay", actualDelay)
		}
		
		// Wait before retrying
		select {
		case <-time.After(actualDelay):
			// Continue to next attempt
		case <-ctx.Done():
			return &RetryTimeoutError{
				OriginalError: lastErr,
				Attempts:      attempt + 1,
				Timeout:       config.Timeout,
			}
		}
		
		// Calculate next delay
		delay = time.Duration(float64(delay) * config.Multiplier)
		if delay > config.MaxDelay {
			delay = config.MaxDelay
		}
	}
	
	return lastErr
}

// shouldRetry determines if an error should be retried
func (rh *DefaultRetryHandler) shouldRetry(err error, config RetryConfig) bool {
	errorType := getErrorType(err)
	
	// Check explicit do-not-retry list
	for _, doNotRetry := range config.DoNotRetryOn {
		if errorType == doNotRetry {
			return false
		}
	}
	
	// Check explicit retry list
	if len(config.RetryOn) > 0 {
		for _, retryOn := range config.RetryOn {
			if errorType == retryOn {
				return true
			}
		}
		return false
	}
	
	// Default retry logic for common error types
	switch errorType {
	case "timeout", "connection_refused", "connection_timeout", "network_error":
		return true
	case "authentication_failed", "authorization_denied", "validation_error":
		return false
	default:
		return true // Retry by default
	}
}

// calculateDelay calculates the actual delay with jitter
func (rh *DefaultRetryHandler) calculateDelay(baseDelay time.Duration, config RetryConfig) time.Duration {
	delay := baseDelay
	
	if config.Jitter {
		// Add jitter to avoid thundering herd
		jitterAmount := float64(delay) * config.JitterFactor
		jitter := time.Duration(rh.rand.Float64() * jitterAmount)
		
		if rh.rand.Float64() < 0.5 {
			delay += jitter
		} else {
			delay -= jitter
		}
		
		// Ensure delay is not negative
		if delay < 0 {
			delay = time.Duration(float64(baseDelay) * 0.1)
		}
	}
	
	return delay
}

// getOrCreateStats gets or creates retry statistics for a plugin
func (rh *DefaultRetryHandler) getOrCreateStats(pluginID string) *RetryStats {
	if pluginID == "" {
		// Return temporary stats for anonymous operations
		return &RetryStats{}
	}
	
	rh.mu.Lock()
	defer rh.mu.Unlock()
	
	if stats, exists := rh.stats[pluginID]; exists {
		return stats
	}
	
	stats := &RetryStats{
		PluginID: pluginID,
	}
	rh.stats[pluginID] = stats
	
	return stats
}

// updateStats safely updates retry statistics
func (rh *DefaultRetryHandler) updateStats(stats *RetryStats, update func(*RetryStats)) {
	if stats.PluginID == "" {
		// Skip updating stats for anonymous operations
		return
	}
	
	rh.mu.Lock()
	defer rh.mu.Unlock()
	
	update(stats)
}

// getErrorType extracts the error type from an error
func getErrorType(err error) string {
	if err == nil {
		return ""
	}
	
	// Check for specific error types
	switch e := err.(type) {
	case *CircuitBreakerError:
		return "circuit_breaker"
	case *RetryExhaustedError:
		return "retry_exhausted"
	case *RetryTimeoutError:
		return "retry_timeout"
	default:
		// Try to infer from error message
		msg := e.Error()
		switch {
		case containsAny(msg, []string{"timeout", "deadline exceeded"}):
			return "timeout"
		case containsAny(msg, []string{"connection refused", "connection reset"}):
			return "connection_refused"
		case containsAny(msg, []string{"network", "dns"}):
			return "network_error"
		case containsAny(msg, []string{"authentication", "unauthorized"}):
			return "authentication_failed"
		case containsAny(msg, []string{"authorization", "forbidden", "permission"}):
			return "authorization_denied"
		case containsAny(msg, []string{"validation", "invalid"}):
			return "validation_error"
		default:
			return "unknown"
		}
	}
}

// containsAny checks if a string contains any of the given substrings
func containsAny(s string, substrings []string) bool {
	s = strings.ToLower(s)
	for _, substr := range substrings {
		if strings.Contains(s, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

// Error types for retry operations

// RetryExhaustedError indicates that max retries have been reached
type RetryExhaustedError struct {
	OriginalError error `json:"original_error"`
	Attempts      int   `json:"attempts"`
	MaxRetries    int   `json:"max_retries"`
}

func (e *RetryExhaustedError) Error() string {
	return fmt.Sprintf("retry exhausted after %d attempts (max %d): %v", 
		e.Attempts, e.MaxRetries, e.OriginalError)
}

func (e *RetryExhaustedError) Unwrap() error {
	return e.OriginalError
}

// RetryTimeoutError indicates that the overall timeout was reached
type RetryTimeoutError struct {
	OriginalError error         `json:"original_error"`
	Attempts      int           `json:"attempts"`
	Timeout       time.Duration `json:"timeout"`
}

func (e *RetryTimeoutError) Error() string {
	return fmt.Sprintf("retry timeout after %v (attempts: %d): %v", 
		e.Timeout, e.Attempts, e.OriginalError)
}

func (e *RetryTimeoutError) Unwrap() error {
	return e.OriginalError
}

// RetryMiddleware provides middleware functionality for retry logic
type RetryMiddleware struct {
	retryHandler RetryHandler
	logger       Logger
}

// NewRetryMiddleware creates new retry middleware
func NewRetryMiddleware(retryHandler RetryHandler, logger Logger) *RetryMiddleware {
	return &RetryMiddleware{
		retryHandler: retryHandler,
		logger:       logger,
	}
}

// Wrap wraps a provider operation with retry logic
func (rm *RetryMiddleware) Wrap(pluginID string, operation func() error) func() error {
	return func() error {
		ctx := context.Background()
		return rm.retryHandler.Execute(ctx, pluginID, operation)
	}
}

// WrapWithConfig wraps a provider operation with custom retry configuration
func (rm *RetryMiddleware) WrapWithConfig(config RetryConfig, operation func() error) func() error {
	return func() error {
		ctx := context.Background()
		return rm.retryHandler.ExecuteWithConfig(ctx, config, operation)
	}
}

// WrapWithContext wraps a provider operation with retry logic and context
func (rm *RetryMiddleware) WrapWithContext(pluginID string, operation func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		return rm.retryHandler.Execute(ctx, pluginID, func() error {
			return operation(ctx)
		})
	}
}

// Exponential backoff utility functions

// ExponentialBackoff calculates delay using exponential backoff
func ExponentialBackoff(attempt int, baseDelay, maxDelay time.Duration, multiplier float64, jitter bool) time.Duration {
	delay := time.Duration(float64(baseDelay) * math.Pow(multiplier, float64(attempt)))
	
	if delay > maxDelay {
		delay = maxDelay
	}
	
	if jitter {
		jitterAmount := float64(delay) * 0.1
		jitterValue := rand.Float64() * jitterAmount
		if rand.Float64() < 0.5 {
			delay += time.Duration(jitterValue)
		} else {
			delay -= time.Duration(jitterValue)
		}
		
		if delay < 0 {
			delay = baseDelay
		}
	}
	
	return delay
}

// LinearBackoff calculates delay using linear backoff
func LinearBackoff(attempt int, baseDelay, maxDelay time.Duration, increment time.Duration, jitter bool) time.Duration {
	delay := baseDelay + time.Duration(attempt)*increment
	
	if delay > maxDelay {
		delay = maxDelay
	}
	
	if jitter {
		jitterAmount := float64(delay) * 0.1
		jitterValue := rand.Float64() * jitterAmount
		if rand.Float64() < 0.5 {
			delay += time.Duration(jitterValue)
		} else {
			delay -= time.Duration(jitterValue)
		}
		
		if delay < 0 {
			delay = baseDelay
		}
	}
	
	return delay
}

// Global retry handler instance
var globalRetryHandler RetryHandler

// SetGlobalRetryHandler sets the global retry handler
func SetGlobalRetryHandler(rh RetryHandler) {
	globalRetryHandler = rh
}

// GetGlobalRetryHandler returns the global retry handler
func GetGlobalRetryHandler() RetryHandler {
	return globalRetryHandler
}

// Convenience functions for global retry handler
func ExecuteWithRetry(ctx context.Context, pluginID string, operation func() error) error {
	if globalRetryHandler != nil {
		return globalRetryHandler.Execute(ctx, pluginID, operation)
	}
	return operation()
}

func ExecuteWithRetryConfig(ctx context.Context, config RetryConfig, operation func() error) error {
	if globalRetryHandler != nil {
		return globalRetryHandler.ExecuteWithConfig(ctx, config, operation)
	}
	return operation()
}

