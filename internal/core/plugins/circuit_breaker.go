package plugins

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitBreaker interface for managing circuit breaker functionality
type CircuitBreaker interface {
	Execute(ctx context.Context, pluginID string, operation func() error) error
	GetState(pluginID string) CircuitBreakerState
	Reset(pluginID string) error
	ForceOpen(pluginID string) error
	ForceClose(pluginID string) error
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState string

const (
	CircuitBreakerStateClosed   CircuitBreakerState = "closed"
	CircuitBreakerStateOpen     CircuitBreakerState = "open"
	CircuitBreakerStateHalfOpen CircuitBreakerState = "half_open"
)

// CircuitBreakerStats represents statistics for a circuit breaker
type CircuitBreakerStats struct {
	State            CircuitBreakerState `json:"state"`
	TotalRequests    uint64              `json:"total_requests"`
	SuccessfulRequests uint64            `json:"successful_requests"`
	FailedRequests   uint64              `json:"failed_requests"`
	ConsecutiveFailures uint64           `json:"consecutive_failures"`
	LastStateChange  time.Time           `json:"last_state_change"`
	LastFailure      *time.Time          `json:"last_failure,omitempty"`
	NextRetryTime    *time.Time          `json:"next_retry_time,omitempty"`
}

// DefaultCircuitBreaker implements the CircuitBreaker interface
type DefaultCircuitBreaker struct {
	mu       sync.RWMutex
	breakers map[string]*circuitBreakerInstance
	logger   Logger
}

type circuitBreakerInstance struct {
	mu                    sync.RWMutex
	pluginID              string
	state                 CircuitBreakerState
	config                CircuitBreakerConfig
	stats                 CircuitBreakerStats
	halfOpenSuccesses     uint64
	nextRetryTime         time.Time
	stateChangeListeners  []StateChangeListener
}

// StateChangeListener is called when circuit breaker state changes
type StateChangeListener func(pluginID string, oldState, newState CircuitBreakerState)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(logger Logger) *DefaultCircuitBreaker {
	return &DefaultCircuitBreaker{
		breakers: make(map[string]*circuitBreakerInstance),
		logger:   logger,
	}
}

// Execute executes an operation with circuit breaker protection
func (cb *DefaultCircuitBreaker) Execute(ctx context.Context, pluginID string, operation func() error) error {
	breaker := cb.getOrCreateBreaker(pluginID)
	
	// Check if circuit breaker allows execution
	if !breaker.allowRequest() {
		return &CircuitBreakerError{
			Code:      "CIRCUIT_BREAKER_OPEN",
			Message:   fmt.Sprintf("Circuit breaker is open for plugin: %s", pluginID),
			State:     breaker.getState(),
			NextRetry: breaker.getNextRetryTime(),
		}
	}
	
	// Execute the operation
	start := time.Now()
	err := operation()
	duration := time.Since(start)
	
	// Record the result
	breaker.recordResult(err == nil, duration)
	
	if err != nil {
		cb.logger.Debug(ctx, "Circuit breaker recorded failure", 
			"plugin", pluginID,
			"error", err,
			"duration", duration)
	}
	
	return err
}

// GetState returns the current state of the circuit breaker
func (cb *DefaultCircuitBreaker) GetState(pluginID string) CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	if breaker, exists := cb.breakers[pluginID]; exists {
		return breaker.getState()
	}
	
	return CircuitBreakerStateClosed
}

// Reset resets the circuit breaker to closed state
func (cb *DefaultCircuitBreaker) Reset(pluginID string) error {
	breaker := cb.getOrCreateBreaker(pluginID)
	breaker.reset()
	return nil
}

// ForceOpen forces the circuit breaker to open state
func (cb *DefaultCircuitBreaker) ForceOpen(pluginID string) error {
	breaker := cb.getOrCreateBreaker(pluginID)
	breaker.forceOpen()
	return nil
}

// ForceClose forces the circuit breaker to closed state
func (cb *DefaultCircuitBreaker) ForceClose(pluginID string) error {
	breaker := cb.getOrCreateBreaker(pluginID)
	breaker.forceClose()
	return nil
}

// GetStats returns statistics for a circuit breaker
func (cb *DefaultCircuitBreaker) GetStats(pluginID string) CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	if breaker, exists := cb.breakers[pluginID]; exists {
		return breaker.getStats()
	}
	
	return CircuitBreakerStats{
		State: CircuitBreakerStateClosed,
	}
}

// AddStateChangeListener adds a listener for state changes
func (cb *DefaultCircuitBreaker) AddStateChangeListener(pluginID string, listener StateChangeListener) {
	breaker := cb.getOrCreateBreaker(pluginID)
	breaker.addStateChangeListener(listener)
}

// getOrCreateBreaker gets or creates a circuit breaker instance
func (cb *DefaultCircuitBreaker) getOrCreateBreaker(pluginID string) *circuitBreakerInstance {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	if breaker, exists := cb.breakers[pluginID]; exists {
		return breaker
	}
	
	// Create new breaker with default config
	breaker := &circuitBreakerInstance{
		pluginID: pluginID,
		state:    CircuitBreakerStateClosed,
		config: CircuitBreakerConfig{
			Enabled:           true,
			FailureThreshold:  5,
			RecoveryTimeout:   30 * time.Second,
			HalfOpenRequests:  3,
		},
		stats: CircuitBreakerStats{
			State:           CircuitBreakerStateClosed,
			LastStateChange: time.Now(),
		},
		stateChangeListeners: make([]StateChangeListener, 0),
	}
	
	cb.breakers[pluginID] = breaker
	return breaker
}

// Circuit breaker instance methods

func (cb *circuitBreakerInstance) allowRequest() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	if !cb.config.Enabled {
		return true
	}
	
	switch cb.state {
	case CircuitBreakerStateClosed:
		return true
	case CircuitBreakerStateOpen:
		// Check if recovery timeout has passed
		if time.Now().After(cb.nextRetryTime) {
			cb.mu.RUnlock()
			cb.mu.Lock()
			cb.transitionToHalfOpen()
			cb.mu.Unlock()
			cb.mu.RLock()
			return true
		}
		return false
	case CircuitBreakerStateHalfOpen:
		// Allow limited requests in half-open state
		return cb.halfOpenSuccesses < uint64(cb.config.HalfOpenRequests)
	default:
		return false
	}
}

func (cb *circuitBreakerInstance) recordResult(success bool, duration time.Duration) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	atomic.AddUint64(&cb.stats.TotalRequests, 1)
	
	if success {
		atomic.AddUint64(&cb.stats.SuccessfulRequests, 1)
		atomic.StoreUint64(&cb.stats.ConsecutiveFailures, 0)
		
		if cb.state == CircuitBreakerStateHalfOpen {
			cb.halfOpenSuccesses++
			if cb.halfOpenSuccesses >= uint64(cb.config.HalfOpenRequests) {
				cb.transitionToClosed()
			}
		}
	} else {
		atomic.AddUint64(&cb.stats.FailedRequests, 1)
		atomic.AddUint64(&cb.stats.ConsecutiveFailures, 1)
		now := time.Now()
		cb.stats.LastFailure = &now
		
		if cb.state == CircuitBreakerStateClosed {
			if cb.stats.ConsecutiveFailures >= uint64(cb.config.FailureThreshold) {
				cb.transitionToOpen()
			}
		} else if cb.state == CircuitBreakerStateHalfOpen {
			cb.transitionToOpen()
		}
	}
}

func (cb *circuitBreakerInstance) transitionToOpen() {
	oldState := cb.state
	cb.state = CircuitBreakerStateOpen
	cb.nextRetryTime = time.Now().Add(cb.config.RecoveryTimeout)
	cb.stats.NextRetryTime = &cb.nextRetryTime
	cb.stats.LastStateChange = time.Now()
	cb.stats.State = CircuitBreakerStateOpen
	cb.halfOpenSuccesses = 0
	
	cb.notifyStateChange(oldState, CircuitBreakerStateOpen)
}

func (cb *circuitBreakerInstance) transitionToHalfOpen() {
	oldState := cb.state
	cb.state = CircuitBreakerStateHalfOpen
	cb.stats.LastStateChange = time.Now()
	cb.stats.State = CircuitBreakerStateHalfOpen
	cb.stats.NextRetryTime = nil
	cb.halfOpenSuccesses = 0
	
	cb.notifyStateChange(oldState, CircuitBreakerStateHalfOpen)
}

func (cb *circuitBreakerInstance) transitionToClosed() {
	oldState := cb.state
	cb.state = CircuitBreakerStateClosed
	cb.stats.LastStateChange = time.Now()
	cb.stats.State = CircuitBreakerStateClosed
	cb.stats.NextRetryTime = nil
	atomic.StoreUint64(&cb.stats.ConsecutiveFailures, 0)
	cb.halfOpenSuccesses = 0
	
	cb.notifyStateChange(oldState, CircuitBreakerStateClosed)
}

func (cb *circuitBreakerInstance) reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	oldState := cb.state
	cb.state = CircuitBreakerStateClosed
	cb.stats = CircuitBreakerStats{
		State:           CircuitBreakerStateClosed,
		LastStateChange: time.Now(),
	}
	cb.halfOpenSuccesses = 0
	
	cb.notifyStateChange(oldState, CircuitBreakerStateClosed)
}

func (cb *circuitBreakerInstance) forceOpen() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	oldState := cb.state
	cb.state = CircuitBreakerStateOpen
	cb.nextRetryTime = time.Now().Add(cb.config.RecoveryTimeout)
	cb.stats.NextRetryTime = &cb.nextRetryTime
	cb.stats.LastStateChange = time.Now()
	cb.stats.State = CircuitBreakerStateOpen
	
	cb.notifyStateChange(oldState, CircuitBreakerStateOpen)
}

func (cb *circuitBreakerInstance) forceClose() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	oldState := cb.state
	cb.state = CircuitBreakerStateClosed
	cb.stats.LastStateChange = time.Now()
	cb.stats.State = CircuitBreakerStateClosed
	cb.stats.NextRetryTime = nil
	atomic.StoreUint64(&cb.stats.ConsecutiveFailures, 0)
	cb.halfOpenSuccesses = 0
	
	cb.notifyStateChange(oldState, CircuitBreakerStateClosed)
}

func (cb *circuitBreakerInstance) getState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

func (cb *circuitBreakerInstance) getNextRetryTime() *time.Time {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	if cb.state == CircuitBreakerStateOpen {
		return &cb.nextRetryTime
	}
	return nil
}

func (cb *circuitBreakerInstance) getStats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.stats
}

func (cb *circuitBreakerInstance) addStateChangeListener(listener StateChangeListener) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.stateChangeListeners = append(cb.stateChangeListeners, listener)
}

func (cb *circuitBreakerInstance) notifyStateChange(oldState, newState CircuitBreakerState) {
	for _, listener := range cb.stateChangeListeners {
		go listener(cb.pluginID, oldState, newState)
	}
}

// CircuitBreakerError represents a circuit breaker error
type CircuitBreakerError struct {
	Code      string               `json:"code"`
	Message   string               `json:"message"`
	State     CircuitBreakerState  `json:"state"`
	NextRetry *time.Time           `json:"next_retry,omitempty"`
}

func (e *CircuitBreakerError) Error() string {
	return e.Message
}

// IsCircuitBreakerError checks if an error is a circuit breaker error
func IsCircuitBreakerError(err error) bool {
	_, ok := err.(*CircuitBreakerError)
	return ok
}

// CircuitBreakerMiddleware provides middleware functionality for circuit breaker
type CircuitBreakerMiddleware struct {
	circuitBreaker CircuitBreaker
	logger         Logger
}

// NewCircuitBreakerMiddleware creates new circuit breaker middleware
func NewCircuitBreakerMiddleware(circuitBreaker CircuitBreaker, logger Logger) *CircuitBreakerMiddleware {
	return &CircuitBreakerMiddleware{
		circuitBreaker: circuitBreaker,
		logger:         logger,
	}
}

// Wrap wraps a provider operation with circuit breaker protection
func (cbm *CircuitBreakerMiddleware) Wrap(pluginID string, operation func() error) func() error {
	return func() error {
		ctx := context.Background()
		return cbm.circuitBreaker.Execute(ctx, pluginID, operation)
	}
}

// WrapWithContext wraps a provider operation with circuit breaker protection and context
func (cbm *CircuitBreakerMiddleware) WrapWithContext(pluginID string, operation func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		return cbm.circuitBreaker.Execute(ctx, pluginID, func() error {
			return operation(ctx)
		})
	}
}

// Global circuit breaker instance
var globalCircuitBreaker CircuitBreaker

// SetGlobalCircuitBreaker sets the global circuit breaker
func SetGlobalCircuitBreaker(cb CircuitBreaker) {
	globalCircuitBreaker = cb
}

// GetGlobalCircuitBreaker returns the global circuit breaker
func GetGlobalCircuitBreaker() CircuitBreaker {
	return globalCircuitBreaker
}

// Convenience functions for global circuit breaker
func ExecuteWithCircuitBreaker(ctx context.Context, pluginID string, operation func() error) error {
	if globalCircuitBreaker != nil {
		return globalCircuitBreaker.Execute(ctx, pluginID, operation)
	}
	return operation()
}

func GetCircuitBreakerState(pluginID string) CircuitBreakerState {
	if globalCircuitBreaker != nil {
		return globalCircuitBreaker.GetState(pluginID)
	}
	return CircuitBreakerStateClosed
}