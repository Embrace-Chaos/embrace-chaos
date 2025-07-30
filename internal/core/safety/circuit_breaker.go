package safety

import (
	"sync"
	"time"
)

// DefaultCircuitBreaker implements the CircuitBreaker interface
type DefaultCircuitBreaker struct {
	config            CircuitBreakerConfig
	state             CircuitBreakerState
	failures          int
	lastFailureTime   time.Time
	halfOpenCalls     int
	halfOpenSuccesses int
	mu                sync.RWMutex
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration
func NewCircuitBreaker(config CircuitBreakerConfig) CircuitBreaker {
	return &DefaultCircuitBreaker{
		config: config,
		state:  CircuitBreakerStateClosed,
	}
}

// CanExecute returns true if the circuit breaker allows execution
func (cb *DefaultCircuitBreaker) CanExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case CircuitBreakerStateClosed:
		return true
	case CircuitBreakerStateOpen:
		// Check if recovery timeout has passed
		if time.Since(cb.lastFailureTime) >= cb.config.RecoveryTimeout {
			// Transition to half-open state
			cb.transitionToHalfOpen()
			return true
		}
		return false
	case CircuitBreakerStateHalfOpen:
		// Allow limited calls in half-open state
		return cb.halfOpenCalls < cb.config.HalfOpenMaxCalls
	default:
		return false
	}
}

// RecordSuccess records a successful execution
func (cb *DefaultCircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitBreakerStateClosed:
		// Reset failure count on success
		cb.failures = 0
	case CircuitBreakerStateHalfOpen:
		cb.halfOpenSuccesses++
		cb.halfOpenCalls++
		
		// Check if we have enough successes to close the circuit
		if cb.halfOpenSuccesses >= cb.config.HalfOpenSuccessThreshold {
			cb.transitionToClosed()
		}
	}
}

// RecordFailure records a failed execution
func (cb *DefaultCircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailureTime = time.Now()

	switch cb.state {
	case CircuitBreakerStateClosed:
		cb.failures++
		// Check if we need to open the circuit
		if cb.failures >= cb.config.FailureThreshold {
			cb.transitionToOpen()
		}
	case CircuitBreakerStateHalfOpen:
		cb.halfOpenCalls++
		// Any failure in half-open state opens the circuit
		cb.transitionToOpen()
	}
}

// GetState returns the current state of the circuit breaker
func (cb *DefaultCircuitBreaker) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Private methods for state transitions

func (cb *DefaultCircuitBreaker) transitionToClosed() {
	cb.state = CircuitBreakerStateClosed
	cb.failures = 0
	cb.halfOpenCalls = 0
	cb.halfOpenSuccesses = 0
}

func (cb *DefaultCircuitBreaker) transitionToOpen() {
	cb.state = CircuitBreakerStateOpen
	cb.halfOpenCalls = 0
	cb.halfOpenSuccesses = 0
}

func (cb *DefaultCircuitBreaker) transitionToHalfOpen() {
	cb.state = CircuitBreakerStateHalfOpen
	cb.halfOpenCalls = 0
	cb.halfOpenSuccesses = 0
}