package safety

import (
	"sync"
	"time"
)

// DefaultRateLimiter implements the RateLimiter interface using token bucket algorithm
type DefaultRateLimiter struct {
	config       RateLimiterConfig
	tokens       int
	lastRefill   time.Time
	mu           sync.Mutex
}

// NewRateLimiter creates a new rate limiter with the given configuration
func NewRateLimiter(config RateLimiterConfig) RateLimiter {
	return &DefaultRateLimiter{
		config:     config,
		tokens:     config.BurstSize,
		lastRefill: time.Now(),
	}
}

// Allow returns true if the rate limiter allows the request
func (rl *DefaultRateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)

	// Refill tokens based on elapsed time
	tokensToAdd := int(elapsed.Seconds() * float64(rl.config.RequestsPerSecond))
	if tokensToAdd > 0 {
		rl.tokens += tokensToAdd
		if rl.tokens > rl.config.BurstSize {
			rl.tokens = rl.config.BurstSize
		}
		rl.lastRefill = now
	}

	// Check if we have tokens available
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}

// GetRemainingTokens returns the number of remaining tokens
func (rl *DefaultRateLimiter) GetRemainingTokens() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)

	// Calculate current token count
	tokensToAdd := int(elapsed.Seconds() * float64(rl.config.RequestsPerSecond))
	currentTokens := rl.tokens + tokensToAdd
	if currentTokens > rl.config.BurstSize {
		currentTokens = rl.config.BurstSize
	}

	return currentTokens
}

// GetResetTime returns the time when the rate limiter will reset
func (rl *DefaultRateLimiter) GetResetTime() time.Time {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.tokens >= rl.config.BurstSize {
		return time.Now() // Already at full capacity
	}

	// Calculate time needed to fill the bucket
	tokensNeeded := rl.config.BurstSize - rl.tokens
	secondsToFill := float64(tokensNeeded) / float64(rl.config.RequestsPerSecond)
	
	return rl.lastRefill.Add(time.Duration(secondsToFill * float64(time.Second)))
}