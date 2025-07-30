package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/embrace-chaos/internal/core/ports"
	"github.com/embrace-chaos/internal/adapters/http/middleware"
)

// HealthHandler handles health and readiness checks
type HealthHandler struct {
	store    ports.Store
	provider ports.Provider
	version  string
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(store ports.Store, provider ports.Provider, version string) *HealthHandler {
	return &HealthHandler{
		store:    store,
		provider: provider,
		version:  version,
	}
}

// HealthCheck handles GET /health
func (h *HealthHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	checks := make(map[string]HealthCheck)
	overallStatus := "healthy"

	// Check database connectivity
	dbStatus, dbMessage, dbDuration := h.checkDatabase(ctx)
	checks["database"] = HealthCheck{
		Status:   dbStatus,
		Message:  dbMessage,
		Duration: dbDuration,
	}
	if dbStatus == "unhealthy" {
		overallStatus = "unhealthy"
	}

	// Check provider connectivity
	providerStatus, providerMessage, providerDuration := h.checkProvider(ctx)
	checks["provider"] = HealthCheck{
		Status:   providerStatus,
		Message:  providerMessage,
		Duration: providerDuration,
	}
	if providerStatus == "unhealthy" {
		overallStatus = "unhealthy"
	}

	response := HealthResponse{
		Status:    overallStatus,
		Timestamp: time.Now(),
		Version:   h.version,
		Checks:    checks,
	}

	statusCode := http.StatusOK
	if overallStatus == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}

	middleware.WriteJSONResponse(w, statusCode, response)
}

// ReadinessCheck handles GET /health/ready
func (h *HealthHandler) ReadinessCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ready := true

	// Check if database is ready
	if !h.isDatabaseReady(ctx) {
		ready = false
	}

	// Check if provider is ready
	if !h.isProviderReady(ctx) {
		ready = false
	}

	response := ReadinessResponse{
		Ready:     ready,
		Timestamp: time.Now(),
	}

	statusCode := http.StatusOK
	if !ready {
		statusCode = http.StatusServiceUnavailable
	}

	middleware.WriteJSONResponse(w, statusCode, response)
}

// Helper methods for health checks

func (h *HealthHandler) checkDatabase(ctx context.Context) (string, string, string) {
	start := time.Now()
	
	// Perform a simple database operation
	if err := h.store.HealthCheck(ctx); err != nil {
		duration := time.Since(start).String()
		return "unhealthy", "Database connection failed: " + err.Error(), duration
	}

	duration := time.Since(start).String()
	return "healthy", "Database connection successful", duration
}

func (h *HealthHandler) checkProvider(ctx context.Context) (string, string, string) {
	start := time.Now()
	
	if h.provider == nil {
		return "healthy", "No provider configured", "0ms"
	}

	// Perform a simple provider operation
	if err := h.provider.HealthCheck(ctx); err != nil {
		duration := time.Since(start).String()
		return "unhealthy", "Provider health check failed: " + err.Error(), duration
	}

	duration := time.Since(start).String()
	return "healthy", "Provider health check successful", duration
}

func (h *HealthHandler) isDatabaseReady(ctx context.Context) bool {
	return h.store.HealthCheck(ctx) == nil
}

func (h *HealthHandler) isProviderReady(ctx context.Context) bool {
	if h.provider == nil {
		return true // No provider configured is considered ready
	}
	return h.provider.HealthCheck(ctx) == nil
}