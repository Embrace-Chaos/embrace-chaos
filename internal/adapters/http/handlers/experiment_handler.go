package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
	"github.com/embrace-chaos/internal/core/ports"
	"github.com/embrace-chaos/internal/adapters/http/middleware"
)

// ExperimentHandler handles experiment-related HTTP requests
type ExperimentHandler struct {
	experimentService ports.ExperimentService
	executionService  ports.ExecutionService
	validator         *middleware.RequestValidator
}

// NewExperimentHandler creates a new experiment handler
func NewExperimentHandler(
	experimentService ports.ExperimentService,
	executionService ports.ExecutionService,
	validator *middleware.RequestValidator,
) *ExperimentHandler {
	return &ExperimentHandler{
		experimentService: experimentService,
		executionService:  executionService,
		validator:         validator,
	}
}

// ListExperiments handles GET /experiments
func (h *ExperimentHandler) ListExperiments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	filters, pagination, err := h.parseListParams(r)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	experiments, total, err := h.experimentService.ListExperiments(ctx, filters, pagination)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	response := ExperimentListResponse{
		Experiments: experiments,
		Pagination: PaginationInfo{
			Page:       pagination.Page,
			PageSize:   pagination.PageSize,
			Total:      total,
			TotalPages: (total + pagination.PageSize - 1) / pagination.PageSize,
		},
	}

	middleware.WriteJSONResponse(w, http.StatusOK, response)
}

// CreateExperiment handles POST /experiments
func (h *ExperimentHandler) CreateExperiment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := middleware.GetUserIDFromContext(ctx)

	var request CreateExperimentRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		middleware.WriteErrorResponse(w, r, errors.NewValidationError("invalid request body"))
		return
	}

	// Validate request
	if err := h.validator.ValidateStruct(request); err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	// Convert request to domain model
	experiment := &domain.Experiment{
		Name:        request.Name,
		Description: request.Description,
		Config:      convertExperimentConfig(request.Config),
		Safety:      convertSafetyConfig(request.Safety),
		Targets:     convertTargets(request.Targets),
		Labels:      request.Labels,
		CreatedBy:   userID,
		Status:      domain.ExperimentStatusDraft,
	}

	createdExperiment, err := h.experimentService.CreateExperiment(ctx, experiment)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	middleware.WriteJSONResponse(w, http.StatusCreated, createdExperiment)
}

// GetExperiment handles GET /experiments/{experimentId}
func (h *ExperimentHandler) GetExperiment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	experimentID := mux.Vars(r)["experimentId"]

	experiment, err := h.experimentService.GetExperiment(ctx, domain.ExperimentID(experimentID))
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	middleware.WriteJSONResponse(w, http.StatusOK, experiment)
}

// UpdateExperiment handles PUT /experiments/{experimentId}
func (h *ExperimentHandler) UpdateExperiment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	experimentID := mux.Vars(r)["experimentId"]

	var request UpdateExperimentRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		middleware.WriteErrorResponse(w, r, errors.NewValidationError("invalid request body"))
		return
	}

	// Get existing experiment
	experiment, err := h.experimentService.GetExperiment(ctx, domain.ExperimentID(experimentID))
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	// Update fields
	if request.Name != "" {
		experiment.Name = request.Name
	}
	if request.Description != nil {
		experiment.Description = *request.Description
	}
	if request.Config != nil {
		experiment.Config = convertExperimentConfig(*request.Config)
	}
	if request.Safety != nil {
		experiment.Safety = convertSafetyConfig(*request.Safety)
	}
	if request.Targets != nil {
		experiment.Targets = convertTargets(*request.Targets)
	}
	if request.Labels != nil {
		experiment.Labels = *request.Labels
	}

	updatedExperiment, err := h.experimentService.UpdateExperiment(ctx, experiment)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	middleware.WriteJSONResponse(w, http.StatusOK, updatedExperiment)
}

// DeleteExperiment handles DELETE /experiments/{experimentId}
func (h *ExperimentHandler) DeleteExperiment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	experimentID := mux.Vars(r)["experimentId"]

	err := h.experimentService.DeleteExperiment(ctx, domain.ExperimentID(experimentID))
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ExecuteExperiment handles POST /experiments/{experimentId}/execute
func (h *ExperimentHandler) ExecuteExperiment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	experimentID := mux.Vars(r)["experimentId"]
	userID := middleware.GetUserIDFromContext(ctx)

	var request ExecuteExperimentRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			middleware.WriteErrorResponse(w, r, errors.NewValidationError("invalid request body"))
			return
		}
	}

	// Get experiment
	experiment, err := h.experimentService.GetExperiment(ctx, domain.ExperimentID(experimentID))
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	// Create execution request
	executionRequest := &domain.ExecutionRequest{
		ExperimentID: experiment.ID,
		DryRun:       request.DryRun,
		Parameters:   request.Parameters,
		TriggerType:  domain.TriggerTypeManual,
		TriggerBy:    userID,
	}

	execution, err := h.executionService.StartExecution(ctx, executionRequest)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	middleware.WriteJSONResponse(w, http.StatusAccepted, execution)
}

// ValidateExperiment handles POST /experiments/{experimentId}/validate
func (h *ExperimentHandler) ValidateExperiment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	experimentID := mux.Vars(r)["experimentId"]

	experiment, err := h.experimentService.GetExperiment(ctx, domain.ExperimentID(experimentID))
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	result, err := h.experimentService.ValidateExperiment(ctx, experiment)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	response := ValidationResult{
		Valid:    result.Valid,
		Message:  result.Message,
		Errors:   result.Errors,
		Warnings: result.Warnings,
	}

	middleware.WriteJSONResponse(w, http.StatusOK, response)
}

// Helper methods

func (h *ExperimentHandler) parseListParams(r *http.Request) (ports.ExperimentFilters, ports.PaginationRequest, error) {
	query := r.URL.Query()
	
	// Parse pagination
	page := 1
	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	pageSize := 20
	if ps := query.Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	orderBy := query.Get("order_by")
	if orderBy == "" {
		orderBy = "created_at"
	}

	orderDir := query.Get("order_dir")
	if orderDir == "" {
		orderDir = "desc"
	}

	// Parse filters
	filters := ports.ExperimentFilters{
		OrderBy:  orderBy,
		OrderDir: orderDir,
	}

	if statuses := query["status"]; len(statuses) > 0 {
		filters.Status = statuses
	}

	if creators := query["created_by"]; len(creators) > 0 {
		filters.CreatedBy = creators
	}

	if nameContains := query.Get("name_contains"); nameContains != "" {
		filters.NameContains = nameContains
	}

	// Parse labels (key:value format)
	if labelsParam := query.Get("labels"); labelsParam != "" {
		labels := make(map[string]string)
		for _, pair := range strings.Split(labelsParam, ",") {
			if parts := strings.SplitN(pair, ":", 2); len(parts) == 2 {
				labels[parts[0]] = parts[1]
			}
		}
		filters.Labels = labels
	}

	pagination := ports.PaginationRequest{
		Page:     page,
		PageSize: pageSize,
	}

	return filters, pagination, nil
}

// Type conversion helpers

func convertExperimentConfig(config ExperimentConfig) domain.ExperimentConfig {
	result := domain.ExperimentConfig{
		Duration:        domain.Duration(config.Duration),
		Parallelism:     config.Parallelism,
		ConcurrencyMode: domain.ConcurrencyMode(config.ConcurrencyMode),
	}

	if config.Timeout != "" {
		result.Timeout = domain.Duration(config.Timeout)
	}

	if config.RetryPolicy != nil {
		result.RetryPolicy = domain.RetryPolicy{
			MaxRetries:      config.RetryPolicy.MaxRetries,
			BackoffStrategy: domain.BackoffStrategy(config.RetryPolicy.BackoffStrategy),
			InitialDelay:    domain.Duration(config.RetryPolicy.InitialDelay),
			MaxDelay:        domain.Duration(config.RetryPolicy.MaxDelay),
		}
	}

	return result
}

func convertSafetyConfig(config SafetyConfig) domain.SafetyConfig {
	result := domain.SafetyConfig{
		MaxFailures:        config.MaxFailures,
		FailureThreshold:   domain.Percentage(config.FailureThreshold),
		AutoRollback:       config.AutoRollback,
		RollbackTimeout:    domain.Duration(config.RollbackTimeout),
		PreflightChecks:    config.PreflightChecks,
		HealthChecks:       config.HealthChecks,
		MonitoringPeriod:   domain.Duration(config.MonitoringPeriod),
		AlertThresholds:    config.AlertThresholds,
	}

	return result
}

func convertTargets(targets []Target) []domain.Target {
	result := make([]domain.Target, len(targets))
	for i, target := range targets {
		result[i] = domain.Target{
			ID:         target.ID,
			ResourceID: target.ResourceID,
			Name:       target.Name,
			Type:       domain.TargetType(target.Type),
			Provider:   domain.Provider(target.Provider),
			Region:     target.Region,
			Tags:       target.Tags,
			Status:     domain.TargetStatus(target.Status),
			Metadata:   target.Metadata,
		}
	}
	return result
}