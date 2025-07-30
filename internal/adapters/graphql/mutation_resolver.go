package graphql

import (
	"context"
	"time"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/adapters/graphql/generated"
	"github.com/embrace-chaos/internal/adapters/graphql/model"
	"github.com/embrace-chaos/internal/adapters/http/middleware"
)

type mutationResolver struct{ *Resolver }

// CreateExperiment creates a new chaos experiment
func (r *mutationResolver) CreateExperiment(ctx context.Context, input model.CreateExperimentInput) (*model.ExperimentPayload, error) {
	userID := middleware.GetUserIDFromContext(ctx)
	if userID == "" {
		return &model.ExperimentPayload{
			Errors: []*model.Error{{
				Message: "Authentication required",
				Code:    "UNAUTHENTICATED",
			}},
		}, nil
	}

	// Convert GraphQL input to domain model
	experiment := &domain.Experiment{
		Name:        input.Name,
		Description: ptrToString(input.Description),
		Config:      convertExperimentConfigInput(input.Config),
		Safety:      convertSafetyConfigInput(input.Safety),
		Targets:     convertTargetInputs(input.Targets),
		Labels:      input.Labels,
		Metadata:    input.Metadata,
		CreatedBy:   userID,
		Status:      domain.ExperimentStatusDraft,
	}

	createdExperiment, err := r.experimentService.CreateExperiment(ctx, experiment)
	if err != nil {
		return &model.ExperimentPayload{
			Errors: []*model.Error{{
				Message: err.Error(),
				Code:    "CREATION_FAILED",
			}},
		}, nil
	}

	return &model.ExperimentPayload{
		Experiment: model.ExperimentFromDomain(createdExperiment),
		Errors:     []*model.Error{},
		UserErrors: []*model.UserError{},
	}, nil
}

// UpdateExperiment updates an existing experiment
func (r *mutationResolver) UpdateExperiment(ctx context.Context, id string, input model.UpdateExperimentInput) (*model.ExperimentPayload, error) {
	// Get existing experiment
	experiment, err := r.experimentService.GetExperiment(ctx, domain.ExperimentID(id))
	if err != nil {
		return &model.ExperimentPayload{
			Errors: []*model.Error{{
				Message: err.Error(),
				Code:    "NOT_FOUND",
			}},
		}, nil
	}

	// Update fields that are provided
	if input.Name != nil {
		experiment.Name = *input.Name
	}
	if input.Description != nil {
		experiment.Description = *input.Description
	}
	if input.Config != nil {
		experiment.Config = convertExperimentConfigInput(*input.Config)
	}
	if input.Safety != nil {
		experiment.Safety = convertSafetyConfigInput(*input.Safety)
	}
	if input.Targets != nil {
		experiment.Targets = convertTargetInputs(*input.Targets)
	}
	if input.Labels != nil {
		experiment.Labels = *input.Labels
	}
	if input.Metadata != nil {
		experiment.Metadata = *input.Metadata
	}

	updatedExperiment, err := r.experimentService.UpdateExperiment(ctx, experiment)
	if err != nil {
		return &model.ExperimentPayload{
			Errors: []*model.Error{{
				Message: err.Error(),
				Code:    "UPDATE_FAILED",
			}},
		}, nil
	}

	return &model.ExperimentPayload{
		Experiment: model.ExperimentFromDomain(updatedExperiment),
		Errors:     []*model.Error{},
		UserErrors: []*model.UserError{},
	}, nil
}

// DeleteExperiment soft-deletes an experiment
func (r *mutationResolver) DeleteExperiment(ctx context.Context, id string) (*model.DeletePayload, error) {
	err := r.experimentService.DeleteExperiment(ctx, domain.ExperimentID(id))
	if err != nil {
		return &model.DeletePayload{
			Success: false,
			Errors: []*model.Error{{
				Message: err.Error(),
				Code:    "DELETE_FAILED",
			}},
		}, nil
	}

	return &model.DeletePayload{
		Success:    true,
		Errors:     []*model.Error{},
		UserErrors: []*model.UserError{},
	}, nil
}

// CloneExperiment creates a copy of an existing experiment
func (r *mutationResolver) CloneExperiment(ctx context.Context, id string, input model.CloneExperimentInput) (*model.ExperimentPayload, error) {
	userID := middleware.GetUserIDFromContext(ctx)
	if userID == "" {
		return &model.ExperimentPayload{
			Errors: []*model.Error{{
				Message: "Authentication required",
				Code:    "UNAUTHENTICATED",
			}},
		}, nil
	}

	// Get original experiment
	originalExperiment, err := r.experimentService.GetExperiment(ctx, domain.ExperimentID(id))
	if err != nil {
		return &model.ExperimentPayload{
			Errors: []*model.Error{{
				Message: err.Error(),
				Code:    "NOT_FOUND",
			}},
		}, nil
	}

	// Create clone
	clonedExperiment := &domain.Experiment{
		Name:        input.Name,
		Description: ptrToString(input.Description),
		Config:      originalExperiment.Config,
		Safety:      originalExperiment.Safety,
		Targets:     originalExperiment.Targets,
		Labels:      originalExperiment.Labels,
		Metadata:    originalExperiment.Metadata,
		CreatedBy:   userID,
		Status:      domain.ExperimentStatusDraft,
	}

	createdExperiment, err := r.experimentService.CreateExperiment(ctx, clonedExperiment)
	if err != nil {
		return &model.ExperimentPayload{
			Errors: []*model.Error{{
				Message: err.Error(),
				Code:    "CLONE_FAILED",
			}},
		}, nil
	}

	return &model.ExperimentPayload{
		Experiment: model.ExperimentFromDomain(createdExperiment),
		Errors:     []*model.Error{},
		UserErrors: []*model.UserError{},
	}, nil
}

// ExecuteExperiment starts execution of an experiment
func (r *mutationResolver) ExecuteExperiment(ctx context.Context, id string, input *model.ExecuteExperimentInput) (*model.ExecutionPayload, error) {
	userID := middleware.GetUserIDFromContext(ctx)
	if userID == "" {
		return &model.ExecutionPayload{
			Errors: []*model.Error{{
				Message: "Authentication required",
				Code:    "UNAUTHENTICATED",
			}},
		}, nil
	}

	// Get experiment
	experiment, err := r.experimentService.GetExperiment(ctx, domain.ExperimentID(id))
	if err != nil {
		return &model.ExecutionPayload{
			Errors: []*model.Error{{
				Message: err.Error(),
				Code:    "NOT_FOUND",
			}},
		}, nil
	}

	// Create execution request
	executionRequest := &domain.ExecutionRequest{
		ExperimentID: experiment.ID,
		TriggerType:  domain.TriggerTypeManual,
		TriggerBy:    userID,
	}

	if input != nil {
		if input.DryRun != nil {
			executionRequest.DryRun = *input.DryRun
		}
		if input.Parameters != nil {
			executionRequest.Parameters = *input.Parameters
		}
	}

	execution, err := r.executionService.StartExecution(ctx, executionRequest)
	if err != nil {
		return &model.ExecutionPayload{
			Errors: []*model.Error{{
				Message: err.Error(),
				Code:    "EXECUTION_FAILED",
			}},
		}, nil
	}

	return &model.ExecutionPayload{
		Execution:  model.ExecutionFromDomain(execution),
		Errors:     []*model.Error{},
		UserErrors: []*model.UserError{},
	}, nil
}

// CancelExecution cancels a running execution
func (r *mutationResolver) CancelExecution(ctx context.Context, id string) (*model.ExecutionPayload, error) {
	userID := middleware.GetUserIDFromContext(ctx)
	if userID == "" {
		return &model.ExecutionPayload{
			Errors: []*model.Error{{
				Message: "Authentication required",
				Code:    "UNAUTHENTICATED",
			}},
		}, nil
	}

	execution, err := r.executionService.CancelExecution(ctx, domain.ExecutionID(id), userID)
	if err != nil {
		return &model.ExecutionPayload{
			Errors: []*model.Error{{
				Message: err.Error(),
				Code:    "CANCEL_FAILED",
			}},
		}, nil
	}

	return &model.ExecutionPayload{
		Execution:  model.ExecutionFromDomain(execution),
		Errors:     []*model.Error{},
		UserErrors: []*model.UserError{},
	}, nil
}

// RetryExecution retries a failed execution
func (r *mutationResolver) RetryExecution(ctx context.Context, id string) (*model.ExecutionPayload, error) {
	userID := middleware.GetUserIDFromContext(ctx)
	if userID == "" {
		return &model.ExecutionPayload{
			Errors: []*model.Error{{
				Message: "Authentication required",
				Code:    "UNAUTHENTICATED",
			}},
		}, nil
	}

	// Get original execution
	originalExecution, err := r.executionService.GetExecution(ctx, domain.ExecutionID(id))
	if err != nil {
		return &model.ExecutionPayload{
			Errors: []*model.Error{{
				Message: err.Error(),
				Code:    "NOT_FOUND",
			}},
		}, nil
	}

	// Create new execution request based on original
	executionRequest := &domain.ExecutionRequest{
		ExperimentID: originalExecution.ExperimentID,
		DryRun:       false, // Retries are never dry runs
		Parameters:   originalExecution.Parameters,
		TriggerType:  domain.TriggerTypeManual,
		TriggerBy:    userID,
	}

	execution, err := r.executionService.StartExecution(ctx, executionRequest)
	if err != nil {
		return &model.ExecutionPayload{
			Errors: []*model.Error{{
				Message: err.Error(),
				Code:    "RETRY_FAILED",
			}},
		}, nil
	}

	return &model.ExecutionPayload{
		Execution:  model.ExecutionFromDomain(execution),
		Errors:     []*model.Error{},
		UserErrors: []*model.UserError{},
	}, nil
}

// RefreshTarget refreshes target information from provider
func (r *mutationResolver) RefreshTarget(ctx context.Context, id string) (*model.TargetPayload, error) {
	target, err := r.targetService.RefreshTarget(ctx, id)
	if err != nil {
		return &model.TargetPayload{
			Errors: []*model.Error{{
				Message: err.Error(),
				Code:    "REFRESH_FAILED",
			}},
		}, nil
	}

	return &model.TargetPayload{
		Target:     model.TargetFromDomain(target),
		Errors:     []*model.Error{},
		UserErrors: []*model.UserError{},
	}, nil
}

// ValidateTarget validates target configuration and connectivity
func (r *mutationResolver) ValidateTarget(ctx context.Context, id string) (*model.ValidationPayload, error) {
	result, err := r.targetService.ValidateTarget(ctx, id)
	if err != nil {
		return &model.ValidationPayload{
			Valid:    false,
			Errors:   []string{err.Error()},
			Warnings: []string{},
		}, nil
	}

	return &model.ValidationPayload{
		Valid:    result.Valid,
		Errors:   result.Errors,
		Warnings: result.Warnings,
	}, nil
}

// GitOps mutations (simplified implementations)

func (r *mutationResolver) SyncFromGitHub(ctx context.Context, input model.GitHubSyncInput) (*model.SyncPayload, error) {
	// Implementation would sync from GitHub repository
	return &model.SyncPayload{
		SyncedExperiments: []*model.Experiment{},
		Errors:            []*model.Error{},
		TotalProcessed:    0,
		Created:           0,
		Updated:           0,
		Failed:            0,
	}, nil
}

func (r *mutationResolver) CreatePullRequest(ctx context.Context, input model.CreatePRInput) (*model.PullRequestPayload, error) {
	// Implementation would create a pull request
	return &model.PullRequestPayload{
		PullRequestURL: stringPtr("https://github.com/example/repo/pull/1"),
		Number:         1,
		Errors:         []*model.Error{},
	}, nil
}

// Schedule mutations

func (r *mutationResolver) ScheduleExperiment(ctx context.Context, id string, input model.ScheduleInput) (*model.SchedulePayload, error) {
	// Implementation would schedule experiment
	schedule := &model.Schedule{
		ID:             "schedule-1",
		CronExpression: input.CronExpression,
		Timezone:       ptrToString(input.Timezone),
		Enabled:        ptrToBool(input.Enabled, true),
		NextRun:        time.Now().Add(time.Hour).Format(time.RFC3339),
		Metadata:       input.Metadata,
	}

	return &model.SchedulePayload{
		Schedule:   schedule,
		Errors:     []*model.Error{},
		UserErrors: []*model.UserError{},
	}, nil
}

func (r *mutationResolver) UnscheduleExperiment(ctx context.Context, id string) (*model.DeletePayload, error) {
	// Implementation would remove schedule
	return &model.DeletePayload{
		Success:    true,
		Errors:     []*model.Error{},
		UserErrors: []*model.UserError{},
	}, nil
}

// Helper functions for converting input types

func convertExperimentConfigInput(input model.ExperimentConfigInput) domain.ExperimentConfig {
	config := domain.ExperimentConfig{
		Duration:    domain.Duration(input.Duration),
		Parallelism: input.Parallelism,
	}

	if input.ConcurrencyMode != nil {
		config.ConcurrencyMode = domain.ConcurrencyMode(*input.ConcurrencyMode)
	}

	if input.Timeout != nil {
		config.Timeout = domain.Duration(*input.Timeout)
	}

	if input.RetryPolicy != nil {
		config.RetryPolicy = domain.RetryPolicy{
			MaxRetries:      ptrToInt(input.RetryPolicy.MaxRetries, 0),
			BackoffStrategy: domain.BackoffStrategy(ptrToBackoffStrategy(input.RetryPolicy.BackoffStrategy, model.BackoffStrategyExponential)),
			InitialDelay:    domain.Duration(ptrToString(input.RetryPolicy.InitialDelay)),
			MaxDelay:        domain.Duration(ptrToString(input.RetryPolicy.MaxDelay)),
		}
	}

	return config
}

func convertSafetyConfigInput(input model.SafetyConfigInput) domain.SafetyConfig {
	config := domain.SafetyConfig{
		MaxFailures:      ptrToInt(input.MaxFailures, 0),
		FailureThreshold: domain.Percentage(ptrToFloat(input.FailureThreshold, 10.0)),
		AutoRollback:     ptrToBool(input.AutoRollback, true),
		RollbackTimeout:  domain.Duration(ptrToString(input.RollbackTimeout)),
		PreflightChecks:  ptrToStringSlice(input.PreflightChecks),
		HealthChecks:     ptrToStringSlice(input.HealthChecks),
		MonitoringPeriod: domain.Duration(ptrToString(input.MonitoringPeriod)),
		AlertThresholds:  input.AlertThresholds,
	}

	return config
}

func convertTargetInputs(inputs []model.TargetInput) []domain.Target {
	targets := make([]domain.Target, len(inputs))
	for i, input := range inputs {
		targets[i] = domain.Target{
			ID:         ptrToString(input.ID),
			ResourceID: input.ResourceID,
			Name:       input.Name,
			Type:       domain.TargetType(input.Type),
			Provider:   domain.Provider(input.Provider),
			Region:     input.Region,
			Tags:       input.Tags,
		}
	}
	return targets
}

// Additional helper functions

func stringPtr(s string) *string {
	return &s
}

func ptrToBool(b *bool, defaultVal bool) bool {
	if b == nil {
		return defaultVal
	}
	return *b
}

func ptrToInt(i *int, defaultVal int) int {
	if i == nil {
		return defaultVal
	}
	return *i
}

func ptrToFloat(f *float64, defaultVal float64) float64 {
	if f == nil {
		return defaultVal
	}
	return *f
}

func ptrToStringSlice(s *[]string) []string {
	if s == nil {
		return []string{}
	}
	return *s
}

func ptrToBackoffStrategy(s *model.BackoffStrategy, defaultVal model.BackoffStrategy) model.BackoffStrategy {
	if s == nil {
		return defaultVal
	}
	return *s
}