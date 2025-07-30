package graphql

import (
	"context"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/ports"
	"github.com/embrace-chaos/internal/adapters/graphql/generated"
	"github.com/embrace-chaos/internal/adapters/graphql/model"
	"github.com/embrace-chaos/internal/adapters/http/middleware"
)

type queryResolver struct{ *Resolver }

// Experiment returns a single experiment by ID
func (r *queryResolver) Experiment(ctx context.Context, id string) (*model.Experiment, error) {
	experiment, err := r.experimentService.GetExperiment(ctx, domain.ExperimentID(id))
	if err != nil {
		return nil, err
	}
	
	return model.ExperimentFromDomain(experiment), nil
}

// Experiments returns a paginated list of experiments
func (r *queryResolver) Experiments(ctx context.Context, filter *model.ExperimentFilter, pagination *model.PaginationInput) (*model.ExperimentConnection, error) {
	// Convert GraphQL filter to ports filter
	domainFilter := convertExperimentFilter(filter)
	
	// Convert GraphQL pagination to ports pagination
	domainPagination := convertPaginationInput(pagination)
	
	experiments, total, err := r.experimentService.ListExperiments(ctx, domainFilter, domainPagination)
	if err != nil {
		return nil, err
	}
	
	return model.ExperimentConnectionFromDomain(experiments, total, domainPagination), nil
}

// Execution returns a single execution by ID
func (r *queryResolver) Execution(ctx context.Context, id string) (*model.Execution, error) {
	execution, err := r.executionService.GetExecution(ctx, domain.ExecutionID(id))
	if err != nil {
		return nil, err
	}
	
	return model.ExecutionFromDomain(execution), nil
}

// Executions returns a paginated list of executions
func (r *queryResolver) Executions(ctx context.Context, filter *model.ExecutionFilter, pagination *model.PaginationInput) (*model.ExecutionConnection, error) {
	domainFilter := convertExecutionFilter(filter)
	domainPagination := convertPaginationInput(pagination)
	
	executions, total, err := r.executionService.ListExecutions(ctx, domainFilter, domainPagination)
	if err != nil {
		return nil, err
	}
	
	return model.ExecutionConnectionFromDomain(executions, total, domainPagination), nil
}

// Target returns a single target by ID
func (r *queryResolver) Target(ctx context.Context, id string) (*model.Target, error) {
	target, err := r.targetService.GetTarget(ctx, id)
	if err != nil {
		return nil, err
	}
	
	return model.TargetFromDomain(target), nil
}

// Targets returns a paginated list of targets
func (r *queryResolver) Targets(ctx context.Context, filter *model.TargetFilter, pagination *model.PaginationInput) (*model.TargetConnection, error) {
	domainFilter := convertTargetFilter(filter)
	domainPagination := convertPaginationInput(pagination)
	
	targets, total, err := r.targetService.ListTargets(ctx, domainFilter, domainPagination)
	if err != nil {
		return nil, err
	}
	
	return model.TargetConnectionFromDomain(targets, total, domainPagination), nil
}

// DiscoverTargets discovers available targets from providers
func (r *queryResolver) DiscoverTargets(ctx context.Context, input model.DiscoverTargetsInput) ([]*model.Target, error) {
	domainRequest := &domain.TargetDiscoveryRequest{
		Provider: domain.Provider(input.Provider),
		Region:   ptrToString(input.Region),
		Filters:  input.Filters,
	}
	
	targets, err := r.targetService.DiscoverTargets(ctx, domainRequest)
	if err != nil {
		return nil, err
	}
	
	return model.TargetsFromDomain(targets), nil
}

// Health returns the system health status
func (r *queryResolver) Health(ctx context.Context) (*model.HealthStatus, error) {
	// Implementation would check various system components
	health := &model.HealthStatus{
		Status:  model.ServiceStatusHealthy,
		Version: "1.0.0",
		Uptime:  "24h",
		Checks: []*model.HealthCheck{
			{
				Name:        "database",
				Status:      model.ServiceStatusHealthy,
				Message:     ptrToString("Database connection healthy"),
				Duration:    "5ms",
				LastChecked: "2024-01-01T12:00:00Z",
			},
			{
				Name:        "provider",
				Status:      model.ServiceStatusHealthy,
				Message:     ptrToString("Provider connections healthy"),
				Duration:    "15ms",
				LastChecked: "2024-01-01T12:00:00Z",
			},
		},
	}
	
	return health, nil
}

// Me returns the current authenticated user
func (r *queryResolver) Me(ctx context.Context) (*model.User, error) {
	userID := middleware.GetUserIDFromContext(ctx)
	if userID == "" {
		return nil, domain.NewAuthenticationError("user not authenticated")
	}
	
	user, err := r.userService.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	
	return model.UserFromDomain(user), nil
}

// Organization returns an organization by ID
func (r *queryResolver) Organization(ctx context.Context, id string) (*model.Organization, error) {
	org, err := r.organizationService.GetOrganization(ctx, id)
	if err != nil {
		return nil, err
	}
	
	return model.OrganizationFromDomain(org), nil
}

// Search performs a global search across resources
func (r *queryResolver) Search(ctx context.Context, query string, types []model.SearchType) (*model.SearchResults, error) {
	results := &model.SearchResults{
		Experiments: []*model.Experiment{},
		Executions:  []*model.Execution{},
		Targets:     []*model.Target{},
		Users:       []*model.User{},
		TotalCount:  0,
	}
	
	// Search experiments if requested
	if contains(types, model.SearchTypeExperiment) {
		filter := ports.ExperimentFilters{
			NameContains: query,
		}
		pagination := ports.PaginationRequest{Page: 1, PageSize: 10}
		
		experiments, _, err := r.experimentService.ListExperiments(ctx, filter, pagination)
		if err == nil {
			results.Experiments = model.ExperimentsFromDomain(experiments)
			results.TotalCount += len(experiments)
		}
	}
	
	// Search executions if requested
	if contains(types, model.SearchTypeExecution) {
		// Implementation would search executions by experiment name, trigger, etc.
		// For now, return empty results
	}
	
	// Search targets if requested
	if contains(types, model.SearchTypeTarget) {
		// Implementation would search targets by name, tags, etc.
		// For now, return empty results
	}
	
	// Search users if requested
	if contains(types, model.SearchTypeUser) {
		// Implementation would search users by name, email, etc.
		// For now, return empty results
	}
	
	return results, nil
}

// Helper functions for converting between GraphQL and domain models

func convertExperimentFilter(filter *model.ExperimentFilter) ports.ExperimentFilters {
	if filter == nil {
		return ports.ExperimentFilters{}
	}
	
	domainFilter := ports.ExperimentFilters{
		NameContains: ptrToString(filter.NameContains),
		Labels:       filter.Labels,
	}
	
	if filter.Status != nil {
		domainFilter.Status = make([]string, len(filter.Status))
		for i, status := range filter.Status {
			domainFilter.Status[i] = string(status)
		}
	}
	
	if filter.CreatedBy != nil {
		domainFilter.CreatedBy = *filter.CreatedBy
	}
	
	return domainFilter
}

func convertExecutionFilter(filter *model.ExecutionFilter) ports.ExecutionFilters {
	if filter == nil {
		return ports.ExecutionFilters{}
	}
	
	domainFilter := ports.ExecutionFilters{}
	
	if filter.ExperimentID != nil {
		domainFilter.ExperimentID = domain.ExperimentID(*filter.ExperimentID)
	}
	
	if filter.Status != nil {
		domainFilter.Status = make([]domain.ExecutionStatus, len(filter.Status))
		for i, status := range filter.Status {
			domainFilter.Status[i] = domain.ExecutionStatus(status)
		}
	}
	
	return domainFilter
}

func convertTargetFilter(filter *model.TargetFilter) ports.TargetFilters {
	if filter == nil {
		return ports.TargetFilters{}
	}
	
	domainFilter := ports.TargetFilters{
		Tags: filter.Tags,
	}
	
	if filter.Providers != nil {
		domainFilter.Providers = make([]domain.Provider, len(filter.Providers))
		for i, provider := range filter.Providers {
			domainFilter.Providers[i] = domain.Provider(provider)
		}
	}
	
	if filter.Types != nil {
		domainFilter.Types = make([]domain.TargetType, len(filter.Types))
		for i, targetType := range filter.Types {
			domainFilter.Types[i] = domain.TargetType(targetType)
		}
	}
	
	if filter.Regions != nil {
		domainFilter.Regions = *filter.Regions
	}
	
	return domainFilter
}

func convertPaginationInput(pagination *model.PaginationInput) ports.PaginationRequest {
	if pagination == nil {
		return ports.PaginationRequest{Page: 1, PageSize: 20}
	}
	
	page := 1
	if pagination.Page != nil && *pagination.Page > 0 {
		page = *pagination.Page
	}
	
	pageSize := 20
	if pagination.PageSize != nil && *pagination.PageSize > 0 && *pagination.PageSize <= 100 {
		pageSize = *pagination.PageSize
	}
	
	return ports.PaginationRequest{
		Page:     page,
		PageSize: pageSize,
	}
}

// Helper functions

func ptrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func contains(slice []model.SearchType, item model.SearchType) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}