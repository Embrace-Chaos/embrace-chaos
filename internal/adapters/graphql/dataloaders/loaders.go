package dataloaders

import (
	"context"
	"time"

	"github.com/graph-gophers/dataloader/v7"
	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/ports"
)

// Loaders contains all DataLoader instances
type Loaders struct {
	ExperimentByID dataloader.Interface[string, *domain.Experiment]
	ExecutionByID  dataloader.Interface[string, *domain.Execution]
	TargetByID     dataloader.Interface[string, *domain.Target]
	UserByID       dataloader.Interface[string, *domain.User]
	
	ExecutionsByExperimentID dataloader.Interface[string, []*domain.Execution]
	TargetsByExperimentID    dataloader.Interface[string, []*domain.Target]
	ExperimentsByUserID      dataloader.Interface[string, []*domain.Experiment]
}

// NewLoaders creates a new set of DataLoaders
func NewLoaders(store ports.Store) *Loaders {
	batchConfig := dataloader.Config[string, any]{
		Wait:     1 * time.Millisecond,
		MaxBatch: 100,
	}

	return &Loaders{
		ExperimentByID: dataloader.NewBatchedLoader(
			newExperimentBatchFunc(store),
			dataloader.Config[string, *domain.Experiment]{
				Wait:     batchConfig.Wait,
				MaxBatch: batchConfig.MaxBatch,
			},
		),
		ExecutionByID: dataloader.NewBatchedLoader(
			newExecutionBatchFunc(store),
			dataloader.Config[string, *domain.Execution]{
				Wait:     batchConfig.Wait,
				MaxBatch: batchConfig.MaxBatch,
			},
		),
		TargetByID: dataloader.NewBatchedLoader(
			newTargetBatchFunc(store),
			dataloader.Config[string, *domain.Target]{
				Wait:     batchConfig.Wait,
				MaxBatch: batchConfig.MaxBatch,
			},
		),
		UserByID: dataloader.NewBatchedLoader(
			newUserBatchFunc(store),
			dataloader.Config[string, *domain.User]{
				Wait:     batchConfig.Wait,
				MaxBatch: batchConfig.MaxBatch,
			},
		),
		ExecutionsByExperimentID: dataloader.NewBatchedLoader(
			newExecutionsByExperimentBatchFunc(store),
			dataloader.Config[string, []*domain.Execution]{
				Wait:     batchConfig.Wait,
				MaxBatch: batchConfig.MaxBatch,
			},
		),
		TargetsByExperimentID: dataloader.NewBatchedLoader(
			newTargetsByExperimentBatchFunc(store),
			dataloader.Config[string, []*domain.Target]{
				Wait:     batchConfig.Wait,
				MaxBatch: batchConfig.MaxBatch,
			},
		),
		ExperimentsByUserID: dataloader.NewBatchedLoader(
			newExperimentsByUserBatchFunc(store),
			dataloader.Config[string, []*domain.Experiment]{
				Wait:     batchConfig.Wait,
				MaxBatch: batchConfig.MaxBatch,
			},
		),
	}
}

// Batch functions for individual entities

func newExperimentBatchFunc(store ports.Store) dataloader.BatchFunc[string, *domain.Experiment] {
	return func(ctx context.Context, keys []string) []*dataloader.Result[*domain.Experiment] {
		experiments, err := store.GetExperimentsByIDs(ctx, convertToExperimentIDs(keys))
		if err != nil {
			// Return error for all keys
			results := make([]*dataloader.Result[*domain.Experiment], len(keys))
			for i := range results {
				results[i] = &dataloader.Result[*domain.Experiment]{Error: err}
			}
			return results
		}

		// Create map for O(1) lookup
		experimentMap := make(map[string]*domain.Experiment)
		for _, experiment := range experiments {
			experimentMap[string(experiment.ID)] = experiment
		}

		// Build results in the same order as keys
		results := make([]*dataloader.Result[*domain.Experiment], len(keys))
		for i, key := range keys {
			if experiment, exists := experimentMap[key]; exists {
				results[i] = &dataloader.Result[*domain.Experiment]{Data: experiment}
			} else {
				results[i] = &dataloader.Result[*domain.Experiment]{
					Error: domain.NewNotFoundError("experiment", key),
				}
			}
		}

		return results
	}
}

func newExecutionBatchFunc(store ports.Store) dataloader.BatchFunc[string, *domain.Execution] {
	return func(ctx context.Context, keys []string) []*dataloader.Result[*domain.Execution] {
		executions, err := store.GetExecutionsByIDs(ctx, convertToExecutionIDs(keys))
		if err != nil {
			results := make([]*dataloader.Result[*domain.Execution], len(keys))
			for i := range results {
				results[i] = &dataloader.Result[*domain.Execution]{Error: err}
			}
			return results
		}

		executionMap := make(map[string]*domain.Execution)
		for _, execution := range executions {
			executionMap[string(execution.ID)] = execution
		}

		results := make([]*dataloader.Result[*domain.Execution], len(keys))
		for i, key := range keys {
			if execution, exists := executionMap[key]; exists {
				results[i] = &dataloader.Result[*domain.Execution]{Data: execution}
			} else {
				results[i] = &dataloader.Result[*domain.Execution]{
					Error: domain.NewNotFoundError("execution", key),
				}
			}
		}

		return results
	}
}

func newTargetBatchFunc(store ports.Store) dataloader.BatchFunc[string, *domain.Target] {
	return func(ctx context.Context, keys []string) []*dataloader.Result[*domain.Target] {
		targets, err := store.GetTargetsByIDs(ctx, keys)
		if err != nil {
			results := make([]*dataloader.Result[*domain.Target], len(keys))
			for i := range results {
				results[i] = &dataloader.Result[*domain.Target]{Error: err}
			}
			return results
		}

		targetMap := make(map[string]*domain.Target)
		for _, target := range targets {
			targetMap[target.ID] = target
		}

		results := make([]*dataloader.Result[*domain.Target], len(keys))
		for i, key := range keys {
			if target, exists := targetMap[key]; exists {
				results[i] = &dataloader.Result[*domain.Target]{Data: target}
			} else {
				results[i] = &dataloader.Result[*domain.Target]{
					Error: domain.NewNotFoundError("target", key),
				}
			}
		}

		return results
	}
}

func newUserBatchFunc(store ports.Store) dataloader.BatchFunc[string, *domain.User] {
	return func(ctx context.Context, keys []string) []*dataloader.Result[*domain.User] {
		users, err := store.GetUsersByIDs(ctx, keys)
		if err != nil {
			results := make([]*dataloader.Result[*domain.User], len(keys))
			for i := range results {
				results[i] = &dataloader.Result[*domain.User]{Error: err}
			}
			return results
		}

		userMap := make(map[string]*domain.User)
		for _, user := range users {
			userMap[user.ID] = user
		}

		results := make([]*dataloader.Result[*domain.User], len(keys))
		for i, key := range keys {
			if user, exists := userMap[key]; exists {
				results[i] = &dataloader.Result[*domain.User]{Data: user}
			} else {
				results[i] = &dataloader.Result[*domain.User]{
					Error: domain.NewNotFoundError("user", key),
				}
			}
		}

		return results
	}
}

// Batch functions for one-to-many relationships

func newExecutionsByExperimentBatchFunc(store ports.Store) dataloader.BatchFunc[string, []*domain.Execution] {
	return func(ctx context.Context, keys []string) []*dataloader.Result[[]*domain.Execution] {
		// Get all executions for the given experiment IDs
		executionMap := make(map[string][]*domain.Execution)
		
		for _, experimentID := range keys {
			filter := ports.ExecutionFilters{
				ExperimentID: domain.ExperimentID(experimentID),
			}
			pagination := ports.PaginationRequest{Page: 1, PageSize: 1000}
			
			executions, _, err := store.ListExecutions(ctx, filter, pagination)
			if err != nil {
				// For this experiment, return empty slice
				executionMap[experimentID] = []*domain.Execution{}
			} else {
				executionMap[experimentID] = executions
			}
		}

		results := make([]*dataloader.Result[[]*domain.Execution], len(keys))
		for i, key := range keys {
			results[i] = &dataloader.Result[[]*domain.Execution]{
				Data: executionMap[key],
			}
		}

		return results
	}
}

func newTargetsByExperimentBatchFunc(store ports.Store) dataloader.BatchFunc[string, []*domain.Target] {
	return func(ctx context.Context, keys []string) []*dataloader.Result[[]*domain.Target] {
		targetMap := make(map[string][]*domain.Target)
		
		for _, experimentID := range keys {
			targets, err := store.GetTargetsByExperimentID(ctx, domain.ExperimentID(experimentID))
			if err != nil {
				targetMap[experimentID] = []*domain.Target{}
			} else {
				targetMap[experimentID] = targets
			}
		}

		results := make([]*dataloader.Result[[]*domain.Target], len(keys))
		for i, key := range keys {
			results[i] = &dataloader.Result[[]*domain.Target]{
				Data: targetMap[key],
			}
		}

		return results
	}
}

func newExperimentsByUserBatchFunc(store ports.Store) dataloader.BatchFunc[string, []*domain.Experiment] {
	return func(ctx context.Context, keys []string) []*dataloader.Result[[]*domain.Experiment] {
		experimentMap := make(map[string][]*domain.Experiment)
		
		for _, userID := range keys {
			filter := ports.ExperimentFilters{
				CreatedBy: []string{userID},
			}
			pagination := ports.PaginationRequest{Page: 1, PageSize: 1000}
			
			experiments, _, err := store.ListExperiments(ctx, filter, pagination)
			if err != nil {
				experimentMap[userID] = []*domain.Experiment{}
			} else {
				experimentMap[userID] = experiments
			}
		}

		results := make([]*dataloader.Result[[]*domain.Experiment], len(keys))
		for i, key := range keys {
			results[i] = &dataloader.Result[[]*domain.Experiment]{
				Data: experimentMap[key],
			}
		}

		return results
	}
}

// Helper functions

func convertToExperimentIDs(keys []string) []domain.ExperimentID {
	ids := make([]domain.ExperimentID, len(keys))
	for i, key := range keys {
		ids[i] = domain.ExperimentID(key)
	}
	return ids
}

func convertToExecutionIDs(keys []string) []domain.ExecutionID {
	ids := make([]domain.ExecutionID, len(keys))
	for i, key := range keys {
		ids[i] = domain.ExecutionID(key)
	}
	return ids
}

// Context key for DataLoaders
type contextKey string

const loadersKey contextKey = "dataloaders"

// NewContext returns a new context with DataLoaders
func NewContext(ctx context.Context, loaders *Loaders) context.Context {
	return context.WithValue(ctx, loadersKey, loaders)
}

// FromContext extracts DataLoaders from context
func FromContext(ctx context.Context) *Loaders {
	if loaders, ok := ctx.Value(loadersKey).(*Loaders); ok {
		return loaders
	}
	return nil
}