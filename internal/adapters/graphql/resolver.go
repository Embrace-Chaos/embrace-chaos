package graphql

import (
	"context"

	"github.com/embrace-chaos/internal/core/ports"
	"github.com/embrace-chaos/internal/adapters/graphql/dataloaders"
	"github.com/embrace-chaos/internal/adapters/graphql/generated"
	"github.com/embrace-chaos/internal/adapters/graphql/model"
)

// Resolver is the root GraphQL resolver
type Resolver struct {
	experimentService ports.ExperimentService
	executionService  ports.ExecutionService
	targetService     ports.TargetService
	userService       ports.UserService
	organizationService ports.OrganizationService
	store             ports.Store
	dataloaders       *dataloaders.Loaders
}

// NewResolver creates a new GraphQL resolver
func NewResolver(
	experimentService ports.ExperimentService,
	executionService ports.ExecutionService,
	targetService ports.TargetService,
	userService ports.UserService,
	organizationService ports.OrganizationService,
	store ports.Store,
) *Resolver {
	return &Resolver{
		experimentService:   experimentService,
		executionService:    executionService,
		targetService:       targetService,
		userService:         userService,
		organizationService: organizationService,
		store:              store,
		dataloaders:        dataloaders.NewLoaders(store),
	}
}

// Query returns the query resolver
func (r *Resolver) Query() generated.QueryResolver {
	return &queryResolver{r}
}

// Mutation returns the mutation resolver
func (r *Resolver) Mutation() generated.MutationResolver {
	return &mutationResolver{r}
}

// Subscription returns the subscription resolver
func (r *Resolver) Subscription() generated.SubscriptionResolver {
	return &subscriptionResolver{r}
}

// Experiment returns the experiment resolver
func (r *Resolver) Experiment() generated.ExperimentResolver {
	return &experimentResolver{r}
}

// Execution returns the execution resolver
func (r *Resolver) Execution() generated.ExecutionResolver {
	return &executionResolver{r}
}

// Target returns the target resolver
func (r *Resolver) Target() generated.TargetResolver {
	return &targetResolver{r}
}

// User returns the user resolver
func (r *Resolver) User() generated.UserResolver {
	return &userResolver{r}
}

// Organization returns the organization resolver
func (r *Resolver) Organization() generated.OrganizationResolver {
	return &organizationResolver{r}
}