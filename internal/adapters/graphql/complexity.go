package graphql

import (
	"fmt"

	"github.com/99designs/gqlgen/graphql"
)

// ComplexityConfig defines query complexity limits
type ComplexityConfig struct {
	MaxComplexity int
	ScalarCost    int
	ObjectCost    int
	ListMultiplier int
}

// DefaultComplexityConfig returns sensible defaults for query complexity
func DefaultComplexityConfig() ComplexityConfig {
	return ComplexityConfig{
		MaxComplexity:  1000,
		ScalarCost:     1,
		ObjectCost:     2,
		ListMultiplier: 10,
	}
}

// ComplexityRoot defines the complexity calculation for all GraphQL types
type ComplexityRoot struct {
	config ComplexityConfig
}

// NewComplexityRoot creates a new complexity calculator
func NewComplexityRoot(config ComplexityConfig) *ComplexityRoot {
	return &ComplexityRoot{
		config: config,
	}
}

// Query complexity calculations

func (c *ComplexityRoot) QueryExperiment(childComplexity int, id string) int {
	return c.config.ObjectCost + childComplexity
}

func (c *ComplexityRoot) QueryExperiments(childComplexity int, filter *interface{}, pagination *interface{}) int {
	baseComplexity := c.config.ObjectCost + childComplexity
	
	// Add cost for pagination - assume reasonable page size
	pageSize := 20
	if pagination != nil {
		// In real implementation, extract page size from pagination input
		// For now, use default
	}
	
	return baseComplexity * pageSize / c.config.ListMultiplier
}

func (c *ComplexityRoot) QueryExecution(childComplexity int, id string) int {
	return c.config.ObjectCost + childComplexity
}

func (c *ComplexityRoot) QueryExecutions(childComplexity int, filter *interface{}, pagination *interface{}) int {
	baseComplexity := c.config.ObjectCost + childComplexity
	pageSize := 20
	return baseComplexity * pageSize / c.config.ListMultiplier
}

func (c *ComplexityRoot) QueryTarget(childComplexity int, id string) int {
	return c.config.ObjectCost + childComplexity
}

func (c *ComplexityRoot) QueryTargets(childComplexity int, filter *interface{}, pagination *interface{}) int {
	baseComplexity := c.config.ObjectCost + childComplexity
	pageSize := 20
	return baseComplexity * pageSize / c.config.ListMultiplier
}

func (c *ComplexityRoot) QueryDiscoverTargets(childComplexity int, input interface{}) int {
	// Discovery operations are expensive
	return c.config.ObjectCost * 20 + childComplexity
}

func (c *ComplexityRoot) QueryHealth(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) QueryMe(childComplexity int) int {
	return c.config.ObjectCost + childComplexity
}

func (c *ComplexityRoot) QueryOrganization(childComplexity int, id string) int {
	return c.config.ObjectCost + childComplexity
}

func (c *ComplexityRoot) QuerySearch(childComplexity int, query string, types []interface{}) int {
	// Search is expensive, especially across multiple types
	baseCost := c.config.ObjectCost * 10
	typeCost := len(types) * c.config.ObjectCost * 5
	return baseCost + typeCost + childComplexity
}

// Experiment type complexity

func (c *ComplexityRoot) ExperimentID(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) ExperimentName(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) ExperimentDescription(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) ExperimentStatus(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) ExperimentConfig(childComplexity int) int {
	return c.config.ObjectCost + childComplexity
}

func (c *ComplexityRoot) ExperimentSafety(childComplexity int) int {
	return c.config.ObjectCost + childComplexity
}

func (c *ComplexityRoot) ExperimentTargets(childComplexity int) int {
	// Targets are a list but usually small
	return c.config.ObjectCost * 3 + childComplexity
}

func (c *ComplexityRoot) ExperimentExecutions(childComplexity int, filter *interface{}, pagination *interface{}) int {
	// Executions for an experiment - expensive operation
	baseComplexity := c.config.ObjectCost * 5 + childComplexity
	pageSize := 20
	return baseComplexity * pageSize / c.config.ListMultiplier
}

func (c *ComplexityRoot) ExperimentSchedule(childComplexity int) int {
	return c.config.ObjectCost + childComplexity
}

func (c *ComplexityRoot) ExperimentLastExecution(childComplexity int) int {
	return c.config.ObjectCost * 2 + childComplexity
}

func (c *ComplexityRoot) ExperimentCreator(childComplexity int) int {
	return c.config.ObjectCost + childComplexity
}

func (c *ComplexityRoot) ExperimentOrganization(childComplexity int) int {
	return c.config.ObjectCost + childComplexity
}

// Computed fields are more expensive
func (c *ComplexityRoot) ExperimentSuccessRate(childComplexity int) int {
	return c.config.ObjectCost * 3 + childComplexity
}

func (c *ComplexityRoot) ExperimentAverageDuration(childComplexity int) int {
	return c.config.ObjectCost * 3 + childComplexity
}

func (c *ComplexityRoot) ExperimentNextScheduledRun(childComplexity int) int {
	return c.config.ObjectCost * 2 + childComplexity
}

func (c *ComplexityRoot) ExperimentIsScheduled(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) ExperimentCanExecute(childComplexity int) int {
	return c.config.ObjectCost * 2 + childComplexity
}

func (c *ComplexityRoot) ExperimentValidationStatus(childComplexity int) int {
	return c.config.ObjectCost * 3 + childComplexity
}

// Execution type complexity

func (c *ComplexityRoot) ExecutionID(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) ExecutionExperiment(childComplexity int) int {
	return c.config.ObjectCost + childComplexity
}

func (c *ComplexityRoot) ExecutionStatus(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) ExecutionResults(childComplexity int) int {
	// Results can be numerous
	return c.config.ObjectCost * 5 + childComplexity
}

func (c *ComplexityRoot) ExecutionMetrics(childComplexity int) int {
	return c.config.ObjectCost * 2 + childComplexity
}

func (c *ComplexityRoot) ExecutionLogs(childComplexity int, tail *int, follow *bool) int {
	// Logs are expensive to fetch
	baseCost := c.config.ObjectCost * 10
	
	if tail != nil && *tail > 100 {
		// Large tail requests are more expensive
		baseCost *= 2
	}
	
	if follow != nil && *follow {
		// Following logs is very expensive
		baseCost *= 5
	}
	
	return baseCost + childComplexity
}

func (c *ComplexityRoot) ExecutionEvents(childComplexity int) int {
	return c.config.ObjectCost * 3 + childComplexity
}

func (c *ComplexityRoot) ExecutionSafetyStatus(childComplexity int) int {
	return c.config.ObjectCost * 2 + childComplexity
}

func (c *ComplexityRoot) ExecutionRollbackStatus(childComplexity int) int {
	return c.config.ObjectCost * 2 + childComplexity
}

// Target type complexity

func (c *ComplexityRoot) TargetID(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) TargetName(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) TargetType(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) TargetProvider(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) TargetExperiments(childComplexity int) int {
	// Can be many experiments per target
	return c.config.ObjectCost * 5 + childComplexity
}

func (c *ComplexityRoot) TargetHealthStatus(childComplexity int) int {
	// Health checks require external calls
	return c.config.ObjectCost * 10 + childComplexity
}

// User and Organization complexity

func (c *ComplexityRoot) UserID(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) UserEmail(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) UserName(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) UserOrganizations(childComplexity int) int {
	return c.config.ObjectCost * 3 + childComplexity
}

func (c *ComplexityRoot) UserExperiments(childComplexity int) int {
	return c.config.ObjectCost * 5 + childComplexity
}

func (c *ComplexityRoot) OrganizationID(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) OrganizationName(childComplexity int) int {
	return c.config.ScalarCost + childComplexity
}

func (c *ComplexityRoot) OrganizationUsers(childComplexity int) int {
	// Can be many users in organization
	return c.config.ObjectCost * 10 + childComplexity
}

func (c *ComplexityRoot) OrganizationExperiments(childComplexity int) int {
	// Can be many experiments in organization
	return c.config.ObjectCost * 20 + childComplexity
}

// Mutation complexity - mutations are generally more expensive

func (c *ComplexityRoot) MutationCreateExperiment(childComplexity int, input interface{}) int {
	return c.config.ObjectCost * 5 + childComplexity
}

func (c *ComplexityRoot) MutationUpdateExperiment(childComplexity int, id string, input interface{}) int {
	return c.config.ObjectCost * 5 + childComplexity
}

func (c *ComplexityRoot) MutationDeleteExperiment(childComplexity int, id string) int {
	return c.config.ObjectCost * 3 + childComplexity
}

func (c *ComplexityRoot) MutationExecuteExperiment(childComplexity int, id string, input *interface{}) int {
	// Execution is expensive
	return c.config.ObjectCost * 20 + childComplexity
}

func (c *ComplexityRoot) MutationCancelExecution(childComplexity int, id string) int {
	return c.config.ObjectCost * 10 + childComplexity
}

func (c *ComplexityRoot) MutationDiscoverTargets(childComplexity int, input interface{}) int {
	// Discovery is very expensive
	return c.config.ObjectCost * 50 + childComplexity
}

// Subscription complexity - subscriptions consume resources over time

func (c *ComplexityRoot) SubscriptionExecutionUpdated(childComplexity int, id string) int {
	// Real-time updates are expensive
	return c.config.ObjectCost * 100 + childComplexity
}

func (c *ComplexityRoot) SubscriptionExecutionLogs(childComplexity int, id string, tail *int) int {
	// Log streaming is very expensive
	baseCost := c.config.ObjectCost * 200
	
	if tail != nil && *tail > 100 {
		baseCost *= 2
	}
	
	return baseCost + childComplexity
}

func (c *ComplexityRoot) SubscriptionExperimentChanged(childComplexity int, id string) int {
	return c.config.ObjectCost * 50 + childComplexity
}

func (c *ComplexityRoot) SubscriptionSafetyAlert(childComplexity int, experimentID *string) int {
	baseCost := c.config.ObjectCost * 75
	
	if experimentID == nil {
		// Monitoring all experiments is more expensive
		baseCost *= 3
	}
	
	return baseCost + childComplexity
}

func (c *ComplexityRoot) SubscriptionOrganizationEvents(childComplexity int, organizationID string) int {
	// Organization-wide events are expensive
	return c.config.ObjectCost * 150 + childComplexity
}

// Connection types have standard costs

func (c *ComplexityRoot) ExperimentConnectionEdges(childComplexity int) int {
	return c.config.ObjectCost + childComplexity
}

func (c *ComplexityRoot) ExperimentConnectionPageInfo(childComplexity int) int {
	return c.config.ObjectCost + childComplexity
}

func (c *ComplexityRoot) ExperimentConnectionTotalCount(childComplexity int) int {
	// Count queries can be expensive
	return c.config.ObjectCost * 3 + childComplexity
}

// Validation function for query complexity
func (c *ComplexityRoot) ValidateComplexity(complexity int) error {
	if complexity > c.config.MaxComplexity {
		return fmt.Errorf("query complexity %d exceeds maximum allowed complexity %d", 
			complexity, c.config.MaxComplexity)
	}
	return nil
}

// Middleware to check query complexity
func ComplexityMiddleware(config ComplexityConfig) graphql.HandlerExtension {
	return &complexityMiddleware{
		config: config,
		root:   NewComplexityRoot(config),
	}
}

type complexityMiddleware struct {
	config ComplexityConfig
	root   *ComplexityRoot
}

func (c *complexityMiddleware) ExtensionName() string {
	return "ComplexityMiddleware"
}

func (c *complexityMiddleware) Validate(schema graphql.ExecutableSchema) error {
	return nil
}

func (c *complexityMiddleware) InterceptOperation(ctx context.Context, next graphql.OperationHandler) graphql.ResponseHandler {
	return func(ctx context.Context) *graphql.Response {
		// Calculate query complexity
		oc := graphql.GetOperationContext(ctx)
		complexity := calculateOperationComplexity(oc, c.root)
		
		// Validate complexity
		if err := c.root.ValidateComplexity(complexity); err != nil {
			return graphql.ErrorResponse(ctx, "Query complexity too high: %s", err.Error())
		}
		
		// Add complexity to context for monitoring
		ctx = context.WithValue(ctx, "query_complexity", complexity)
		
		return next(ctx)
	}
}

// Helper function to calculate operation complexity
func calculateOperationComplexity(oc *graphql.OperationContext, root *ComplexityRoot) int {
	// This would integrate with the actual GraphQL complexity calculation
	// For now, return a placeholder
	return 100
}