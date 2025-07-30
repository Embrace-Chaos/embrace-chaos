package domain

import (
	"fmt"
	"strings"
)

// Target represents a resource that can be targeted by chaos experiments
type Target struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       TargetType        `json:"type"`
	Provider   string            `json:"provider"`
	Region     string            `json:"region,omitempty"`
	
	// Resource identification
	ResourceID string            `json:"resource_id"`
	ARN        string            `json:"arn,omitempty"`
	
	// Filtering and selection
	Selector   TargetSelector    `json:"selector"`
	
	// Configuration
	Config     TargetConfig      `json:"config"`
	
	// Status
	Status     TargetStatus      `json:"status"`
	
	// Metadata
	Labels     map[string]string `json:"labels"`
	Tags       map[string]string `json:"tags"`
	
	// Health information
	Health     TargetHealth      `json:"health"`
}

// TargetType defines the type of target resource
type TargetType string

const (
	// AWS target types
	TargetTypeEC2Instance      TargetType = "ec2_instance"
	TargetTypeECSService       TargetType = "ecs_service"
	TargetTypeECSTask          TargetType = "ecs_task"
	TargetTypeRDSInstance      TargetType = "rds_instance"
	TargetTypeLambdaFunction   TargetType = "lambda_function"
	TargetTypeELBLoadBalancer  TargetType = "elb_load_balancer"
	TargetTypeS3Bucket         TargetType = "s3_bucket"
	
	// GCP target types
	TargetTypeGCEInstance      TargetType = "gce_instance"
	TargetTypeCloudSQLInstance TargetType = "cloudsql_instance"
	TargetTypeGKECluster       TargetType = "gke_cluster"
	TargetTypeGKENode          TargetType = "gke_node"
	TargetTypeGKEPod           TargetType = "gke_pod"
	TargetTypeCloudFunction    TargetType = "cloud_function"
	TargetTypeCloudStorage     TargetType = "cloud_storage"
	
	// Azure target types
	TargetTypeAzureVM          TargetType = "azure_vm"
	TargetTypeAKSCluster       TargetType = "aks_cluster"
	
	// Kubernetes target types
	TargetTypeKubernetesPod    TargetType = "kubernetes_pod"
	TargetTypeKubernetesNode   TargetType = "kubernetes_node"
	TargetTypeKubernetesService TargetType = "kubernetes_service"
	
	// Generic target types
	TargetTypeCustom           TargetType = "custom"
)

// TargetStatus represents the current status of a target
type TargetStatus string

const (
	TargetStatusHealthy     TargetStatus = "healthy"
	TargetStatusUnhealthy   TargetStatus = "unhealthy"
	TargetStatusUnknown     TargetStatus = "unknown"
	TargetStatusMaintenance TargetStatus = "maintenance"
	TargetStatusTerminated  TargetStatus = "terminated"
)

// TargetSelector defines how to select and filter targets
type TargetSelector struct {
	// Selection strategy
	Strategy      SelectionStrategy     `json:"strategy"`
	
	// Filtering criteria
	Filters       []TargetFilter        `json:"filters"`
	
	// Percentage or count of targets to select
	Percentage    *Percentage           `json:"percentage,omitempty"`
	Count         *int                  `json:"count,omitempty"`
	
	// Ordering for selection
	OrderBy       string                `json:"order_by,omitempty"`
	OrderDir      string                `json:"order_dir,omitempty"`
}

// SelectionStrategy defines how targets are selected
type SelectionStrategy string

const (
	SelectionStrategyRandom     SelectionStrategy = "random"
	SelectionStrategyAll        SelectionStrategy = "all"
	SelectionStrategyFirst      SelectionStrategy = "first"
	SelectionStrategyLast       SelectionStrategy = "last"
	SelectionStrategyRoundRobin SelectionStrategy = "round_robin"
	SelectionStrategyWeighted   SelectionStrategy = "weighted"
)

// TargetFilter defines filtering criteria for target selection
type TargetFilter struct {
	Field     string      `json:"field"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	Values    []string    `json:"values,omitempty"`
}

// TargetConfig holds target-specific configuration
type TargetConfig struct {
	// Actions that can be performed on this target
	AllowedActions   []string          `json:"allowed_actions"`
	
	// Exclusion periods
	MaintenanceWindows []MaintenanceWindow `json:"maintenance_windows"`
	
	// Safety constraints
	MaxConcurrentExperiments int `json:"max_concurrent_experiments"`
	
	// Recovery configuration
	RecoveryTimeout Duration           `json:"recovery_timeout"`
	
	// Custom parameters
	Parameters      map[string]any    `json:"parameters"`
}

// MaintenanceWindow defines when a target should not be experimented on
type MaintenanceWindow struct {
	Name      string    `json:"name"`
	StartTime string    `json:"start_time"` // Format: "15:04" or "Mon 15:04"
	EndTime   string    `json:"end_time"`
	Timezone  string    `json:"timezone"`
	Days      []string  `json:"days"` // ["monday", "tuesday", ...]
	Enabled   bool      `json:"enabled"`
}

// TargetHealth represents the health status of a target
type TargetHealth struct {
	Status       TargetStatus      `json:"status"`
	LastChecked  *time.Time        `json:"last_checked,omitempty"`
	CheckResults []HealthCheck     `json:"check_results"`
	Metrics      map[string]float64 `json:"metrics"`
}

// HealthCheck represents a single health check result
type HealthCheck struct {
	Name      string                 `json:"name"`
	Status    string                 `json:"status"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Duration  time.Duration          `json:"duration"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// NewTarget creates a new target with required fields
func NewTarget(name string, targetType TargetType, provider, resourceID string) *Target {
	return &Target{
		ID:         generateID(),
		Name:       name,
		Type:       targetType,
		Provider:   provider,
		ResourceID: resourceID,
		Selector: TargetSelector{
			Strategy: SelectionStrategyAll,
			Filters:  make([]TargetFilter, 0),
		},
		Config: TargetConfig{
			AllowedActions:           make([]string, 0),
			MaintenanceWindows:       make([]MaintenanceWindow, 0),
			MaxConcurrentExperiments: 1,
			RecoveryTimeout:          Duration(5 * time.Minute),
			Parameters:               make(map[string]any),
		},
		Status: TargetStatusUnknown,
		Labels: make(map[string]string),
		Tags:   make(map[string]string),
		Health: TargetHealth{
			Status:       TargetStatusUnknown,
			CheckResults: make([]HealthCheck, 0),
			Metrics:      make(map[string]float64),
		},
	}
}

// Validate validates the target configuration
func (t *Target) Validate() error {
	if t.Name == "" {
		return NewValidationError("target name is required")
	}
	
	if t.Type == "" {
		return NewValidationError("target type is required")
	}
	
	if t.Provider == "" {
		return NewValidationError("target provider is required")
	}
	
	if t.ResourceID == "" {
		return NewValidationError("target resource ID is required")
	}
	
	// Validate selector
	if t.Selector.Percentage != nil && (*t.Selector.Percentage < 0 || *t.Selector.Percentage > 100) {
		return NewValidationError("selector percentage must be between 0 and 100")
	}
	
	if t.Selector.Count != nil && *t.Selector.Count < 0 {
		return NewValidationError("selector count must be non-negative")
	}
	
	// Validate filters
	for i, filter := range t.Selector.Filters {
		if err := t.validateFilter(filter); err != nil {
			return fmt.Errorf("invalid filter at index %d: %w", i, err)
		}
	}
	
	return nil
}

// validateFilter validates a single target filter
func (t *Target) validateFilter(filter TargetFilter) error {
	if filter.Field == "" {
		return NewValidationError("filter field is required")
	}
	
	validOperators := []string{"eq", "ne", "in", "not_in", "contains", "starts_with", "ends_with", "regex"}
	isValidOperator := false
	for _, op := range validOperators {
		if filter.Operator == op {
			isValidOperator = true
			break
		}
	}
	
	if !isValidOperator {
		return NewValidationError("invalid filter operator: %s", filter.Operator)
	}
	
	// Check that appropriate value is provided
	if filter.Operator == "in" || filter.Operator == "not_in" {
		if filter.Values == nil || len(filter.Values) == 0 {
			return NewValidationError("filter with operator %s requires values array", filter.Operator)
		}
	} else {
		if filter.Value == nil {
			return NewValidationError("filter with operator %s requires value", filter.Operator)
		}
	}
	
	return nil
}

// IsHealthy checks if the target is healthy
func (t *Target) IsHealthy() bool {
	return t.Health.Status == TargetStatusHealthy
}

// CanExecuteExperiment checks if an experiment can be executed on this target
func (t *Target) CanExecuteExperiment(action string) bool {
	// Check if target is healthy
	if !t.IsHealthy() {
		return false
	}
	
	// Check if action is allowed
	if len(t.Config.AllowedActions) > 0 {
		allowed := false
		for _, allowedAction := range t.Config.AllowedActions {
			if allowedAction == action || allowedAction == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	
	// TODO: Check maintenance windows
	// TODO: Check concurrent experiment limits
	
	return true
}

// AddLabel adds a label to the target
func (t *Target) AddLabel(key, value string) {
	if t.Labels == nil {
		t.Labels = make(map[string]string)
	}
	t.Labels[key] = value
}

// AddTag adds a tag to the target
func (t *Target) AddTag(key, value string) {
	if t.Tags == nil {
		t.Tags = make(map[string]string)
	}
	t.Tags[key] = value
}

// UpdateHealth updates the target's health status
func (t *Target) UpdateHealth(status TargetStatus, checks []HealthCheck) {
	now := time.Now()
	t.Health.Status = status
	t.Health.LastChecked = &now
	t.Health.CheckResults = checks
	t.Status = status
}

// AddHealthCheck adds a single health check result
func (t *Target) AddHealthCheck(check HealthCheck) {
	t.Health.CheckResults = append(t.Health.CheckResults, check)
	
	// Update overall health based on latest checks
	hasFailures := false
	for _, c := range t.Health.CheckResults {
		if c.Status != "healthy" && c.Status != "pass" {
			hasFailures = true
			break
		}
	}
	
	if hasFailures {
		t.Health.Status = TargetStatusUnhealthy
		t.Status = TargetStatusUnhealthy
	} else {
		t.Health.Status = TargetStatusHealthy
		t.Status = TargetStatusHealthy
	}
}

// MatchesFilter checks if the target matches a given filter
func (t *Target) MatchesFilter(filter TargetFilter) bool {
	value := t.getFieldValue(filter.Field)
	
	switch filter.Operator {
	case "eq":
		return fmt.Sprintf("%v", value) == fmt.Sprintf("%v", filter.Value)
	case "ne":
		return fmt.Sprintf("%v", value) != fmt.Sprintf("%v", filter.Value)
	case "in":
		strValue := fmt.Sprintf("%v", value)
		for _, v := range filter.Values {
			if strValue == v {
				return true
			}
		}
		return false
	case "not_in":
		strValue := fmt.Sprintf("%v", value)
		for _, v := range filter.Values {
			if strValue == v {
				return false
			}
		}
		return true
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", value), fmt.Sprintf("%v", filter.Value))
	case "starts_with":
		return strings.HasPrefix(fmt.Sprintf("%v", value), fmt.Sprintf("%v", filter.Value))
	case "ends_with":
		return strings.HasSuffix(fmt.Sprintf("%v", value), fmt.Sprintf("%v", filter.Value))
	default:
		return false
	}
}

// getFieldValue gets the value of a field by name
func (t *Target) getFieldValue(field string) interface{} {
	switch field {
	case "id":
		return t.ID
	case "name":
		return t.Name
	case "type":
		return string(t.Type)
	case "provider":
		return t.Provider
	case "region":
		return t.Region
	case "resource_id":
		return t.ResourceID
	case "status":
		return string(t.Status)
	default:
		// Check labels
		if strings.HasPrefix(field, "label.") {
			labelKey := strings.TrimPrefix(field, "label.")
			return t.Labels[labelKey]
		}
		// Check tags
		if strings.HasPrefix(field, "tag.") {
			tagKey := strings.TrimPrefix(field, "tag.")
			return t.Tags[tagKey]
		}
		return nil
	}
}