package ports

import (
	"context"

	"github.com/embrace-chaos/internal/core/domain"
)

// ValidationService defines the primary port for validation operations
type ValidationService interface {
	// Experiment validation
	ValidateExperiment(ctx context.Context, experiment *domain.Experiment) (*ValidationResult, error)
	ValidateExperimentConfig(ctx context.Context, config domain.ExperimentConfig) (*ValidationResult, error)
	ValidateExperimentTargets(ctx context.Context, targets []domain.Target) (*ValidationResult, error)
	ValidateExperimentSafety(ctx context.Context, safety domain.SafetyConfig) (*ValidationResult, error)
	ValidateExperimentSchedule(ctx context.Context, schedule *domain.Schedule) (*ValidationResult, error)
	
	// Target validation
	ValidateTarget(ctx context.Context, target *domain.Target) (*ValidationResult, error)
	ValidateTargetSelector(ctx context.Context, selector domain.TargetSelector) (*ValidationResult, error)
	ValidateTargetFilters(ctx context.Context, filters []domain.TargetFilter) (*ValidationResult, error)
	ValidateTargetHealth(ctx context.Context, target *domain.Target) (*TargetHealthValidation, error)
	
	// Provider validation
	ValidateProvider(ctx context.Context, provider domain.Provider) (*ValidationResult, error)
	ValidateProviderConfig(ctx context.Context, config domain.ProviderConfig) (*ValidationResult, error)
	ValidateProviderCapabilities(ctx context.Context, provider domain.Provider, requirements CapabilityRequirements) (*ValidationResult, error)
	
	// Execution validation
	ValidateExecutionRequest(ctx context.Context, req StartExecutionRequest) (*ValidationResult, error)
	ValidateExecutionConfig(ctx context.Context, config domain.ExecutionConfig) (*ValidationResult, error)
	ValidateExecutionPrerequisites(ctx context.Context, execution *domain.Execution) (*PrerequisiteValidation, error)
	
	// Cross-cutting validation
	ValidateBusinessRules(ctx context.Context, req BusinessRuleValidationRequest) (*ValidationResult, error)
	ValidatePermissions(ctx context.Context, req PermissionValidationRequest) (*ValidationResult, error)
	ValidateResourceConstraints(ctx context.Context, req ResourceConstraintValidationRequest) (*ValidationResult, error)
	
	// Batch validation
	ValidateBatch(ctx context.Context, req BatchValidationRequest) (*BatchValidationResponse, error)
	
	// Custom validation
	RegisterValidator(name string, validator CustomValidator) error
	UnregisterValidator(name string) error
	ValidateCustom(ctx context.Context, name string, data interface{}) (*ValidationResult, error)
	
	// Validation rules management
	GetValidationRules(ctx context.Context, entityType string) ([]ValidationRule, error)
	AddValidationRule(ctx context.Context, rule ValidationRule) error
	UpdateValidationRule(ctx context.Context, ruleID string, rule ValidationRule) error
	RemoveValidationRule(ctx context.Context, ruleID string) error
	
	// Validation schemas
	GetValidationSchema(ctx context.Context, schemaType string) (*ValidationSchema, error)
	ValidateAgainstSchema(ctx context.Context, schemaType string, data interface{}) (*ValidationResult, error)
}

// ValidationResult represents the result of a validation operation
type ValidationResult struct {
	Valid       bool                    `json:"valid"`
	Errors      []ValidationError       `json:"errors,omitempty"`
	Warnings    []ValidationWarning     `json:"warnings,omitempty"`
	Suggestions []ValidationSuggestion  `json:"suggestions,omitempty"`
	Score       float64                 `json:"score"`
	Details     map[string]interface{}  `json:"details,omitempty"`
	ValidatedAt string                  `json:"validated_at"`
	Duration    domain.Duration         `json:"duration"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Code        string                 `json:"code"`
	Message     string                 `json:"message"`
	Field       string                 `json:"field,omitempty"`
	Value       interface{}            `json:"value,omitempty"`
	Constraint  string                 `json:"constraint,omitempty"`
	Path        string                 `json:"path,omitempty"`
	Severity    string                 `json:"severity"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Suggestions []string               `json:"suggestions,omitempty"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Code        string                 `json:"code"`
	Message     string                 `json:"message"`
	Field       string                 `json:"field,omitempty"`
	Value       interface{}            `json:"value,omitempty"`
	Reason      string                 `json:"reason"`
	Impact      string                 `json:"impact"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Suggestions []string               `json:"suggestions,omitempty"`
}

// ValidationSuggestion represents a suggestion for improvement
type ValidationSuggestion struct {
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Field       string                 `json:"field,omitempty"`
	Current     interface{}            `json:"current,omitempty"`
	Suggested   interface{}            `json:"suggested,omitempty"`
	Reason      string                 `json:"reason"`
	Impact      string                 `json:"impact"`
	Confidence  float64                `json:"confidence"`
}

// TargetHealthValidation represents target health validation result
type TargetHealthValidation struct {
	TargetID        string                  `json:"target_id"`
	TargetName      string                  `json:"target_name"`
	IsHealthy       bool                    `json:"is_healthy"`
	HealthScore     float64                 `json:"health_score"`
	HealthChecks    []HealthCheckResult     `json:"health_checks"`
	Accessibility   AccessibilityCheck      `json:"accessibility"`
	Prerequisites   []PrerequisiteCheck     `json:"prerequisites"`
	Recommendations []string                `json:"recommendations"`
	LastChecked     string                  `json:"last_checked"`
}

// HealthCheckResult represents the result of a health check
type HealthCheckResult struct {
	Name        string                 `json:"name"`
	Status      string                 `json:"status"`
	Success     bool                   `json:"success"`
	Message     string                 `json:"message"`
	Duration    domain.Duration        `json:"duration"`
	Value       float64                `json:"value,omitempty"`
	Threshold   float64                `json:"threshold,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// AccessibilityCheck represents target accessibility validation
type AccessibilityCheck struct {
	Accessible      bool                   `json:"accessible"`
	NetworkReachable bool                  `json:"network_reachable"`
	AuthenticationValid bool               `json:"authentication_valid"`
	PermissionsSufficient bool             `json:"permissions_sufficient"`
	ServiceAvailable bool                  `json:"service_available"`
	Issues          []AccessibilityIssue   `json:"issues,omitempty"`
	CheckedAt       string                 `json:"checked_at"`
}

// AccessibilityIssue represents an accessibility issue
type AccessibilityIssue struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Resolution  string `json:"resolution,omitempty"`
}

// PrerequisiteCheck represents a prerequisite validation
type PrerequisiteCheck struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Required    bool                   `json:"required"`
	Met         bool                   `json:"met"`
	Details     string                 `json:"details,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// PrerequisiteValidation represents execution prerequisite validation
type PrerequisiteValidation struct {
	Valid               bool                    `json:"valid"`
	AllPrerequisitesMet bool                    `json:"all_prerequisites_met"`
	Prerequisites       []PrerequisiteCheck     `json:"prerequisites"`
	BlockingIssues      []ValidationError       `json:"blocking_issues"`
	Warnings            []ValidationWarning     `json:"warnings"`
	ReadinessScore      float64                 `json:"readiness_score"`
	EstimatedReadyTime  *string                 `json:"estimated_ready_time,omitempty"`
}

// CapabilityRequirements represents required capabilities for validation
type CapabilityRequirements struct {
	SupportedTargetTypes []domain.TargetType    `json:"supported_target_types"`
	RequiredActions      []string               `json:"required_actions"`
	RequiredFeatures     []string               `json:"required_features"`
	MinVersion           *domain.Version        `json:"min_version,omitempty"`
	MaxConcurrentExperiments *int               `json:"max_concurrent_experiments,omitempty"`
	MaxTargetsPerExperiment *int                `json:"max_targets_per_experiment,omitempty"`
	RequiredAuth         []string               `json:"required_auth,omitempty"`
	RequiredRegions      []string               `json:"required_regions,omitempty"`
}

// BusinessRuleValidationRequest represents a business rule validation request
type BusinessRuleValidationRequest struct {
	EntityType  string                 `json:"entity_type"`
	EntityID    string                 `json:"entity_id,omitempty"`
	Action      string                 `json:"action"`
	Data        interface{}            `json:"data"`
	Context     map[string]interface{} `json:"context,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	TenantID    string                 `json:"tenant_id,omitempty"`
}

// PermissionValidationRequest represents a permission validation request
type PermissionValidationRequest struct {
	UserID      string                 `json:"user_id"`
	Action      string                 `json:"action"`
	Resource    string                 `json:"resource"`
	ResourceID  string                 `json:"resource_id,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	TenantID    string                 `json:"tenant_id,omitempty"`
}

// ResourceConstraintValidationRequest represents a resource constraint validation request
type ResourceConstraintValidationRequest struct {
	ResourceType string                 `json:"resource_type"`
	Action       string                 `json:"action"`
	Quantity     int64                  `json:"quantity"`
	Duration     *domain.Duration       `json:"duration,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty"`
	UserID       string                 `json:"user_id,omitempty"`
	TenantID     string                 `json:"tenant_id,omitempty"`
}

// BatchValidationRequest represents a batch validation request
type BatchValidationRequest struct {
	Items       []ValidationItem       `json:"items"`
	FailFast    bool                   `json:"fail_fast"`
	Parallel    bool                   `json:"parallel"`
	MaxWorkers  int                    `json:"max_workers,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// ValidationItem represents an item in a batch validation request
type ValidationItem struct {
	ID          string      `json:"id"`
	Type        string      `json:"type"`
	Data        interface{} `json:"data"`
	Rules       []string    `json:"rules,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// BatchValidationResponse represents the response for batch validation
type BatchValidationResponse struct {
	Valid       bool                           `json:"valid"`
	Results     map[string]*ValidationResult   `json:"results"`
	Summary     BatchValidationSummary         `json:"summary"`
	Errors      []BatchValidationError         `json:"errors,omitempty"`
	Duration    domain.Duration                `json:"duration"`
	ProcessedAt string                         `json:"processed_at"`
}

// BatchValidationSummary represents a summary of batch validation results
type BatchValidationSummary struct {
	TotalItems      int     `json:"total_items"`
	ValidItems      int     `json:"valid_items"`
	InvalidItems    int     `json:"invalid_items"`
	ErrorItems      int     `json:"error_items"`
	SuccessRate     float64 `json:"success_rate"`
	AverageScore    float64 `json:"average_score"`
	TotalErrors     int     `json:"total_errors"`
	TotalWarnings   int     `json:"total_warnings"`
}

// BatchValidationError represents an error in batch validation
type BatchValidationError struct {
	ItemID  string `json:"item_id"`
	Error   string `json:"error"`
	Code    string `json:"code"`
}

// CustomValidator defines the interface for custom validators
type CustomValidator interface {
	Name() string
	Description() string
	Validate(ctx context.Context, data interface{}) (*ValidationResult, error)
	SupportsType(dataType string) bool
}

// ValidationRule represents a validation rule
type ValidationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	EntityType  string                 `json:"entity_type"`
	Field       string                 `json:"field,omitempty"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Enabled     bool                   `json:"enabled"`
	
	// Rule definition
	Condition   RuleCondition          `json:"condition"`
	Message     string                 `json:"message"`
	Suggestions []string               `json:"suggestions,omitempty"`
	
	// Metadata
	Category    string                 `json:"category,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Version     string                 `json:"version"`
	CreatedBy   string                 `json:"created_by"`
	CreatedAt   string                 `json:"created_at"`
	UpdatedAt   string                 `json:"updated_at"`
}

// RuleCondition represents a rule condition
type RuleCondition struct {
	Type        string                 `json:"type"`
	Operator    string                 `json:"operator"`
	Value       interface{}            `json:"value,omitempty"`
	Values      []interface{}          `json:"values,omitempty"`
	Field       string                 `json:"field,omitempty"`
	Expression  string                 `json:"expression,omitempty"`
	Conditions  []RuleCondition        `json:"conditions,omitempty"`
	Logic       string                 `json:"logic,omitempty"` // "and", "or", "not"
}

// ValidationSchema represents a validation schema
type ValidationSchema struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Version     string                 `json:"version"`
	
	// Schema definition
	Schema      interface{}            `json:"schema"`
	Format      string                 `json:"format"` // "json-schema", "yaml-schema", etc.
	
	// Validation options
	StrictMode  bool                   `json:"strict_mode"`
	AllowAdditionalProperties bool     `json:"allow_additional_properties"`
	
	// Metadata
	Category    string                 `json:"category,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	CreatedBy   string                 `json:"created_by"`
	CreatedAt   string                 `json:"created_at"`
	UpdatedAt   string                 `json:"updated_at"`
}

// Validation utilities and helpers

// ValidationBuilder helps build validation results
type ValidationBuilder struct {
	result *ValidationResult
}

// NewValidationBuilder creates a new validation builder
func NewValidationBuilder() *ValidationBuilder {
	return &ValidationBuilder{
		result: &ValidationResult{
			Valid:       true,
			Errors:      make([]ValidationError, 0),
			Warnings:    make([]ValidationWarning, 0),
			Suggestions: make([]ValidationSuggestion, 0),
			Score:       100.0,
			Details:     make(map[string]interface{}),
		},
	}
}

// AddError adds a validation error
func (vb *ValidationBuilder) AddError(code, message, field string) *ValidationBuilder {
	vb.result.Valid = false
	vb.result.Errors = append(vb.result.Errors, ValidationError{
		Code:     code,
		Message:  message,
		Field:    field,
		Severity: "error",
	})
	vb.result.Score = max(0, vb.result.Score-10)
	return vb
}

// AddWarning adds a validation warning
func (vb *ValidationBuilder) AddWarning(code, message, field string) *ValidationBuilder {
	vb.result.Warnings = append(vb.result.Warnings, ValidationWarning{
		Code:    code,
		Message: message,
		Field:   field,
	})
	vb.result.Score = max(0, vb.result.Score-5)
	return vb
}

// AddSuggestion adds a validation suggestion
func (vb *ValidationBuilder) AddSuggestion(title, description string) *ValidationBuilder {
	vb.result.Suggestions = append(vb.result.Suggestions, ValidationSuggestion{
		Type:        "improvement",
		Title:       title,
		Description: description,
		Confidence:  0.8,
	})
	return vb
}

// SetDetail sets a detail field
func (vb *ValidationBuilder) SetDetail(key string, value interface{}) *ValidationBuilder {
	vb.result.Details[key] = value
	return vb
}

// Build returns the validation result
func (vb *ValidationBuilder) Build() *ValidationResult {
	return vb.result
}

// max returns the maximum of two float64 values
func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// Common validation constants
const (
	// Validation types
	ValidationTypeRequired    = "required"
	ValidationTypeFormat      = "format"
	ValidationTypeRange       = "range"
	ValidationTypeLength      = "length"
	ValidationTypePattern     = "pattern"
	ValidationTypeCustom      = "custom"
	ValidationTypeBusinessRule = "business_rule"
	
	// Severity levels
	SeverityError   = "error"
	SeverityWarning = "warning"
	SeverityInfo    = "info"
	
	// Rule operators
	OperatorEquals       = "eq"
	OperatorNotEquals    = "ne"
	OperatorGreaterThan  = "gt"
	OperatorGreaterEqual = "ge"
	OperatorLessThan     = "lt"
	OperatorLessEqual    = "le"
	OperatorContains     = "contains"
	OperatorStartsWith   = "starts_with"
	OperatorEndsWith     = "ends_with"
	OperatorMatches      = "matches"
	OperatorIn           = "in"
	OperatorNotIn        = "not_in"
	OperatorExists       = "exists"
	OperatorNotExists    = "not_exists"
)