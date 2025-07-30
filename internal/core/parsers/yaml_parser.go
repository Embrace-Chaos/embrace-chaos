package parsers

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// YAMLParser handles parsing and validation of chaos experiment YAML files
type YAMLParser struct {
	validator      *SchemaValidator
	variableEngine *VariableEngine
	templates      map[string]*ExperimentTemplate
}

// NewYAMLParser creates a new YAML parser with schema validation
func NewYAMLParser() *YAMLParser {
	return &YAMLParser{
		validator:      NewSchemaValidator(),
		variableEngine: NewVariableEngine(),
		templates:      make(map[string]*ExperimentTemplate),
	}
}

// ParseExperiment parses a YAML experiment definition into a domain.Experiment
func (p *YAMLParser) ParseExperiment(ctx context.Context, yamlContent string, variables map[string]interface{}) (*domain.Experiment, error) {
	// Step 1: Validate YAML syntax
	if err := p.validateYAMLSyntax(yamlContent); err != nil {
		return nil, errors.NewValidationError("invalid YAML syntax: %w", err)
	}

	// Step 2: Substitute variables
	processedContent, err := p.variableEngine.SubstituteVariables(ctx, yamlContent, variables)
	if err != nil {
		return nil, errors.NewValidationError("variable substitution failed: %w", err)
	}

	// Step 3: Parse YAML into intermediate structure
	var rawExperiment RawExperiment
	if err := yaml.Unmarshal([]byte(processedContent), &rawExperiment); err != nil {
		return nil, errors.NewValidationError("failed to parse YAML: %w", err)
	}

	// Step 4: Validate against schema
	if err := p.validator.ValidateExperiment(ctx, &rawExperiment); err != nil {
		return nil, errors.NewValidationError("schema validation failed: %w", err)
	}

	// Step 5: Handle experiment inheritance
	if rawExperiment.Extends != "" {
		if err := p.processInheritance(ctx, &rawExperiment); err != nil {
			return nil, errors.NewValidationError("inheritance processing failed: %w", err)
		}
	}

	// Step 6: Convert to domain model
	experiment, err := p.convertToDomainModel(ctx, &rawExperiment)
	if err != nil {
		return nil, errors.NewValidationError("domain model conversion failed: %w", err)
	}

	return experiment, nil
}

// ParseTemplate parses a YAML template for reuse
func (p *YAMLParser) ParseTemplate(ctx context.Context, templateName string, yamlContent string) error {
	var template ExperimentTemplate
	if err := yaml.Unmarshal([]byte(yamlContent), &template); err != nil {
		return errors.NewValidationError("failed to parse template %s: %w", templateName, err)
	}

	// Validate template structure
	if err := p.validator.ValidateTemplate(ctx, &template); err != nil {
		return errors.NewValidationError("template validation failed: %w", err)
	}

	p.templates[templateName] = &template
	return nil
}

// ValidateSchema validates YAML content against the experiment schema
func (p *YAMLParser) ValidateSchema(ctx context.Context, yamlContent string) error {
	var rawExperiment RawExperiment
	if err := yaml.Unmarshal([]byte(yamlContent), &rawExperiment); err != nil {
		return errors.NewValidationError("failed to parse YAML for validation: %w", err)
	}

	return p.validator.ValidateExperiment(ctx, &rawExperiment)
}

// GenerateSchema generates JSON Schema for IDE support
func (p *YAMLParser) GenerateSchema(ctx context.Context) (string, error) {
	return p.validator.GenerateJSONSchema(ctx)
}

// Private methods

func (p *YAMLParser) validateYAMLSyntax(yamlContent string) error {
	var temp interface{}
	return yaml.Unmarshal([]byte(yamlContent), &temp)
}

func (p *YAMLParser) processInheritance(ctx context.Context, experiment *RawExperiment) error {
	template, exists := p.templates[experiment.Extends]
	if !exists {
		return errors.NewValidationError("template '%s' not found", experiment.Extends)
	}

	// Merge template with experiment (experiment overrides template)
	if err := p.mergeTemplate(experiment, template); err != nil {
		return errors.NewValidationError("failed to merge template: %w", err)
	}

	return nil
}

func (p *YAMLParser) mergeTemplate(experiment *RawExperiment, template *ExperimentTemplate) error {
	// Merge metadata
	if experiment.Name == "" {
		experiment.Name = template.Name
	}
	if experiment.Description == "" {
		experiment.Description = template.Description
	}

	// Merge labels
	if experiment.Labels == nil {
		experiment.Labels = make(map[string]string)
	}
	for key, value := range template.Labels {
		if _, exists := experiment.Labels[key]; !exists {
			experiment.Labels[key] = value
		}
	}

	// Merge configuration
	if experiment.Config.Duration == "" && template.Config.Duration != "" {
		experiment.Config.Duration = template.Config.Duration
	}
	if experiment.Config.Parallelism == 0 && template.Config.Parallelism > 0 {
		experiment.Config.Parallelism = template.Config.Parallelism
	}

	// Merge safety configuration
	if experiment.Safety.MaxFailures == 0 && template.Safety.MaxFailures > 0 {
		experiment.Safety.MaxFailures = template.Safety.MaxFailures
	}

	// Merge targets if none specified
	if len(experiment.Targets) == 0 {
		experiment.Targets = template.Targets
	}

	// Merge steps if none specified
	if len(experiment.Steps) == 0 {
		experiment.Steps = template.Steps
	}

	return nil
}

func (p *YAMLParser) convertToDomainModel(ctx context.Context, raw *RawExperiment) (*domain.Experiment, error) {
	// Generate experiment ID
	experimentID := domain.ExperimentID(fmt.Sprintf("exp-%d", time.Now().Unix()))

	// Parse duration
	duration, err := domain.ParseDuration(raw.Config.Duration)
	if err != nil {
		return nil, errors.NewValidationError("invalid duration format: %w", err)
	}

	// Convert targets
	targets := make([]domain.Target, 0, len(raw.Targets))
	for _, rawTarget := range raw.Targets {
		target, err := p.convertTarget(ctx, &rawTarget)
		if err != nil {
			return nil, errors.NewValidationError("failed to convert target: %w", err)
		}
		targets = append(targets, *target)
	}

	// Convert experiment configuration
	config := domain.ExperimentConfig{
		Duration:        duration,
		Parallelism:     raw.Config.Parallelism,
		ConcurrencyMode: domain.ConcurrencyMode(raw.Config.ConcurrencyMode),
		Timeout:         duration, // Use same duration for timeout initially
		RetryPolicy: domain.RetryPolicy{
			MaxRetries: raw.Config.RetryPolicy.MaxRetries,
			BackoffStrategy: domain.BackoffStrategy(raw.Config.RetryPolicy.BackoffStrategy),
			InitialDelay: domain.Duration(time.Duration(raw.Config.RetryPolicy.InitialDelayMs) * time.Millisecond),
			MaxDelay:     domain.Duration(time.Duration(raw.Config.RetryPolicy.MaxDelayMs) * time.Millisecond),
		},
	}

	// Convert safety configuration
	safetyConfig := domain.SafetyConfig{
		MaxFailures:          raw.Safety.MaxFailures,
		FailureThreshold:     domain.Percentage(raw.Safety.FailureThreshold),
		AutoRollback:         raw.Safety.AutoRollback,
		RollbackTimeout:      domain.Duration(time.Duration(raw.Safety.RollbackTimeoutMs) * time.Millisecond),
		PreflightChecks:      raw.Safety.PreflightChecks,
		HealthChecks:         raw.Safety.HealthChecks,
		MonitoringPeriod:     domain.Duration(time.Duration(raw.Safety.MonitoringPeriodMs) * time.Millisecond),
		AlertThresholds:      p.convertAlertThresholds(raw.Safety.AlertThresholds),
	}

	// Create the experiment
	experiment := &domain.Experiment{
		ID:          experimentID,
		Name:        raw.Name,
		Description: raw.Description,
		Status:      domain.ExperimentStatusDraft,
		Config:      config,
		Targets:     targets,
		Safety:      safetyConfig,
		Labels:      raw.Labels,
		Metadata: map[string]interface{}{
			"parsed_at":      time.Now(),
			"parser_version": "1.0.0",
			"original_yaml":  raw.OriginalYAML,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Version:   1,
	}

	return experiment, nil
}

func (p *YAMLParser) convertTarget(ctx context.Context, raw *RawTarget) (*domain.Target, error) {
	// Generate target ID
	targetID := fmt.Sprintf("%s-%s-%s", raw.Provider, raw.Type, raw.Name)

	// Convert target type
	targetType, err := p.parseTargetType(raw.Type)
	if err != nil {
		return nil, errors.NewValidationError("invalid target type: %w", err)
	}

	target := &domain.Target{
		ID:         targetID,
		ResourceID: raw.ResourceID,
		Name:       raw.Name,
		Type:       targetType,
		Provider:   raw.Provider,
		Region:     raw.Region,
		Tags:       raw.Tags,
		Status:     domain.TargetStatusActive,
		Metadata: map[string]interface{}{
			"selector":    raw.Selector,
			"actions":     raw.Actions,
			"constraints": raw.Constraints,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return target, nil
}

func (p *YAMLParser) parseTargetType(typeStr string) (domain.TargetType, error) {
	switch strings.ToLower(typeStr) {
	case "ec2_instance":
		return domain.TargetTypeEC2Instance, nil
	case "ecs_service":
		return domain.TargetTypeECSService, nil
	case "rds_instance":
		return domain.TargetTypeRDSInstance, nil
	case "lambda_function":
		return domain.TargetTypeLambdaFunction, nil
	case "gce_instance":
		return domain.TargetTypeGCEInstance, nil
	case "cloudsql_instance":
		return domain.TargetTypeCloudSQLInstance, nil
	case "gke_node":
		return domain.TargetTypeGKENode, nil
	default:
		return "", errors.NewValidationError("unsupported target type: %s", typeStr)
	}
}

func (p *YAMLParser) convertAlertThresholds(raw map[string]float64) map[string]domain.Percentage {
	thresholds := make(map[string]domain.Percentage)
	for key, value := range raw {
		thresholds[key] = domain.Percentage(value)
	}
	return thresholds
}

// RawExperiment represents the raw YAML structure before domain conversion
type RawExperiment struct {
	APIVersion  string            `yaml:"apiVersion"`
	Kind        string            `yaml:"kind"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Extends     string            `yaml:"extends,omitempty"`
	Config      RawConfig         `yaml:"config"`
	Safety      RawSafety         `yaml:"safety"`
	Targets     []RawTarget       `yaml:"targets"`
	Steps       []RawStep         `yaml:"steps"`
	Variables   map[string]interface{} `yaml:"variables,omitempty"`
	OriginalYAML string           `yaml:"-"` // Store original for metadata
}

type RawConfig struct {
	Duration        string        `yaml:"duration"`
	Parallelism     int           `yaml:"parallelism"`
	ConcurrencyMode string        `yaml:"concurrencyMode"`
	RetryPolicy     RawRetryPolicy `yaml:"retryPolicy"`
}

type RawRetryPolicy struct {
	MaxRetries       int    `yaml:"maxRetries"`
	BackoffStrategy  string `yaml:"backoffStrategy"`
	InitialDelayMs   int    `yaml:"initialDelayMs"`
	MaxDelayMs       int    `yaml:"maxDelayMs"`
}

type RawSafety struct {
	MaxFailures          int                    `yaml:"maxFailures"`
	FailureThreshold     float64                `yaml:"failureThreshold"`
	AutoRollback         bool                   `yaml:"autoRollback"`
	RollbackTimeoutMs    int                    `yaml:"rollbackTimeoutMs"`
	PreflightChecks      []string               `yaml:"preflightChecks"`
	HealthChecks         []string               `yaml:"healthChecks"`
	MonitoringPeriodMs   int                    `yaml:"monitoringPeriodMs"`
	AlertThresholds      map[string]float64     `yaml:"alertThresholds"`
}

type RawTarget struct {
	Name        string                 `yaml:"name"`
	Type        string                 `yaml:"type"`
	Provider    string                 `yaml:"provider"`
	Region      string                 `yaml:"region"`
	ResourceID  string                 `yaml:"resourceId,omitempty"`
	Selector    map[string]interface{} `yaml:"selector,omitempty"`
	Tags        map[string]string      `yaml:"tags,omitempty"`
	Actions     []RawAction            `yaml:"actions"`
	Constraints map[string]interface{} `yaml:"constraints,omitempty"`
}

type RawAction struct {
	Name       string                 `yaml:"name"`
	Type       string                 `yaml:"type"`
	Parameters map[string]interface{} `yaml:"parameters,omitempty"`
	Duration   string                 `yaml:"duration,omitempty"`
	DryRun     bool                   `yaml:"dryRun,omitempty"`
	Conditions []RawCondition         `yaml:"conditions,omitempty"`
}

type RawCondition struct {
	Type       string                 `yaml:"type"`
	Expression string                 `yaml:"expression"`
	Parameters map[string]interface{} `yaml:"parameters,omitempty"`
}

type RawStep struct {
	Name        string                 `yaml:"name"`
	Type        string                 `yaml:"type"`
	Parameters  map[string]interface{} `yaml:"parameters,omitempty"`
	DependsOn   []string               `yaml:"dependsOn,omitempty"`
	Timeout     string                 `yaml:"timeout,omitempty"`
	Conditions  []RawCondition         `yaml:"conditions,omitempty"`
}

// ExperimentTemplate represents a reusable experiment template
type ExperimentTemplate struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Config      RawConfig         `yaml:"config"`
	Safety      RawSafety         `yaml:"safety"`
	Targets     []RawTarget       `yaml:"targets"`
	Steps       []RawStep         `yaml:"steps"`
	Variables   map[string]interface{} `yaml:"variables,omitempty"`
}