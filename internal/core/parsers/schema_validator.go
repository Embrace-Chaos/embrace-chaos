package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/embrace-chaos/internal/core/errors"
)

// SchemaValidator validates experiment YAML against predefined schemas
type SchemaValidator struct {
	experimentSchema *ExperimentSchema
	templateSchema   *TemplateSchema
}

// NewSchemaValidator creates a new schema validator
func NewSchemaValidator() *SchemaValidator {
	return &SchemaValidator{
		experimentSchema: newExperimentSchema(),
		templateSchema:   newTemplateSchema(),
	}
}

// ValidateExperiment validates a raw experiment against the schema
func (v *SchemaValidator) ValidateExperiment(ctx context.Context, experiment *RawExperiment) error {
	// Validate required fields
	if err := v.validateRequiredFields(experiment); err != nil {
		return err
	}

	// Validate API version
	if err := v.validateAPIVersion(experiment.APIVersion); err != nil {
		return err
	}

	// Validate kind
	if err := v.validateKind(experiment.Kind); err != nil {
		return err
	}

	// Validate name format
	if err := v.validateName(experiment.Name); err != nil {
		return err
	}

	// Validate configuration
	if err := v.validateConfig(&experiment.Config); err != nil {
		return err
	}

	// Validate safety configuration
	if err := v.validateSafety(&experiment.Safety); err != nil {
		return err
	}

	// Validate targets
	if err := v.validateTargets(experiment.Targets); err != nil {
		return err
	}

	// Validate steps
	if err := v.validateSteps(experiment.Steps); err != nil {
		return err
	}

	// Validate labels
	if err := v.validateLabels(experiment.Labels); err != nil {
		return err
	}

	return nil
}

// ValidateTemplate validates a template against the schema
func (v *SchemaValidator) ValidateTemplate(ctx context.Context, template *ExperimentTemplate) error {
	// Convert template to raw experiment format for validation
	rawExperiment := &RawExperiment{
		APIVersion:  "chaos.embrace.io/v1",
		Kind:        "ExperimentTemplate",
		Name:        template.Name,
		Description: template.Description,
		Labels:      template.Labels,
		Config:      template.Config,
		Safety:      template.Safety,
		Targets:     template.Targets,
		Steps:       template.Steps,
		Variables:   template.Variables,
	}

	return v.ValidateExperiment(ctx, rawExperiment)
}

// GenerateJSONSchema generates JSON Schema for IDE support
func (v *SchemaValidator) GenerateJSONSchema(ctx context.Context) (string, error) {
	schema := map[string]interface{}{
		"$schema":     "http://json-schema.org/draft-07/schema#",
		"title":       "Chaos Experiment",
		"description": "Schema for Embrace Chaos experiment definitions",
		"type":        "object",
		"required":    []string{"apiVersion", "kind", "name", "config", "safety", "targets"},
		"properties": map[string]interface{}{
			"apiVersion": map[string]interface{}{
				"type":        "string",
				"pattern":     "^chaos\\.embrace\\.io/v[0-9]+$",
				"description": "API version for the experiment",
			},
			"kind": map[string]interface{}{
				"type": "string",
				"enum": []string{"Experiment", "ExperimentTemplate"},
				"description": "Kind of the resource",
			},
			"name": map[string]interface{}{
				"type":        "string",
				"pattern":     "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
				"maxLength":   63,
				"description": "Name of the experiment",
			},
			"description": map[string]interface{}{
				"type":        "string",
				"maxLength":   1000,
				"description": "Description of the experiment",
			},
			"labels": map[string]interface{}{
				"type": "object",
				"patternProperties": map[string]interface{}{
					"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$": map[string]interface{}{
						"type":      "string",
						"maxLength": 63,
					},
				},
				"additionalProperties": false,
				"description":          "Labels for the experiment",
			},
			"extends": map[string]interface{}{
				"type":        "string",
				"description": "Template to extend from",
			},
			"config":    v.generateConfigSchema(),
			"safety":    v.generateSafetySchema(),
			"targets":   v.generateTargetsSchema(),
			"steps":     v.generateStepsSchema(),
			"variables": v.generateVariablesSchema(),
		},
		"additionalProperties": false,
	}

	jsonBytes, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return "", errors.NewValidationError("failed to generate JSON schema: %w", err)
	}

	return string(jsonBytes), nil
}

// Private validation methods

func (v *SchemaValidator) validateRequiredFields(experiment *RawExperiment) error {
	if experiment.APIVersion == "" {
		return errors.NewValidationError("apiVersion is required")
	}
	if experiment.Kind == "" {
		return errors.NewValidationError("kind is required")
	}
	if experiment.Name == "" {
		return errors.NewValidationError("name is required")
	}
	if len(experiment.Targets) == 0 {
		return errors.NewValidationError("at least one target is required")
	}
	return nil
}

func (v *SchemaValidator) validateAPIVersion(apiVersion string) error {
	pattern := regexp.MustCompile(`^chaos\.embrace\.io/v[0-9]+$`)
	if !pattern.MatchString(apiVersion) {
		return errors.NewValidationError("invalid apiVersion format: %s", apiVersion)
	}
	return nil
}

func (v *SchemaValidator) validateKind(kind string) error {
	validKinds := []string{"Experiment", "ExperimentTemplate"}
	for _, validKind := range validKinds {
		if kind == validKind {
			return nil
		}
	}
	return errors.NewValidationError("invalid kind: %s, must be one of %v", kind, validKinds)
}

func (v *SchemaValidator) validateName(name string) error {
	if len(name) > 63 {
		return errors.NewValidationError("name too long: %d characters, maximum 63", len(name))
	}

	pattern := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	if !pattern.MatchString(name) {
		return errors.NewValidationError("invalid name format: %s", name)
	}

	return nil
}

func (v *SchemaValidator) validateConfig(config *RawConfig) error {
	// Validate duration format
	if config.Duration == "" {
		return errors.NewValidationError("config.duration is required")
	}
	if err := v.validateDurationFormat(config.Duration); err != nil {
		return errors.NewValidationError("invalid config.duration: %w", err)
	}

	// Validate parallelism
	if config.Parallelism < 1 {
		return errors.NewValidationError("config.parallelism must be at least 1")
	}
	if config.Parallelism > 100 {
		return errors.NewValidationError("config.parallelism cannot exceed 100")
	}

	// Validate concurrency mode
	validModes := []string{"sequential", "parallel", "pipeline"}
	if config.ConcurrencyMode != "" {
		found := false
		for _, mode := range validModes {
			if config.ConcurrencyMode == mode {
				found = true
				break
			}
		}
		if !found {
			return errors.NewValidationError("invalid config.concurrencyMode: %s", config.ConcurrencyMode)
		}
	}

	// Validate retry policy
	if err := v.validateRetryPolicy(&config.RetryPolicy); err != nil {
		return err
	}

	return nil
}

func (v *SchemaValidator) validateRetryPolicy(policy *RawRetryPolicy) error {
	if policy.MaxRetries < 0 {
		return errors.NewValidationError("retryPolicy.maxRetries cannot be negative")
	}
	if policy.MaxRetries > 10 {
		return errors.NewValidationError("retryPolicy.maxRetries cannot exceed 10")
	}

	validStrategies := []string{"fixed", "exponential", "linear"}
	if policy.BackoffStrategy != "" {
		found := false
		for _, strategy := range validStrategies {
			if policy.BackoffStrategy == strategy {
				found = true
				break
			}
		}
		if !found {
			return errors.NewValidationError("invalid retryPolicy.backoffStrategy: %s", policy.BackoffStrategy)
		}
	}

	if policy.InitialDelayMs < 0 {
		return errors.NewValidationError("retryPolicy.initialDelayMs cannot be negative")
	}
	if policy.MaxDelayMs < policy.InitialDelayMs {
		return errors.NewValidationError("retryPolicy.maxDelayMs must be >= initialDelayMs")
	}

	return nil
}

func (v *SchemaValidator) validateSafety(safety *RawSafety) error {
	if safety.MaxFailures < 0 {
		return errors.NewValidationError("safety.maxFailures cannot be negative")
	}

	if safety.FailureThreshold < 0 || safety.FailureThreshold > 100 {
		return errors.NewValidationError("safety.failureThreshold must be between 0 and 100")
	}

	if safety.RollbackTimeoutMs < 0 {
		return errors.NewValidationError("safety.rollbackTimeoutMs cannot be negative")
	}

	if safety.MonitoringPeriodMs < 1000 {
		return errors.NewValidationError("safety.monitoringPeriodMs must be at least 1000ms")
	}

	// Validate alert thresholds
	for key, value := range safety.AlertThresholds {
		if value < 0 || value > 100 {
			return errors.NewValidationError("safety.alertThresholds.%s must be between 0 and 100", key)
		}
	}

	return nil
}

func (v *SchemaValidator) validateTargets(targets []RawTarget) error {
	if len(targets) == 0 {
		return errors.NewValidationError("at least one target is required")
	}

	targetNames := make(map[string]bool)
	for i, target := range targets {
		// Validate target name uniqueness
		if targetNames[target.Name] {
			return errors.NewValidationError("duplicate target name: %s", target.Name)
		}
		targetNames[target.Name] = true

		// Validate target fields
		if err := v.validateTarget(&target, i); err != nil {
			return err
		}
	}

	return nil
}

func (v *SchemaValidator) validateTarget(target *RawTarget, index int) error {
	if target.Name == "" {
		return errors.NewValidationError("targets[%d].name is required", index)
	}
	if target.Type == "" {
		return errors.NewValidationError("targets[%d].type is required", index)
	}
	if target.Provider == "" {
		return errors.NewValidationError("targets[%d].provider is required", index)
	}

	// Validate target type
	validTypes := []string{
		"ec2_instance", "ecs_service", "rds_instance", "lambda_function",
		"gce_instance", "cloudsql_instance", "gke_node",
	}
	found := false
	for _, validType := range validTypes {
		if target.Type == validType {
			found = true
			break
		}
	}
	if !found {
		return errors.NewValidationError("targets[%d].type invalid: %s", index, target.Type)
	}

	// Validate provider
	validProviders := []string{"aws", "gcp", "azure", "kubernetes"}
	found = false
	for _, validProvider := range validProviders {
		if target.Provider == validProvider {
			found = true
			break
		}
	}
	if !found {
		return errors.NewValidationError("targets[%d].provider invalid: %s", index, target.Provider)
	}

	// Validate actions
	if len(target.Actions) == 0 {
		return errors.NewValidationError("targets[%d].actions cannot be empty", index)
	}

	for j, action := range target.Actions {
		if err := v.validateAction(&action, index, j); err != nil {
			return err
		}
	}

	return nil
}

func (v *SchemaValidator) validateAction(action *RawAction, targetIndex, actionIndex int) error {
	if action.Name == "" {
		return errors.NewValidationError("targets[%d].actions[%d].name is required", targetIndex, actionIndex)
	}
	if action.Type == "" {
		return errors.NewValidationError("targets[%d].actions[%d].type is required", targetIndex, actionIndex)
	}

	// Validate duration format if provided
	if action.Duration != "" {
		if err := v.validateDurationFormat(action.Duration); err != nil {
			return errors.NewValidationError("targets[%d].actions[%d].duration invalid: %w", targetIndex, actionIndex, err)
		}
	}

	return nil
}

func (v *SchemaValidator) validateSteps(steps []RawStep) error {
	stepNames := make(map[string]bool)
	for i, step := range steps {
		// Validate step name uniqueness
		if stepNames[step.Name] {
			return errors.NewValidationError("duplicate step name: %s", step.Name)
		}
		stepNames[step.Name] = true

		// Validate step fields
		if err := v.validateStep(&step, i); err != nil {
			return err
		}
	}

	// Validate step dependencies
	for i, step := range steps {
		for _, dep := range step.DependsOn {
			if !stepNames[dep] {
				return errors.NewValidationError("steps[%d].dependsOn references unknown step: %s", i, dep)
			}
		}
	}

	return nil
}

func (v *SchemaValidator) validateStep(step *RawStep, index int) error {
	if step.Name == "" {
		return errors.NewValidationError("steps[%d].name is required", index)
	}
	if step.Type == "" {
		return errors.NewValidationError("steps[%d].type is required", index)
	}

	// Validate timeout format if provided
	if step.Timeout != "" {
		if err := v.validateDurationFormat(step.Timeout); err != nil {
			return errors.NewValidationError("steps[%d].timeout invalid: %w", index, err)
		}
	}

	return nil
}

func (v *SchemaValidator) validateLabels(labels map[string]string) error {
	for key, value := range labels {
		// Validate key format
		pattern := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
		if !pattern.MatchString(key) {
			return errors.NewValidationError("invalid label key format: %s", key)
		}
		if len(key) > 63 {
			return errors.NewValidationError("label key too long: %s", key)
		}

		// Validate value length
		if len(value) > 63 {
			return errors.NewValidationError("label value too long for key %s", key)
		}
	}
	return nil
}

func (v *SchemaValidator) validateDurationFormat(duration string) error {
	// Support formats like: 30s, 5m, 1h, 2m30s
	pattern := regexp.MustCompile(`^(\d+[smhd])+$`)
	if !pattern.MatchString(duration) {
		return errors.NewValidationError("invalid duration format: %s", duration)
	}
	return nil
}

// Schema generation methods for JSON Schema

func (v *SchemaValidator) generateConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"type":     "object",
		"required": []string{"duration", "parallelism"},
		"properties": map[string]interface{}{
			"duration": map[string]interface{}{
				"type":        "string",
				"pattern":     `^(\d+[smhd])+$`,
				"description": "Duration of the experiment (e.g., 30s, 5m, 1h)",
			},
			"parallelism": map[string]interface{}{
				"type":        "integer",
				"minimum":     1,
				"maximum":     100,
				"description": "Number of parallel executions",
			},
			"concurrencyMode": map[string]interface{}{
				"type":        "string",
				"enum":        []string{"sequential", "parallel", "pipeline"},
				"description": "How to execute multiple targets",
			},
			"retryPolicy": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"maxRetries": map[string]interface{}{
						"type":    "integer",
						"minimum": 0,
						"maximum": 10,
					},
					"backoffStrategy": map[string]interface{}{
						"type": "string",
						"enum": []string{"fixed", "exponential", "linear"},
					},
					"initialDelayMs": map[string]interface{}{
						"type":    "integer",
						"minimum": 0,
					},
					"maxDelayMs": map[string]interface{}{
						"type":    "integer",
						"minimum": 0,
					},
				},
			},
		},
	}
}

func (v *SchemaValidator) generateSafetySchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"maxFailures": map[string]interface{}{
				"type":    "integer",
				"minimum": 0,
			},
			"failureThreshold": map[string]interface{}{
				"type":    "number",
				"minimum": 0,
				"maximum": 100,
			},
			"autoRollback": map[string]interface{}{
				"type": "boolean",
			},
			"rollbackTimeoutMs": map[string]interface{}{
				"type":    "integer",
				"minimum": 0,
			},
			"preflightChecks": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "string",
				},
			},
			"healthChecks": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "string",
				},
			},
			"monitoringPeriodMs": map[string]interface{}{
				"type":    "integer",
				"minimum": 1000,
			},
			"alertThresholds": map[string]interface{}{
				"type": "object",
				"patternProperties": map[string]interface{}{
					".*": map[string]interface{}{
						"type":    "number",
						"minimum": 0,
						"maximum": 100,
					},
				},
			},
		},
	}
}

func (v *SchemaValidator) generateTargetsSchema() map[string]interface{} {
	return map[string]interface{}{
		"type":     "array",
		"minItems": 1,
		"items": map[string]interface{}{
			"type":     "object",
			"required": []string{"name", "type", "provider", "actions"},
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type": "string",
				},
				"type": map[string]interface{}{
					"type": "string",
					"enum": []string{
						"ec2_instance", "ecs_service", "rds_instance", "lambda_function",
						"gce_instance", "cloudsql_instance", "gke_node",
					},
				},
				"provider": map[string]interface{}{
					"type": "string",
					"enum": []string{"aws", "gcp", "azure", "kubernetes"},
				},
				"region": map[string]interface{}{
					"type": "string",
				},
				"resourceId": map[string]interface{}{
					"type": "string",
				},
				"selector": map[string]interface{}{
					"type": "object",
				},
				"tags": map[string]interface{}{
					"type": "object",
					"patternProperties": map[string]interface{}{
						".*": map[string]interface{}{
							"type": "string",
						},
					},
				},
				"actions": map[string]interface{}{
					"type":     "array",
					"minItems": 1,
					"items": map[string]interface{}{
						"type":     "object",
						"required": []string{"name", "type"},
						"properties": map[string]interface{}{
							"name": map[string]interface{}{
								"type": "string",
							},
							"type": map[string]interface{}{
								"type": "string",
							},
							"parameters": map[string]interface{}{
								"type": "object",
							},
							"duration": map[string]interface{}{
								"type":    "string",
								"pattern": `^(\d+[smhd])+$`,
							},
							"dryRun": map[string]interface{}{
								"type": "boolean",
							},
						},
					},
				},
			},
		},
	}
}

func (v *SchemaValidator) generateStepsSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "array",
		"items": map[string]interface{}{
			"type":     "object",
			"required": []string{"name", "type"},
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type": "string",
				},
				"type": map[string]interface{}{
					"type": "string",
				},
				"parameters": map[string]interface{}{
					"type": "object",
				},
				"dependsOn": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "string",
					},
				},
				"timeout": map[string]interface{}{
					"type":    "string",
					"pattern": `^(\d+[smhd])+$`,
				},
			},
		},
	}
}

func (v *SchemaValidator) generateVariablesSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"description": "Variables for template substitution",
	}
}

// Schema definitions
type ExperimentSchema struct {
	// Schema definition would be here
}

type TemplateSchema struct {
	// Template schema definition would be here
}

func newExperimentSchema() *ExperimentSchema {
	return &ExperimentSchema{}
}

func newTemplateSchema() *TemplateSchema {
	return &TemplateSchema{}
}