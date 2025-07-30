package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// AWSProvider implements the Provider interface for AWS infrastructure
type AWSProvider struct {
	*domain.BaseProvider
	
	// AWS clients
	config    aws.Config
	ec2Client *ec2.Client
	ecsClient *ecs.Client
	rdsClient *rds.Client
	lambdaClient *lambda.Client
	stsClient *sts.Client
	
	// Provider configuration
	providerConfig AWSProviderConfig
	
	// Service handlers
	ec2Handler    *EC2Handler
	ecsHandler    *ECSHandler
	rdsHandler    *RDSHandler
	lambdaHandler *LambdaHandler
	
	// Runtime state
	dryRunMode bool
	regions    []string
	
	// Metrics and monitoring
	startTime    time.Time
	lastActivity time.Time
}

// AWSProviderConfig holds AWS-specific configuration
type AWSProviderConfig struct {
	// Authentication
	Region          string            `json:"region"`
	AssumeRoleArn   string            `json:"assume_role_arn,omitempty"`
	ExternalID      string            `json:"external_id,omitempty"`
	SessionName     string            `json:"session_name,omitempty"`
	
	// Global settings
	DryRunMode       bool             `json:"dry_run_mode"`
	MaxConcurrency   int              `json:"max_concurrency"`
	DefaultTimeout   time.Duration    `json:"default_timeout"`
	EnabledServices  []string         `json:"enabled_services"`
	
	// Retry configuration
	MaxRetries       int              `json:"max_retries"`
	RetryTimeout     time.Duration    `json:"retry_timeout"`
	
	// Safety settings
	SafetyChecks     bool             `json:"safety_checks"`
	RequireTags      []string         `json:"require_tags"`
	ForbiddenTags    []string         `json:"forbidden_tags"`
	AllowedRegions   []string         `json:"allowed_regions"`
	
	// Service-specific configurations
	EC2Config        EC2Config        `json:"ec2_config"`
	ECSConfig        ECSConfig        `json:"ecs_config"`
	RDSConfig        RDSConfig        `json:"rds_config"`
	LambdaConfig     LambdaConfig     `json:"lambda_config"`
}

// Service-specific configurations
type EC2Config struct {
	AllowedInstanceTypes []string          `json:"allowed_instance_types"`
	ForbiddenInstanceTypes []string        `json:"forbidden_instance_types"`
	RequiredTags         map[string]string `json:"required_tags"`
	MaxInstancesPerBatch int               `json:"max_instances_per_batch"`
	StopTimeout          time.Duration     `json:"stop_timeout"`
	StartTimeout         time.Duration     `json:"start_timeout"`
}

type ECSConfig struct {
	AllowedClusterPatterns []string          `json:"allowed_cluster_patterns"`
	ForbiddenClusters      []string          `json:"forbidden_clusters"`
	RequiredTags           map[string]string `json:"required_tags"`
	MaxTasksPerBatch       int               `json:"max_tasks_per_batch"`
	DrainTimeout           time.Duration     `json:"drain_timeout"`
}

type RDSConfig struct {
	AllowedEngines         []string          `json:"allowed_engines"`
	ForbiddenInstances     []string          `json:"forbidden_instances"`
	RequiredTags           map[string]string `json:"required_tags"`
	MaxInstancesPerBatch   int               `json:"max_instances_per_batch"`
	StopTimeout            time.Duration     `json:"stop_timeout"`
	BackupBeforeAction     bool              `json:"backup_before_action"`
}

type LambdaConfig struct {
	AllowedRuntimes        []string          `json:"allowed_runtimes"`
	ForbiddenFunctions     []string          `json:"forbidden_functions"`
	RequiredTags           map[string]string `json:"required_tags"`
	MaxFunctionsPerBatch   int               `json:"max_functions_per_batch"`
	InvocationTimeout      time.Duration     `json:"invocation_timeout"`
}

// NewAWSProvider creates a new AWS provider instance
func NewAWSProvider(providerConfig map[string]interface{}) (domain.Provider, error) {
	// Parse configuration
	config, err := parseAWSConfig(providerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AWS provider config: %w", err)
	}
	
	// Create base provider
	baseProvider := domain.NewBaseProvider("aws", "AWS Chaos Provider", "1.0.0")
	
	provider := &AWSProvider{
		BaseProvider:   baseProvider,
		providerConfig: config,
		dryRunMode:     config.DryRunMode,
		startTime:      time.Now(),
		lastActivity:   time.Now(),
	}
	
	// Initialize AWS configuration
	if err := provider.initializeAWS(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize AWS: %w", err)
	}
	
	// Set provider capabilities
	provider.setCapabilities()
	
	return provider, nil
}

// Initialize AWS SDK and clients
func (p *AWSProvider) initializeAWS(ctx context.Context) error {
	// Load AWS configuration
	cfg, err := p.loadAWSConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	
	p.config = cfg
	
	// Initialize service clients
	p.ec2Client = ec2.NewFromConfig(cfg)
	p.ecsClient = ecs.NewFromConfig(cfg)
	p.rdsClient = rds.NewFromConfig(cfg)
	p.lambdaClient = lambda.NewFromConfig(cfg)
	p.stsClient = sts.NewFromConfig(cfg)
	
	// Initialize service handlers
	p.ec2Handler = NewEC2Handler(p.ec2Client, p.providerConfig.EC2Config)
	p.ecsHandler = NewECSHandler(p.ecsClient, p.providerConfig.ECSConfig)
	p.rdsHandler = NewRDSHandler(p.rdsClient, p.providerConfig.RDSConfig)
	p.lambdaHandler = NewLambdaHandler(p.lambdaClient, p.providerConfig.LambdaConfig)
	
	// Verify AWS credentials and permissions
	if err := p.verifyCredentials(ctx); err != nil {
		return fmt.Errorf("failed to verify AWS credentials: %w", err)
	}
	
	// Discover available regions
	if err := p.discoverRegions(ctx); err != nil {
		return fmt.Errorf("failed to discover regions: %w", err)
	}
	
	return nil
}

// loadAWSConfig loads AWS configuration with optional assume role
func (p *AWSProvider) loadAWSConfig(ctx context.Context) (aws.Config, error) {
	// Load default configuration
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(p.providerConfig.Region),
		config.WithRetryMaxAttempts(p.providerConfig.MaxRetries),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %w", err)
	}
	
	// Configure assume role if specified
	if p.providerConfig.AssumeRoleArn != "" {
		stsClient := sts.NewFromConfig(cfg)
		
		provider := stscreds.NewAssumeRoleProvider(stsClient, p.providerConfig.AssumeRoleArn, func(o *stscreds.AssumeRoleOptions) {
			if p.providerConfig.ExternalID != "" {
				o.ExternalID = aws.String(p.providerConfig.ExternalID)
			}
			if p.providerConfig.SessionName != "" {
				o.RoleSessionName = p.providerConfig.SessionName
			} else {
				o.RoleSessionName = "embrace-chaos-session"
			}
		})
		
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}
	
	return cfg, nil
}

// verifyCredentials verifies AWS credentials and permissions
func (p *AWSProvider) verifyCredentials(ctx context.Context) error {
	// Get caller identity to verify credentials
	result, err := p.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return errors.NewProviderError("aws", "credential_verification", err)
	}
	
	// Store identity information for logging
	p.SetMetric("aws_account_id", *result.Account)
	p.SetMetric("aws_user_id", *result.UserId)
	if result.Arn != nil {
		p.SetMetric("aws_arn", *result.Arn)
	}
	
	return nil
}

// discoverRegions discovers available AWS regions
func (p *AWSProvider) discoverRegions(ctx context.Context) error {
	result, err := p.ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return fmt.Errorf("failed to describe regions: %w", err)
	}
	
	var regions []string
	for _, region := range result.Regions {
		if region.RegionName != nil {
			regions = append(regions, *region.RegionName)
		}
	}
	
	// Filter by allowed regions if configured
	if len(p.providerConfig.AllowedRegions) > 0 {
		var allowedRegions []string
		for _, region := range regions {
			for _, allowed := range p.providerConfig.AllowedRegions {
				if region == allowed {
					allowedRegions = append(allowedRegions, region)
					break
				}
			}
		}
		regions = allowedRegions
	}
	
	p.regions = regions
	return nil
}

// setCapabilities sets the provider capabilities
func (p *AWSProvider) setCapabilities() {
	capabilities := domain.ProviderCapabilities{
		SupportedTargetTypes: []domain.TargetType{
			domain.TargetTypeEC2Instance,
			domain.TargetTypeECSService,
			domain.TargetTypeECSTask,
			domain.TargetTypeRDSInstance,
			domain.TargetTypeLambdaFunction,
		},
		SupportedActions: []domain.ActionCapability{
			{
				Name:        "stop_instances",
				Description: "Stop EC2 instances",
				TargetTypes: []domain.TargetType{domain.TargetTypeEC2Instance},
				Parameters: []domain.ActionParameter{
					{
						Name:        "force",
						Type:        "boolean",
						Required:    false,
						Default:     false,
						Description: "Force stop instances",
					},
				},
				Reversible:  true,
				Destructive: false,
			},
			{
				Name:        "terminate_instances",
				Description: "Terminate EC2 instances",
				TargetTypes: []domain.TargetType{domain.TargetTypeEC2Instance},
				Reversible:  false,
				Destructive: true,
			},
			{
				Name:        "stop_tasks",
				Description: "Stop ECS tasks",
				TargetTypes: []domain.TargetType{domain.TargetTypeECSTask},
				Reversible:  false,
				Destructive: false,
			},
			{
				Name:        "update_service",
				Description: "Update ECS service desired count",
				TargetTypes: []domain.TargetType{domain.TargetTypeECSService},
				Parameters: []domain.ActionParameter{
					{
						Name:        "desired_count",
						Type:        "integer",
						Required:    true,
						Description: "New desired count for the service",
						Validation: domain.Validation{
							Min: aws.Float64(0),
							Max: aws.Float64(1000),
						},
					},
				},
				Reversible: true,
			},
			{
				Name:        "reboot_db_instance",
				Description: "Reboot RDS instance",
				TargetTypes: []domain.TargetType{domain.TargetTypeRDSInstance},
				Parameters: []domain.ActionParameter{
					{
						Name:        "force_failover",
						Type:        "boolean",
						Required:    false,
						Default:     false,
						Description: "Force failover during reboot",
					},
				},
				Reversible: false,
			},
			{
				Name:        "invoke_function",
				Description: "Invoke Lambda function with chaos payload",
				TargetTypes: []domain.TargetType{domain.TargetTypeLambdaFunction},
				Parameters: []domain.ActionParameter{
					{
						Name:        "payload",
						Type:        "object",
						Required:    false,
						Description: "Payload to send to the function",
					},
					{
						Name:        "invocation_type",
						Type:        "string",
						Required:    false,
						Default:     "RequestResponse",
						Description: "Lambda invocation type",
						Validation: domain.Validation{
							Options: []string{"RequestResponse", "Event", "DryRun"},
						},
					},
				},
				Reversible: false,
			},
		},
		SupportsRollback:         true,
		SupportsDryRun:          true,
		SupportsScheduling:      true,
		SupportsTargetDiscovery: true,
		MaxConcurrentExperiments: p.providerConfig.MaxConcurrency,
		MaxTargetsPerExperiment:  100,
		MaxExperimentDuration:    24 * time.Hour,
		AuthMethods:             []string{"iam", "assume_role"},
		SupportedRegions:        p.regions,
	}
	
	// Set capabilities in base provider
	p.BaseProvider.SetCapabilities(capabilities)
}

// Provider interface implementation

// SupportsTarget checks if the provider supports a given target
func (p *AWSProvider) SupportsTarget(target domain.Target) bool {
	// Check if target provider matches
	if target.Provider != "aws" {
		return false
	}
	
	// Check if target type is supported
	capabilities := p.GetCapabilities()
	for _, supportedType := range capabilities.SupportedTargetTypes {
		if target.Type == supportedType {
			return true
		}
	}
	
	return false
}

// SupportedActions returns supported actions for this provider
func (p *AWSProvider) SupportedActions() []string {
	capabilities := p.GetCapabilities()
	actions := make([]string, len(capabilities.SupportedActions))
	for i, action := range capabilities.SupportedActions {
		actions[i] = action.Name
	}
	return actions
}

// HealthCheck performs a health check
func (p *AWSProvider) HealthCheck(ctx context.Context) error {
	// Check AWS connectivity
	_, err := p.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return errors.NewProviderError("aws", "health_check", err)
	}
	
	// Update health status
	p.UpdateStatus("healthy", true)
	p.lastActivity = time.Now()
	
	return nil
}

// ValidateExperiment validates an experiment before execution
func (p *AWSProvider) ValidateExperiment(ctx context.Context, experiment domain.Experiment) error {
	// Validate each target
	for _, target := range experiment.Targets {
		if !p.SupportsTarget(target) {
			return errors.NewValidationError("unsupported target: %s", target.ID)
		}
		
		// Validate target exists and is accessible
		if err := p.validateTarget(ctx, target); err != nil {
			return err
		}
		
		// Validate safety constraints
		if err := p.validateSafetyConstraints(ctx, target); err != nil {
			return err
		}
	}
	
	return nil
}

// ExecuteExperiment executes a chaos experiment
func (p *AWSProvider) ExecuteExperiment(ctx context.Context, execution *domain.Execution) error {
	p.lastActivity = time.Now()
	
	// Update execution phase
	execution.UpdatePhase(domain.ExecutionPhaseSetup)
	
	// Execute actions on each target
	for _, target := range execution.Config.Targets {
		// Determine action based on target type and experiment config
		action, err := p.determineAction(target, execution.Config)
		if err != nil {
			return err
		}
		
		// Execute the action
		result, err := p.executeAction(ctx, target, action, execution.Config.Parameters)
		if err != nil {
			execution.AddResult(domain.ExecutionResult{
				ID:        generateID(),
				TargetID:  target.ID,
				Action:    action,
				Status:    "failed",
				Error:     err.Error(),
				StartTime: time.Now(),
			})
			return err
		}
		
		// Record successful result
		execution.AddResult(*result)
	}
	
	// Update execution phase
	execution.UpdatePhase(domain.ExecutionPhaseExecution)
	
	return nil
}

// RollbackExperiment rolls back a chaos experiment
func (p *AWSProvider) RollbackExperiment(ctx context.Context, execution *domain.Execution) error {
	p.lastActivity = time.Now()
	
	// Update execution phase
	execution.UpdatePhase(domain.ExecutionPhaseRollback)
	
	// Rollback each result in reverse order
	for i := len(execution.Results) - 1; i >= 0; i-- {
		result := execution.Results[i]
		
		// Skip failed results
		if result.Status != "success" {
			continue
		}
		
		// Find target for this result
		var target domain.Target
		for _, t := range execution.Config.Targets {
			if t.ID == result.TargetID {
				target = t
				break
			}
		}
		
		// Execute rollback action
		if err := p.rollbackAction(ctx, target, result.Action, result.Metadata); err != nil {
			return err
		}
	}
	
	return nil
}

// DiscoverTargets discovers targets based on criteria
func (p *AWSProvider) DiscoverTargets(ctx context.Context, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target
	
	// Discover targets by type
	for _, targetType := range criteria.TargetTypes {
		switch targetType {
		case domain.TargetTypeEC2Instance:
			ec2Targets, err := p.ec2Handler.DiscoverInstances(ctx, criteria)
			if err != nil {
				return nil, err
			}
			targets = append(targets, ec2Targets...)
			
		case domain.TargetTypeECSService:
			ecsTargets, err := p.ecsHandler.DiscoverServices(ctx, criteria)
			if err != nil {
				return nil, err
			}
			targets = append(targets, ecsTargets...)
			
		case domain.TargetTypeECSTask:
			ecsTaskTargets, err := p.ecsHandler.DiscoverTasks(ctx, criteria)
			if err != nil {
				return nil, err
			}
			targets = append(targets, ecsTaskTargets...)
			
		case domain.TargetTypeRDSInstance:
			rdsTargets, err := p.rdsHandler.DiscoverInstances(ctx, criteria)
			if err != nil {
				return nil, err
			}
			targets = append(targets, rdsTargets...)
			
		case domain.TargetTypeLambdaFunction:
			lambdaTargets, err := p.lambdaHandler.DiscoverFunctions(ctx, criteria)
			if err != nil {
				return nil, err
			}
			targets = append(targets, lambdaTargets...)
		}
	}
	
	// Apply filters
	targets = p.applyFilters(targets, criteria.Filters)
	
	// Apply limit
	if criteria.Limit > 0 && len(targets) > criteria.Limit {
		targets = targets[:criteria.Limit]
	}
	
	return targets, nil
}

// GetTargetInfo gets detailed information about a target
func (p *AWSProvider) GetTargetInfo(ctx context.Context, target domain.Target) (*domain.TargetInfo, error) {
	switch target.Type {
	case domain.TargetTypeEC2Instance:
		return p.ec2Handler.GetInstanceInfo(ctx, target)
	case domain.TargetTypeECSService:
		return p.ecsHandler.GetServiceInfo(ctx, target)
	case domain.TargetTypeECSTask:
		return p.ecsHandler.GetTaskInfo(ctx, target)
	case domain.TargetTypeRDSInstance:
		return p.rdsHandler.GetInstanceInfo(ctx, target)
	case domain.TargetTypeLambdaFunction:
		return p.lambdaHandler.GetFunctionInfo(ctx, target)
	default:
		return nil, errors.NewValidationError("unsupported target type: %s", target.Type)
	}
}

// Configure configures the provider
func (p *AWSProvider) Configure(config domain.ProviderConfig) error {
	// Parse AWS-specific configuration
	awsConfig, err := parseAWSConfigFromDomain(config)
	if err != nil {
		return err
	}
	
	p.providerConfig = awsConfig
	
	// Reinitialize AWS with new configuration
	ctx := context.Background()
	return p.initializeAWS(ctx)
}

// Helper methods

func (p *AWSProvider) validateTarget(ctx context.Context, target domain.Target) error {
	// Implementation would validate that target exists and is accessible
	return nil
}

func (p *AWSProvider) validateSafetyConstraints(ctx context.Context, target domain.Target) error {
	// Check required tags
	for _, requiredTag := range p.providerConfig.RequireTags {
		if _, exists := target.Tags[requiredTag]; !exists {
			return errors.NewValidationError("target missing required tag: %s", requiredTag)
		}
	}
	
	// Check forbidden tags
	for _, forbiddenTag := range p.providerConfig.ForbiddenTags {
		if _, exists := target.Tags[forbiddenTag]; exists {
			return errors.NewValidationError("target has forbidden tag: %s", forbiddenTag)
		}
	}
	
	return nil
}

func (p *AWSProvider) determineAction(target domain.Target, config domain.ExecutionConfig) (string, error) {
	// Simple action determination logic - in practice this would be more sophisticated
	switch target.Type {
	case domain.TargetTypeEC2Instance:
		return "stop_instances", nil
	case domain.TargetTypeECSTask:
		return "stop_tasks", nil
	case domain.TargetTypeECSService:
		return "update_service", nil
	case domain.TargetTypeRDSInstance:
		return "reboot_db_instance", nil
	case domain.TargetTypeLambdaFunction:
		return "invoke_function", nil
	default:
		return "", errors.NewValidationError("unsupported target type: %s", target.Type)
	}
}

func (p *AWSProvider) executeAction(ctx context.Context, target domain.Target, action string, parameters map[string]any) (*domain.ExecutionResult, error) {
	start := time.Now()
	
	var err error
	var metadata map[string]any
	
	switch target.Type {
	case domain.TargetTypeEC2Instance:
		metadata, err = p.ec2Handler.ExecuteAction(ctx, target, action, parameters, p.dryRunMode)
	case domain.TargetTypeECSService, domain.TargetTypeECSTask:
		metadata, err = p.ecsHandler.ExecuteAction(ctx, target, action, parameters, p.dryRunMode)
	case domain.TargetTypeRDSInstance:
		metadata, err = p.rdsHandler.ExecuteAction(ctx, target, action, parameters, p.dryRunMode)
	case domain.TargetTypeLambdaFunction:
		metadata, err = p.lambdaHandler.ExecuteAction(ctx, target, action, parameters, p.dryRunMode)
	default:
		return nil, errors.NewValidationError("unsupported target type: %s", target.Type)
	}
	
	end := time.Now()
	duration := domain.Duration(end.Sub(start))
	
	result := &domain.ExecutionResult{
		ID:        generateID(),
		TargetID:  target.ID,
		Action:    action,
		StartTime: start,
		EndTime:   &end,
		Duration:  &duration,
		Metadata:  metadata,
	}
	
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
	} else {
		result.Status = "success"
	}
	
	return result, err
}

func (p *AWSProvider) rollbackAction(ctx context.Context, target domain.Target, action string, metadata map[string]any) error {
	// Implementation would rollback the specific action based on metadata
	switch action {
	case "stop_instances":
		return p.ec2Handler.StartInstances(ctx, target, metadata)
	case "update_service":
		return p.ecsHandler.RollbackService(ctx, target, metadata)
	// Add other rollback actions as needed
	default:
		return nil // Some actions don't need rollback
	}
}

func (p *AWSProvider) applyFilters(targets []domain.Target, filters []domain.TargetFilter) []domain.Target {
	var filtered []domain.Target
	
	for _, target := range targets {
		include := true
		
		for _, filter := range filters {
			if !target.MatchesFilter(filter) {
				include = false
				break
			}
		}
		
		if include {
			filtered = append(filtered, target)
		}
	}
	
	return filtered
}

// Utility functions

func parseAWSConfig(config map[string]interface{}) (AWSProviderConfig, error) {
	// Implementation would parse the configuration map into AWSProviderConfig
	// This is a simplified version
	awsConfig := AWSProviderConfig{
		Region:         getStringValue(config, "region", "us-east-1"),
		DryRunMode:     getBoolValue(config, "dry_run_mode", false),
		MaxConcurrency: getIntValue(config, "max_concurrency", 10),
		DefaultTimeout: getDurationValue(config, "default_timeout", 30*time.Second),
		MaxRetries:     getIntValue(config, "max_retries", 3),
		SafetyChecks:   getBoolValue(config, "safety_checks", true),
	}
	
	return awsConfig, nil
}

func parseAWSConfigFromDomain(config domain.ProviderConfig) (AWSProviderConfig, error) {
	// Convert domain config to AWS config
	return parseAWSConfig(config.Settings)
}

func getStringValue(config map[string]interface{}, key, defaultValue string) string {
	if val, exists := config[key]; exists {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultValue
}

func getBoolValue(config map[string]interface{}, key string, defaultValue bool) bool {
	if val, exists := config[key]; exists {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

func getIntValue(config map[string]interface{}, key string, defaultValue int) int {
	if val, exists := config[key]; exists {
		if i, ok := val.(int); ok {
			return i
		}
		if f, ok := val.(float64); ok {
			return int(f)
		}
	}
	return defaultValue
}

func getDurationValue(config map[string]interface{}, key string, defaultValue time.Duration) time.Duration {
	if val, exists := config[key]; exists {
		if str, ok := val.(string); ok {
			if d, err := time.ParseDuration(str); err == nil {
				return d
			}
		}
	}
	return defaultValue
}

func generateID() string {
	// Simple ID generation - in practice would use proper UUID
	return fmt.Sprintf("aws-%d", time.Now().UnixNano())
}