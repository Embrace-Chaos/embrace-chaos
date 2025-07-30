package gcp

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/sql/apiv1"
	"cloud.google.com/go/container/apiv1"
	"google.golang.org/api/option"
	"google.golang.org/api/transport"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// GCPProvider implements the Provider interface for Google Cloud Platform infrastructure
type GCPProvider struct {
	*domain.BaseProvider
	
	// GCP clients
	projectID         string
	computeClient     *compute.InstancesClient
	sqlClient         *sql.SqlInstancesService
	containerClient   *container.ClusterManagerClient
	
	// Provider configuration
	providerConfig    GCPProviderConfig
	
	// Service handlers
	computeHandler    *ComputeHandler
	sqlHandler        *SQLHandler
	gkeHandler        *GKEHandler
	
	// Runtime state
	dryRunMode        bool
	zones             []string
	regions           []string
	
	// Metrics and monitoring
	startTime         time.Time
	lastActivity      time.Time
}

// GCPProviderConfig holds GCP-specific configuration
type GCPProviderConfig struct {
	// Authentication
	ProjectID            string            `json:"project_id"`
	CredentialsFile      string            `json:"credentials_file,omitempty"`
	CredentialsJSON      string            `json:"credentials_json,omitempty"`
	ImpersonateUser      string            `json:"impersonate_user,omitempty"`
	Scopes               []string          `json:"scopes,omitempty"`
	
	// Workload Identity settings
	WorkloadIdentity     WorkloadIdentityConfig `json:"workload_identity,omitempty"`
	
	// Global settings
	DryRunMode           bool              `json:"dry_run_mode"`
	MaxConcurrency       int               `json:"max_concurrency"`
	DefaultTimeout       time.Duration     `json:"default_timeout"`
	EnabledServices      []string          `json:"enabled_services"`
	
	// Retry configuration
	MaxRetries           int               `json:"max_retries"`
	RetryTimeout         time.Duration     `json:"retry_timeout"`
	
	// Safety settings
	SafetyChecks         bool              `json:"safety_checks"`
	RequiredLabels       []string          `json:"required_labels"`
	ForbiddenLabels      []string          `json:"forbidden_labels"`
	AllowedZones         []string          `json:"allowed_zones"`
	AllowedRegions       []string          `json:"allowed_regions"`
	
	// Service-specific configurations
	ComputeConfig        ComputeConfig     `json:"compute_config"`
	SQLConfig            SQLConfig         `json:"sql_config"`
	GKEConfig            GKEConfig         `json:"gke_config"`
}

// WorkloadIdentityConfig holds workload identity specific configuration
type WorkloadIdentityConfig struct {
	Enabled              bool     `json:"enabled"`
	ServiceAccount       string   `json:"service_account,omitempty"`
	KubernetesServiceAccount string `json:"kubernetes_service_account,omitempty"`
	Namespace            string   `json:"namespace,omitempty"`
	TokenPath            string   `json:"token_path,omitempty"`
	Audience             string   `json:"audience,omitempty"`
}

// Service-specific configurations
type ComputeConfig struct {
	AllowedMachineTypes     []string          `json:"allowed_machine_types"`
	ForbiddenMachineTypes   []string          `json:"forbidden_machine_types"`
	RequiredLabels          map[string]string `json:"required_labels"`
	MaxInstancesPerBatch    int               `json:"max_instances_per_batch"`
	StopTimeout             time.Duration     `json:"stop_timeout"`
	StartTimeout            time.Duration     `json:"start_timeout"`
	AllowPreemptible        bool              `json:"allow_preemptible"`
}

type SQLConfig struct {
	AllowedDatabaseVersions []string          `json:"allowed_database_versions"`
	ForbiddenInstances      []string          `json:"forbidden_instances"`
	RequiredLabels          map[string]string `json:"required_labels"`
	MaxInstancesPerBatch    int               `json:"max_instances_per_batch"`
	RestartTimeout          time.Duration     `json:"restart_timeout"`
	BackupBeforeAction      bool              `json:"backup_before_action"`
	AllowProductionTier     bool              `json:"allow_production_tier"`
}

type GKEConfig struct {
	AllowedClusterNames     []string          `json:"allowed_cluster_names"`
	ForbiddenClusters       []string          `json:"forbidden_clusters"`
	RequiredLabels          map[string]string `json:"required_labels"`
	MaxNodesPerBatch        int               `json:"max_nodes_per_batch"`
	DrainTimeout            time.Duration     `json:"drain_timeout"`
	AllowAutopilot          bool              `json:"allow_autopilot"`
}

// NewGCPProvider creates a new GCP provider instance
func NewGCPProvider(providerConfig map[string]interface{}) (domain.Provider, error) {
	// Parse configuration
	config, err := parseGCPConfig(providerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GCP provider config: %w", err)
	}
	
	// Validate required configuration
	if config.ProjectID == "" {
		return nil, fmt.Errorf("project_id is required for GCP provider")
	}
	
	// Create base provider
	baseProvider := domain.NewBaseProvider("gcp", "Google Cloud Platform Chaos Provider", "1.0.0")
	
	provider := &GCPProvider{
		BaseProvider:   baseProvider,
		projectID:      config.ProjectID,
		providerConfig: config,
		dryRunMode:     config.DryRunMode,
		startTime:      time.Now(),
		lastActivity:   time.Now(),
	}
	
	// Initialize GCP clients
	if err := provider.initializeGCP(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize GCP: %w", err)
	}
	
	// Set provider capabilities
	provider.setCapabilities()
	
	return provider, nil
}

// Initialize GCP clients and services
func (p *GCPProvider) initializeGCP(ctx context.Context) error {
	// Create client options
	opts, err := p.createClientOptions()
	if err != nil {
		return fmt.Errorf("failed to create client options: %w", err)
	}
	
	// Initialize Compute Engine client
	if p.shouldEnableService("compute") {
		computeClient, err := compute.NewInstancesRESTClient(ctx, opts...)
		if err != nil {
			return fmt.Errorf("failed to create compute client: %w", err)
		}
		p.computeClient = computeClient
		p.computeHandler = NewComputeHandler(computeClient, p.projectID, p.providerConfig.ComputeConfig)
	}
	
	// Initialize Cloud SQL client
	if p.shouldEnableService("sql") {
		// Note: Cloud SQL uses a different client pattern
		httpClient, _, err := transport.NewHTTPClient(ctx, opts...)
		if err != nil {
			return fmt.Errorf("failed to create HTTP client for SQL: %w", err)
		}
		
		sqlService, err := sql.New(httpClient)
		if err != nil {
			return fmt.Errorf("failed to create SQL service: %w", err)
		}
		
		p.sqlClient = sqlService.Instances
		p.sqlHandler = NewSQLHandler(p.sqlClient, p.projectID, p.providerConfig.SQLConfig)
	}
	
	// Initialize GKE client
	if p.shouldEnableService("container") {
		containerClient, err := container.NewClusterManagerRESTClient(ctx, opts...)
		if err != nil {
			return fmt.Errorf("failed to create container client: %w", err)
		}
		p.containerClient = containerClient
		p.gkeHandler = NewGKEHandler(containerClient, p.projectID, p.providerConfig.GKEConfig)
	}
	
	// Discover available zones and regions
	if err := p.discoverZonesAndRegions(ctx); err != nil {
		return fmt.Errorf("failed to discover zones and regions: %w", err)
	}
	
	return nil
}

// createClientOptions creates client options for GCP services with workload identity support
func (p *GCPProvider) createClientOptions() ([]option.ClientOption, error) {
	var opts []option.ClientOption
	
	// Priority order for authentication:
	// 1. Explicit credentials (file or JSON)
	// 2. Workload Identity (via service account impersonation)
	// 3. Default credentials (metadata service, gcloud, etc.)
	
	if p.providerConfig.CredentialsFile != "" {
		// Explicit credentials file
		opts = append(opts, option.WithCredentialsFile(p.providerConfig.CredentialsFile))
	} else if p.providerConfig.CredentialsJSON != "" {
		// Explicit credentials JSON
		opts = append(opts, option.WithCredentialsJSON([]byte(p.providerConfig.CredentialsJSON)))
	} else if p.providerConfig.ImpersonateUser != "" {
		// Workload Identity: impersonate a service account
		// This is typically used in Kubernetes with Workload Identity
		opts = append(opts, option.ImpersonateCredentials(
			p.providerConfig.ImpersonateUser,
			option.WithScopes(p.getDefaultScopes()...),
		))
	} else if p.providerConfig.WorkloadIdentity.Enabled {
		// Explicit workload identity configuration
		opts = p.configureWorkloadIdentity(opts)
	} else {
		// Use default credentials with workload identity detection
		// This will automatically detect workload identity in GKE environments
		if p.isWorkloadIdentityEnvironment() {
			// In GKE with Workload Identity, default credentials will work
			// but we can be explicit about the scopes
			if len(p.providerConfig.Scopes) == 0 {
				opts = append(opts, option.WithScopes(p.getDefaultScopes()...))
			}
		}
	}
	
	// Add custom scopes if specified (overrides defaults)
	if len(p.providerConfig.Scopes) > 0 {
		opts = append(opts, option.WithScopes(p.providerConfig.Scopes...))
	}
	
	// Add quota project if specified (important for workload identity)
	if p.providerConfig.ProjectID != "" {
		opts = append(opts, option.WithQuotaProject(p.providerConfig.ProjectID))
	}
	
	return opts, nil
}

// configureWorkloadIdentity configures explicit workload identity options
func (p *GCPProvider) configureWorkloadIdentity(opts []option.ClientOption) []option.ClientOption {
	config := p.providerConfig.WorkloadIdentity
	
	// If service account is specified, use impersonation
	if config.ServiceAccount != "" {
		opts = append(opts, option.ImpersonateCredentials(
			config.ServiceAccount,
			option.WithScopes(p.getDefaultScopes()...),
		))
	}
	
	// Configure custom token path if specified
	if config.TokenPath != "" {
		// This would typically be used with external credential sources
		// For now, we'll just ensure the path exists and is readable
		if _, err := os.Stat(config.TokenPath); err == nil {
			// Token file exists, default credentials should pick it up
			// via GOOGLE_APPLICATION_CREDENTIALS or similar mechanisms
		}
	}
	
	// Configure audience if specified (for external identity providers)
	if config.Audience != "" {
		// This would be used with external identity providers
		// The audience is typically configured in the credential source
	}
	
	return opts
}

// isWorkloadIdentityEnvironment detects if running in a workload identity environment
func (p *GCPProvider) isWorkloadIdentityEnvironment() bool {
	// Check for Kubernetes service account token
	// This is the standard location for workload identity tokens
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}
	
	// Check for workload identity environment variables
	if os.Getenv("GOOGLE_SERVICE_ACCOUNT_NAME") != "" {
		return true
	}
	
	// Check metadata server for workload identity
	// This would require a metadata server call, but we can check for GKE environment
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	
	return false
}

// getDefaultScopes returns the default OAuth2 scopes needed for chaos operations
func (p *GCPProvider) getDefaultScopes() []string {
	return []string{
		"https://www.googleapis.com/auth/cloud-platform",
		"https://www.googleapis.com/auth/compute",
		"https://www.googleapis.com/auth/sqlservice.admin",
		"https://www.googleapis.com/auth/container",
		"https://www.googleapis.com/auth/logging.write",
		"https://www.googleapis.com/auth/monitoring.write",
	}
}

// shouldEnableService checks if a service should be enabled
func (p *GCPProvider) shouldEnableService(service string) bool {
	if len(p.providerConfig.EnabledServices) == 0 {
		return true // Enable all services by default
	}
	
	for _, enabledService := range p.providerConfig.EnabledServices {
		if enabledService == service {
			return true
		}
	}
	return false
}

// discoverZonesAndRegions discovers available GCP zones and regions
func (p *GCPProvider) discoverZonesAndRegions(ctx context.Context) error {
	if p.computeClient == nil {
		return nil // Skip if compute client is not initialized
	}
	
	// Discover zones
	zones, err := p.computeHandler.listZones(ctx)
	if err != nil {
		return fmt.Errorf("failed to list zones: %w", err)
	}
	
	// Filter by allowed zones if configured
	if len(p.providerConfig.AllowedZones) > 0 {
		var allowedZones []string
		for _, zone := range zones {
			for _, allowed := range p.providerConfig.AllowedZones {
				if zone == allowed {
					allowedZones = append(allowedZones, zone)
					break
				}
			}
		}
		zones = allowedZones
	}
	p.zones = zones
	
	// Extract regions from zones
	regionMap := make(map[string]bool)
	for _, zone := range zones {
		// Extract region from zone (e.g., "us-central1-a" -> "us-central1")
		parts := strings.Split(zone, "-")
		if len(parts) >= 3 {
			region := strings.Join(parts[:len(parts)-1], "-")
			regionMap[region] = true
		}
	}
	
	var regions []string
	for region := range regionMap {
		regions = append(regions, region)
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
func (p *GCPProvider) setCapabilities() {
	var supportedTargetTypes []domain.TargetType
	var supportedActions []domain.ActionCapability
	var authMethods []string
	
	// Add Compute Engine capabilities
	if p.computeHandler != nil {
		supportedTargetTypes = append(supportedTargetTypes, domain.TargetTypeGCEInstance)
		supportedActions = append(supportedActions, []domain.ActionCapability{
			{
				Name:        "stop_instance",
				Description: "Stop GCE instance",
				TargetTypes: []domain.TargetType{domain.TargetTypeGCEInstance},
				Parameters: []domain.ActionParameter{
					{
						Name:        "force",
						Type:        "boolean",
						Required:    false,
						Default:     false,
						Description: "Force stop instance",
					},
				},
				Reversible:  true,
				Destructive: false,
			},
			{
				Name:        "reset_instance",
				Description: "Reset GCE instance",
				TargetTypes: []domain.TargetType{domain.TargetTypeGCEInstance},
				Reversible:  false,
				Destructive: false,
			},
		}...)
	}
	
	// Add Cloud SQL capabilities
	if p.sqlHandler != nil {
		supportedTargetTypes = append(supportedTargetTypes, domain.TargetTypeCloudSQLInstance)
		supportedActions = append(supportedActions, []domain.ActionCapability{
			{
				Name:        "restart_instance",
				Description: "Restart Cloud SQL instance",
				TargetTypes: []domain.TargetType{domain.TargetTypeCloudSQLInstance},
				Reversible:  false,
				Destructive: false,
			},
			{
				Name:        "failover_instance",
				Description: "Trigger failover for Cloud SQL instance",
				TargetTypes: []domain.TargetType{domain.TargetTypeCloudSQLInstance},
				Reversible:  false,
				Destructive: false,
			},
		}...)
	}
	
	// Add GKE capabilities
	if p.gkeHandler != nil {
		supportedTargetTypes = append(supportedTargetTypes, domain.TargetTypeGKENode)
		supportedActions = append(supportedActions, []domain.ActionCapability{
			{
				Name:        "drain_node",
				Description: "Drain GKE node",
				TargetTypes: []domain.TargetType{domain.TargetTypeGKENode},
				Parameters: []domain.ActionParameter{
					{
						Name:        "timeout",
						Type:        "duration",
						Required:    false,
						Default:     "5m",
						Description: "Drain timeout",
					},
				},
				Reversible:  true,
				Destructive: false,
			},
		}...)
	}
	
	// Set authentication methods
	authMethods = []string{"service_account", "workload_identity", "user_credentials"}
	
	capabilities := domain.ProviderCapabilities{
		SupportedTargetTypes:      supportedTargetTypes,
		SupportedActions:          supportedActions,
		SupportsRollback:          true,
		SupportsDryRun:           true,
		SupportsScheduling:       true,
		SupportsTargetDiscovery:  true,
		MaxConcurrentExperiments: p.providerConfig.MaxConcurrency,
		MaxTargetsPerExperiment:  100,
		MaxExperimentDuration:    24 * time.Hour,
		AuthMethods:              authMethods,
		SupportedRegions:         p.regions,
	}
	
	// Set capabilities in base provider
	p.BaseProvider.SetCapabilities(capabilities)
}

// Provider interface implementation

// SupportsTarget checks if the provider supports a given target
func (p *GCPProvider) SupportsTarget(target domain.Target) bool {
	// Check if target provider matches
	if target.Provider != "gcp" {
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
func (p *GCPProvider) SupportedActions() []string {
	capabilities := p.GetCapabilities()
	actions := make([]string, len(capabilities.SupportedActions))
	for i, action := range capabilities.SupportedActions {
		actions[i] = action.Name
	}
	return actions
}

// HealthCheck performs a health check
func (p *GCPProvider) HealthCheck(ctx context.Context) error {
	// Check connectivity to enabled services
	if p.computeClient != nil {
		if err := p.computeHandler.healthCheck(ctx); err != nil {
			return errors.NewProviderError("gcp", "compute_health_check", err)
		}
	}
	
	if p.sqlHandler != nil {
		if err := p.sqlHandler.healthCheck(ctx); err != nil {
			return errors.NewProviderError("gcp", "sql_health_check", err)
		}
	}
	
	if p.gkeHandler != nil {
		if err := p.gkeHandler.healthCheck(ctx); err != nil {
			return errors.NewProviderError("gcp", "gke_health_check", err)
		}
	}
	
	// Update health status
	p.UpdateStatus("healthy", true)
	p.lastActivity = time.Now()
	
	return nil
}

// ValidateExperiment validates an experiment before execution
func (p *GCPProvider) ValidateExperiment(ctx context.Context, experiment domain.Experiment) error {
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
func (p *GCPProvider) ExecuteExperiment(ctx context.Context, execution *domain.Execution) error {
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
				ID:        generateGCPID(),
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
func (p *GCPProvider) RollbackExperiment(ctx context.Context, execution *domain.Execution) error {
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
func (p *GCPProvider) DiscoverTargets(ctx context.Context, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target
	
	// Discover targets by type
	for _, targetType := range criteria.TargetTypes {
		switch targetType {
		case domain.TargetTypeGCEInstance:
			if p.computeHandler != nil {
				gceTargets, err := p.computeHandler.DiscoverInstances(ctx, criteria)
				if err != nil {
					return nil, err
				}
				targets = append(targets, gceTargets...)
			}
			
		case domain.TargetTypeCloudSQLInstance:
			if p.sqlHandler != nil {
				sqlTargets, err := p.sqlHandler.DiscoverInstances(ctx, criteria)
				if err != nil {
					return nil, err
				}
				targets = append(targets, sqlTargets...)
			}
			
		case domain.TargetTypeGKENode:
			if p.gkeHandler != nil {
				gkeTargets, err := p.gkeHandler.DiscoverNodes(ctx, criteria)
				if err != nil {
					return nil, err
				}
				targets = append(targets, gkeTargets...)
			}
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
func (p *GCPProvider) GetTargetInfo(ctx context.Context, target domain.Target) (*domain.TargetInfo, error) {
	switch target.Type {
	case domain.TargetTypeGCEInstance:
		if p.computeHandler != nil {
			return p.computeHandler.GetInstanceInfo(ctx, target)
		}
	case domain.TargetTypeCloudSQLInstance:
		if p.sqlHandler != nil {
			return p.sqlHandler.GetInstanceInfo(ctx, target)
		}
	case domain.TargetTypeGKENode:
		if p.gkeHandler != nil {
			return p.gkeHandler.GetNodeInfo(ctx, target)
		}
	}
	
	return nil, errors.NewValidationError("unsupported target type: %s", target.Type)
}

// Configure configures the provider
func (p *GCPProvider) Configure(config domain.ProviderConfig) error {
	// Parse GCP-specific configuration
	gcpConfig, err := parseGCPConfigFromDomain(config)
	if err != nil {
		return err
	}
	
	p.providerConfig = gcpConfig
	
	// Reinitialize GCP with new configuration
	ctx := context.Background()
	return p.initializeGCP(ctx)
}

// Helper methods

func (p *GCPProvider) validateTarget(ctx context.Context, target domain.Target) error {
	// Implementation would validate that target exists and is accessible
	return nil
}

func (p *GCPProvider) validateSafetyConstraints(ctx context.Context, target domain.Target) error {
	// Check required labels
	for _, requiredLabel := range p.providerConfig.RequiredLabels {
		if _, exists := target.Tags[requiredLabel]; !exists {
			return errors.NewValidationError("target missing required label: %s", requiredLabel)
		}
	}
	
	// Check forbidden labels
	for _, forbiddenLabel := range p.providerConfig.ForbiddenLabels {
		if _, exists := target.Tags[forbiddenLabel]; exists {
			return errors.NewValidationError("target has forbidden label: %s", forbiddenLabel)
		}
	}
	
	return nil
}

func (p *GCPProvider) determineAction(target domain.Target, config domain.ExecutionConfig) (string, error) {
	// Simple action determination logic
	switch target.Type {
	case domain.TargetTypeGCEInstance:
		return "stop_instance", nil
	case domain.TargetTypeCloudSQLInstance:
		return "restart_instance", nil
	case domain.TargetTypeGKENode:
		return "drain_node", nil
	default:
		return "", errors.NewValidationError("unsupported target type: %s", target.Type)
	}
}

func (p *GCPProvider) executeAction(ctx context.Context, target domain.Target, action string, parameters map[string]any) (*domain.ExecutionResult, error) {
	start := time.Now()
	
	var err error
	var metadata map[string]any
	
	switch target.Type {
	case domain.TargetTypeGCEInstance:
		if p.computeHandler != nil {
			metadata, err = p.computeHandler.ExecuteAction(ctx, target, action, parameters, p.dryRunMode)
		}
	case domain.TargetTypeCloudSQLInstance:
		if p.sqlHandler != nil {
			metadata, err = p.sqlHandler.ExecuteAction(ctx, target, action, parameters, p.dryRunMode)
		}
	case domain.TargetTypeGKENode:
		if p.gkeHandler != nil {
			metadata, err = p.gkeHandler.ExecuteAction(ctx, target, action, parameters, p.dryRunMode)
		}
	default:
		return nil, errors.NewValidationError("unsupported target type: %s", target.Type)
	}
	
	end := time.Now()
	duration := domain.Duration(end.Sub(start))
	
	result := &domain.ExecutionResult{
		ID:        generateGCPID(),
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

func (p *GCPProvider) rollbackAction(ctx context.Context, target domain.Target, action string, metadata map[string]any) error {
	// Implementation would rollback the specific action based on metadata
	switch action {
	case "stop_instance":
		if p.computeHandler != nil {
			return p.computeHandler.StartInstance(ctx, target, metadata)
		}
	case "drain_node":
		if p.gkeHandler != nil {
			return p.gkeHandler.UncordonNode(ctx, target, metadata)
		}
	// Add other rollback actions as needed
	default:
		return nil // Some actions don't need rollback
	}
	return nil
}

func (p *GCPProvider) applyFilters(targets []domain.Target, filters []domain.TargetFilter) []domain.Target {
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

func parseGCPConfig(config map[string]interface{}) (GCPProviderConfig, error) {
	// Implementation would parse the configuration map into GCPProviderConfig
	gcpConfig := GCPProviderConfig{
		ProjectID:        getStringValue(config, "project_id", ""),
		DryRunMode:       getBoolValue(config, "dry_run_mode", false),
		MaxConcurrency:   getIntValue(config, "max_concurrency", 10),
		DefaultTimeout:   getDurationValue(config, "default_timeout", 30*time.Second),
		MaxRetries:       getIntValue(config, "max_retries", 3),
		SafetyChecks:     getBoolValue(config, "safety_checks", true),
	}
	
	return gcpConfig, nil
}

func parseGCPConfigFromDomain(config domain.ProviderConfig) (GCPProviderConfig, error) {
	// Convert domain config to GCP config
	return parseGCPConfig(config.Settings)
}

func generateGCPID() string {
	// Simple ID generation - in practice would use proper UUID
	return fmt.Sprintf("gcp-%d", time.Now().UnixNano())
}