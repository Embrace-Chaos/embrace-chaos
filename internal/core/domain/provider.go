package domain

import (
	"context"
	"time"
)

// Provider represents a chaos provider that can execute experiments
type Provider interface {
	// Identity
	ID() string
	Name() string
	Version() string
	
	// Capabilities
	GetCapabilities() ProviderCapabilities
	SupportsTarget(target Target) bool
	SupportedActions() []string
	
	// Health and status
	HealthCheck(ctx context.Context) error
	GetStatus() ProviderStatus
	
	// Experiment execution
	ValidateExperiment(ctx context.Context, experiment Experiment) error
	ExecuteExperiment(ctx context.Context, execution *Execution) error
	RollbackExperiment(ctx context.Context, execution *Execution) error
	
	// Resource discovery
	DiscoverTargets(ctx context.Context, criteria DiscoveryCriteria) ([]Target, error)
	GetTargetInfo(ctx context.Context, target Target) (*TargetInfo, error)
	
	// Configuration
	Configure(config ProviderConfig) error
	GetConfig() ProviderConfig
}

// ProviderCapabilities describes what a provider can do
type ProviderCapabilities struct {
	SupportedTargetTypes []TargetType       `json:"supported_target_types"`
	SupportedActions     []ActionCapability `json:"supported_actions"`
	
	// Features supported
	SupportsRollback     bool               `json:"supports_rollback"`
	SupportsDryRun       bool               `json:"supports_dry_run"`
	SupportsScheduling   bool               `json:"supports_scheduling"`
	SupportsTargetDiscovery bool            `json:"supports_target_discovery"`
	
	// Limits
	MaxConcurrentExperiments int            `json:"max_concurrent_experiments"`
	MaxTargetsPerExperiment  int            `json:"max_targets_per_experiment"`
	MaxExperimentDuration    Duration       `json:"max_experiment_duration"`
	
	// Authentication methods supported
	AuthMethods          []string           `json:"auth_methods"`
	
	// Regions supported
	SupportedRegions     []string           `json:"supported_regions"`
}

// ActionCapability describes an action that can be performed
type ActionCapability struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	TargetTypes  []TargetType           `json:"target_types"`
	Parameters   []ActionParameter      `json:"parameters"`
	Reversible   bool                   `json:"reversible"`
	Destructive  bool                   `json:"destructive"`
	RequiresRoot bool                   `json:"requires_root"`
}

// ActionParameter describes a parameter for an action
type ActionParameter struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Required     bool        `json:"required"`
	Default      interface{} `json:"default,omitempty"`
	Description  string      `json:"description"`
	Validation   Validation  `json:"validation,omitempty"`
}

// Validation describes parameter validation rules
type Validation struct {
	Min      *float64 `json:"min,omitempty"`
	Max      *float64 `json:"max,omitempty"`
	Pattern  string   `json:"pattern,omitempty"`
	Options  []string `json:"options,omitempty"`
}

// ProviderStatus represents the current status of a provider
type ProviderStatus struct {
	Status           string                    `json:"status"`
	Healthy          bool                      `json:"healthy"`
	LastHealthCheck  *time.Time                `json:"last_health_check,omitempty"`
	RunningExperiments int                     `json:"running_experiments"`
	TotalExperiments   int                     `json:"total_experiments"`
	Errors           []ProviderError           `json:"errors"`
	Metrics          map[string]interface{}    `json:"metrics"`
}

// ProviderError represents an error from a provider
type ProviderError struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Context   map[string]interface{} `json:"context"`
}

// ProviderConfig holds configuration for a provider
type ProviderConfig struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	Version      string                 `json:"version"`
	Enabled      bool                   `json:"enabled"`
	
	// Authentication
	AuthMethod   string                 `json:"auth_method"`
	Credentials  map[string]string      `json:"credentials"`
	
	// Connection settings
	Endpoint     string                 `json:"endpoint,omitempty"`
	Region       string                 `json:"region,omitempty"`
	Timeout      Duration               `json:"timeout"`
	RetryCount   int                    `json:"retry_count"`
	
	// Provider-specific settings
	Settings     map[string]interface{} `json:"settings"`
	
	// Rate limiting
	RateLimit    RateLimitConfig        `json:"rate_limit"`
}

// RateLimitConfig defines rate limiting for provider operations
type RateLimitConfig struct {
	Enabled          bool     `json:"enabled"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	BurstSize        int      `json:"burst_size"`
}

// DiscoveryCriteria defines criteria for target discovery
type DiscoveryCriteria struct {
	Region       string            `json:"region,omitempty"`
	TargetTypes  []TargetType      `json:"target_types,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Filters      []TargetFilter    `json:"filters,omitempty"`
	Limit        int               `json:"limit,omitempty"`
}

// TargetInfo provides detailed information about a target
type TargetInfo struct {
	Target       Target                 `json:"target"`
	Metadata     map[string]interface{} `json:"metadata"`
	Dependencies []string               `json:"dependencies"`
	Health       TargetHealth           `json:"health"`
	LastSeen     time.Time              `json:"last_seen"`
}

// BaseProvider provides common functionality for all providers
type BaseProvider struct {
	id           string
	name         string
	version      string
	config       ProviderConfig
	status       ProviderStatus
	capabilities ProviderCapabilities
}

// NewBaseProvider creates a new base provider
func NewBaseProvider(id, name, version string) *BaseProvider {
	return &BaseProvider{
		id:      id,
		name:    name,
		version: version,
		status: ProviderStatus{
			Status:             "initialized",
			Healthy:            false,
			RunningExperiments: 0,
			TotalExperiments:   0,
			Errors:             make([]ProviderError, 0),
			Metrics:            make(map[string]interface{}),
		},
		config: ProviderConfig{
			ID:         id,
			Name:       name,
			Version:    version,
			Enabled:    true,
			Timeout:    Duration(30 * time.Second),
			RetryCount: 3,
			Settings:   make(map[string]interface{}),
			RateLimit: RateLimitConfig{
				Enabled:           false,
				RequestsPerSecond: 10.0,
				BurstSize:         20,
			},
		},
	}
}

// ID returns the provider ID
func (bp *BaseProvider) ID() string {
	return bp.id
}

// Name returns the provider name
func (bp *BaseProvider) Name() string {
	return bp.name
}

// Version returns the provider version
func (bp *BaseProvider) Version() string {
	return bp.version
}

// GetCapabilities returns the provider capabilities
func (bp *BaseProvider) GetCapabilities() ProviderCapabilities {
	return bp.capabilities
}

// GetStatus returns the current provider status
func (bp *BaseProvider) GetStatus() ProviderStatus {
	return bp.status
}

// Configure configures the provider
func (bp *BaseProvider) Configure(config ProviderConfig) error {
	bp.config = config
	return nil
}

// GetConfig returns the provider configuration
func (bp *BaseProvider) GetConfig() ProviderConfig {
	return bp.config
}

// UpdateStatus updates the provider status
func (bp *BaseProvider) UpdateStatus(status string, healthy bool) {
	bp.status.Status = status
	bp.status.Healthy = healthy
	now := time.Now()
	bp.status.LastHealthCheck = &now
}

// AddError adds an error to the provider status
func (bp *BaseProvider) AddError(code, message string, context map[string]interface{}) {
	error := ProviderError{
		Code:      code,
		Message:   message,
		Timestamp: time.Now(),
		Context:   context,
	}
	
	bp.status.Errors = append(bp.status.Errors, error)
	
	// Keep only last 10 errors
	if len(bp.status.Errors) > 10 {
		bp.status.Errors = bp.status.Errors[len(bp.status.Errors)-10:]
	}
}

// SetMetric sets a metric value
func (bp *BaseProvider) SetMetric(name string, value interface{}) {
	bp.status.Metrics[name] = value
}

// ProviderRegistry manages registered providers
type ProviderRegistry struct {
	providers map[string]Provider
}

// NewProviderRegistry creates a new provider registry
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]Provider),
	}
}

// Register registers a provider
func (pr *ProviderRegistry) Register(provider Provider) error {
	if provider == nil {
		return NewValidationError("provider cannot be nil")
	}
	
	id := provider.ID()
	if id == "" {
		return NewValidationError("provider ID cannot be empty")
	}
	
	if _, exists := pr.providers[id]; exists {
		return NewValidationError("provider with ID %s already registered", id)
	}
	
	pr.providers[id] = provider
	return nil
}

// Unregister unregisters a provider
func (pr *ProviderRegistry) Unregister(id string) error {
	if _, exists := pr.providers[id]; !exists {
		return NewValidationError("provider with ID %s not found", id)
	}
	
	delete(pr.providers, id)
	return nil
}

// Get gets a provider by ID
func (pr *ProviderRegistry) Get(id string) (Provider, error) {
	provider, exists := pr.providers[id]
	if !exists {
		return nil, NewValidationError("provider with ID %s not found", id)
	}
	
	return provider, nil
}

// List lists all registered providers
func (pr *ProviderRegistry) List() []Provider {
	providers := make([]Provider, 0, len(pr.providers))
	for _, provider := range pr.providers {
		providers = append(providers, provider)
	}
	return providers
}

// GetByTargetType gets providers that support a specific target type
func (pr *ProviderRegistry) GetByTargetType(targetType TargetType) []Provider {
	var providers []Provider
	
	for _, provider := range pr.providers {
		capabilities := provider.GetCapabilities()
		for _, supportedType := range capabilities.SupportedTargetTypes {
			if supportedType == targetType {
				providers = append(providers, provider)
				break
			}
		}
	}
	
	return providers
}