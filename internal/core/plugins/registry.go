package plugins

import (
	"context"
	"fmt"
	"path/filepath"
	"plugin"
	"sync"
	"time"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// PluginRegistry manages the lifecycle of chaos provider plugins
type PluginRegistry struct {
	mu                sync.RWMutex
	plugins          map[string]*PluginInfo
	providers        map[string]domain.Provider
	pluginPaths      []string
	healthChecker    HealthChecker
	circuitBreaker   CircuitBreaker
	retryHandler     RetryHandler
	logger           Logger
	eventPublisher   EventPublisher
	config           RegistryConfig
	
	// Plugin lifecycle hooks
	beforeLoad       []BeforeLoadHook
	afterLoad        []AfterLoadHook
	beforeUnload     []BeforeUnloadHook
	afterUnload      []AfterUnloadHook
}

// PluginInfo holds metadata about a loaded plugin
type PluginInfo struct {
	ID              string                    `json:"id"`
	Name            string                    `json:"name"`
	Version         string                    `json:"version"`
	Description     string                    `json:"description"`
	Author          string                    `json:"author"`
	
	// File information
	FilePath        string                    `json:"file_path"`
	Checksum        string                    `json:"checksum"`
	LoadedAt        time.Time                 `json:"loaded_at"`
	
	// Plugin state
	Status          PluginStatus              `json:"status"`
	Health          PluginHealth              `json:"health"`
	Capabilities    domain.ProviderCapabilities `json:"capabilities"`
	
	// Runtime information
	Plugin          *plugin.Plugin            `json:"-"`
	Provider        domain.Provider           `json:"-"`
	Config          PluginConfig              `json:"config"`
	
	// Dependency information
	Dependencies    []PluginDependency        `json:"dependencies"`
	Dependents      []string                  `json:"dependents"`
	
	// Metrics
	LoadTime        time.Duration             `json:"load_time"`
	UsageCount      int64                     `json:"usage_count"`
	ErrorCount      int64                     `json:"error_count"`
	LastUsed        *time.Time                `json:"last_used,omitempty"`
	LastError       *time.Time                `json:"last_error,omitempty"`
}

// PluginStatus represents the status of a plugin
type PluginStatus string

const (
	PluginStatusLoading   PluginStatus = "loading"
	PluginStatusLoaded    PluginStatus = "loaded"
	PluginStatusActive    PluginStatus = "active"
	PluginStatusInactive  PluginStatus = "inactive"
	PluginStatusError     PluginStatus = "error"
	PluginStatusUnloading PluginStatus = "unloading"
	PluginStatusUnloaded  PluginStatus = "unloaded"
)

// PluginHealth represents the health status of a plugin
type PluginHealth struct {
	Status          string                    `json:"status"`
	LastCheck       time.Time                 `json:"last_check"`
	CheckInterval   time.Duration             `json:"check_interval"`
	HealthScore     float64                   `json:"health_score"`
	Issues          []HealthIssue             `json:"issues"`
	ResponseTime    time.Duration             `json:"response_time"`
}

// HealthIssue represents a health issue with a plugin
type HealthIssue struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	DetectedAt  time.Time `json:"detected_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// PluginConfig holds configuration for a plugin
type PluginConfig struct {
	Enabled         bool                      `json:"enabled"`
	AutoStart       bool                      `json:"auto_start"`
	HealthCheck     HealthCheckConfig         `json:"health_check"`
	CircuitBreaker  CircuitBreakerConfig      `json:"circuit_breaker"`
	RetryPolicy     RetryPolicyConfig         `json:"retry_policy"`
	RateLimit       RateLimitConfig           `json:"rate_limit"`
	Timeout         time.Duration             `json:"timeout"`
	Settings        map[string]interface{}    `json:"settings"`
}

// PluginDependency represents a plugin dependency
type PluginDependency struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Optional    bool   `json:"optional"`
	Condition   string `json:"condition,omitempty"`
}

// RegistryConfig holds configuration for the plugin registry
type RegistryConfig struct {
	PluginPaths         []string      `json:"plugin_paths"`
	AutoDiscovery       bool          `json:"auto_discovery"`
	AutoLoad            bool          `json:"auto_load"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	MaxPlugins          int           `json:"max_plugins"`
	AllowUnsigned       bool          `json:"allow_unsigned"`
	SecurityPolicy      SecurityPolicy `json:"security_policy"`
}

// SecurityPolicy defines security constraints for plugins
type SecurityPolicy struct {
	RequireSigning      bool     `json:"require_signing"`
	TrustedKeys         []string `json:"trusted_keys"`
	AllowedCapabilities []string `json:"allowed_capabilities"`
	SandboxMode         bool     `json:"sandbox_mode"`
	NetworkAccess       bool     `json:"network_access"`
	FileSystemAccess    bool     `json:"file_system_access"`
}

// Hook types for plugin lifecycle events
type BeforeLoadHook func(ctx context.Context, pluginPath string) error
type AfterLoadHook func(ctx context.Context, info *PluginInfo) error
type BeforeUnloadHook func(ctx context.Context, info *PluginInfo) error
type AfterUnloadHook func(ctx context.Context, pluginID string) error

// Logger interface for plugin registry
type Logger interface {
	Debug(ctx context.Context, msg string, fields ...interface{})
	Info(ctx context.Context, msg string, fields ...interface{})
	Warn(ctx context.Context, msg string, fields ...interface{})
	Error(ctx context.Context, msg string, fields ...interface{})
}

// EventPublisher interface for publishing plugin events
type EventPublisher interface {
	PublishPluginEvent(ctx context.Context, event PluginEvent) error
}

// PluginEvent represents a plugin lifecycle event
type PluginEvent struct {
	Type        string                    `json:"type"`
	PluginID    string                    `json:"plugin_id"`
	Timestamp   time.Time                 `json:"timestamp"`
	Details     map[string]interface{}    `json:"details"`
	Context     map[string]string         `json:"context"`
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry(config RegistryConfig, logger Logger, eventPublisher EventPublisher) *PluginRegistry {
	return &PluginRegistry{
		plugins:        make(map[string]*PluginInfo),
		providers:      make(map[string]domain.Provider),
		pluginPaths:    config.PluginPaths,
		logger:         logger,
		eventPublisher: eventPublisher,
		config:         config,
		healthChecker:  NewHealthChecker(config.HealthCheckInterval, logger),
		circuitBreaker: NewCircuitBreaker(logger),
		retryHandler:   NewRetryHandler(logger),
		beforeLoad:     make([]BeforeLoadHook, 0),
		afterLoad:      make([]AfterLoadHook, 0),
		beforeUnload:   make([]BeforeUnloadHook, 0),
		afterUnload:    make([]AfterUnloadHook, 0),
	}
}

// LoadPlugin loads a plugin from the specified path
func (r *PluginRegistry) LoadPlugin(ctx context.Context, pluginPath string) (*PluginInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Execute before load hooks
	for _, hook := range r.beforeLoad {
		if err := hook(ctx, pluginPath); err != nil {
			return nil, fmt.Errorf("before load hook failed: %w", err)
		}
	}
	
	start := time.Now()
	
	// Check if plugin is already loaded
	checksum, err := r.calculateChecksum(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate checksum: %w", err)
	}
	
	for _, info := range r.plugins {
		if info.FilePath == pluginPath && info.Checksum == checksum {
			r.logger.Info(ctx, "Plugin already loaded", "path", pluginPath, "id", info.ID)
			return info, nil
		}
	}
	
	// Validate plugin before loading
	if err := r.validatePlugin(ctx, pluginPath); err != nil {
		return nil, fmt.Errorf("plugin validation failed: %w", err)
	}
	
	// Load the plugin
	p, err := plugin.Open(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin: %w", err)
	}
	
	// Look for the required symbols
	providerSym, err := p.Lookup("NewProvider")
	if err != nil {
		return nil, fmt.Errorf("plugin missing NewProvider function: %w", err)
	}
	
	metadataSym, err := p.Lookup("GetMetadata")
	if err != nil {
		return nil, fmt.Errorf("plugin missing GetMetadata function: %w", err)
	}
	
	// Get plugin metadata
	getMetadata, ok := metadataSym.(func() PluginMetadata)
	if !ok {
		return nil, fmt.Errorf("GetMetadata has wrong signature")
	}
	
	metadata := getMetadata()
	
	// Create provider instance
	newProvider, ok := providerSym.(func(config map[string]interface{}) (domain.Provider, error))
	if !ok {
		return nil, fmt.Errorf("NewProvider has wrong signature")
	}
	
	provider, err := newProvider(make(map[string]interface{}))
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}
	
	// Create plugin info
	info := &PluginInfo{
		ID:           metadata.ID,
		Name:         metadata.Name,
		Version:      metadata.Version,
		Description:  metadata.Description,
		Author:       metadata.Author,
		FilePath:     pluginPath,
		Checksum:     checksum,
		LoadedAt:     time.Now(),
		Status:       PluginStatusLoaded,
		Plugin:       p,
		Provider:     provider,
		LoadTime:     time.Since(start),
		Capabilities: provider.GetCapabilities(),
		Config: PluginConfig{
			Enabled:     true,
			AutoStart:   true,
			Timeout:     30 * time.Second,
			Settings:    make(map[string]interface{}),
		},
		Dependencies: metadata.Dependencies,
		Dependents:   make([]string, 0),
	}
	
	// Initialize health status
	info.Health = PluginHealth{
		Status:        "unknown",
		LastCheck:     time.Now(),
		CheckInterval: r.config.HealthCheckInterval,
		HealthScore:   0.0,
		Issues:        make([]HealthIssue, 0),
	}
	
	// Check dependencies
	if err := r.checkDependencies(ctx, info); err != nil {
		return nil, fmt.Errorf("dependency check failed: %w", err)
	}
	
	// Register the plugin
	r.plugins[info.ID] = info
	r.providers[info.ID] = provider
	
	// Start health checking
	r.healthChecker.StartMonitoring(ctx, info)
	
	// Execute after load hooks
	for _, hook := range r.afterLoad {
		if err := hook(ctx, info); err != nil {
			r.logger.Warn(ctx, "After load hook failed", "error", err, "plugin", info.ID)
		}
	}
	
	// Publish event
	if r.eventPublisher != nil {
		event := PluginEvent{
			Type:      "plugin.loaded",
			PluginID:  info.ID,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"name":      info.Name,
				"version":   info.Version,
				"load_time": info.LoadTime,
			},
		}
		r.eventPublisher.PublishPluginEvent(ctx, event)
	}
	
	r.logger.Info(ctx, "Plugin loaded successfully", 
		"id", info.ID, 
		"name", info.Name, 
		"version", info.Version,
		"load_time", info.LoadTime)
	
	return info, nil
}

// UnloadPlugin unloads a plugin
func (r *PluginRegistry) UnloadPlugin(ctx context.Context, pluginID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	info, exists := r.plugins[pluginID]
	if !exists {
		return errors.NewDomainError(errors.ErrProviderNotFound, "plugin not found: "+pluginID)
	}
	
	// Execute before unload hooks
	for _, hook := range r.beforeUnload {
		if err := hook(ctx, info); err != nil {
			r.logger.Warn(ctx, "Before unload hook failed", "error", err, "plugin", pluginID)
		}
	}
	
	info.Status = PluginStatusUnloading
	
	// Stop health checking
	r.healthChecker.StopMonitoring(ctx, pluginID)
	
	// Remove from registry
	delete(r.plugins, pluginID)
	delete(r.providers, pluginID)
	
	info.Status = PluginStatusUnloaded
	
	// Execute after unload hooks
	for _, hook := range r.afterUnload {
		if err := hook(ctx, pluginID); err != nil {
			r.logger.Warn(ctx, "After unload hook failed", "error", err, "plugin", pluginID)
		}
	}
	
	// Publish event
	if r.eventPublisher != nil {
		event := PluginEvent{
			Type:      "plugin.unloaded",
			PluginID:  pluginID,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"name": info.Name,
			},
		}
		r.eventPublisher.PublishPluginEvent(ctx, event)
	}
	
	r.logger.Info(ctx, "Plugin unloaded", "id", pluginID, "name", info.Name)
	
	return nil
}

// GetPlugin returns plugin information
func (r *PluginRegistry) GetPlugin(pluginID string) (*PluginInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	info, exists := r.plugins[pluginID]
	if !exists {
		return nil, errors.NewDomainError(errors.ErrProviderNotFound, "plugin not found: "+pluginID)
	}
	
	return info, nil
}

// GetProvider returns a provider by ID
func (r *PluginRegistry) GetProvider(providerID string) (domain.Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	provider, exists := r.providers[providerID]
	if !exists {
		return nil, errors.NewDomainError(errors.ErrProviderNotFound, "provider not found: "+providerID)
	}
	
	// Update usage statistics
	if info, exists := r.plugins[providerID]; exists {
		info.UsageCount++
		now := time.Now()
		info.LastUsed = &now
	}
	
	return provider, nil
}

// ListPlugins returns all registered plugins
func (r *PluginRegistry) ListPlugins() []*PluginInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	plugins := make([]*PluginInfo, 0, len(r.plugins))
	for _, info := range r.plugins {
		plugins = append(plugins, info)
	}
	
	return plugins
}

// ListProviders returns all active providers
func (r *PluginRegistry) ListProviders() []domain.Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	providers := make([]domain.Provider, 0, len(r.providers))
	for _, provider := range r.providers {
		providers = append(providers, provider)
	}
	
	return providers
}

// DiscoverPlugins discovers plugins in configured paths
func (r *PluginRegistry) DiscoverPlugins(ctx context.Context) ([]*PluginInfo, error) {
	var discovered []*PluginInfo
	
	for _, path := range r.pluginPaths {
		plugins, err := r.discoverInPath(ctx, path)
		if err != nil {
			r.logger.Warn(ctx, "Failed to discover plugins in path", "path", path, "error", err)
			continue
		}
		discovered = append(discovered, plugins...)
	}
	
	r.logger.Info(ctx, "Plugin discovery completed", "discovered", len(discovered))
	
	return discovered, nil
}

// RegisterHooks registers lifecycle hooks
func (r *PluginRegistry) RegisterHooks(before BeforeLoadHook, after AfterLoadHook, beforeUnload BeforeUnloadHook, afterUnload AfterUnloadHook) {
	if before != nil {
		r.beforeLoad = append(r.beforeLoad, before)
	}
	if after != nil {
		r.afterLoad = append(r.afterLoad, after)
	}
	if beforeUnload != nil {
		r.beforeUnload = append(r.beforeUnload, beforeUnload)
	}
	if afterUnload != nil {
		r.afterUnload = append(r.afterUnload, afterUnload)
	}
}

// GetHealthStatus returns the health status of all plugins
func (r *PluginRegistry) GetHealthStatus(ctx context.Context) map[string]PluginHealth {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	health := make(map[string]PluginHealth)
	for id, info := range r.plugins {
		health[id] = info.Health
	}
	
	return health
}

// Helper methods

func (r *PluginRegistry) calculateChecksum(filePath string) (string, error) {
	// Implementation would calculate SHA256 of the plugin file
	return "sha256:placeholder", nil
}

func (r *PluginRegistry) validatePlugin(ctx context.Context, pluginPath string) error {
	// Validate plugin signature, permissions, etc.
	if !r.config.SecurityPolicy.RequireSigning || r.config.AllowUnsigned {
		return nil
	}
	
	// Implementation would validate plugin signature
	return nil
}

func (r *PluginRegistry) checkDependencies(ctx context.Context, info *PluginInfo) error {
	for _, dep := range info.Dependencies {
		if _, exists := r.plugins[dep.ID]; !exists && !dep.Optional {
			return fmt.Errorf("required dependency not found: %s", dep.ID)
		}
	}
	return nil
}

func (r *PluginRegistry) discoverInPath(ctx context.Context, path string) ([]*PluginInfo, error) {
	var plugins []*PluginInfo
	
	// Implementation would scan directory for .so files
	matches, err := filepath.Glob(filepath.Join(path, "*.so"))
	if err != nil {
		return nil, err
	}
	
	for _, match := range matches {
		if r.config.AutoLoad {
			if info, err := r.LoadPlugin(ctx, match); err == nil {
				plugins = append(plugins, info)
			} else {
				r.logger.Warn(ctx, "Failed to auto-load discovered plugin", "path", match, "error", err)
			}
		}
	}
	
	return plugins, nil
}

// PluginMetadata represents plugin metadata
type PluginMetadata struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Version      string              `json:"version"`
	Description  string              `json:"description"`
	Author       string              `json:"author"`
	License      string              `json:"license"`
	Homepage     string              `json:"homepage"`
	Dependencies []PluginDependency  `json:"dependencies"`
	Capabilities []string            `json:"capabilities"`
	MinCoreVersion string            `json:"min_core_version"`
}

// Configuration types for plugin features

// HealthCheckConfig configures health checking for plugins
type HealthCheckConfig struct {
	Enabled   bool          `json:"enabled"`
	Interval  time.Duration `json:"interval"`
	Timeout   time.Duration `json:"timeout"`
	Retries   int           `json:"retries"`
	Endpoint  string        `json:"endpoint,omitempty"`
}

// CircuitBreakerConfig configures circuit breaker for plugins
type CircuitBreakerConfig struct {
	Enabled           bool          `json:"enabled"`
	FailureThreshold  int           `json:"failure_threshold"`
	RecoveryTimeout   time.Duration `json:"recovery_timeout"`
	HalfOpenRequests  int           `json:"half_open_requests"`
}

// RetryPolicyConfig configures retry policy for plugins
type RetryPolicyConfig struct {
	Enabled     bool          `json:"enabled"`
	MaxRetries  int           `json:"max_retries"`
	BaseDelay   time.Duration `json:"base_delay"`
	MaxDelay    time.Duration `json:"max_delay"`
	Multiplier  float64       `json:"multiplier"`
	Jitter      bool          `json:"jitter"`
}

// RateLimitConfig configures rate limiting for plugins
type RateLimitConfig struct {
	Enabled       bool    `json:"enabled"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	BurstSize     int     `json:"burst_size"`
}