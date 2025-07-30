package ports

import (
	"context"
	"io"

	"github.com/embrace-chaos/internal/core/domain"
)

// Store defines the secondary port for data persistence
type Store interface {
	// Experiment storage
	SaveExperiment(ctx context.Context, experiment *domain.Experiment) error
	GetExperiment(ctx context.Context, id domain.ExperimentID) (*domain.Experiment, error)
	GetExperimentByName(ctx context.Context, name string) (*domain.Experiment, error)
	UpdateExperiment(ctx context.Context, experiment *domain.Experiment) error
	DeleteExperiment(ctx context.Context, id domain.ExperimentID) error
	ListExperiments(ctx context.Context, filters ExperimentFilters, pagination PaginationRequest) ([]domain.Experiment, int64, error)
	
	// Execution storage
	SaveExecution(ctx context.Context, execution *domain.Execution) error
	GetExecution(ctx context.Context, id domain.ExecutionID) (*domain.Execution, error)
	UpdateExecution(ctx context.Context, execution *domain.Execution) error
	ListExecutions(ctx context.Context, filters ExecutionFilters, pagination PaginationRequest) ([]domain.Execution, int64, error)
	ListExecutionsByExperiment(ctx context.Context, experimentID domain.ExperimentID) ([]domain.Execution, error)
	
	// Target storage
	SaveTarget(ctx context.Context, target *domain.Target) error
	GetTarget(ctx context.Context, id string) (*domain.Target, error)
	UpdateTarget(ctx context.Context, target *domain.Target) error
	DeleteTarget(ctx context.Context, id string) error
	ListTargets(ctx context.Context, filters TargetFilters) ([]domain.Target, error)
	
	// Result storage
	SaveResult(ctx context.Context, result *domain.Result) error
	GetResult(ctx context.Context, id string) (*domain.Result, error)
	GetResultByExecution(ctx context.Context, executionID domain.ExecutionID) (*domain.Result, error)
	ListResults(ctx context.Context, filters ResultFilters, pagination PaginationRequest) ([]domain.Result, int64, error)
	
	// Provider configuration storage
	SaveProviderConfig(ctx context.Context, config domain.ProviderConfig) error
	GetProviderConfig(ctx context.Context, id string) (*domain.ProviderConfig, error)
	UpdateProviderConfig(ctx context.Context, config domain.ProviderConfig) error
	DeleteProviderConfig(ctx context.Context, id string) error
	ListProviderConfigs(ctx context.Context) ([]domain.ProviderConfig, error)
	
	// Event storage
	SaveEvent(ctx context.Context, event domain.DomainEvent) error
	GetEvents(ctx context.Context, aggregateID string, fromVersion int) ([]domain.DomainEvent, error)
	ListEvents(ctx context.Context, filters EventFilters, pagination PaginationRequest) ([]domain.DomainEvent, int64, error)
	
	// Transaction support
	BeginTransaction(ctx context.Context) (Transaction, error)
}

// Transaction defines transaction operations
type Transaction interface {
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
	Store() Store
}

// TargetFilters represents filters for target queries
type TargetFilters struct {
	Type      []domain.TargetType   `json:"type,omitempty"`
	Provider  []string              `json:"provider,omitempty"`
	Region    []string              `json:"region,omitempty"`
	Status    []domain.TargetStatus `json:"status,omitempty"`
	Labels    map[string]string     `json:"labels,omitempty"`
	Tags      map[string]string     `json:"tags,omitempty"`
	Healthy   *bool                 `json:"healthy,omitempty"`
}

// ResultFilters represents filters for result queries
type ResultFilters struct {
	Status        []domain.ResultStatus `json:"status,omitempty"`
	ExperimentID  []domain.ExperimentID `json:"experiment_id,omitempty"`
	ExecutionID   []domain.ExecutionID  `json:"execution_id,omitempty"`
	CreatedBy     []string              `json:"created_by,omitempty"`
	CreatedFrom   *string               `json:"created_from,omitempty"`
	CreatedTo     *string               `json:"created_to,omitempty"`
	MinDuration   *domain.Duration      `json:"min_duration,omitempty"`
	MaxDuration   *domain.Duration      `json:"max_duration,omitempty"`
	HasFailures   *bool                 `json:"has_failures,omitempty"`
	HasViolations *bool                 `json:"has_violations,omitempty"`
}

// EventFilters represents filters for event queries
type EventFilters struct {
	EventType     []string `json:"event_type,omitempty"`
	AggregateType []string `json:"aggregate_type,omitempty"`
	AggregateID   []string `json:"aggregate_id,omitempty"`
	FromTime      *string  `json:"from_time,omitempty"`
	ToTime        *string  `json:"to_time,omitempty"`
}

// Notifier defines the secondary port for notifications
type Notifier interface {
	// Send notifications
	SendNotification(ctx context.Context, notification Notification) error
	SendBulkNotifications(ctx context.Context, notifications []Notification) error
	
	// Notification templates
	SendFromTemplate(ctx context.Context, templateID string, data NotificationData) error
	
	// Channel management
	AddChannel(ctx context.Context, channel NotificationChannel) error
	RemoveChannel(ctx context.Context, channelID string) error
	UpdateChannel(ctx context.Context, channel NotificationChannel) error
	ListChannels(ctx context.Context) ([]NotificationChannel, error)
	TestChannel(ctx context.Context, channelID string) error
	
	// Subscription management
	Subscribe(ctx context.Context, subscription NotificationSubscription) error
	Unsubscribe(ctx context.Context, subscriptionID string) error
	ListSubscriptions(ctx context.Context, userID string) ([]NotificationSubscription, error)
	
	// Notification history
	GetNotificationHistory(ctx context.Context, filters NotificationFilters, pagination PaginationRequest) ([]NotificationRecord, int64, error)
	GetNotificationStatus(ctx context.Context, notificationID string) (*NotificationStatus, error)
}

// Notification represents a notification to be sent
type Notification struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Subject     string                 `json:"subject"`
	Message     string                 `json:"message"`
	Recipients  []NotificationRecipient `json:"recipients"`
	Channels    []string               `json:"channels"`
	Priority    domain.Priority        `json:"priority"`
	Data        map[string]interface{} `json:"data,omitempty"`
	ScheduledAt *string                `json:"scheduled_at,omitempty"`
	ExpiresAt   *string                `json:"expires_at,omitempty"`
	Context     map[string]string      `json:"context,omitempty"`
}

// NotificationRecipient represents a notification recipient
type NotificationRecipient struct {
	Type       string            `json:"type"` // "user", "role", "group", "email"
	ID         string            `json:"id"`
	Name       string            `json:"name,omitempty"`
	Email      string            `json:"email,omitempty"`
	Phone      string            `json:"phone,omitempty"`
	Preferences map[string]bool  `json:"preferences,omitempty"`
}

// NotificationChannel represents a notification channel
type NotificationChannel struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // "email", "slack", "webhook", "sms", "teams"
	Config      map[string]interface{} `json:"config"`
	Enabled     bool                   `json:"enabled"`
	RateLimit   *RateLimit             `json:"rate_limit,omitempty"`
	CreatedAt   string                 `json:"created_at"`
	UpdatedAt   string                 `json:"updated_at"`
}

// RateLimit represents rate limiting configuration
type RateLimit struct {
	MaxRequests int               `json:"max_requests"`
	TimeWindow  domain.Duration   `json:"time_window"`
	BurstLimit  int               `json:"burst_limit"`
}

// NotificationSubscription represents a notification subscription
type NotificationSubscription struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	EventTypes  []string               `json:"event_types"`
	Channels    []string               `json:"channels"`
	Filters     map[string]interface{} `json:"filters,omitempty"`
	Enabled     bool                   `json:"enabled"`
	CreatedAt   string                 `json:"created_at"`
	UpdatedAt   string                 `json:"updated_at"`
}

// NotificationData represents template data for notifications
type NotificationData struct {
	TemplateVars map[string]interface{} `json:"template_vars"`
	Recipients   []NotificationRecipient `json:"recipients"`
	Context      map[string]string      `json:"context,omitempty"`
}

// NotificationRecord represents a sent notification record
type NotificationRecord struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Subject     string                 `json:"subject"`
	Recipients  []NotificationRecipient `json:"recipients"`
	Channels    []string               `json:"channels"`
	Status      string                 `json:"status"`
	SentAt      *string                `json:"sent_at,omitempty"`
	DeliveredAt *string                `json:"delivered_at,omitempty"`
	ReadAt      *string                `json:"read_at,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NotificationStatus represents the status of a notification
type NotificationStatus struct {
	NotificationID string                    `json:"notification_id"`
	Status         string                    `json:"status"`
	ChannelResults []NotificationChannelResult `json:"channel_results"`
	CreatedAt      string                    `json:"created_at"`
	UpdatedAt      string                    `json:"updated_at"`
}

// NotificationChannelResult represents the result for a specific channel
type NotificationChannelResult struct {
	Channel     string    `json:"channel"`
	Status      string    `json:"status"`
	SentAt      *string   `json:"sent_at,omitempty"`
	DeliveredAt *string   `json:"delivered_at,omitempty"`
	Error       string    `json:"error,omitempty"`
	Attempts    int       `json:"attempts"`
}

// NotificationFilters represents filters for notification queries
type NotificationFilters struct {
	Type        []string `json:"type,omitempty"`
	Status      []string `json:"status,omitempty"`
	Recipients  []string `json:"recipients,omitempty"`
	Channels    []string `json:"channels,omitempty"`
	SentFrom    *string  `json:"sent_from,omitempty"`
	SentTo      *string  `json:"sent_to,omitempty"`
}

// SecretManager defines the secondary port for secret management
type SecretManager interface {
	// Secret operations
	StoreSecret(ctx context.Context, key string, value []byte, metadata SecretMetadata) error
	GetSecret(ctx context.Context, key string) ([]byte, error)
	UpdateSecret(ctx context.Context, key string, value []byte, metadata SecretMetadata) error
	DeleteSecret(ctx context.Context, key string) error
	ListSecrets(ctx context.Context, filters SecretFilters) ([]SecretInfo, error)
	
	// Secret versioning
	GetSecretVersion(ctx context.Context, key string, version int) ([]byte, error)
	ListSecretVersions(ctx context.Context, key string) ([]SecretVersion, error)
	
	// Secret rotation
	RotateSecret(ctx context.Context, key string) error
	GetRotationStatus(ctx context.Context, key string) (*RotationStatus, error)
	
	// Encryption/Decryption
	Encrypt(ctx context.Context, plaintext []byte, keyID string) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte, keyID string) ([]byte, error)
	
	// Key management
	CreateKey(ctx context.Context, keyID string, keyType string) error
	DeleteKey(ctx context.Context, keyID string) error
	ListKeys(ctx context.Context) ([]KeyInfo, error)
	
	// Access control
	GrantAccess(ctx context.Context, key string, principal string, permissions []string) error
	RevokeAccess(ctx context.Context, key string, principal string) error
	ListAccess(ctx context.Context, key string) ([]AccessGrant, error)
}

// SecretMetadata represents metadata for a secret
type SecretMetadata struct {
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	TTL         *domain.Duration  `json:"ttl,omitempty"`
	Rotation    *RotationConfig   `json:"rotation,omitempty"`
}

// SecretInfo represents information about a secret
type SecretInfo struct {
	Key         string            `json:"key"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Version     int               `json:"version"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
	ExpiresAt   *string           `json:"expires_at,omitempty"`
}

// SecretVersion represents a version of a secret
type SecretVersion struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
	Active    bool   `json:"active"`
}

// RotationConfig represents secret rotation configuration
type RotationConfig struct {
	Enabled     bool              `json:"enabled"`
	Interval    domain.Duration   `json:"interval"`
	Provider    string            `json:"provider,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

// RotationStatus represents the status of secret rotation
type RotationStatus struct {
	Key            string   `json:"key"`
	LastRotated    *string  `json:"last_rotated,omitempty"`
	NextRotation   *string  `json:"next_rotation,omitempty"`
	Status         string   `json:"status"`
	Error          string   `json:"error,omitempty"`
}

// KeyInfo represents information about an encryption key
type KeyInfo struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
	CreatedAt string `json:"created_at"`
	Status    string `json:"status"`
}

// AccessGrant represents an access grant for a secret
type AccessGrant struct {
	Principal   string   `json:"principal"`
	Permissions []string `json:"permissions"`
	GrantedAt   string   `json:"granted_at"`
	GrantedBy   string   `json:"granted_by"`
	ExpiresAt   *string  `json:"expires_at,omitempty"`
}

// SecretFilters represents filters for secret queries
type SecretFilters struct {
	Keys        []string          `json:"keys,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	CreatedFrom *string           `json:"created_from,omitempty"`
	CreatedTo   *string           `json:"created_to,omitempty"`
	ExpiringBefore *string        `json:"expiring_before,omitempty"`
}

// MetricsCollector defines the secondary port for metrics collection
type MetricsCollector interface {
	// Counter metrics
	IncrementCounter(ctx context.Context, name string, tags map[string]string) error
	IncrementCounterBy(ctx context.Context, name string, value float64, tags map[string]string) error
	
	// Gauge metrics
	SetGauge(ctx context.Context, name string, value float64, tags map[string]string) error
	
	// Histogram metrics
	RecordHistogram(ctx context.Context, name string, value float64, tags map[string]string) error
	
	// Timer metrics
	StartTimer(ctx context.Context, name string, tags map[string]string) Timer
	RecordDuration(ctx context.Context, name string, duration domain.Duration, tags map[string]string) error
	
	// Custom metrics
	RecordMetric(ctx context.Context, metric Metric) error
	RecordBatch(ctx context.Context, metrics []Metric) error
	
	// Metric queries
	GetMetric(ctx context.Context, name string, filters MetricFilters) (*MetricData, error)
	QueryMetrics(ctx context.Context, query MetricQuery) (*MetricQueryResult, error)
	
	// Health and status
	IsHealthy(ctx context.Context) bool
	GetStatus(ctx context.Context) (*MetricsCollectorStatus, error)
	
	// Configuration
	Configure(ctx context.Context, config MetricsConfig) error
	GetConfig(ctx context.Context) (*MetricsConfig, error)
}

// Timer represents a timer for measuring durations
type Timer interface {
	Stop() domain.Duration
	Record() error
}

// Metric represents a metric data point
type Metric struct {
	Name      string                 `json:"name"`
	Type      string                 `json:"type"`
	Value     float64                `json:"value"`
	Tags      map[string]string      `json:"tags,omitempty"`
	Timestamp *string                `json:"timestamp,omitempty"`
	Unit      string                 `json:"unit,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// MetricFilters represents filters for metric queries
type MetricFilters struct {
	Tags      map[string]string `json:"tags,omitempty"`
	From      *string           `json:"from,omitempty"`
	To        *string           `json:"to,omitempty"`
	Aggregation string          `json:"aggregation,omitempty"`
	Granularity string          `json:"granularity,omitempty"`
}

// MetricQuery represents a metric query
type MetricQuery struct {
	Expression  string                 `json:"expression"`
	Filters     MetricFilters          `json:"filters"`
	GroupBy     []string               `json:"group_by,omitempty"`
	OrderBy     string                 `json:"order_by,omitempty"`
	Limit       int                    `json:"limit,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// MetricData represents metric data
type MetricData struct {
	Name        string              `json:"name"`
	Type        string              `json:"type"`
	Unit        string              `json:"unit"`
	Description string              `json:"description"`
	DataPoints  []MetricDataPoint   `json:"data_points"`
	Aggregation MetricAggregation   `json:"aggregation"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// MetricQueryResult represents the result of a metric query
type MetricQueryResult struct {
	Query       MetricQuery         `json:"query"`
	Series      []MetricData        `json:"series"`
	Total       int64               `json:"total"`
	Duration    domain.Duration     `json:"duration"`
	ExecutedAt  string              `json:"executed_at"`
}

// MetricsCollectorStatus represents the status of the metrics collector
type MetricsCollectorStatus struct {
	Healthy         bool                   `json:"healthy"`
	Status          string                 `json:"status"`
	LastMetricTime  *string                `json:"last_metric_time,omitempty"`
	TotalMetrics    int64                  `json:"total_metrics"`
	MetricsPerSecond float64               `json:"metrics_per_second"`
	BufferSize      int                    `json:"buffer_size"`
	BufferUsage     float64                `json:"buffer_usage"`
	Errors          []MetricsError         `json:"errors,omitempty"`
	Uptime          domain.Duration        `json:"uptime"`
}

// MetricsError represents a metrics collection error
type MetricsError struct {
	Type        string `json:"type"`
	Message     string `json:"message"`
	Timestamp   string `json:"timestamp"`
	Count       int64  `json:"count"`
}

// MetricsConfig represents metrics collector configuration
type MetricsConfig struct {
	Enabled         bool                   `json:"enabled"`
	BufferSize      int                    `json:"buffer_size"`
	FlushInterval   domain.Duration        `json:"flush_interval"`
	BatchSize       int                    `json:"batch_size"`
	RetentionPeriod domain.Duration        `json:"retention_period"`
	Endpoints       []MetricsEndpoint      `json:"endpoints"`
	DefaultTags     map[string]string      `json:"default_tags,omitempty"`
	Sampling        *SamplingConfig        `json:"sampling,omitempty"`
}

// MetricsEndpoint represents a metrics endpoint configuration
type MetricsEndpoint struct {
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	URL      string                 `json:"url"`
	Auth     map[string]interface{} `json:"auth,omitempty"`
	Headers  map[string]string      `json:"headers,omitempty"`
	Timeout  domain.Duration        `json:"timeout"`
	Enabled  bool                   `json:"enabled"`
}

// SamplingConfig represents sampling configuration
type SamplingConfig struct {
	Enabled    bool    `json:"enabled"`
	Rate       float64 `json:"rate"`
	MaxPerSecond int   `json:"max_per_second"`
}

// FileStore defines the secondary port for file storage
type FileStore interface {
	// File operations
	StoreFile(ctx context.Context, path string, content io.Reader, metadata FileMetadata) (*FileInfo, error)
	GetFile(ctx context.Context, path string) (io.ReadCloser, error)
	GetFileInfo(ctx context.Context, path string) (*FileInfo, error)
	DeleteFile(ctx context.Context, path string) error
	ListFiles(ctx context.Context, prefix string, filters FileFilters) ([]FileInfo, error)
	
	// Directory operations
	CreateDirectory(ctx context.Context, path string) error
	DeleteDirectory(ctx context.Context, path string, recursive bool) error
	ListDirectory(ctx context.Context, path string) ([]FileInfo, error)
	
	// File operations with streaming
	StreamFile(ctx context.Context, path string) (<-chan []byte, error)
	
	// Temporary files
	CreateTempFile(ctx context.Context, prefix string, content io.Reader) (*FileInfo, error)
	CleanupTempFiles(ctx context.Context, olderThan domain.Duration) error
	
	// Versioning
	GetFileVersions(ctx context.Context, path string) ([]FileVersion, error)
	GetFileVersion(ctx context.Context, path string, version int) (io.ReadCloser, error)
	
	// Access control
	SetFilePermissions(ctx context.Context, path string, permissions FilePermissions) error
	GetFilePermissions(ctx context.Context, path string) (*FilePermissions, error)
}

// FileMetadata represents file metadata
type FileMetadata struct {
	ContentType string            `json:"content_type,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	TTL         *domain.Duration  `json:"ttl,omitempty"`
	Permissions *FilePermissions  `json:"permissions,omitempty"`
	CustomData  map[string]interface{} `json:"custom_data,omitempty"`
}

// FileInfo represents information about a file
type FileInfo struct {
	Path        string            `json:"path"`
	Name        string            `json:"name"`
	Size        int64             `json:"size"`
	ContentType string            `json:"content_type"`
	MD5         string            `json:"md5,omitempty"`
	SHA256      string            `json:"sha256,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Version     int               `json:"version"`
	IsDirectory bool              `json:"is_directory"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
	ExpiresAt   *string           `json:"expires_at,omitempty"`
	URL         string            `json:"url,omitempty"`
}

// FileVersion represents a version of a file
type FileVersion struct {
	Version   int    `json:"version"`
	Size      int64  `json:"size"`
	MD5       string `json:"md5"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
}

// FilePermissions represents file permissions
type FilePermissions struct {
	Owner       string   `json:"owner"`
	Group       string   `json:"group"`
	Permissions string   `json:"permissions"`
	ACL         []ACLEntry `json:"acl,omitempty"`
}

// ACLEntry represents an access control list entry
type ACLEntry struct {
	Principal   string   `json:"principal"`
	Permissions []string `json:"permissions"`
	Type        string   `json:"type"` // "user", "group", "role"
}

// FileFilters represents filters for file queries
type FileFilters struct {
	Extensions    []string          `json:"extensions,omitempty"`
	MinSize       *int64            `json:"min_size,omitempty"`
	MaxSize       *int64            `json:"max_size,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
	CreatedFrom   *string           `json:"created_from,omitempty"`
	CreatedTo     *string           `json:"created_to,omitempty"`
	ContentType   []string          `json:"content_type,omitempty"`
}