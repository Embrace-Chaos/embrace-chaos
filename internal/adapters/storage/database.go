package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/embrace-chaos/internal/core/domain"
)

// DatabaseAdapter defines the secure database interface that enforces prepared statements
// This interface ensures all SQL operations use prepared statements to prevent SQL injection attacks
type DatabaseAdapter interface {
	// Connection management
	Connect(ctx context.Context, dsn string) error
	Close() error
	Ping(ctx context.Context) error
	
	// Transaction management
	BeginTx(ctx context.Context) (Transaction, error)
	
	// Prepared statement management
	PrepareStatement(ctx context.Context, query string) (PreparedStatement, error)
	
	// Migration support
	Migrate(ctx context.Context, version int) error
	GetSchemaVersion(ctx context.Context) (int, error)
}

// Transaction represents a database transaction with prepared statement support
type Transaction interface {
	// Statement preparation within transaction
	PrepareStatement(ctx context.Context, query string) (PreparedStatement, error)
	
	// Transaction control
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
	
	// Helper methods for common operations
	ExecPrepared(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryPrepared(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowPrepared(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// PreparedStatement represents a prepared SQL statement
type PreparedStatement interface {
	// Execute the prepared statement
	Exec(ctx context.Context, args ...interface{}) (sql.Result, error)
	Query(ctx context.Context, args ...interface{}) (*sql.Rows, error)
	QueryRow(ctx context.Context, args ...interface{}) *sql.Row
	
	// Close the prepared statement
	Close() error
}

// SecureRepository defines repository operations using only prepared statements
type SecureRepository interface {
	// Experiment operations
	SaveExperiment(ctx context.Context, tx Transaction, experiment *domain.Experiment) error
	GetExperiment(ctx context.Context, tx Transaction, id domain.ExperimentID) (*domain.Experiment, error)
	GetExperimentByName(ctx context.Context, tx Transaction, name string) (*domain.Experiment, error)
	UpdateExperiment(ctx context.Context, tx Transaction, experiment *domain.Experiment) error
	DeleteExperiment(ctx context.Context, tx Transaction, id domain.ExperimentID) error
	ListExperiments(ctx context.Context, tx Transaction, filters ExperimentFilters, pagination PaginationRequest) ([]domain.Experiment, int64, error)
	
	// Execution operations
	SaveExecution(ctx context.Context, tx Transaction, execution *domain.Execution) error
	GetExecution(ctx context.Context, tx Transaction, id domain.ExecutionID) (*domain.Execution, error)
	UpdateExecution(ctx context.Context, tx Transaction, execution *domain.Execution) error
	ListExecutions(ctx context.Context, tx Transaction, filters ExecutionFilters, pagination PaginationRequest) ([]domain.Execution, int64, error)
	ListExecutionsByExperiment(ctx context.Context, tx Transaction, experimentID domain.ExperimentID) ([]domain.Execution, error)
	
	// Target operations
	SaveTarget(ctx context.Context, tx Transaction, target *domain.Target) error
	GetTarget(ctx context.Context, tx Transaction, id string) (*domain.Target, error)
	UpdateTarget(ctx context.Context, tx Transaction, target *domain.Target) error
	DeleteTarget(ctx context.Context, tx Transaction, id string) error
	ListTargets(ctx context.Context, tx Transaction, filters TargetFilters) ([]domain.Target, error)
	
	// Result operations
	SaveResult(ctx context.Context, tx Transaction, result *domain.Result) error
	GetResult(ctx context.Context, tx Transaction, id string) (*domain.Result, error)
	GetResultByExecution(ctx context.Context, tx Transaction, executionID domain.ExecutionID) (*domain.Result, error)
	ListResults(ctx context.Context, tx Transaction, filters ResultFilters, pagination PaginationRequest) ([]domain.Result, int64, error)
	
	// Provider configuration operations
	SaveProviderConfig(ctx context.Context, tx Transaction, config domain.ProviderConfig) error
	GetProviderConfig(ctx context.Context, tx Transaction, id string) (*domain.ProviderConfig, error)
	UpdateProviderConfig(ctx context.Context, tx Transaction, config domain.ProviderConfig) error
	DeleteProviderConfig(ctx context.Context, tx Transaction, id string) error
	ListProviderConfigs(ctx context.Context, tx Transaction) ([]domain.ProviderConfig, error)
	
	// Event operations
	SaveEvent(ctx context.Context, tx Transaction, event domain.DomainEvent) error
	GetEvents(ctx context.Context, tx Transaction, aggregateID string, fromVersion int) ([]domain.DomainEvent, error)
	ListEvents(ctx context.Context, tx Transaction, filters EventFilters, pagination PaginationRequest) ([]domain.DomainEvent, int64, error)
}

// Filter and pagination types
type ExperimentFilters struct {
	Status       []domain.ExperimentStatus `json:"status,omitempty"`
	CreatedBy    []string                  `json:"created_by,omitempty"`
	CreatedFrom  *time.Time                `json:"created_from,omitempty"`
	CreatedTo    *time.Time                `json:"created_to,omitempty"`
	Tags         map[string]string         `json:"tags,omitempty"`
	NameContains string                    `json:"name_contains,omitempty"`
}

type ExecutionFilters struct {
	Status        []domain.ExecutionStatus `json:"status,omitempty"`
	ExperimentID  []domain.ExperimentID    `json:"experiment_id,omitempty"`
	CreatedBy     []string                 `json:"created_by,omitempty"`
	CreatedFrom   *time.Time               `json:"created_from,omitempty"`
	CreatedTo     *time.Time               `json:"created_to,omitempty"`
	MinDuration   *domain.Duration         `json:"min_duration,omitempty"`
	MaxDuration   *domain.Duration         `json:"max_duration,omitempty"`
}

type TargetFilters struct {
	Type      []domain.TargetType   `json:"type,omitempty"`
	Provider  []string              `json:"provider,omitempty"`
	Region    []string              `json:"region,omitempty"`
	Status    []domain.TargetStatus `json:"status,omitempty"`
	Labels    map[string]string     `json:"labels,omitempty"`
	Tags      map[string]string     `json:"tags,omitempty"`
	Healthy   *bool                 `json:"healthy,omitempty"`
}

type ResultFilters struct {
	Status        []domain.ResultStatus `json:"status,omitempty"`
	ExperimentID  []domain.ExperimentID `json:"experiment_id,omitempty"`
	ExecutionID   []domain.ExecutionID  `json:"execution_id,omitempty"`
	CreatedBy     []string              `json:"created_by,omitempty"`
	CreatedFrom   *time.Time            `json:"created_from,omitempty"`
	CreatedTo     *time.Time            `json:"created_to,omitempty"`
	MinDuration   *domain.Duration      `json:"min_duration,omitempty"`
	MaxDuration   *domain.Duration      `json:"max_duration,omitempty"`
	HasFailures   *bool                 `json:"has_failures,omitempty"`
	HasViolations *bool                 `json:"has_violations,omitempty"`
}

type EventFilters struct {
	EventType     []string   `json:"event_type,omitempty"`
	AggregateType []string   `json:"aggregate_type,omitempty"`
	AggregateID   []string   `json:"aggregate_id,omitempty"`
	FromTime      *time.Time `json:"from_time,omitempty"`
	ToTime        *time.Time `json:"to_time,omitempty"`
}

type PaginationRequest struct {
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
	OrderBy  string `json:"order_by,omitempty"`
	OrderDir string `json:"order_dir,omitempty"` // "asc" or "desc"
}

// SecurityConfig defines security settings for database operations
type SecurityConfig struct {
	// Prepared statement settings
	MaxPreparedStatements int           `json:"max_prepared_statements"`
	StatementTimeout      time.Duration `json:"statement_timeout"`
	
	// Connection security
	RequireSSL            bool   `json:"require_ssl"`
	SSLMode              string `json:"ssl_mode"`
	SSLCert              string `json:"ssl_cert,omitempty"`
	SSLKey               string `json:"ssl_key,omitempty"`
	SSLRootCert          string `json:"ssl_root_cert,omitempty"`
	
	// Query validation
	MaxQueryLength        int      `json:"max_query_length"`
	AllowedOperations     []string `json:"allowed_operations"` // SELECT, INSERT, UPDATE, DELETE
	ForbiddenKeywords     []string `json:"forbidden_keywords"` // DROP, TRUNCATE, etc.
	
	// Audit settings
	AuditQueries          bool `json:"audit_queries"`
	AuditParameters       bool `json:"audit_parameters"`
	AuditSlowQueries      bool `json:"audit_slow_queries"`
	SlowQueryThreshold    time.Duration `json:"slow_query_threshold"`
}

// QueryValidator validates SQL queries before execution
type QueryValidator interface {
	ValidateQuery(ctx context.Context, query string) error
	ValidateParameters(ctx context.Context, query string, params []interface{}) error
	SanitizeQuery(ctx context.Context, query string) (string, error)
}

// AuditLogger logs database operations for security monitoring
type AuditLogger interface {
	LogQuery(ctx context.Context, query string, params []interface{}, duration time.Duration, err error)
	LogTransaction(ctx context.Context, operation string, duration time.Duration, err error)
	LogSlowQuery(ctx context.Context, query string, params []interface{}, duration time.Duration)
}