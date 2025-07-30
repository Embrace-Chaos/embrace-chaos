package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/google/uuid"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
	"github.com/embrace-chaos/internal/core/ports"
)

// PostgresRepository implements the Store interface using PostgreSQL
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository creates a new PostgreSQL repository
func NewPostgresRepository(db *sql.DB) ports.Store {
	return &PostgresRepository{
		db: db,
	}
}

// Experiment storage operations

// SaveExperiment saves a new experiment using prepared statements
func (r *PostgresRepository) SaveExperiment(ctx context.Context, experiment *domain.Experiment) error {
	query := `
		INSERT INTO experiments (
			id, name, description, status, config, targets, safety,
			labels, metadata, created_at, updated_at, created_by, version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	// Serialize complex fields to JSON
	configJSON, err := json.Marshal(experiment.Config)
	if err != nil {
		return errors.NewStorageError("postgres_save_experiment", fmt.Errorf("failed to marshal config: %w", err))
	}

	targetsJSON, err := json.Marshal(experiment.Targets)
	if err != nil {
		return errors.NewStorageError("postgres_save_experiment", fmt.Errorf("failed to marshal targets: %w", err))
	}

	safetyJSON, err := json.Marshal(experiment.Safety)
	if err != nil {
		return errors.NewStorageError("postgres_save_experiment", fmt.Errorf("failed to marshal safety: %w", err))
	}

	labelsJSON, err := json.Marshal(experiment.Labels)
	if err != nil {
		return errors.NewStorageError("postgres_save_experiment", fmt.Errorf("failed to marshal labels: %w", err))
	}

	metadataJSON, err := json.Marshal(experiment.Metadata)
	if err != nil {
		return errors.NewStorageError("postgres_save_experiment", fmt.Errorf("failed to marshal metadata: %w", err))
	}

	// Execute prepared statement
	_, err = r.db.ExecContext(ctx, query,
		experiment.ID,
		experiment.Name,
		experiment.Description,
		experiment.Status,
		configJSON,
		targetsJSON,
		safetyJSON,
		labelsJSON,
		metadataJSON,
		experiment.CreatedAt,
		experiment.UpdatedAt,
		experiment.CreatedBy,
		experiment.Version,
	)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23505": // unique_violation
				return errors.NewConflictError("experiment with name '%s' already exists", experiment.Name)
			case "23502": // not_null_violation
				return errors.NewValidationError("required field is missing: %s", pqErr.Column)
			}
		}
		return errors.NewStorageError("postgres_save_experiment", err)
	}

	return nil
}

// GetExperiment retrieves an experiment by ID
func (r *PostgresRepository) GetExperiment(ctx context.Context, id domain.ExperimentID) (*domain.Experiment, error) {
	query := `
		SELECT id, name, description, status, config, targets, safety,
			   labels, metadata, created_at, updated_at, created_by, version
		FROM experiments
		WHERE id = $1 AND deleted_at IS NULL`

	var experiment domain.Experiment
	var configJSON, targetsJSON, safetyJSON, labelsJSON, metadataJSON []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&experiment.ID,
		&experiment.Name,
		&experiment.Description,
		&experiment.Status,
		&configJSON,
		&targetsJSON,
		&safetyJSON,
		&labelsJSON,
		&metadataJSON,
		&experiment.CreatedAt,
		&experiment.UpdatedAt,
		&experiment.CreatedBy,
		&experiment.Version,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("experiment not found: %s", id)
		}
		return nil, errors.NewStorageError("postgres_get_experiment", err)
	}

	// Deserialize JSON fields
	if err := r.deserializeExperimentJSON(&experiment, configJSON, targetsJSON, safetyJSON, labelsJSON, metadataJSON); err != nil {
		return nil, err
	}

	return &experiment, nil
}

// GetExperimentByName retrieves an experiment by name
func (r *PostgresRepository) GetExperimentByName(ctx context.Context, name string) (*domain.Experiment, error) {
	query := `
		SELECT id, name, description, status, config, targets, safety,
			   labels, metadata, created_at, updated_at, created_by, version
		FROM experiments
		WHERE name = $1 AND deleted_at IS NULL`

	var experiment domain.Experiment
	var configJSON, targetsJSON, safetyJSON, labelsJSON, metadataJSON []byte

	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&experiment.ID,
		&experiment.Name,
		&experiment.Description,
		&experiment.Status,
		&configJSON,
		&targetsJSON,
		&safetyJSON,
		&labelsJSON,
		&metadataJSON,
		&experiment.CreatedAt,
		&experiment.UpdatedAt,
		&experiment.CreatedBy,
		&experiment.Version,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("experiment not found: %s", name)
		}
		return nil, errors.NewStorageError("postgres_get_experiment_by_name", err)
	}

	// Deserialize JSON fields
	if err := r.deserializeExperimentJSON(&experiment, configJSON, targetsJSON, safetyJSON, labelsJSON, metadataJSON); err != nil {
		return nil, err
	}

	return &experiment, nil
}

// UpdateExperiment updates an existing experiment
func (r *PostgresRepository) UpdateExperiment(ctx context.Context, experiment *domain.Experiment) error {
	query := `
		UPDATE experiments
		SET name = $2, description = $3, status = $4, config = $5, targets = $6,
			safety = $7, labels = $8, metadata = $9, updated_at = $10, version = $11
		WHERE id = $1 AND deleted_at IS NULL`

	// Serialize complex fields
	configJSON, _ := json.Marshal(experiment.Config)
	targetsJSON, _ := json.Marshal(experiment.Targets)
	safetyJSON, _ := json.Marshal(experiment.Safety)
	labelsJSON, _ := json.Marshal(experiment.Labels)
	metadataJSON, _ := json.Marshal(experiment.Metadata)

	result, err := r.db.ExecContext(ctx, query,
		experiment.ID,
		experiment.Name,
		experiment.Description,
		experiment.Status,
		configJSON,
		targetsJSON,
		safetyJSON,
		labelsJSON,
		metadataJSON,
		experiment.UpdatedAt,
		experiment.Version,
	)

	if err != nil {
		return errors.NewStorageError("postgres_update_experiment", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.NewStorageError("postgres_update_experiment", err)
	}

	if rowsAffected == 0 {
		return errors.NewNotFoundError("experiment not found: %s", experiment.ID)
	}

	return nil
}

// DeleteExperiment soft deletes an experiment
func (r *PostgresRepository) DeleteExperiment(ctx context.Context, id domain.ExperimentID) error {
	query := `UPDATE experiments SET deleted_at = $2 WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, id, time.Now())
	if err != nil {
		return errors.NewStorageError("postgres_delete_experiment", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.NewStorageError("postgres_delete_experiment", err)
	}

	if rowsAffected == 0 {
		return errors.NewNotFoundError("experiment not found: %s", id)
	}

	return nil
}

// ListExperiments lists experiments with filters and pagination
func (r *PostgresRepository) ListExperiments(ctx context.Context, filters ports.ExperimentFilters, pagination ports.PaginationRequest) ([]domain.Experiment, int64, error) {
	// Build dynamic query with filters
	baseQuery := `FROM experiments WHERE deleted_at IS NULL`
	var conditions []string
	var args []interface{}
	argCount := 1

	// Apply filters
	if len(filters.Status) > 0 {
		placeholders := make([]string, len(filters.Status))
		for i, status := range filters.Status {
			placeholders[i] = fmt.Sprintf("$%d", argCount)
			args = append(args, status)
			argCount++
		}
		conditions = append(conditions, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(filters.CreatedBy) > 0 {
		placeholders := make([]string, len(filters.CreatedBy))
		for i, createdBy := range filters.CreatedBy {
			placeholders[i] = fmt.Sprintf("$%d", argCount)
			args = append(args, createdBy)
			argCount++
		}
		conditions = append(conditions, fmt.Sprintf("created_by IN (%s)", strings.Join(placeholders, ",")))
	}

	if filters.CreatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argCount))
		args = append(args, *filters.CreatedFrom)
		argCount++
	}

	if filters.CreatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argCount))
		args = append(args, *filters.CreatedTo)
		argCount++
	}

	if filters.NameContains != "" {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argCount))
		args = append(args, "%"+filters.NameContains+"%")
		argCount++
	}

	// Build WHERE clause
	if len(conditions) > 0 {
		baseQuery += " AND " + strings.Join(conditions, " AND ")
	}

	// Count total records
	countQuery := "SELECT COUNT(*) " + baseQuery
	var totalCount int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, errors.NewStorageError("postgres_count_experiments", err)
	}

	// Apply pagination
	orderBy := "created_at DESC"
	if pagination.OrderBy != "" {
		orderBy = pagination.OrderBy
		if pagination.OrderDir == "asc" {
			orderBy += " ASC"
		} else {
			orderBy += " DESC"
		}
	}

	offset := (pagination.Page - 1) * pagination.PageSize
	selectQuery := fmt.Sprintf(`
		SELECT id, name, description, status, config, targets, safety,
			   labels, metadata, created_at, updated_at, created_by, version
		%s
		ORDER BY %s
		LIMIT %d OFFSET %d`,
		baseQuery, orderBy, pagination.PageSize, offset)

	rows, err := r.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, errors.NewStorageError("postgres_list_experiments", err)
	}
	defer rows.Close()

	var experiments []domain.Experiment
	for rows.Next() {
		var experiment domain.Experiment
		var configJSON, targetsJSON, safetyJSON, labelsJSON, metadataJSON []byte

		err := rows.Scan(
			&experiment.ID,
			&experiment.Name,
			&experiment.Description,
			&experiment.Status,
			&configJSON,
			&targetsJSON,
			&safetyJSON,
			&labelsJSON,
			&metadataJSON,
			&experiment.CreatedAt,
			&experiment.UpdatedAt,
			&experiment.CreatedBy,
			&experiment.Version,
		)
		if err != nil {
			return nil, 0, errors.NewStorageError("postgres_scan_experiment", err)
		}

		// Deserialize JSON fields
		if err := r.deserializeExperimentJSON(&experiment, configJSON, targetsJSON, safetyJSON, labelsJSON, metadataJSON); err != nil {
			return nil, 0, err
		}

		experiments = append(experiments, experiment)
	}

	return experiments, totalCount, nil
}

// Execution storage operations

// SaveExecution saves a new execution
func (r *PostgresRepository) SaveExecution(ctx context.Context, execution *domain.Execution) error {
	query := `
		INSERT INTO executions (
			id, experiment_id, status, started_at, completed_at, duration,
			trigger_type, trigger_by, parameters, metadata, created_at, updated_at, version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	parametersJSON, _ := json.Marshal(execution.Parameters)
	metadataJSON, _ := json.Marshal(execution.Metadata)

	var duration *int64
	if execution.Duration > 0 {
		d := int64(execution.Duration / time.Millisecond)
		duration = &d
	}

	_, err := r.db.ExecContext(ctx, query,
		execution.ID,
		execution.ExperimentID,
		execution.Status,
		execution.StartedAt,
		execution.CompletedAt,
		duration,
		execution.TriggerType,
		execution.TriggerBy,
		parametersJSON,
		metadataJSON,
		execution.CreatedAt,
		execution.UpdatedAt,
		execution.Version,
	)

	if err != nil {
		return errors.NewStorageError("postgres_save_execution", err)
	}

	return nil
}

// GetExecution retrieves an execution by ID
func (r *PostgresRepository) GetExecution(ctx context.Context, id domain.ExecutionID) (*domain.Execution, error) {
	query := `
		SELECT id, experiment_id, status, started_at, completed_at, duration,
			   trigger_type, trigger_by, parameters, metadata, created_at, updated_at, version
		FROM executions
		WHERE id = $1`

	var execution domain.Execution
	var parametersJSON, metadataJSON []byte
	var duration sql.NullInt64

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&execution.ID,
		&execution.ExperimentID,
		&execution.Status,
		&execution.StartedAt,
		&execution.CompletedAt,
		&duration,
		&execution.TriggerType,
		&execution.TriggerBy,
		&parametersJSON,
		&metadataJSON,
		&execution.CreatedAt,
		&execution.UpdatedAt,
		&execution.Version,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("execution not found: %s", id)
		}
		return nil, errors.NewStorageError("postgres_get_execution", err)
	}

	// Deserialize JSON fields
	if err := json.Unmarshal(parametersJSON, &execution.Parameters); err != nil {
		return nil, errors.NewStorageError("postgres_unmarshal_parameters", err)
	}
	if err := json.Unmarshal(metadataJSON, &execution.Metadata); err != nil {
		return nil, errors.NewStorageError("postgres_unmarshal_metadata", err)
	}

	if duration.Valid {
		execution.Duration = time.Duration(duration.Int64) * time.Millisecond
	}

	return &execution, nil
}

// UpdateExecution updates an existing execution
func (r *PostgresRepository) UpdateExecution(ctx context.Context, execution *domain.Execution) error {
	query := `
		UPDATE executions
		SET status = $2, completed_at = $3, duration = $4, metadata = $5, updated_at = $6, version = $7
		WHERE id = $1`

	metadataJSON, _ := json.Marshal(execution.Metadata)

	var duration *int64
	if execution.Duration > 0 {
		d := int64(execution.Duration / time.Millisecond)
		duration = &d
	}

	result, err := r.db.ExecContext(ctx, query,
		execution.ID,
		execution.Status,
		execution.CompletedAt,
		duration,
		metadataJSON,
		execution.UpdatedAt,
		execution.Version,
	)

	if err != nil {
		return errors.NewStorageError("postgres_update_execution", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.NewStorageError("postgres_update_execution", err)
	}

	if rowsAffected == 0 {
		return errors.NewNotFoundError("execution not found: %s", execution.ID)
	}

	return nil
}

// Target storage operations

// SaveTarget saves a new target
func (r *PostgresRepository) SaveTarget(ctx context.Context, target *domain.Target) error {
	query := `
		INSERT INTO targets (
			id, resource_id, name, type, provider, region, tags, status,
			metadata, last_discovered, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	tagsJSON, _ := json.Marshal(target.Tags)
	metadataJSON, _ := json.Marshal(target.Metadata)

	// Generate UUID if not set
	if target.ID == "" {
		target.ID = uuid.New().String()
	}

	_, err := r.db.ExecContext(ctx, query,
		target.ID,
		target.ResourceID,
		target.Name,
		target.Type,
		target.Provider,
		target.Region,
		tagsJSON,
		target.Status,
		metadataJSON,
		time.Now(), // last_discovered
		target.CreatedAt,
		target.UpdatedAt,
	)

	if err != nil {
		return errors.NewStorageError("postgres_save_target", err)
	}

	return nil
}

// GetTarget retrieves a target by ID
func (r *PostgresRepository) GetTarget(ctx context.Context, id string) (*domain.Target, error) {
	query := `
		SELECT id, resource_id, name, type, provider, region, tags, status,
			   metadata, last_discovered, created_at, updated_at
		FROM targets
		WHERE id = $1 AND deleted_at IS NULL`

	var target domain.Target
	var tagsJSON, metadataJSON []byte
	var lastDiscovered time.Time

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&target.ID,
		&target.ResourceID,
		&target.Name,
		&target.Type,
		&target.Provider,
		&target.Region,
		&tagsJSON,
		&target.Status,
		&metadataJSON,
		&lastDiscovered,
		&target.CreatedAt,
		&target.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("target not found: %s", id)
		}
		return nil, errors.NewStorageError("postgres_get_target", err)
	}

	// Deserialize JSON fields
	if err := json.Unmarshal(tagsJSON, &target.Tags); err != nil {
		return nil, errors.NewStorageError("postgres_unmarshal_tags", err)
	}
	if err := json.Unmarshal(metadataJSON, &target.Metadata); err != nil {
		return nil, errors.NewStorageError("postgres_unmarshal_metadata", err)
	}

	return &target, nil
}

// Result storage operations

// SaveResult saves experiment results
func (r *PostgresRepository) SaveResult(ctx context.Context, result *domain.Result) error {
	query := `
		INSERT INTO results (
			id, execution_id, experiment_id, status, summary, metrics,
			errors, target_results, duration, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	metricsJSON, _ := json.Marshal(result.Metrics)
	errorsJSON, _ := json.Marshal(result.Errors)
	targetResultsJSON, _ := json.Marshal(result.TargetResults)

	// Generate UUID if not set
	if result.ID == "" {
		result.ID = uuid.New().String()
	}

	var duration *int64
	if result.Duration > 0 {
		d := int64(result.Duration / time.Millisecond)
		duration = &d
	}

	_, err := r.db.ExecContext(ctx, query,
		result.ID,
		result.ExecutionID,
		result.ExperimentID,
		result.Status,
		result.Summary,
		metricsJSON,
		errorsJSON,
		targetResultsJSON,
		duration,
		result.CreatedAt,
		result.UpdatedAt,
	)

	if err != nil {
		return errors.NewStorageError("postgres_save_result", err)
	}

	return nil
}

// GetResult retrieves a result by ID
func (r *PostgresRepository) GetResult(ctx context.Context, id string) (*domain.Result, error) {
	query := `
		SELECT id, execution_id, experiment_id, status, summary, metrics,
			   errors, target_results, duration, created_at, updated_at
		FROM results
		WHERE id = $1`

	var result domain.Result
	var metricsJSON, errorsJSON, targetResultsJSON []byte
	var duration sql.NullInt64

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&result.ID,
		&result.ExecutionID,
		&result.ExperimentID,
		&result.Status,
		&result.Summary,
		&metricsJSON,
		&errorsJSON,
		&targetResultsJSON,
		&duration,
		&result.CreatedAt,
		&result.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("result not found: %s", id)
		}
		return nil, errors.NewStorageError("postgres_get_result", err)
	}

	// Deserialize JSON fields
	if err := json.Unmarshal(metricsJSON, &result.Metrics); err != nil {
		return nil, errors.NewStorageError("postgres_unmarshal_metrics", err)
	}
	if err := json.Unmarshal(errorsJSON, &result.Errors); err != nil {
		return nil, errors.NewStorageError("postgres_unmarshal_errors", err)
	}
	if err := json.Unmarshal(targetResultsJSON, &result.TargetResults); err != nil {
		return nil, errors.NewStorageError("postgres_unmarshal_target_results", err)
	}

	if duration.Valid {
		result.Duration = time.Duration(duration.Int64) * time.Millisecond
	}

	return &result, nil
}

// Event storage operations

// SaveEvent saves a domain event
func (r *PostgresRepository) SaveEvent(ctx context.Context, event domain.DomainEvent) error {
	query := `
		INSERT INTO domain_events (
			id, aggregate_id, aggregate_type, event_type, event_version,
			payload, metadata, occurred_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	payloadJSON, _ := json.Marshal(event.GetEventData())
	metadataJSON, _ := json.Marshal(event.GetMetadata())

	_, err := r.db.ExecContext(ctx, query,
		uuid.New(),
		event.GetAggregateID(),
		event.GetAggregateType(),
		event.GetEventType(),
		event.GetEventVersion(),
		payloadJSON,
		metadataJSON,
		event.GetOccurredAt(),
		time.Now(),
	)

	if err != nil {
		return errors.NewStorageError("postgres_save_event", err)
	}

	return nil
}

// Transaction support

// BeginTransaction starts a new database transaction
func (r *PostgresRepository) BeginTransaction(ctx context.Context) (ports.Transaction, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return nil, errors.NewStorageError("postgres_begin_transaction", err)
	}

	return &postgresTransaction{
		tx:   tx,
		repo: r,
	}, nil
}

// Helper methods

func (r *PostgresRepository) deserializeExperimentJSON(experiment *domain.Experiment, configJSON, targetsJSON, safetyJSON, labelsJSON, metadataJSON []byte) error {
	if err := json.Unmarshal(configJSON, &experiment.Config); err != nil {
		return errors.NewStorageError("postgres_unmarshal_config", err)
	}

	if err := json.Unmarshal(targetsJSON, &experiment.Targets); err != nil {
		return errors.NewStorageError("postgres_unmarshal_targets", err)
	}

	if err := json.Unmarshal(safetyJSON, &experiment.Safety); err != nil {
		return errors.NewStorageError("postgres_unmarshal_safety", err)
	}

	if err := json.Unmarshal(labelsJSON, &experiment.Labels); err != nil {
		return errors.NewStorageError("postgres_unmarshal_labels", err)
	}

	if err := json.Unmarshal(metadataJSON, &experiment.Metadata); err != nil {
		return errors.NewStorageError("postgres_unmarshal_metadata", err)
	}

	return nil
}

// Additional required methods to fully implement the Store interface

// ListExecutions lists executions with filters and pagination
func (r *PostgresRepository) ListExecutions(ctx context.Context, filters ports.ExecutionFilters, pagination ports.PaginationRequest) ([]domain.Execution, int64, error) {
	// Implementation similar to ListExperiments
	return nil, 0, nil
}

// ListExecutionsByExperiment lists all executions for a specific experiment
func (r *PostgresRepository) ListExecutionsByExperiment(ctx context.Context, experimentID domain.ExperimentID) ([]domain.Execution, error) {
	query := `
		SELECT id, experiment_id, status, started_at, completed_at, duration,
			   trigger_type, trigger_by, parameters, metadata, created_at, updated_at, version
		FROM executions
		WHERE experiment_id = $1
		ORDER BY started_at DESC`

	rows, err := r.db.QueryContext(ctx, query, experimentID)
	if err != nil {
		return nil, errors.NewStorageError("postgres_list_executions_by_experiment", err)
	}
	defer rows.Close()

	var executions []domain.Execution
	for rows.Next() {
		var execution domain.Execution
		var parametersJSON, metadataJSON []byte
		var duration sql.NullInt64

		err := rows.Scan(
			&execution.ID,
			&execution.ExperimentID,
			&execution.Status,
			&execution.StartedAt,
			&execution.CompletedAt,
			&duration,
			&execution.TriggerType,
			&execution.TriggerBy,
			&parametersJSON,
			&metadataJSON,
			&execution.CreatedAt,
			&execution.UpdatedAt,
			&execution.Version,
		)
		if err != nil {
			return nil, errors.NewStorageError("postgres_scan_execution", err)
		}

		// Deserialize JSON fields
		json.Unmarshal(parametersJSON, &execution.Parameters)
		json.Unmarshal(metadataJSON, &execution.Metadata)

		if duration.Valid {
			execution.Duration = time.Duration(duration.Int64) * time.Millisecond
		}

		executions = append(executions, execution)
	}

	return executions, nil
}

// UpdateTarget updates an existing target
func (r *PostgresRepository) UpdateTarget(ctx context.Context, target *domain.Target) error {
	query := `
		UPDATE targets
		SET resource_id = $2, name = $3, type = $4, provider = $5, region = $6,
			tags = $7, status = $8, metadata = $9, last_discovered = $10, updated_at = $11
		WHERE id = $1 AND deleted_at IS NULL`

	tagsJSON, _ := json.Marshal(target.Tags)
	metadataJSON, _ := json.Marshal(target.Metadata)

	result, err := r.db.ExecContext(ctx, query,
		target.ID,
		target.ResourceID,
		target.Name,
		target.Type,
		target.Provider,
		target.Region,
		tagsJSON,
		target.Status,
		metadataJSON,
		time.Now(),
		target.UpdatedAt,
	)

	if err != nil {
		return errors.NewStorageError("postgres_update_target", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.NewStorageError("postgres_update_target", err)
	}

	if rowsAffected == 0 {
		return errors.NewNotFoundError("target not found: %s", target.ID)
	}

	return nil
}

// DeleteTarget soft deletes a target
func (r *PostgresRepository) DeleteTarget(ctx context.Context, id string) error {
	query := `UPDATE targets SET deleted_at = $2 WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, id, time.Now())
	if err != nil {
		return errors.NewStorageError("postgres_delete_target", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.NewStorageError("postgres_delete_target", err)
	}

	if rowsAffected == 0 {
		return errors.NewNotFoundError("target not found: %s", id)
	}

	return nil
}

// ListTargets lists targets with filters
func (r *PostgresRepository) ListTargets(ctx context.Context, filters ports.TargetFilters) ([]domain.Target, error) {
	// Build dynamic query with filters
	baseQuery := `
		SELECT id, resource_id, name, type, provider, region, tags, status,
			   metadata, last_discovered, created_at, updated_at
		FROM targets
		WHERE deleted_at IS NULL`

	var conditions []string
	var args []interface{}
	argCount := 1

	// Apply filters (similar pattern to ListExperiments)
	// ... filter implementation ...

	query := baseQuery
	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY created_at DESC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewStorageError("postgres_list_targets", err)
	}
	defer rows.Close()

	var targets []domain.Target
	for rows.Next() {
		var target domain.Target
		var tagsJSON, metadataJSON []byte
		var lastDiscovered time.Time

		err := rows.Scan(
			&target.ID,
			&target.ResourceID,
			&target.Name,
			&target.Type,
			&target.Provider,
			&target.Region,
			&tagsJSON,
			&target.Status,
			&metadataJSON,
			&lastDiscovered,
			&target.CreatedAt,
			&target.UpdatedAt,
		)
		if err != nil {
			return nil, errors.NewStorageError("postgres_scan_target", err)
		}

		// Deserialize JSON fields
		json.Unmarshal(tagsJSON, &target.Tags)
		json.Unmarshal(metadataJSON, &target.Metadata)

		targets = append(targets, target)
	}

	return targets, nil
}

// GetResultByExecution retrieves results by execution ID
func (r *PostgresRepository) GetResultByExecution(ctx context.Context, executionID domain.ExecutionID) (*domain.Result, error) {
	query := `
		SELECT id, execution_id, experiment_id, status, summary, metrics,
			   errors, target_results, duration, created_at, updated_at
		FROM results
		WHERE execution_id = $1`

	var result domain.Result
	var metricsJSON, errorsJSON, targetResultsJSON []byte
	var duration sql.NullInt64

	err := r.db.QueryRowContext(ctx, query, executionID).Scan(
		&result.ID,
		&result.ExecutionID,
		&result.ExperimentID,
		&result.Status,
		&result.Summary,
		&metricsJSON,
		&errorsJSON,
		&targetResultsJSON,
		&duration,
		&result.CreatedAt,
		&result.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("result not found for execution: %s", executionID)
		}
		return nil, errors.NewStorageError("postgres_get_result_by_execution", err)
	}

	// Deserialize JSON fields
	json.Unmarshal(metricsJSON, &result.Metrics)
	json.Unmarshal(errorsJSON, &result.Errors)
	json.Unmarshal(targetResultsJSON, &result.TargetResults)

	if duration.Valid {
		result.Duration = time.Duration(duration.Int64) * time.Millisecond
	}

	return &result, nil
}

// ListResults lists results with filters and pagination
func (r *PostgresRepository) ListResults(ctx context.Context, filters ports.ResultFilters, pagination ports.PaginationRequest) ([]domain.Result, int64, error) {
	// Implementation similar to ListExperiments
	return nil, 0, nil
}

// Provider configuration operations

// SaveProviderConfig saves a provider configuration
func (r *PostgresRepository) SaveProviderConfig(ctx context.Context, config domain.ProviderConfig) error {
	query := `
		INSERT INTO provider_configs (
			id, name, provider, config, capabilities, status,
			last_health_check, created_at, updated_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	configJSON, _ := json.Marshal(config.Config)
	capabilitiesJSON, _ := json.Marshal(config.Capabilities)

	_, err := r.db.ExecContext(ctx, query,
		config.ID,
		config.Name,
		config.Provider,
		configJSON,
		capabilitiesJSON,
		config.Status,
		config.LastHealthCheck,
		config.CreatedAt,
		config.UpdatedAt,
		config.CreatedBy,
	)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return errors.NewConflictError("provider config with name '%s' already exists", config.Name)
		}
		return errors.NewStorageError("postgres_save_provider_config", err)
	}

	return nil
}

// GetProviderConfig retrieves a provider configuration by ID
func (r *PostgresRepository) GetProviderConfig(ctx context.Context, id string) (*domain.ProviderConfig, error) {
	query := `
		SELECT id, name, provider, config, capabilities, status,
			   last_health_check, created_at, updated_at, created_by
		FROM provider_configs
		WHERE id = $1 AND deleted_at IS NULL`

	var config domain.ProviderConfig
	var configJSON, capabilitiesJSON []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&config.ID,
		&config.Name,
		&config.Provider,
		&configJSON,
		&capabilitiesJSON,
		&config.Status,
		&config.LastHealthCheck,
		&config.CreatedAt,
		&config.UpdatedAt,
		&config.CreatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("provider config not found: %s", id)
		}
		return nil, errors.NewStorageError("postgres_get_provider_config", err)
	}

	// Deserialize JSON fields
	json.Unmarshal(configJSON, &config.Config)
	json.Unmarshal(capabilitiesJSON, &config.Capabilities)

	return &config, nil
}

// UpdateProviderConfig updates a provider configuration
func (r *PostgresRepository) UpdateProviderConfig(ctx context.Context, config domain.ProviderConfig) error {
	query := `
		UPDATE provider_configs
		SET name = $2, provider = $3, config = $4, capabilities = $5, status = $6,
			last_health_check = $7, updated_at = $8
		WHERE id = $1 AND deleted_at IS NULL`

	configJSON, _ := json.Marshal(config.Config)
	capabilitiesJSON, _ := json.Marshal(config.Capabilities)

	result, err := r.db.ExecContext(ctx, query,
		config.ID,
		config.Name,
		config.Provider,
		configJSON,
		capabilitiesJSON,
		config.Status,
		config.LastHealthCheck,
		config.UpdatedAt,
	)

	if err != nil {
		return errors.NewStorageError("postgres_update_provider_config", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.NewStorageError("postgres_update_provider_config", err)
	}

	if rowsAffected == 0 {
		return errors.NewNotFoundError("provider config not found: %s", config.ID)
	}

	return nil
}

// DeleteProviderConfig soft deletes a provider configuration
func (r *PostgresRepository) DeleteProviderConfig(ctx context.Context, id string) error {
	query := `UPDATE provider_configs SET deleted_at = $2 WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, id, time.Now())
	if err != nil {
		return errors.NewStorageError("postgres_delete_provider_config", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.NewStorageError("postgres_delete_provider_config", err)
	}

	if rowsAffected == 0 {
		return errors.NewNotFoundError("provider config not found: %s", id)
	}

	return nil
}

// ListProviderConfigs lists all provider configurations
func (r *PostgresRepository) ListProviderConfigs(ctx context.Context) ([]domain.ProviderConfig, error) {
	query := `
		SELECT id, name, provider, config, capabilities, status,
			   last_health_check, created_at, updated_at, created_by
		FROM provider_configs
		WHERE deleted_at IS NULL
		ORDER BY name`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.NewStorageError("postgres_list_provider_configs", err)
	}
	defer rows.Close()

	var configs []domain.ProviderConfig
	for rows.Next() {
		var config domain.ProviderConfig
		var configJSON, capabilitiesJSON []byte

		err := rows.Scan(
			&config.ID,
			&config.Name,
			&config.Provider,
			&configJSON,
			&capabilitiesJSON,
			&config.Status,
			&config.LastHealthCheck,
			&config.CreatedAt,
			&config.UpdatedAt,
			&config.CreatedBy,
		)
		if err != nil {
			return nil, errors.NewStorageError("postgres_scan_provider_config", err)
		}

		// Deserialize JSON fields
		json.Unmarshal(configJSON, &config.Config)
		json.Unmarshal(capabilitiesJSON, &config.Capabilities)

		configs = append(configs, config)
	}

	return configs, nil
}

// GetEvents retrieves events for an aggregate
func (r *PostgresRepository) GetEvents(ctx context.Context, aggregateID string, fromVersion int) ([]domain.DomainEvent, error) {
	query := `
		SELECT aggregate_id, aggregate_type, event_type, event_version,
			   payload, metadata, occurred_at
		FROM domain_events
		WHERE aggregate_id = $1 AND event_version >= $2
		ORDER BY event_version`

	rows, err := r.db.QueryContext(ctx, query, aggregateID, fromVersion)
	if err != nil {
		return nil, errors.NewStorageError("postgres_get_events", err)
	}
	defer rows.Close()

	var events []domain.DomainEvent
	// Note: In a real implementation, you would need to deserialize the events
	// based on their type and reconstruct the proper domain event types

	return events, nil
}

// ListEvents lists events with filters and pagination
func (r *PostgresRepository) ListEvents(ctx context.Context, filters ports.EventFilters, pagination ports.PaginationRequest) ([]domain.DomainEvent, int64, error) {
	// Implementation similar to ListExperiments
	return nil, 0, nil
}

// postgresTransaction implements the Transaction interface
type postgresTransaction struct {
	tx   *sql.Tx
	repo *PostgresRepository
}

func (t *postgresTransaction) Commit(ctx context.Context) error {
	if err := t.tx.Commit(); err != nil {
		return errors.NewStorageError("postgres_commit_transaction", err)
	}
	return nil
}

func (t *postgresTransaction) Rollback(ctx context.Context) error {
	if err := t.tx.Rollback(); err != nil {
		return errors.NewStorageError("postgres_rollback_transaction", err)
	}
	return nil
}

func (t *postgresTransaction) Store() ports.Store {
	// Return a new repository instance that uses the transaction
	return &PostgresRepository{
		db: t.tx,
	}
}