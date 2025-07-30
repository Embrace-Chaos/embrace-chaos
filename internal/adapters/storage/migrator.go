package storage

import (
	"database/sql"
	"embed"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/embrace-chaos/internal/core/errors"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrator handles database migrations
type Migrator struct {
	db *sql.DB
}

// NewMigrator creates a new database migrator
func NewMigrator(db *sql.DB) *Migrator {
	return &Migrator{
		db: db,
	}
}

// Migrate runs all pending migrations
func (m *Migrator) Migrate() error {
	driver, err := postgres.WithInstance(m.db, &postgres.Config{})
	if err != nil {
		return errors.NewStorageError("migrator_create_driver", err)
	}

	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return errors.NewStorageError("migrator_create_source", err)
	}

	migration, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return errors.NewStorageError("migrator_create_migration", err)
	}

	if err := migration.Up(); err != nil && err != migrate.ErrNoChange {
		return errors.NewStorageError("migrator_run_migration", err)
	}

	return nil
}

// MigrateUp runs n migrations up
func (m *Migrator) MigrateUp(n int) error {
	driver, err := postgres.WithInstance(m.db, &postgres.Config{})
	if err != nil {
		return errors.NewStorageError("migrator_create_driver", err)
	}

	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return errors.NewStorageError("migrator_create_source", err)
	}

	migration, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return errors.NewStorageError("migrator_create_migration", err)
	}

	if err := migration.Steps(n); err != nil && err != migrate.ErrNoChange {
		return errors.NewStorageError("migrator_run_steps", err)
	}

	return nil
}

// MigrateDown runs n migrations down
func (m *Migrator) MigrateDown(n int) error {
	driver, err := postgres.WithInstance(m.db, &postgres.Config{})
	if err != nil {
		return errors.NewStorageError("migrator_create_driver", err)
	}

	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return errors.NewStorageError("migrator_create_source", err)
	}

	migration, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return errors.NewStorageError("migrator_create_migration", err)
	}

	if err := migration.Steps(-n); err != nil && err != migrate.ErrNoChange {
		return errors.NewStorageError("migrator_run_steps", err)
	}

	return nil
}

// MigrateToVersion migrates to a specific version
func (m *Migrator) MigrateToVersion(version uint) error {
	driver, err := postgres.WithInstance(m.db, &postgres.Config{})
	if err != nil {
		return errors.NewStorageError("migrator_create_driver", err)
	}

	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return errors.NewStorageError("migrator_create_source", err)
	}

	migration, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return errors.NewStorageError("migrator_create_migration", err)
	}

	if err := migration.Migrate(version); err != nil && err != migrate.ErrNoChange {
		return errors.NewStorageError("migrator_migrate_to_version", err)
	}

	return nil
}

// GetVersion returns the current migration version
func (m *Migrator) GetVersion() (uint, bool, error) {
	driver, err := postgres.WithInstance(m.db, &postgres.Config{})
	if err != nil {
		return 0, false, errors.NewStorageError("migrator_create_driver", err)
	}

	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return 0, false, errors.NewStorageError("migrator_create_source", err)
	}

	migration, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return 0, false, errors.NewStorageError("migrator_create_migration", err)
	}

	version, dirty, err := migration.Version()
	if err != nil {
		return 0, false, errors.NewStorageError("migrator_get_version", err)
	}

	return version, dirty, nil
}

// Reset drops all tables and re-runs migrations
func (m *Migrator) Reset() error {
	driver, err := postgres.WithInstance(m.db, &postgres.Config{})
	if err != nil {
		return errors.NewStorageError("migrator_create_driver", err)
	}

	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return errors.NewStorageError("migrator_create_source", err)
	}

	migration, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return errors.NewStorageError("migrator_create_migration", err)
	}

	// Drop all tables
	if err := migration.Drop(); err != nil {
		return errors.NewStorageError("migrator_drop", err)
	}

	// Re-run all migrations
	if err := migration.Up(); err != nil {
		return errors.NewStorageError("migrator_reset_up", err)
	}

	return nil
}

// ValidateSchema validates that the database schema matches expectations
func (m *Migrator) ValidateSchema() error {
	// Check if essential tables exist
	tables := []string{
		"experiments",
		"executions",
		"targets",
		"results",
		"provider_configs",
		"domain_events",
		"audit_logs",
		"scheduled_experiments",
		"experiment_templates",
		"safety_metrics",
	}

	for _, table := range tables {
		var exists bool
		query := `
			SELECT EXISTS (
				SELECT 1
				FROM information_schema.tables
				WHERE table_schema = 'public'
				AND table_name = $1
			)`

		err := m.db.QueryRow(query, table).Scan(&exists)
		if err != nil {
			return errors.NewStorageError("migrator_check_table", err)
		}

		if !exists {
			return errors.NewStorageError("migrator_table_missing", fmt.Errorf("required table '%s' does not exist", table))
		}
	}

	return nil
}