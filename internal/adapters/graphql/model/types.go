package model

import (
	"time"

	"github.com/embrace-chaos/internal/core/domain"
)

// Core GraphQL model types that map to domain entities

// Experiment represents a chaos experiment
type Experiment struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description *string                `json:"description"`
	Status      ExperimentStatus       `json:"status"`
	Config      *ExperimentConfig      `json:"config"`
	Safety      *SafetyConfig          `json:"safety"`
	Targets     []*Target              `json:"targets"`
	Labels      map[string]interface{} `json:"labels"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   string                 `json:"createdAt"`
	UpdatedAt   string                 `json:"updatedAt"`
	Version     int                    `json:"version"`
}

// ExperimentConfig defines experiment execution parameters
type ExperimentConfig struct {
	Duration        string         `json:"duration"`
	Parallelism     int            `json:"parallelism"`
	ConcurrencyMode *string        `json:"concurrencyMode"`
	Timeout         *string        `json:"timeout"`
	RetryPolicy     *RetryPolicy   `json:"retryPolicy"`
	Parameters      []*Parameter   `json:"parameters"`
}

// SafetyConfig defines safety constraints for experiments
type SafetyConfig struct {
	MaxFailures        int                    `json:"maxFailures"`
	FailureThreshold   float64                `json:"failureThreshold"`
	AutoRollback       bool                   `json:"autoRollback"`
	RollbackTimeout    string                 `json:"rollbackTimeout"`
	PreflightChecks    []string               `json:"preflightChecks"`
	HealthChecks       []string               `json:"healthChecks"`
	MonitoringPeriod   string                 `json:"monitoringPeriod"`
	AlertThresholds    map[string]interface{} `json:"alertThresholds"`
}

// Target represents an infrastructure target
type Target struct {
	ID         string                 `json:"id"`
	ResourceID string                 `json:"resourceId"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Provider   string                 `json:"provider"`
	Region     string                 `json:"region"`
	Tags       map[string]interface{} `json:"tags"`
	Status     string                 `json:"status"`
	Metadata   map[string]interface{} `json:"metadata"`
	CreatedAt  string                 `json:"createdAt"`
	UpdatedAt  string                 `json:"updatedAt"`
}

// Execution represents a running or completed experiment execution
type Execution struct {
	ID           string                 `json:"id"`
	ExperimentID string                 `json:"experimentId"`
	Status       ExecutionStatus        `json:"status"`
	StartedAt    string                 `json:"startedAt"`
	CompletedAt  *string                `json:"completedAt"`
	Duration     *string                `json:"duration"`
	TriggerType  string                 `json:"triggerType"`
	TriggerBy    string                 `json:"triggerBy"`
	Parameters   map[string]interface{} `json:"parameters"`
	Metadata     map[string]interface{} `json:"metadata"`
	CreatedAt    string                 `json:"createdAt"`
	UpdatedAt    string                 `json:"updatedAt"`
	Version      int                    `json:"version"`
}

// ExecutionMetrics provides statistics about execution
type ExecutionMetrics struct {
	TargetsAffected   int    `json:"targetsAffected"`
	SuccessCount      int    `json:"successCount"`
	FailureCount      int    `json:"failureCount"`
	RollbackCount     int    `json:"rollbackCount"`
	TotalDuration     string `json:"totalDuration"`
	AvgTargetDuration string `json:"avgTargetDuration"`
}

// User represents a system user
type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	Role          UserRole  `json:"role"`
	CreatedAt     string    `json:"createdAt"`
}

// Organization represents a tenant organization
type Organization struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	CreatedAt string `json:"createdAt"`
}

// Connection types for pagination

type ExperimentConnection struct {
	Edges      []*ExperimentEdge `json:"edges"`
	PageInfo   *PageInfo         `json:"pageInfo"`
	TotalCount int               `json:"totalCount"`
}

type ExperimentEdge struct {
	Cursor string      `json:"cursor"`
	Node   *Experiment `json:"node"`
}

type ExecutionConnection struct {
	Edges      []*ExecutionEdge `json:"edges"`
	PageInfo   *PageInfo        `json:"pageInfo"`
	TotalCount int              `json:"totalCount"`
}

type ExecutionEdge struct {
	Cursor string     `json:"cursor"`
	Node   *Execution `json:"node"`
}

type TargetConnection struct {
	Edges      []*TargetEdge `json:"edges"`
	PageInfo   *PageInfo     `json:"pageInfo"`
	TotalCount int           `json:"totalCount"`
}

type TargetEdge struct {
	Cursor string  `json:"cursor"`
	Node   *Target `json:"node"`
}

type PageInfo struct {
	HasNextPage     bool     `json:"hasNextPage"`
	HasPreviousPage bool     `json:"hasPreviousPage"`
	StartCursor     *string  `json:"startCursor"`
	EndCursor       *string  `json:"endCursor"`
}

// Input types

type CreateExperimentInput struct {
	Name        string                 `json:"name"`
	Description *string                `json:"description"`
	Config      ExperimentConfigInput  `json:"config"`
	Safety      SafetyConfigInput      `json:"safety"`
	Targets     []TargetInput          `json:"targets"`
	Labels      map[string]interface{} `json:"labels"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type UpdateExperimentInput struct {
	Name        *string                `json:"name"`
	Description *string                `json:"description"`
	Config      *ExperimentConfigInput `json:"config"`
	Safety      *SafetyConfigInput     `json:"safety"`
	Targets     *[]TargetInput         `json:"targets"`
	Labels      *map[string]interface{} `json:"labels"`
	Metadata    *map[string]interface{} `json:"metadata"`
}

type ExperimentConfigInput struct {
	Duration        string             `json:"duration"`
	Parallelism     int                `json:"parallelism"`
	ConcurrencyMode *ConcurrencyMode   `json:"concurrencyMode"`
	Timeout         *string            `json:"timeout"`
	RetryPolicy     *RetryPolicyInput  `json:"retryPolicy"`
	Parameters      *[]ParameterInput  `json:"parameters"`
}

type SafetyConfigInput struct {
	MaxFailures        *int                    `json:"maxFailures"`
	FailureThreshold   *float64                `json:"failureThreshold"`
	AutoRollback       *bool                   `json:"autoRollback"`
	RollbackTimeout    *string                 `json:"rollbackTimeout"`
	PreflightChecks    *[]string               `json:"preflightChecks"`
	HealthChecks       *[]string               `json:"healthChecks"`
	MonitoringPeriod   *string                 `json:"monitoringPeriod"`
	AlertThresholds    map[string]interface{}  `json:"alertThresholds"`
}

type TargetInput struct {
	ID         *string                `json:"id"`
	ResourceID string                 `json:"resourceId"`
	Name       string                 `json:"name"`
	Type       TargetType             `json:"type"`
	Provider   Provider               `json:"provider"`
	Region     string                 `json:"region"`
	Tags       map[string]interface{} `json:"tags"`
}

type ExecuteExperimentInput struct {
	DryRun                 *bool                   `json:"dryRun"`
	Parameters             *map[string]interface{} `json:"parameters"`
	SkipPreflightChecks    *bool                   `json:"skipPreflightChecks"`
	NotificationChannels   *[]string               `json:"notificationChannels"`
}

// Filter types

type ExperimentFilter struct {
	Status       *[]ExperimentStatus    `json:"status"`
	CreatedBy    *[]string              `json:"createdBy"`
	Labels       map[string]interface{} `json:"labels"`
	NameContains *string                `json:"nameContains"`
	HasSchedule  *bool                  `json:"hasSchedule"`
	Providers    *[]Provider            `json:"providers"`
	TargetTypes  *[]TargetType          `json:"targetTypes"`
}

type ExecutionFilter struct {
	ExperimentID       *string             `json:"experimentId"`
	Status             *[]ExecutionStatus  `json:"status"`
	TriggerType        *[]TriggerType      `json:"triggerType"`
	StartedAfter       *string             `json:"startedAfter"`
	StartedBefore      *string             `json:"startedBefore"`
	DurationGreaterThan *string            `json:"durationGreaterThan"`
	DurationLessThan   *string             `json:"durationLessThan"`
}

type TargetFilter struct {
	Providers *[]Provider           `json:"providers"`
	Types     *[]TargetType         `json:"types"`
	Regions   *[]string             `json:"regions"`
	Tags      map[string]interface{} `json:"tags"`
	Status    *[]TargetStatus       `json:"status"`
}

type PaginationInput struct {
	Page           *int             `json:"page"`
	PageSize       *int             `json:"pageSize"`
	OrderBy        *string          `json:"orderBy"`
	OrderDirection *OrderDirection  `json:"orderDirection"`
}

// Utility types

type RetryPolicy struct {
	MaxRetries      *int              `json:"maxRetries"`
	BackoffStrategy *BackoffStrategy  `json:"backoffStrategy"`
	InitialDelay    *string           `json:"initialDelay"`
	MaxDelay        *string           `json:"maxDelay"`
}

type RetryPolicyInput struct {
	MaxRetries      *int              `json:"maxRetries"`
	BackoffStrategy *BackoffStrategy  `json:"backoffStrategy"`
	InitialDelay    *string           `json:"initialDelay"`
	MaxDelay        *string           `json:"maxDelay"`
}

type Parameter struct {
	Name         string         `json:"name"`
	Type         ParameterType  `json:"type"`
	Required     bool           `json:"required"`
	DefaultValue *string        `json:"defaultValue"`
	Description  *string        `json:"description"`
	Validation   *string        `json:"validation"`
}

type ParameterInput struct {
	Name         string         `json:"name"`
	Type         ParameterType  `json:"type"`
	Required     *bool          `json:"required"`
	DefaultValue *string        `json:"defaultValue"`
	Description  *string        `json:"description"`
	Validation   *string        `json:"validation"`
}

// Conversion functions from domain to GraphQL models

func ExperimentFromDomain(exp *domain.Experiment) *Experiment {
	if exp == nil {
		return nil
	}

	return &Experiment{
		ID:          string(exp.ID),
		Name:        exp.Name,
		Description: stringPtr(exp.Description),
		Status:      ExperimentStatus(exp.Status),
		CreatedAt:   exp.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   exp.UpdatedAt.Format(time.RFC3339),
		Version:     exp.Version,
	}
}

func ExperimentsFromDomain(experiments []*domain.Experiment) []*Experiment {
	result := make([]*Experiment, len(experiments))
	for i, exp := range experiments {
		result[i] = ExperimentFromDomain(exp)
	}
	return result
}

func ExecutionFromDomain(exec *domain.Execution) *Execution {
	if exec == nil {
		return nil
	}

	execution := &Execution{
		ID:           string(exec.ID),
		ExperimentID: string(exec.ExperimentID),
		Status:       ExecutionStatus(exec.Status),
		StartedAt:    exec.StartedAt.Format(time.RFC3339),
		TriggerBy:    exec.TriggerBy,
		Parameters:   exec.Parameters,
		Metadata:     exec.Metadata,
		CreatedAt:    exec.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    exec.UpdatedAt.Format(time.RFC3339),
		Version:      exec.Version,
	}

	if !exec.CompletedAt.IsZero() {
		execution.CompletedAt = stringPtr(exec.CompletedAt.Format(time.RFC3339))
	}

	if exec.Duration > 0 {
		execution.Duration = stringPtr(exec.Duration.String())
	}

	return execution
}

func ExecutionsFromDomain(executions []*domain.Execution) []*Execution {
	result := make([]*Execution, len(executions))
	for i, exec := range executions {
		result[i] = ExecutionFromDomain(exec)
	}
	return result
}

func TargetFromDomain(target *domain.Target) *Target {
	if target == nil {
		return nil
	}

	return &Target{
		ID:         target.ID,
		ResourceID: target.ResourceID,
		Name:       target.Name,
		Type:       string(target.Type),
		Provider:   string(target.Provider),
		Region:     target.Region,
		Tags:       convertStringMapToInterface(target.Tags),
		Status:     string(target.Status),
		Metadata:   target.Metadata,
		CreatedAt:  target.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  target.UpdatedAt.Format(time.RFC3339),
	}
}

func TargetsFromDomain(targets []*domain.Target) []*Target {
	result := make([]*Target, len(targets))
	for i, target := range targets {
		result[i] = TargetFromDomain(target)
	}
	return result
}

func UserFromDomain(user *domain.User) *User {
	if user == nil {
		return nil
	}

	return &User{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Role:      UserRole(user.Role),
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}
}

func OrganizationFromDomain(org *domain.Organization) *Organization {
	if org == nil {
		return nil
	}

	return &Organization{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		CreatedAt: org.CreatedAt.Format(time.RFC3339),
	}
}

// Connection helpers

func ExperimentConnectionFromDomain(experiments []*domain.Experiment, total int, pagination domain.PaginationRequest) *ExperimentConnection {
	edges := make([]*ExperimentEdge, len(experiments))
	for i, exp := range experiments {
		edges[i] = &ExperimentEdge{
			Cursor: encodeCursor(string(exp.ID)),
			Node:   ExperimentFromDomain(exp),
		}
	}

	hasNextPage := (pagination.Page * pagination.PageSize) < total
	hasPreviousPage := pagination.Page > 1

	pageInfo := &PageInfo{
		HasNextPage:     hasNextPage,
		HasPreviousPage: hasPreviousPage,
	}

	if len(edges) > 0 {
		pageInfo.StartCursor = &edges[0].Cursor
		pageInfo.EndCursor = &edges[len(edges)-1].Cursor
	}

	return &ExperimentConnection{
		Edges:      edges,
		PageInfo:   pageInfo,
		TotalCount: total,
	}
}

func ExecutionConnectionFromDomain(executions []*domain.Execution, total int, pagination domain.PaginationRequest) *ExecutionConnection {
	edges := make([]*ExecutionEdge, len(executions))
	for i, exec := range executions {
		edges[i] = &ExecutionEdge{
			Cursor: encodeCursor(string(exec.ID)),
			Node:   ExecutionFromDomain(exec),
		}
	}

	hasNextPage := (pagination.Page * pagination.PageSize) < total
	hasPreviousPage := pagination.Page > 1

	pageInfo := &PageInfo{
		HasNextPage:     hasNextPage,
		HasPreviousPage: hasPreviousPage,
	}

	if len(edges) > 0 {
		pageInfo.StartCursor = &edges[0].Cursor
		pageInfo.EndCursor = &edges[len(edges)-1].Cursor
	}

	return &ExecutionConnection{
		Edges:      edges,
		PageInfo:   pageInfo,
		TotalCount: total,
	}
}

func TargetConnectionFromDomain(targets []*domain.Target, total int, pagination domain.PaginationRequest) *TargetConnection {
	edges := make([]*TargetEdge, len(targets))
	for i, target := range targets {
		edges[i] = &TargetEdge{
			Cursor: encodeCursor(target.ID),
			Node:   TargetFromDomain(target),
		}
	}

	hasNextPage := (pagination.Page * pagination.PageSize) < total
	hasPreviousPage := pagination.Page > 1

	pageInfo := &PageInfo{
		HasNextPage:     hasNextPage,
		HasPreviousPage: hasPreviousPage,
	}

	if len(edges) > 0 {
		pageInfo.StartCursor = &edges[0].Cursor
		pageInfo.EndCursor = &edges[len(edges)-1].Cursor
	}

	return &TargetConnection{
		Edges:      edges,
		PageInfo:   pageInfo,
		TotalCount: total,
	}
}

// Helper functions

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func convertStringMapToInterface(m map[string]string) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		result[k] = v
	}
	return result
}

func encodeCursor(id string) string {
	// In a real implementation, this would encode the cursor properly
	// For now, just return the ID
	return id
}