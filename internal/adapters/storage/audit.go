package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/embrace-chaos/internal/core/domain"
)

// DefaultAuditLogger implements AuditLogger with structured logging
type DefaultAuditLogger struct {
	logger *slog.Logger
	config SecurityConfig
}

// NewDefaultAuditLogger creates a new audit logger
func NewDefaultAuditLogger(logger *slog.Logger, config SecurityConfig) *DefaultAuditLogger {
	return &DefaultAuditLogger{
		logger: logger,
		config: config,
	}
}

// LogQuery logs a database query execution
func (a *DefaultAuditLogger) LogQuery(ctx context.Context, query string, params []interface{}, duration time.Duration, err error) {
	if !a.config.AuditQueries {
		return
	}

	// Extract correlation ID from context if available
	correlationID := a.getCorrelationID(ctx)
	userID := a.getUserID(ctx)

	// Prepare log attributes
	attrs := []slog.Attr{
		slog.String("event_type", "database_query"),
		slog.String("query", query),
		slog.Duration("duration", duration),
		slog.String("correlation_id", correlationID),
		slog.String("user_id", userID),
		slog.Time("timestamp", time.Now()),
	}

	// Add parameters if auditing is enabled
	if a.config.AuditParameters && params != nil {
		paramStr, _ := json.Marshal(params)
		attrs = append(attrs, slog.String("parameters", string(paramStr)))
		attrs = append(attrs, slog.Int("param_count", len(params)))
	}

	// Add error information if present
	if err != nil {
		attrs = append(attrs, 
			slog.Bool("success", false),
			slog.String("error", err.Error()),
		)
		a.logger.ErrorContext(ctx, "Database query failed", attrs...)
	} else {
		attrs = append(attrs, slog.Bool("success", true))
		a.logger.InfoContext(ctx, "Database query executed", attrs...)
	}
}

// LogTransaction logs a database transaction operation
func (a *DefaultAuditLogger) LogTransaction(ctx context.Context, operation string, duration time.Duration, err error) {
	// Extract correlation ID from context if available
	correlationID := a.getCorrelationID(ctx)
	userID := a.getUserID(ctx)

	// Prepare log attributes
	attrs := []slog.Attr{
		slog.String("event_type", "database_transaction"),
		slog.String("operation", operation),
		slog.Duration("duration", duration),
		slog.String("correlation_id", correlationID),
		slog.String("user_id", userID),
		slog.Time("timestamp", time.Now()),
	}

	// Add error information if present
	if err != nil {
		attrs = append(attrs, 
			slog.Bool("success", false),
			slog.String("error", err.Error()),
		)
		a.logger.ErrorContext(ctx, "Database transaction failed", attrs...)
	} else {
		attrs = append(attrs, slog.Bool("success", true))
		a.logger.InfoContext(ctx, "Database transaction completed", attrs...)
	}
}

// LogSlowQuery logs a slow database query
func (a *DefaultAuditLogger) LogSlowQuery(ctx context.Context, query string, params []interface{}, duration time.Duration) {
	if !a.config.AuditSlowQueries {
		return
	}

	// Extract correlation ID from context if available
	correlationID := a.getCorrelationID(ctx)
	userID := a.getUserID(ctx)

	// Prepare log attributes
	attrs := []slog.Attr{
		slog.String("event_type", "slow_database_query"),
		slog.String("query", query),
		slog.Duration("duration", duration),
		slog.Duration("threshold", a.config.SlowQueryThreshold),
		slog.String("correlation_id", correlationID),
		slog.String("user_id", userID),
		slog.Time("timestamp", time.Now()),
	}

	// Add parameters if auditing is enabled
	if a.config.AuditParameters && params != nil {
		paramStr, _ := json.Marshal(params)
		attrs = append(attrs, slog.String("parameters", string(paramStr)))
		attrs = append(attrs, slog.Int("param_count", len(params)))
	}

	a.logger.WarnContext(ctx, "Slow database query detected", attrs...)
}

// Private helper methods

func (a *DefaultAuditLogger) getCorrelationID(ctx context.Context) string {
	if correlationID, ok := ctx.Value("correlation_id").(string); ok {
		return correlationID
	}
	if correlationID, ok := ctx.Value(domain.CorrelationIDKey).(string); ok {
		return correlationID
	}
	return "unknown"
}

func (a *DefaultAuditLogger) getUserID(ctx context.Context) string {
	if userID, ok := ctx.Value("user_id").(string); ok {
		return userID
	}
	if userID, ok := ctx.Value(domain.UserIDKey).(string); ok {
		return userID
	}
	return "system"
}

// NoOpAuditLogger is an audit logger that doesn't log anything (for testing)
type NoOpAuditLogger struct{}

// NewNoOpAuditLogger creates an audit logger that doesn't log anything
func NewNoOpAuditLogger() *NoOpAuditLogger {
	return &NoOpAuditLogger{}
}

func (n *NoOpAuditLogger) LogQuery(ctx context.Context, query string, params []interface{}, duration time.Duration, err error) {
	// No-op
}

func (n *NoOpAuditLogger) LogTransaction(ctx context.Context, operation string, duration time.Duration, err error) {
	// No-op
}

func (n *NoOpAuditLogger) LogSlowQuery(ctx context.Context, query string, params []interface{}, duration time.Duration) {
	// No-op
}

// SecurityAuditLogger extends the basic audit logger with security-specific logging
type SecurityAuditLogger struct {
	*DefaultAuditLogger
}

// NewSecurityAuditLogger creates a new security-focused audit logger
func NewSecurityAuditLogger(logger *slog.Logger, config SecurityConfig) *SecurityAuditLogger {
	return &SecurityAuditLogger{
		DefaultAuditLogger: NewDefaultAuditLogger(logger, config),
	}
}

// LogSecurityEvent logs security-related database events
func (s *SecurityAuditLogger) LogSecurityEvent(ctx context.Context, eventType string, details map[string]interface{}) {
	correlationID := s.getCorrelationID(ctx)
	userID := s.getUserID(ctx)

	attrs := []slog.Attr{
		slog.String("event_type", "database_security_event"),
		slog.String("security_event_type", eventType),
		slog.String("correlation_id", correlationID),
		slog.String("user_id", userID),
		slog.Time("timestamp", time.Now()),
	}

	// Add details
	for key, value := range details {
		attrs = append(attrs, slog.Any(key, value))
	}

	s.logger.WarnContext(ctx, fmt.Sprintf("Database security event: %s", eventType), attrs...)
}

// LogSuspiciousActivity logs potentially malicious database activity
func (s *SecurityAuditLogger) LogSuspiciousActivity(ctx context.Context, activity string, query string, reason string) {
	s.LogSecurityEvent(ctx, "suspicious_activity", map[string]interface{}{
		"activity": activity,
		"query":    query,
		"reason":   reason,
		"severity": "high",
	})
}

// LogAccessViolation logs access control violations
func (s *SecurityAuditLogger) LogAccessViolation(ctx context.Context, resource string, operation string, reason string) {
	s.LogSecurityEvent(ctx, "access_violation", map[string]interface{}{
		"resource":  resource,
		"operation": operation,
		"reason":    reason,
		"severity":  "critical",
	})
}

// LogPrivilegeEscalation logs potential privilege escalation attempts
func (s *SecurityAuditLogger) LogPrivilegeEscalation(ctx context.Context, fromRole string, toRole string, reason string) {
	s.LogSecurityEvent(ctx, "privilege_escalation", map[string]interface{}{
		"from_role": fromRole,
		"to_role":   toRole,
		"reason":    reason,
		"severity":  "critical",
	})
}

// LogDataExfiltration logs potential data exfiltration attempts
func (s *SecurityAuditLogger) LogDataExfiltration(ctx context.Context, query string, rowCount int64, reason string) {
	s.LogSecurityEvent(ctx, "data_exfiltration", map[string]interface{}{
		"query":     query,
		"row_count": rowCount,
		"reason":    reason,
		"severity":  "high",
	})
}