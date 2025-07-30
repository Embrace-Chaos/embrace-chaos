package errors

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

// Logger defines the interface for structured logging
type Logger interface {
	// Core logging methods
	Debug(ctx context.Context, msg string, fields ...Field)
	Info(ctx context.Context, msg string, fields ...Field)
	Warn(ctx context.Context, msg string, fields ...Field)
	Error(ctx context.Context, msg string, fields ...Field)
	Fatal(ctx context.Context, msg string, fields ...Field)
	
	// Error-specific logging
	LogError(ctx context.Context, err error, msg string, fields ...Field)
	LogDomainError(ctx context.Context, domainErr *DomainError, fields ...Field)
	
	// Structured logging with levels
	Log(ctx context.Context, level LogLevel, msg string, fields ...Field)
	
	// Logger configuration
	WithFields(fields ...Field) Logger
	WithError(err error) Logger
	WithContext(ctx context.Context) Logger
	
	// Sub-loggers
	WithComponent(component string) Logger
	WithRequestID(requestID string) Logger
	WithUserID(userID string) Logger
}

// LogLevel represents logging levels
type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	case FatalLevel:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Field represents a structured logging field
type Field struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
	Type  FieldType   `json:"type"`
}

// FieldType represents the type of a logging field
type FieldType int

const (
	StringField FieldType = iota
	IntField
	Int64Field
	Float64Field
	BoolField
	TimeField
	DurationField
	ErrorField
	ObjectField
	ArrayField
)

// Field constructors
func String(key, value string) Field {
	return Field{Key: key, Value: value, Type: StringField}
}

func Int(key string, value int) Field {
	return Field{Key: key, Value: value, Type: IntField}
}

func Int64(key string, value int64) Field {
	return Field{Key: key, Value: value, Type: Int64Field}
}

func Float64(key string, value float64) Field {
	return Field{Key: key, Value: value, Type: Float64Field}
}

func Bool(key string, value bool) Field {
	return Field{Key: key, Value: value, Type: BoolField}
}

func Time(key string, value time.Time) Field {
	return Field{Key: key, Value: value, Type: TimeField}
}

func Duration(key string, value time.Duration) Field {
	return Field{Key: key, Value: value, Type: DurationField}
}

func Error(key string, value error) Field {
	return Field{Key: key, Value: value, Type: ErrorField}
}

func Object(key string, value interface{}) Field {
	return Field{Key: key, Value: value, Type: ObjectField}
}

func Array(key string, value interface{}) Field {
	return Field{Key: key, Value: value, Type: ArrayField}
}

// StructuredLogger is the default implementation of Logger
type StructuredLogger struct {
	level     LogLevel
	fields    []Field
	component string
	writer    LogWriter
}

// LogWriter defines the interface for writing log entries
type LogWriter interface {
	WriteLog(entry LogEntry) error
	Flush() error
	Close() error
}

// LogEntry represents a single log entry
type LogEntry struct {
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Fields    map[string]interface{} `json:"fields"`
	Context   LogContext             `json:"context"`
	Caller    *CallerInfo            `json:"caller,omitempty"`
	Error     *LoggedError           `json:"error,omitempty"`
}

// LogContext represents contextual information for logging
type LogContext struct {
	RequestID   string `json:"request_id,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	TenantID    string `json:"tenant_id,omitempty"`
	Component   string `json:"component,omitempty"`
	TraceID     string `json:"trace_id,omitempty"`
	SpanID      string `json:"span_id,omitempty"`
	Operation   string `json:"operation,omitempty"`
	Environment string `json:"environment,omitempty"`
}

// CallerInfo represents information about the calling code
type CallerInfo struct {
	File     string `json:"file"`
	Function string `json:"function"`
	Line     int    `json:"line"`
}

// LoggedError represents error information in logs
type LoggedError struct {
	Type       string                 `json:"type"`
	Message    string                 `json:"message"`
	Code       string                 `json:"code,omitempty"`
	StackTrace string                 `json:"stack_trace,omitempty"`
	Cause      *LoggedError           `json:"cause,omitempty"`
	Context    map[string]interface{} `json:"context,omitempty"`
}

// NewStructuredLogger creates a new structured logger
func NewStructuredLogger(level LogLevel, writer LogWriter) *StructuredLogger {
	return &StructuredLogger{
		level:  level,
		fields: make([]Field, 0),
		writer: writer,
	}
}

// Debug logs a debug message
func (l *StructuredLogger) Debug(ctx context.Context, msg string, fields ...Field) {
	if l.level <= DebugLevel {
		l.log(ctx, DebugLevel, msg, fields...)
	}
}

// Info logs an info message
func (l *StructuredLogger) Info(ctx context.Context, msg string, fields ...Field) {
	if l.level <= InfoLevel {
		l.log(ctx, InfoLevel, msg, fields...)
	}
}

// Warn logs a warning message
func (l *StructuredLogger) Warn(ctx context.Context, msg string, fields ...Field) {
	if l.level <= WarnLevel {
		l.log(ctx, WarnLevel, msg, fields...)
	}
}

// Error logs an error message
func (l *StructuredLogger) Error(ctx context.Context, msg string, fields ...Field) {
	if l.level <= ErrorLevel {
		l.log(ctx, ErrorLevel, msg, fields...)
	}
}

// Fatal logs a fatal message
func (l *StructuredLogger) Fatal(ctx context.Context, msg string, fields ...Field) {
	l.log(ctx, FatalLevel, msg, fields...)
}

// LogError logs an error with additional context
func (l *StructuredLogger) LogError(ctx context.Context, err error, msg string, fields ...Field) {
	if l.level <= ErrorLevel {
		errorFields := append(fields, Error("error", err))
		l.log(ctx, ErrorLevel, msg, errorFields...)
	}
}

// LogDomainError logs a domain error with full context
func (l *StructuredLogger) LogDomainError(ctx context.Context, domainErr *DomainError, fields ...Field) {
	if l.level <= ErrorLevel {
		errorFields := append(fields,
			String("error_code", string(domainErr.Code)),
			String("error_message", domainErr.Message),
			Object("error_details", domainErr.Details),
			Object("error_context", domainErr.Context),
			Time("error_timestamp", domainErr.Timestamp),
		)
		
		if domainErr.StackTrace != "" {
			errorFields = append(errorFields, String("stack_trace", domainErr.StackTrace))
		}
		
		l.log(ctx, ErrorLevel, domainErr.Message, errorFields...)
	}
}

// Log logs a message at the specified level
func (l *StructuredLogger) Log(ctx context.Context, level LogLevel, msg string, fields ...Field) {
	if l.level <= level {
		l.log(ctx, level, msg, fields...)
	}
}

// WithFields creates a new logger with additional fields
func (l *StructuredLogger) WithFields(fields ...Field) Logger {
	newLogger := &StructuredLogger{
		level:     l.level,
		fields:    append(l.fields, fields...),
		component: l.component,
		writer:    l.writer,
	}
	return newLogger
}

// WithError creates a new logger with an error field
func (l *StructuredLogger) WithError(err error) Logger {
	return l.WithFields(Error("error", err))
}

// WithContext creates a new logger with context
func (l *StructuredLogger) WithContext(ctx context.Context) Logger {
	// Extract context values and create fields
	var fields []Field
	
	if requestID := getRequestID(ctx); requestID != "" {
		fields = append(fields, String("request_id", requestID))
	}
	
	if userID := getUserID(ctx); userID != "" {
		fields = append(fields, String("user_id", userID))
	}
	
	if traceID := getTraceID(ctx); traceID != "" {
		fields = append(fields, String("trace_id", traceID))
	}
	
	return l.WithFields(fields...)
}

// WithComponent creates a new logger with a component field
func (l *StructuredLogger) WithComponent(component string) Logger {
	newLogger := &StructuredLogger{
		level:     l.level,
		fields:    l.fields,
		component: component,
		writer:    l.writer,
	}
	return newLogger
}

// WithRequestID creates a new logger with a request ID field
func (l *StructuredLogger) WithRequestID(requestID string) Logger {
	return l.WithFields(String("request_id", requestID))
}

// WithUserID creates a new logger with a user ID field
func (l *StructuredLogger) WithUserID(userID string) Logger {
	return l.WithFields(String("user_id", userID))
}

// log is the internal logging method
func (l *StructuredLogger) log(ctx context.Context, level LogLevel, msg string, fields ...Field) {
	entry := LogEntry{
		Level:     level,
		Message:   msg,
		Timestamp: time.Now(),
		Fields:    l.fieldsToMap(append(l.fields, fields...)),
		Context:   l.extractContext(ctx),
	}
	
	// Add caller information for error level and above
	if level >= ErrorLevel {
		entry.Caller = l.getCaller()
	}
	
	// Write the log entry
	if err := l.writer.WriteLog(entry); err != nil {
		// Fallback logging - in a real implementation, you might want to
		// write to stderr or a fallback logger
		fmt.Printf("Failed to write log entry: %v\n", err)
	}
}

// fieldsToMap converts fields to a map
func (l *StructuredLogger) fieldsToMap(fields []Field) map[string]interface{} {
	result := make(map[string]interface{})
	
	for _, field := range fields {
		result[field.Key] = field.Value
	}
	
	return result
}

// extractContext extracts logging context from the context
func (l *StructuredLogger) extractContext(ctx context.Context) LogContext {
	logCtx := LogContext{
		Component: l.component,
	}
	
	if requestID := getRequestID(ctx); requestID != "" {
		logCtx.RequestID = requestID
	}
	
	if userID := getUserID(ctx); userID != "" {
		logCtx.UserID = userID
	}
	
	if tenantID := getTenantID(ctx); tenantID != "" {
		logCtx.TenantID = tenantID
	}
	
	if traceID := getTraceID(ctx); traceID != "" {
		logCtx.TraceID = traceID
	}
	
	if spanID := getSpanID(ctx); spanID != "" {
		logCtx.SpanID = spanID
	}
	
	if operation := getOperation(ctx); operation != "" {
		logCtx.Operation = operation
	}
	
	return logCtx
}

// getCaller gets information about the calling function
func (l *StructuredLogger) getCaller() *CallerInfo {
	// Skip frames: getCaller -> log -> LogError/Error/etc -> actual caller
	pc, file, line, ok := runtime.Caller(3)
	if !ok {
		return nil
	}
	
	function := runtime.FuncForPC(pc)
	var funcName string
	if function != nil {
		funcName = function.Name()
	}
	
	return &CallerInfo{
		File:     file,
		Function: funcName,
		Line:     line,
	}
}

// Context value keys
type contextKey string

const (
	requestIDKey contextKey = "request_id"
	userIDKey    contextKey = "user_id"
	tenantIDKey  contextKey = "tenant_id"
	traceIDKey   contextKey = "trace_id"
	spanIDKey    contextKey = "span_id"
	operationKey contextKey = "operation"
)

// Context helper functions
func getRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

func getUserID(ctx context.Context) string {
	if id, ok := ctx.Value(userIDKey).(string); ok {
		return id
	}
	return ""
}

func getTenantID(ctx context.Context) string {
	if id, ok := ctx.Value(tenantIDKey).(string); ok {
		return id
	}
	return ""
}

func getTraceID(ctx context.Context) string {
	if id, ok := ctx.Value(traceIDKey).(string); ok {
		return id
	}
	return ""
}

func getSpanID(ctx context.Context) string {
	if id, ok := ctx.Value(spanIDKey).(string); ok {
		return id
	}
	return ""
}

func getOperation(ctx context.Context) string {
	if op, ok := ctx.Value(operationKey).(string); ok {
		return op
	}
	return ""
}

// Context builder functions
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey, traceID)
}

func WithSpanID(ctx context.Context, spanID string) context.Context {
	return context.WithValue(ctx, spanIDKey, spanID)
}

func WithOperation(ctx context.Context, operation string) context.Context {
	return context.WithValue(ctx, operationKey, operation)
}

// JSONLogWriter writes logs in JSON format
type JSONLogWriter struct {
	output    LogOutput
	formatter LogFormatter
}

// LogOutput defines where logs are written
type LogOutput interface {
	Write(data []byte) error
	Flush() error
	Close() error
}

// LogFormatter defines how logs are formatted
type LogFormatter interface {
	Format(entry LogEntry) ([]byte, error)
}

// NewJSONLogWriter creates a new JSON log writer
func NewJSONLogWriter(output LogOutput, formatter LogFormatter) *JSONLogWriter {
	return &JSONLogWriter{
		output:    output,
		formatter: formatter,
	}
}

// WriteLog writes a log entry
func (w *JSONLogWriter) WriteLog(entry LogEntry) error {
	data, err := w.formatter.Format(entry)
	if err != nil {
		return fmt.Errorf("failed to format log entry: %w", err)
	}
	
	return w.output.Write(data)
}

// Flush flushes the output
func (w *JSONLogWriter) Flush() error {
	return w.output.Flush()
}

// Close closes the output
func (w *JSONLogWriter) Close() error {
	return w.output.Close()
}

// LogConfiguration represents logger configuration
type LogConfiguration struct {
	Level       LogLevel              `json:"level"`
	Format      string                `json:"format"`
	Output      string                `json:"output"`
	Component   string                `json:"component"`
	Environment string                `json:"environment"`
	Fields      map[string]interface{} `json:"fields,omitempty"`
	
	// Output configuration
	File struct {
		Path       string `json:"path"`
		MaxSize    int    `json:"max_size"`
		MaxBackups int    `json:"max_backups"`
		MaxAge     int    `json:"max_age"`
		Compress   bool   `json:"compress"`
	} `json:"file,omitempty"`
	
	// Console configuration
	Console struct {
		Colored bool `json:"colored"`
	} `json:"console,omitempty"`
	
	// Sampling configuration
	Sampling struct {
		Enabled    bool    `json:"enabled"`
		Rate       float64 `json:"rate"`
		MaxPerSec  int     `json:"max_per_sec"`
	} `json:"sampling,omitempty"`
}

// LogMetrics represents logging metrics
type LogMetrics struct {
	TotalLogs    int64            `json:"total_logs"`
	LogsByLevel  map[string]int64 `json:"logs_by_level"`
	ErrorRate    float64          `json:"error_rate"`
	LogsPerSecond float64         `json:"logs_per_second"`
	LastLogTime  time.Time        `json:"last_log_time"`
	DroppedLogs  int64            `json:"dropped_logs"`
}

// Global logger instance
var globalLogger Logger

// SetGlobalLogger sets the global logger instance
func SetGlobalLogger(logger Logger) {
	globalLogger = logger
}

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() Logger {
	if globalLogger == nil {
		// Return a no-op logger if none is set
		return &NoOpLogger{}
	}
	return globalLogger
}

// NoOpLogger is a no-operation logger that discards all logs
type NoOpLogger struct{}

func (l *NoOpLogger) Debug(ctx context.Context, msg string, fields ...Field)      {}
func (l *NoOpLogger) Info(ctx context.Context, msg string, fields ...Field)       {}
func (l *NoOpLogger) Warn(ctx context.Context, msg string, fields ...Field)       {}
func (l *NoOpLogger) Error(ctx context.Context, msg string, fields ...Field)      {}
func (l *NoOpLogger) Fatal(ctx context.Context, msg string, fields ...Field)      {}
func (l *NoOpLogger) LogError(ctx context.Context, err error, msg string, fields ...Field) {}
func (l *NoOpLogger) LogDomainError(ctx context.Context, domainErr *DomainError, fields ...Field) {}
func (l *NoOpLogger) Log(ctx context.Context, level LogLevel, msg string, fields ...Field) {}
func (l *NoOpLogger) WithFields(fields ...Field) Logger                           { return l }
func (l *NoOpLogger) WithError(err error) Logger                                  { return l }
func (l *NoOpLogger) WithContext(ctx context.Context) Logger                      { return l }
func (l *NoOpLogger) WithComponent(component string) Logger                       { return l }
func (l *NoOpLogger) WithRequestID(requestID string) Logger                       { return l }
func (l *NoOpLogger) WithUserID(userID string) Logger                             { return l }

// Convenience functions that use the global logger
func Debug(ctx context.Context, msg string, fields ...Field) {
	GetGlobalLogger().Debug(ctx, msg, fields...)
}

func Info(ctx context.Context, msg string, fields ...Field) {
	GetGlobalLogger().Info(ctx, msg, fields...)
}

func Warn(ctx context.Context, msg string, fields ...Field) {
	GetGlobalLogger().Warn(ctx, msg, fields...)
}

func LogError(ctx context.Context, err error, msg string, fields ...Field) {
	GetGlobalLogger().LogError(ctx, err, msg, fields...)
}

func LogDomainError(ctx context.Context, domainErr *DomainError, fields ...Field) {
	GetGlobalLogger().LogDomainError(ctx, domainErr, fields...)
}