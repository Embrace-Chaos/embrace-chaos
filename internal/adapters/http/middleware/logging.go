package middleware

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// LoggingMiddleware provides request/response logging
type LoggingMiddleware struct {
	logger Logger
}

// Logger interface for structured logging
type Logger interface {
	Info(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
}

// Field represents a log field
type Field struct {
	Key   string
	Value interface{}
}

// ResponseWriter wrapper to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.written += n
	return n, err
}

// NewLoggingMiddleware creates a new logging middleware
func NewLoggingMiddleware(logger Logger) *LoggingMiddleware {
	if logger == nil {
		logger = &defaultLogger{}
	}
	return &LoggingMiddleware{
		logger: logger,
	}
}

// Middleware returns the HTTP middleware function
func (l *LoggingMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Generate request ID
		requestID := uuid.New().String()
		ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
		r = r.WithContext(ctx)
		
		// Add request ID to response headers
		w.Header().Set("X-Request-ID", requestID)
		
		// Wrap response writer
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     0,
		}
		
		// Log request
		l.logger.Info("HTTP request started",
			Field{Key: "request_id", Value: requestID},
			Field{Key: "method", Value: r.Method},
			Field{Key: "path", Value: r.URL.Path},
			Field{Key: "query", Value: r.URL.RawQuery},
			Field{Key: "user_agent", Value: r.UserAgent()},
			Field{Key: "remote_addr", Value: r.RemoteAddr},
		)
		
		// Process request
		next.ServeHTTP(wrapped, r)
		
		// Calculate duration
		duration := time.Since(start)
		
		// Log response
		logLevel := "info"
		if wrapped.statusCode >= 400 {
			logLevel = "error"
		} else if wrapped.statusCode >= 300 {
			logLevel = "warn"
		}
		
		fields := []Field{
			{Key: "request_id", Value: requestID},
			{Key: "method", Value: r.Method},
			{Key: "path", Value: r.URL.Path},
			{Key: "status_code", Value: wrapped.statusCode},
			{Key: "response_size", Value: wrapped.written},
			{Key: "duration_ms", Value: duration.Milliseconds()},
		}
		
		switch logLevel {
		case "error":
			l.logger.Error("HTTP request completed", fields...)
		case "warn":
			l.logger.Warn("HTTP request completed", fields...)
		default:
			l.logger.Info("HTTP request completed", fields...)
		}
	})
}

// Default logger implementation for demo purposes
type defaultLogger struct{}

func (d *defaultLogger) Info(msg string, fields ...Field) {
	d.log("INFO", msg, fields...)
}

func (d *defaultLogger) Error(msg string, fields ...Field) {
	d.log("ERROR", msg, fields...)
}

func (d *defaultLogger) Warn(msg string, fields ...Field) {
	d.log("WARN", msg, fields...)
}

func (d *defaultLogger) log(level, msg string, fields ...Field) {
	logStr := level + ": " + msg
	for _, field := range fields {
		logStr += " " + field.Key + "=" + toString(field.Value)
	}
	log.Println(logStr)
}

func toString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case int:
		return string(rune(val))
	case int64:
		return string(rune(val))
	default:
		return ""
	}
}