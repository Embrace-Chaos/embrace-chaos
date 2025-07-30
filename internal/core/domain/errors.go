package domain

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/embrace-chaos/internal/core/errors"
)

// DomainError represents a domain-specific error
type DomainError struct {
	Code        errors.ErrorCode       `json:"code"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Cause       error                  `json:"-"`
	Timestamp   time.Time              `json:"timestamp"`
	StackTrace  string                 `json:"stack_trace,omitempty"`
	Context     map[string]string      `json:"context,omitempty"`
}

// Error implements the error interface
func (e *DomainError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("[%s] %s", e.Code, e.Message)
	}
	
	if def, exists := errors.GetErrorDefinition(e.Code); exists {
		return fmt.Sprintf("[%s] %s", e.Code, def.Title)
	}
	
	return fmt.Sprintf("[%s] Unknown error", e.Code)
}

// Unwrap returns the underlying cause
func (e *DomainError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches a specific error code
func (e *DomainError) Is(target error) bool {
	if t, ok := target.(*DomainError); ok {
		return e.Code == t.Code
	}
	return false
}

// GetCode returns the error code
func (e *DomainError) GetCode() errors.ErrorCode {
	return e.Code
}

// GetHTTPStatus returns the HTTP status code for this error
func (e *DomainError) GetHTTPStatus() int {
	if def, exists := errors.GetErrorDefinition(e.Code); exists {
		return def.HTTPStatus
	}
	return 500 // Default to internal server error
}

// GetUserMessage returns a user-friendly message
func (e *DomainError) GetUserMessage() string {
	if def, exists := errors.GetErrorDefinition(e.Code); exists {
		return def.UserMessage
	}
	return "An unexpected error occurred"
}

// IsRecoverable returns whether this error is recoverable
func (e *DomainError) IsRecoverable() bool {
	if def, exists := errors.GetErrorDefinition(e.Code); exists {
		return def.Recoverable
	}
	return false
}

// GetSeverity returns the error severity
func (e *DomainError) GetSeverity() string {
	if def, exists := errors.GetErrorDefinition(e.Code); exists {
		return def.Severity
	}
	return "error"
}

// AddContext adds context information to the error
func (e *DomainError) AddContext(key, value string) *DomainError {
	if e.Context == nil {
		e.Context = make(map[string]string)
	}
	e.Context[key] = value
	return e
}

// AddDetail adds detail information to the error
func (e *DomainError) AddDetail(key string, value interface{}) *DomainError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// WithCause sets the underlying cause
func (e *DomainError) WithCause(cause error) *DomainError {
	e.Cause = cause
	return e
}

// NewDomainError creates a new domain error
func NewDomainError(code errors.ErrorCode, message string) *DomainError {
	return &DomainError{
		Code:      code,
		Message:   message,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
		Context:   make(map[string]string),
	}
}

// NewDomainErrorf creates a new domain error with formatted message
func NewDomainErrorf(code errors.ErrorCode, format string, args ...interface{}) *DomainError {
	return NewDomainError(code, fmt.Sprintf(format, args...))
}

// NewDomainErrorWithCause creates a new domain error with a cause
func NewDomainErrorWithCause(code errors.ErrorCode, message string, cause error) *DomainError {
	err := NewDomainError(code, message)
	err.Cause = cause
	return err
}

// WrapError wraps an existing error as a domain error
func WrapError(code errors.ErrorCode, cause error) *DomainError {
	return &DomainError{
		Code:      code,
		Message:   cause.Error(),
		Cause:     cause,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
		Context:   make(map[string]string),
	}
}

// WithStackTrace adds stack trace to the error
func (e *DomainError) WithStackTrace() *DomainError {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	e.StackTrace = string(buf[:n])
	return e
}

// Convenience constructors for common error types

// NewValidationError creates a validation error
func NewValidationError(format string, args ...interface{}) *DomainError {
	return NewDomainErrorf(errors.ErrValidationRequired, format, args...)
}

// NewNotFoundError creates a not found error
func NewNotFoundError(resource, id string) *DomainError {
	var code errors.ErrorCode
	switch strings.ToLower(resource) {
	case "experiment":
		code = errors.ErrExperimentNotFound
	case "execution":
		code = errors.ErrExecutionNotFound
	case "target":
		code = errors.ErrTargetNotFound
	case "provider":
		code = errors.ErrProviderNotFound
	default:
		code = errors.ErrStorageNotFound
	}
	
	return NewDomainError(code, fmt.Sprintf("%s with ID '%s' not found", resource, id)).
		AddDetail("resource_type", resource).
		AddDetail("resource_id", id)
}

// NewAuthenticationError creates an authentication error
func NewAuthenticationError(message string) *DomainError {
	return NewDomainError(errors.ErrAuthenticationFailed, message)
}

// NewAuthorizationError creates an authorization error
func NewAuthorizationError(action, resource string) *DomainError {
	return NewDomainError(errors.ErrAuthorizationDenied, 
		fmt.Sprintf("Permission denied for action '%s' on resource '%s'", action, resource)).
		AddDetail("action", action).
		AddDetail("resource", resource)
}

// NewProviderError creates a provider error
func NewProviderError(providerName, operation string, cause error) *DomainError {
	return NewDomainErrorWithCause(errors.ErrProviderNotAvailable,
		fmt.Sprintf("Provider '%s' failed during '%s'", providerName, operation), cause).
		AddDetail("provider", providerName).
		AddDetail("operation", operation)
}

// NewSafetyError creates a safety error
func NewSafetyError(checkName string, value, threshold float64) *DomainError {
	return NewDomainError(errors.ErrSafetyThresholdExceeded,
		fmt.Sprintf("Safety check '%s' failed: value %.2f exceeds threshold %.2f", checkName, value, threshold)).
		AddDetail("check_name", checkName).
		AddDetail("value", value).
		AddDetail("threshold", threshold)
}

// NewExecutionError creates an execution error
func NewExecutionError(executionID string, phase string, cause error) *DomainError {
	return NewDomainErrorWithCause(errors.ErrExecutionFailed,
		fmt.Sprintf("Execution '%s' failed in phase '%s'", executionID, phase), cause).
		AddDetail("execution_id", executionID).
		AddDetail("phase", phase)
}

// NewStorageError creates a storage error
func NewStorageError(operation string, cause error) *DomainError {
	code := errors.ErrStorageQueryFailed
	if strings.Contains(cause.Error(), "connection") {
		code = errors.ErrStorageConnectionFailed
	} else if strings.Contains(cause.Error(), "timeout") {
		code = errors.ErrStorageTimeout
	}
	
	return NewDomainErrorWithCause(code,
		fmt.Sprintf("Storage operation '%s' failed", operation), cause).
		AddDetail("operation", operation)
}

// Error checking utilities

// IsNotFoundError checks if an error is a not found error
func IsNotFoundError(err error) bool {
	if domainErr, ok := err.(*DomainError); ok {
		switch domainErr.Code {
		case errors.ErrExperimentNotFound,
			 errors.ErrExecutionNotFound,
			 errors.ErrTargetNotFound,
			 errors.ErrProviderNotFound,
			 errors.ErrStorageNotFound:
			return true
		}
	}
	return false
}

// IsValidationError checks if an error is a validation error
func IsValidationError(err error) bool {
	if domainErr, ok := err.(*DomainError); ok {
		category := errors.GetCategoryFromCode(domainErr.Code)
		return category == "validation"
	}
	return false
}

// IsAuthenticationError checks if an error is an authentication error
func IsAuthenticationError(err error) bool {
	if domainErr, ok := err.(*DomainError); ok {
		return domainErr.Code == errors.ErrAuthenticationFailed ||
			   domainErr.Code == errors.ErrAuthTokenInvalid ||
			   domainErr.Code == errors.ErrAuthTokenExpired
	}
	return false
}

// IsAuthorizationError checks if an error is an authorization error
func IsAuthorizationError(err error) bool {
	if domainErr, ok := err.(*DomainError); ok {
		return domainErr.Code == errors.ErrAuthorizationDenied ||
			   domainErr.Code == errors.ErrAuthPermissionDenied
	}
	return false
}

// IsSafetyError checks if an error is a safety error
func IsSafetyError(err error) bool {
	if domainErr, ok := err.(*DomainError); ok {
		category := errors.GetCategoryFromCode(domainErr.Code)
		return category == "safety"
	}
	return false
}

// IsProviderError checks if an error is a provider error
func IsProviderError(err error) bool {
	if domainErr, ok := err.(*DomainError); ok {
		category := errors.GetCategoryFromCode(domainErr.Code)
		return category == "provider"
	}
	return false
}

// IsRecoverableError checks if an error is recoverable
func IsRecoverableError(err error) bool {
	if domainErr, ok := err.(*DomainError); ok {
		return domainErr.IsRecoverable()
	}
	return false
}

// IsCriticalError checks if an error is critical
func IsCriticalError(err error) bool {
	if domainErr, ok := err.(*DomainError); ok {
		return domainErr.GetSeverity() == "critical"
	}
	return false
}

// Error aggregation for multiple errors

// ErrorCollection holds multiple errors
type ErrorCollection struct {
	Errors []*DomainError `json:"errors"`
}

// NewErrorCollection creates a new error collection
func NewErrorCollection() *ErrorCollection {
	return &ErrorCollection{
		Errors: make([]*DomainError, 0),
	}
}

// Add adds an error to the collection
func (ec *ErrorCollection) Add(err *DomainError) {
	ec.Errors = append(ec.Errors, err)
}

// AddError adds an error with code and message
func (ec *ErrorCollection) AddError(code errors.ErrorCode, message string) {
	ec.Add(NewDomainError(code, message))
}

// HasErrors returns true if there are any errors
func (ec *ErrorCollection) HasErrors() bool {
	return len(ec.Errors) > 0
}

// Count returns the number of errors
func (ec *ErrorCollection) Count() int {
	return len(ec.Errors)
}

// Error implements the error interface
func (ec *ErrorCollection) Error() string {
	if len(ec.Errors) == 0 {
		return "no errors"
	}
	
	if len(ec.Errors) == 1 {
		return ec.Errors[0].Error()
	}
	
	var messages []string
	for _, err := range ec.Errors {
		messages = append(messages, err.Error())
	}
	
	return fmt.Sprintf("multiple errors: %s", strings.Join(messages, "; "))
}

// GetByCode returns errors with a specific code
func (ec *ErrorCollection) GetByCode(code errors.ErrorCode) []*DomainError {
	var result []*DomainError
	for _, err := range ec.Errors {
		if err.Code == code {
			result = append(result, err)
		}
	}
	return result
}

// GetBySeverity returns errors with a specific severity
func (ec *ErrorCollection) GetBySeverity(severity string) []*DomainError {
	var result []*DomainError
	for _, err := range ec.Errors {
		if err.GetSeverity() == severity {
			result = append(result, err)
		}
	}
	return result
}

// HasCriticalErrors returns true if there are any critical errors
func (ec *ErrorCollection) HasCriticalErrors() bool {
	return len(ec.GetBySeverity("critical")) > 0
}

// First returns the first error or nil
func (ec *ErrorCollection) First() *DomainError {
	if len(ec.Errors) > 0 {
		return ec.Errors[0]
	}
	return nil
}

// Clear removes all errors
func (ec *ErrorCollection) Clear() {
	ec.Errors = ec.Errors[:0]
}