package errors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HTTPErrorMapper maps domain errors to HTTP responses
type HTTPErrorMapper interface {
	MapToHTTP(ctx context.Context, err error) HTTPErrorResponse
	MapDomainErrorToHTTP(ctx context.Context, domainErr *DomainError) HTTPErrorResponse
	MapValidationErrorsToHTTP(ctx context.Context, errors []ValidationError) HTTPErrorResponse
}

// HTTPErrorResponse represents an HTTP error response
type HTTPErrorResponse struct {
	StatusCode   int                    `json:"-"`
	ErrorCode    string                 `json:"error_code"`
	Message      string                 `json:"message"`
	UserMessage  string                 `json:"user_message,omitempty"`
	Details      map[string]interface{} `json:"details,omitempty"`
	Errors       []HTTPFieldError       `json:"errors,omitempty"`
	RequestID    string                 `json:"request_id,omitempty"`
	Timestamp    string                 `json:"timestamp"`
	Path         string                 `json:"path,omitempty"`
	Method       string                 `json:"method,omitempty"`
	TraceID      string                 `json:"trace_id,omitempty"`
	Suggestions  []string               `json:"suggestions,omitempty"`
	DocumentationURL string             `json:"documentation_url,omitempty"`
}

// HTTPFieldError represents a field-specific error in HTTP responses
type HTTPFieldError struct {
	Field       string      `json:"field"`
	Code        string      `json:"code"`
	Message     string      `json:"message"`
	Value       interface{} `json:"value,omitempty"`
	Constraint  string      `json:"constraint,omitempty"`
	Suggestions []string    `json:"suggestions,omitempty"`
}

// ValidationError represents a validation error (imported from validation package)
type ValidationError struct {
	Code        string                 `json:"code"`
	Message     string                 `json:"message"`
	Field       string                 `json:"field,omitempty"`
	Value       interface{}            `json:"value,omitempty"`
	Constraint  string                 `json:"constraint,omitempty"`
	Path        string                 `json:"path,omitempty"`
	Severity    string                 `json:"severity"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Suggestions []string               `json:"suggestions,omitempty"`
}

// StandardHTTPErrorMapper is the standard implementation of HTTPErrorMapper
type StandardHTTPErrorMapper struct {
	includeStackTrace bool
	includeCause      bool
	baseURL           string
	docsBaseURL       string
}

// NewStandardHTTPErrorMapper creates a new standard HTTP error mapper
func NewStandardHTTPErrorMapper(options HTTPMapperOptions) *StandardHTTPErrorMapper {
	return &StandardHTTPErrorMapper{
		includeStackTrace: options.IncludeStackTrace,
		includeCause:      options.IncludeCause,
		baseURL:           options.BaseURL,
		docsBaseURL:       options.DocsBaseURL,
	}
}

// HTTPMapperOptions represents options for HTTP error mapping
type HTTPMapperOptions struct {
	IncludeStackTrace bool
	IncludeCause      bool
	BaseURL           string
	DocsBaseURL       string
}

// MapToHTTP maps any error to an HTTP response
func (m *StandardHTTPErrorMapper) MapToHTTP(ctx context.Context, err error) HTTPErrorResponse {
	if err == nil {
		return HTTPErrorResponse{
			StatusCode: http.StatusOK,
			Message:    "Success",
		}
	}
	
	// Try to cast to domain error first
	if domainErr, ok := err.(*DomainError); ok {
		return m.MapDomainErrorToHTTP(ctx, domainErr)
	}
	
	// Handle validation errors collection
	if validationErrors, ok := err.(ValidationErrorCollection); ok {
		return m.MapValidationErrorsToHTTP(ctx, validationErrors.Errors)
	}
	
	// Handle other known error types
	switch {
	case strings.Contains(err.Error(), "not found"):
		return m.createHTTPResponse(ctx, http.StatusNotFound, "RESOURCE_NOT_FOUND", err.Error(), "The requested resource was not found", nil, nil)
	case strings.Contains(err.Error(), "unauthorized"):
		return m.createHTTPResponse(ctx, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), "You are not authorized to access this resource", nil, nil)
	case strings.Contains(err.Error(), "forbidden"):
		return m.createHTTPResponse(ctx, http.StatusForbidden, "FORBIDDEN", err.Error(), "Access to this resource is forbidden", nil, nil)
	case strings.Contains(err.Error(), "timeout"):
		return m.createHTTPResponse(ctx, http.StatusRequestTimeout, "TIMEOUT", err.Error(), "The request timed out", nil, nil)
	default:
		return m.createHTTPResponse(ctx, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), "An internal error occurred", nil, nil)
	}
}

// MapDomainErrorToHTTP maps a domain error to an HTTP response
func (m *StandardHTTPErrorMapper) MapDomainErrorToHTTP(ctx context.Context, domainErr *DomainError) HTTPErrorResponse {
	statusCode := domainErr.GetHTTPStatus()
	userMessage := domainErr.GetUserMessage()
	
	// Build details
	details := make(map[string]interface{})
	if domainErr.Details != nil {
		details = domainErr.Details
	}
	
	// Add context information
	if domainErr.Context != nil {
		for k, v := range domainErr.Context {
			details["context_"+k] = v
		}
	}
	
	// Add cause if configured
	if m.includeCause && domainErr.Cause != nil {
		details["cause"] = domainErr.Cause.Error()
	}
	
	// Add stack trace if configured
	if m.includeStackTrace && domainErr.StackTrace != "" {
		details["stack_trace"] = domainErr.StackTrace
	}
	
	// Add timestamp
	details["error_timestamp"] = domainErr.Timestamp.Format("2006-01-02T15:04:05Z07:00")
	
	// Generate suggestions based on error code
	suggestions := m.generateSuggestions(domainErr.Code)
	
	// Generate documentation URL
	docURL := m.generateDocumentationURL(domainErr.Code)
	
	return m.createHTTPResponse(ctx, statusCode, string(domainErr.Code), domainErr.Message, userMessage, details, suggestions, docURL)
}

// MapValidationErrorsToHTTP maps validation errors to an HTTP response
func (m *StandardHTTPErrorMapper) MapValidationErrorsToHTTP(ctx context.Context, errors []ValidationError) HTTPErrorResponse {
	fieldErrors := make([]HTTPFieldError, 0, len(errors))
	
	for _, err := range errors {
		fieldError := HTTPFieldError{
			Field:       err.Field,
			Code:        err.Code,
			Message:     err.Message,
			Value:       err.Value,
			Constraint:  err.Constraint,
			Suggestions: err.Suggestions,
		}
		fieldErrors = append(fieldErrors, fieldError)
	}
	
	details := map[string]interface{}{
		"validation_errors_count": len(errors),
		"failed_fields":          m.extractFailedFields(errors),
	}
	
	return HTTPErrorResponse{
		StatusCode:       http.StatusBadRequest,
		ErrorCode:        "VALIDATION_FAILED",
		Message:          fmt.Sprintf("Validation failed with %d error(s)", len(errors)),
		UserMessage:      "Please check your input and try again",
		Details:          details,
		Errors:           fieldErrors,
		RequestID:        getRequestID(ctx),
		Timestamp:        getCurrentTimestamp(),
		Path:             getRequestPath(ctx),
		Method:           getRequestMethod(ctx),
		TraceID:          getTraceID(ctx),
		DocumentationURL: m.generateDocumentationURL("VALIDATION_FAILED"),
	}
}

// createHTTPResponse creates a standard HTTP error response
func (m *StandardHTTPErrorMapper) createHTTPResponse(ctx context.Context, statusCode int, errorCode, message, userMessage string, details map[string]interface{}, suggestions []string, docURL ...string) HTTPErrorResponse {
	response := HTTPErrorResponse{
		StatusCode:  statusCode,
		ErrorCode:   errorCode,
		Message:     message,
		UserMessage: userMessage,
		Details:     details,
		RequestID:   getRequestID(ctx),
		Timestamp:   getCurrentTimestamp(),
		Path:        getRequestPath(ctx),
		Method:      getRequestMethod(ctx),
		TraceID:     getTraceID(ctx),
		Suggestions: suggestions,
	}
	
	if len(docURL) > 0 && docURL[0] != "" {
		response.DocumentationURL = docURL[0]
	}
	
	return response
}

// generateSuggestions generates suggestions based on error code
func (m *StandardHTTPErrorMapper) generateSuggestions(code ErrorCode) []string {
	suggestions := make([]string, 0)
	
	switch code {
	case ErrExperimentNotFound:
		suggestions = append(suggestions, "Check if the experiment ID is correct", "Verify you have access to this experiment")
	case ErrExperimentValidationFailed:
		suggestions = append(suggestions, "Review the experiment configuration", "Check the validation errors for specific issues")
	case ErrTargetUnhealthy:
		suggestions = append(suggestions, "Wait for the target to become healthy", "Check target health status", "Contact system administrator")
	case ErrProviderAuthFailed:
		suggestions = append(suggestions, "Verify your provider credentials", "Check if credentials have expired", "Ensure proper permissions are set")
	case ErrSafetyThresholdExceeded:
		suggestions = append(suggestions, "Review safety configuration", "Check if thresholds are appropriate", "Contact system administrator")
	case ErrValidationRequired:
		suggestions = append(suggestions, "Provide all required fields", "Check field formats and constraints")
	case ErrAuthenticationFailed:
		suggestions = append(suggestions, "Check your credentials", "Ensure you are logged in", "Contact administrator if issues persist")
	case ErrAuthorizationDenied:
		suggestions = append(suggestions, "Verify you have necessary permissions", "Contact administrator for access", "Check your role assignments")
	}
	
	return suggestions
}

// generateDocumentationURL generates a documentation URL for the error
func (m *StandardHTTPErrorMapper) generateDocumentationURL(code ErrorCode) string {
	if m.docsBaseURL == "" {
		return ""
	}
	
	// Convert error code to URL-friendly format
	urlCode := strings.ToLower(strings.ReplaceAll(string(code), "_", "-"))
	return fmt.Sprintf("%s/errors/%s", m.docsBaseURL, urlCode)
}

// extractFailedFields extracts field names from validation errors
func (m *StandardHTTPErrorMapper) extractFailedFields(errors []ValidationError) []string {
	fields := make([]string, 0, len(errors))
	fieldSet := make(map[string]bool)
	
	for _, err := range errors {
		if err.Field != "" && !fieldSet[err.Field] {
			fields = append(fields, err.Field)
			fieldSet[err.Field] = true
		}
	}
	
	return fields
}

// ValidationErrorCollection represents a collection of validation errors
type ValidationErrorCollection struct {
	Errors []ValidationError
}

func (vec ValidationErrorCollection) Error() string {
	if len(vec.Errors) == 0 {
		return "no validation errors"
	}
	
	if len(vec.Errors) == 1 {
		return vec.Errors[0].Message
	}
	
	return fmt.Sprintf("validation failed with %d errors", len(vec.Errors))
}

// gRPC Error Mapping

// GRPCErrorMapper maps domain errors to gRPC status errors
type GRPCErrorMapper interface {
	MapToGRPC(ctx context.Context, err error) error
	MapDomainErrorToGRPC(ctx context.Context, domainErr *DomainError) error
}

// StandardGRPCErrorMapper is the standard implementation of GRPCErrorMapper
type StandardGRPCErrorMapper struct {
	includeDetails bool
}

// NewStandardGRPCErrorMapper creates a new standard gRPC error mapper
func NewStandardGRPCErrorMapper(includeDetails bool) *StandardGRPCErrorMapper {
	return &StandardGRPCErrorMapper{
		includeDetails: includeDetails,
	}
}

// MapToGRPC maps any error to a gRPC status error
func (m *StandardGRPCErrorMapper) MapToGRPC(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	
	// Try to cast to domain error first
	if domainErr, ok := err.(*DomainError); ok {
		return m.MapDomainErrorToGRPC(ctx, domainErr)
	}
	
	// Handle other known error types
	switch {
	case strings.Contains(err.Error(), "not found"):
		return status.Error(codes.NotFound, err.Error())
	case strings.Contains(err.Error(), "unauthorized"):
		return status.Error(codes.Unauthenticated, err.Error())
	case strings.Contains(err.Error(), "forbidden"):
		return status.Error(codes.PermissionDenied, err.Error())
	case strings.Contains(err.Error(), "timeout"):
		return status.Error(codes.DeadlineExceeded, err.Error())
	case strings.Contains(err.Error(), "invalid"):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// MapDomainErrorToGRPC maps a domain error to a gRPC status error
func (m *StandardGRPCErrorMapper) MapDomainErrorToGRPC(ctx context.Context, domainErr *DomainError) error {
	code := m.mapErrorCodeToGRPCCode(domainErr.Code)
	
	if !m.includeDetails {
		return status.Error(code, domainErr.Message)
	}
	
	// Create detailed status
	st := status.New(code, domainErr.Message)
	
	// Add error details
	details := &ErrorDetails{
		ErrorCode:   string(domainErr.Code),
		UserMessage: domainErr.GetUserMessage(),
		Details:     domainErr.Details,
		Context:     domainErr.Context,
		Timestamp:   domainErr.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	
	if detailedStatus, err := st.WithDetails(details); err == nil {
		return detailedStatus.Err()
	}
	
	// Fallback to simple status if details can't be added
	return st.Err()
}

// mapErrorCodeToGRPCCode maps domain error codes to gRPC codes
func (m *StandardGRPCErrorMapper) mapErrorCodeToGRPCCode(errorCode ErrorCode) codes.Code {
	switch errorCode {
	// Not found errors
	case ErrExperimentNotFound, ErrExecutionNotFound, ErrTargetNotFound, ErrProviderNotFound, ErrStorageNotFound:
		return codes.NotFound
	
	// Invalid argument errors
	case ErrValidationRequired, ErrValidationInvalidFormat, ErrValidationOutOfRange, ErrValidationTooLong, ErrValidationTooShort:
		return codes.InvalidArgument
	
	// Authentication errors
	case ErrAuthenticationFailed, ErrAuthTokenInvalid, ErrAuthTokenExpired:
		return codes.Unauthenticated
	
	// Authorization errors
	case ErrAuthorizationDenied, ErrAuthPermissionDenied:
		return codes.PermissionDenied
	
	// Precondition failures
	case ErrExperimentInvalidStatus, ErrExecutionInvalidStatus, ErrTargetUnhealthy:
		return codes.FailedPrecondition
	
	// Resource exhausted
	case ErrSystemResourceExhausted, ErrSystemMemoryExhausted, ErrSystemDiskSpaceExhausted:
		return codes.ResourceExhausted
	
	// Deadline exceeded
	case ErrExecutionTimeout, ErrProviderTimeout:
		return codes.DeadlineExceeded
	
	// Already exists
	case ErrExperimentAlreadyExists:
		return codes.AlreadyExists
	
	// Unavailable
	case ErrProviderNotAvailable, ErrSystemServiceUnavailable:
		return codes.Unavailable
	
	// Aborted (safety violations)
	case ErrSafetyCheckFailed, ErrSafetyThresholdExceeded, ErrSafetyViolationCritical:
		return codes.Aborted
	
	// Out of range
	case ErrValidationOutOfRange:
		return codes.OutOfRange
	
	// Unimplemented
	case ErrProviderCapabilityMissing:
		return codes.Unimplemented
	
	// Data loss
	case ErrStorageBackupFailed:
		return codes.DataLoss
	
	// Default to internal error
	default:
		return codes.Internal
	}
}

// ErrorDetails represents detailed error information for gRPC
type ErrorDetails struct {
	ErrorCode   string                 `json:"error_code"`
	UserMessage string                 `json:"user_message"`
	Details     map[string]interface{} `json:"details"`
	Context     map[string]string      `json:"context"`
	Timestamp   string                 `json:"timestamp"`
}

// JSON Error Mapping

// JSONErrorMapper maps errors to JSON format
type JSONErrorMapper interface {
	MapToJSON(ctx context.Context, err error) ([]byte, error)
	MapDomainErrorToJSON(ctx context.Context, domainErr *DomainError) ([]byte, error)
}

// StandardJSONErrorMapper is the standard implementation of JSONErrorMapper
type StandardJSONErrorMapper struct {
	prettyPrint       bool
	includeStackTrace bool
}

// NewStandardJSONErrorMapper creates a new standard JSON error mapper
func NewStandardJSONErrorMapper(prettyPrint, includeStackTrace bool) *StandardJSONErrorMapper {
	return &StandardJSONErrorMapper{
		prettyPrint:       prettyPrint,
		includeStackTrace: includeStackTrace,
	}
}

// MapToJSON maps any error to JSON
func (m *StandardJSONErrorMapper) MapToJSON(ctx context.Context, err error) ([]byte, error) {
	if err == nil {
		return []byte(`{"status":"success"}`), nil
	}
	
	// Try to cast to domain error first
	if domainErr, ok := err.(*DomainError); ok {
		return m.MapDomainErrorToJSON(ctx, domainErr)
	}
	
	// Create generic error response
	response := map[string]interface{}{
		"error":     true,
		"message":   err.Error(),
		"timestamp": getCurrentTimestamp(),
	}
	
	if requestID := getRequestID(ctx); requestID != "" {
		response["request_id"] = requestID
	}
	
	return m.marshalJSON(response)
}

// MapDomainErrorToJSON maps a domain error to JSON
func (m *StandardJSONErrorMapper) MapDomainErrorToJSON(ctx context.Context, domainErr *DomainError) ([]byte, error) {
	response := map[string]interface{}{
		"error":        true,
		"error_code":   string(domainErr.Code),
		"message":      domainErr.Message,
		"user_message": domainErr.GetUserMessage(),
		"severity":     domainErr.GetSeverity(),
		"recoverable":  domainErr.IsRecoverable(),
		"timestamp":    domainErr.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	
	if domainErr.Details != nil && len(domainErr.Details) > 0 {
		response["details"] = domainErr.Details
	}
	
	if domainErr.Context != nil && len(domainErr.Context) > 0 {
		response["context"] = domainErr.Context
	}
	
	if m.includeStackTrace && domainErr.StackTrace != "" {
		response["stack_trace"] = domainErr.StackTrace
	}
	
	if requestID := getRequestID(ctx); requestID != "" {
		response["request_id"] = requestID
	}
	
	if traceID := getTraceID(ctx); traceID != "" {
		response["trace_id"] = traceID
	}
	
	return m.marshalJSON(response)
}

// marshalJSON marshals data to JSON with optional pretty printing
func (m *StandardJSONErrorMapper) marshalJSON(data interface{}) ([]byte, error) {
	if m.prettyPrint {
		return json.MarshalIndent(data, "", "  ")
	}
	return json.Marshal(data)
}

// Helper functions

// getCurrentTimestamp returns the current timestamp in ISO 8601 format
func getCurrentTimestamp() string {
	return fmt.Sprintf("%d", getCurrentUnixTimestamp())
}

// getCurrentUnixTimestamp returns the current Unix timestamp
func getCurrentUnixTimestamp() int64 {
	return 1609459200 // Placeholder - in real implementation, use time.Now().Unix()
}

// getRequestPath gets the request path from context
func getRequestPath(ctx context.Context) string {
	if path, ok := ctx.Value("request_path").(string); ok {
		return path
	}
	return ""
}

// getRequestMethod gets the request method from context
func getRequestMethod(ctx context.Context) string {
	if method, ok := ctx.Value("request_method").(string); ok {
		return method
	}
	return ""
}

// Global mappers
var (
	defaultHTTPMapper = NewStandardHTTPErrorMapper(HTTPMapperOptions{
		IncludeStackTrace: false,
		IncludeCause:      true,
		DocsBaseURL:       "https://docs.embrace-chaos.io",
	})
	
	defaultGRPCMapper = NewStandardGRPCErrorMapper(true)
	defaultJSONMapper = NewStandardJSONErrorMapper(false, false)
)

// Global mapping functions
func MapToHTTP(ctx context.Context, err error) HTTPErrorResponse {
	return defaultHTTPMapper.MapToHTTP(ctx, err)
}

func MapToGRPC(ctx context.Context, err error) error {
	return defaultGRPCMapper.MapToGRPC(ctx, err)
}

func MapToJSON(ctx context.Context, err error) ([]byte, error) {
	return defaultJSONMapper.MapToJSON(ctx, err)
}