package middleware

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/embrace-chaos/internal/core/errors"
)

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Code      string    `json:"code"`
	Message   string    `json:"message"`
	Details   string    `json:"details,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	RequestID string    `json:"request_id,omitempty"`
}

// WriteJSONResponse writes a JSON response with the given status code
func WriteJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Log error but don't try to write another response
		// Logger would be injected in a real implementation
	}
}

// WriteErrorResponse writes an error response based on the error type
func WriteErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
	requestID := GetRequestIDFromContext(r.Context())
	
	errorResponse := ErrorResponse{
		Timestamp: time.Now(),
		RequestID: requestID,
	}
	
	statusCode := getHTTPStatusFromError(err)
	
	// Handle different error types
	switch e := err.(type) {
	case *errors.ValidationError:
		errorResponse.Code = "VALIDATION_ERROR"
		errorResponse.Message = e.Error()
		errorResponse.Details = "Request validation failed"
		
	case *errors.NotFoundError:
		errorResponse.Code = "RESOURCE_NOT_FOUND"
		errorResponse.Message = e.Error()
		errorResponse.Details = "The requested resource was not found"
		
	case *errors.ConflictError:
		errorResponse.Code = "RESOURCE_CONFLICT"
		errorResponse.Message = e.Error()
		errorResponse.Details = "The request conflicts with the current state of the resource"
		
	case *errors.AuthenticationError:
		errorResponse.Code = "AUTHENTICATION_ERROR"
		errorResponse.Message = "Authentication required"
		errorResponse.Details = "Valid authentication credentials are required"
		
	case *errors.AuthorizationError:
		errorResponse.Code = "AUTHORIZATION_ERROR"
		errorResponse.Message = "Access denied"
		errorResponse.Details = "Insufficient permissions to access this resource"
		
	case *errors.ProviderError:
		errorResponse.Code = "PROVIDER_ERROR"
		errorResponse.Message = "Provider operation failed"
		errorResponse.Details = e.Error()
		
	case *errors.StorageError:
		errorResponse.Code = "STORAGE_ERROR"
		errorResponse.Message = "Storage operation failed"
		errorResponse.Details = "An error occurred while accessing the data store"
		
	default:
		errorResponse.Code = "INTERNAL_ERROR"
		errorResponse.Message = "An internal error occurred"
		errorResponse.Details = "Please try again later or contact support"
	}
	
	WriteJSONResponse(w, statusCode, errorResponse)
}

// getHTTPStatusFromError maps domain errors to HTTP status codes
func getHTTPStatusFromError(err error) int {
	switch err.(type) {
	case *errors.ValidationError:
		return http.StatusBadRequest
	case *errors.NotFoundError:
		return http.StatusNotFound
	case *errors.ConflictError:
		return http.StatusConflict
	case *errors.AuthenticationError:
		return http.StatusUnauthorized
	case *errors.AuthorizationError:
		return http.StatusForbidden
	case *errors.ProviderError:
		return http.StatusBadGateway
	case *errors.StorageError:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}