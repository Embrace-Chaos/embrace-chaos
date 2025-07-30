package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/embrace-chaos/internal/core/errors"
)

type contextKey string

const (
	UserIDKey   contextKey = "user_id"
	RequestIDKey contextKey = "request_id"
)

// AuthMiddleware handles JWT authentication
type AuthMiddleware struct {
	jwtSecret []byte
	skipper   func(r *http.Request) bool
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(jwtSecret []byte) *AuthMiddleware {
	return &AuthMiddleware{
		jwtSecret: jwtSecret,
		skipper:   defaultSkipper,
	}
}

// Middleware returns the HTTP middleware function
func (a *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for certain endpoints
		if a.skipper(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			WriteErrorResponse(w, r, errors.NewAuthenticationError("missing authorization header"))
			return
		}

		// Check Bearer prefix
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			WriteErrorResponse(w, r, errors.NewAuthenticationError("invalid authorization header format"))
			return
		}

		token := strings.TrimPrefix(authHeader, bearerPrefix)
		if token == "" {
			WriteErrorResponse(w, r, errors.NewAuthenticationError("missing token"))
			return
		}

		// Validate token and extract user information
		userID, err := a.validateToken(token)
		if err != nil {
			WriteErrorResponse(w, r, errors.NewAuthenticationError("invalid token"))
			return
		}

		// Add user ID to context
		ctx := context.WithValue(r.Context(), UserIDKey, userID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// validateToken validates the JWT token and returns the user ID
func (a *AuthMiddleware) validateToken(token string) (string, error) {
	// In a real implementation, this would:
	// 1. Parse the JWT token
	// 2. Verify the signature using the secret
	// 3. Check expiration and other claims
	// 4. Extract user ID from claims
	
	// For demo purposes, return a mock user ID
	if token == "valid-token" {
		return "user-123", nil
	}
	
	return "", errors.NewAuthenticationError("invalid token")
}

// defaultSkipper defines which routes should skip authentication
func defaultSkipper(r *http.Request) bool {
	path := r.URL.Path
	
	// Skip auth for health endpoints
	if strings.HasPrefix(path, "/health") {
		return true
	}
	
	// Skip auth for OpenAPI spec
	if path == "/openapi.yaml" || path == "/swagger.yaml" {
		return true
	}
	
	return false
}

// GetUserIDFromContext extracts user ID from context
func GetUserIDFromContext(ctx context.Context) string {
	if userID, ok := ctx.Value(UserIDKey).(string); ok {
		return userID
	}
	return ""
}

// GetRequestIDFromContext extracts request ID from context
func GetRequestIDFromContext(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		return requestID
	}
	return ""
}