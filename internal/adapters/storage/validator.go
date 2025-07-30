package storage

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/embrace-chaos/internal/core/errors"
)

// DefaultQueryValidator implements QueryValidator with security best practices
type DefaultQueryValidator struct {
	config SecurityConfig
	
	// Pre-compiled regular expressions for performance
	sqlInjectionPatterns []*regexp.Regexp
	allowedOperations    map[string]bool
	forbiddenKeywords    map[string]bool
}

// NewDefaultQueryValidator creates a new query validator with security rules
func NewDefaultQueryValidator(config SecurityConfig) *DefaultQueryValidator {
	validator := &DefaultQueryValidator{
		config:            config,
		allowedOperations: make(map[string]bool),
		forbiddenKeywords: make(map[string]bool),
	}

	// Set up allowed operations
	for _, op := range config.AllowedOperations {
		validator.allowedOperations[strings.ToUpper(op)] = true
	}

	// Set up forbidden keywords
	for _, keyword := range config.ForbiddenKeywords {
		validator.forbiddenKeywords[strings.ToUpper(keyword)] = true
	}

	// Initialize SQL injection detection patterns
	validator.initializeInjectionPatterns()

	return validator
}

// ValidateQuery validates a SQL query for security issues
func (v *DefaultQueryValidator) ValidateQuery(ctx context.Context, query string) error {
	// Check query length
	if len(query) > v.config.MaxQueryLength {
		return errors.NewValidationError("query exceeds maximum length of %d characters", v.config.MaxQueryLength)
	}

	// Normalize query for analysis
	normalizedQuery := strings.TrimSpace(strings.ToUpper(query))
	
	// Check for empty query
	if normalizedQuery == "" {
		return errors.NewValidationError("empty query not allowed")
	}

	// Extract operation from query
	operation := v.extractOperation(normalizedQuery)
	
	// Check if operation is allowed
	if len(v.config.AllowedOperations) > 0 && !v.allowedOperations[operation] {
		return errors.NewValidationError("operation '%s' is not allowed", operation)
	}

	// Check for forbidden keywords
	if err := v.checkForbiddenKeywords(normalizedQuery); err != nil {
		return err
	}

	// Check for SQL injection patterns
	if err := v.checkInjectionPatterns(query); err != nil {
		return err
	}

	// Check for dangerous constructs
	if err := v.checkDangerousConstructs(normalizedQuery); err != nil {
		return err
	}

	return nil
}

// ValidateParameters validates query parameters for security issues
func (v *DefaultQueryValidator) ValidateParameters(ctx context.Context, query string, params []interface{}) error {
	if len(params) == 0 {
		return nil
	}

	// Count parameter placeholders in query
	placeholderCount := strings.Count(query, "$")
	if placeholderCount != len(params) {
		return errors.NewValidationError("parameter count mismatch: expected %d, got %d", placeholderCount, len(params))
	}

	// Validate each parameter
	for i, param := range params {
		if err := v.validateParameter(i+1, param); err != nil {
			return err
		}
	}

	return nil
}

// SanitizeQuery sanitizes a SQL query (basic implementation)
func (v *DefaultQueryValidator) SanitizeQuery(ctx context.Context, query string) (string, error) {
	// Remove comments
	sanitized := v.removeComments(query)
	
	// Normalize whitespace
	sanitized = v.normalizeWhitespace(sanitized)
	
	// Validate the sanitized query
	if err := v.ValidateQuery(ctx, sanitized); err != nil {
		return "", err
	}

	return sanitized, nil
}

// Private helper methods

func (v *DefaultQueryValidator) initializeInjectionPatterns() {
	// Common SQL injection patterns
	patterns := []string{
		// Union-based injection
		`(?i)union\s+select`,
		`(?i)union\s+all\s+select`,
		
		// Boolean-based injection
		`(?i)or\s+1\s*=\s*1`,
		`(?i)and\s+1\s*=\s*1`,
		`(?i)or\s+'1'\s*=\s*'1'`,
		`(?i)and\s+'1'\s*=\s*'1'`,
		
		// Time-based injection
		`(?i)sleep\s*\(`,
		`(?i)pg_sleep\s*\(`,
		`(?i)waitfor\s+delay`,
		
		// Information schema access
		`(?i)information_schema`,
		`(?i)pg_catalog`,
		`(?i)sys\.|master\.`,
		
		// Function calls that could be dangerous
		`(?i)load_file\s*\(`,
		`(?i)into\s+outfile`,
		`(?i)into\s+dumpfile`,
		
		// Stacked queries
		`;\s*drop\s+`,
		`;\s*delete\s+`,
		`;\s*update\s+`,
		`;\s*insert\s+`,
		
		// Comment injection
		`/\*.*\*/`,
		`--\s`,
		`#\s`,
	}

	v.sqlInjectionPatterns = make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			v.sqlInjectionPatterns = append(v.sqlInjectionPatterns, regex)
		}
	}
}

func (v *DefaultQueryValidator) extractOperation(query string) string {
	// Extract the first word (operation) from the query
	words := strings.Fields(query)
	if len(words) == 0 {
		return ""
	}
	return words[0]
}

func (v *DefaultQueryValidator) checkForbiddenKeywords(query string) error {
	words := strings.Fields(query)
	for _, word := range words {
		if v.forbiddenKeywords[word] {
			return errors.NewValidationError("forbidden keyword '%s' detected", word)
		}
	}
	return nil
}

func (v *DefaultQueryValidator) checkInjectionPatterns(query string) error {
	for _, pattern := range v.sqlInjectionPatterns {
		if pattern.MatchString(query) {
			return errors.NewValidationError("potential SQL injection detected: pattern '%s'", pattern.String())
		}
	}
	return nil
}

func (v *DefaultQueryValidator) checkDangerousConstructs(query string) error {
	// Check for multiple statements (stacked queries)
	if strings.Contains(query, ";") && !strings.HasSuffix(strings.TrimSpace(query), ";") {
		return errors.NewValidationError("multiple statements not allowed")
	}

	// Check for hex encoding attempts
	if strings.Contains(query, "0X") || strings.Contains(query, "\\X") {
		return errors.NewValidationError("hex encoding detected")
	}

	// Check for excessive nested parentheses (potential DoS)
	openParens := strings.Count(query, "(")
	closeParens := strings.Count(query, ")")
	if openParens != closeParens {
		return errors.NewValidationError("unbalanced parentheses")
	}
	if openParens > 50 { // Arbitrary limit
		return errors.NewValidationError("excessive nesting detected")
	}

	return nil
}

func (v *DefaultQueryValidator) validateParameter(index int, param interface{}) error {
	if param == nil {
		return nil // NULL values are generally safe
	}

	switch p := param.(type) {
	case string:
		return v.validateStringParameter(index, p)
	case []byte:
		return v.validateBytesParameter(index, p)
	case int, int8, int16, int32, int64:
		return nil // Numbers are safe
	case uint, uint8, uint16, uint32, uint64:
		return nil // Numbers are safe
	case float32, float64:
		return nil // Numbers are safe
	case bool:
		return nil // Booleans are safe
	default:
		// For other types, convert to string and validate
		return v.validateStringParameter(index, fmt.Sprintf("%v", param))
	}
}

func (v *DefaultQueryValidator) validateStringParameter(index int, value string) error {
	// Check for SQL injection patterns in parameter values
	for _, pattern := range v.sqlInjectionPatterns {
		if pattern.MatchString(value) {
			return errors.NewValidationError("parameter %d contains potential SQL injection: %s", index, pattern.String())
		}
	}

	// Check for control characters
	for i, r := range value {
		if r < 32 && r != 9 && r != 10 && r != 13 { // Allow tab, LF, CR
			return errors.NewValidationError("parameter %d contains control character at position %d", index, i)
		}
	}

	// Check length (prevent DoS)
	if len(value) > 10000 { // Arbitrary limit
		return errors.NewValidationError("parameter %d exceeds maximum length", index)
	}

	return nil
}

func (v *DefaultQueryValidator) validateBytesParameter(index int, value []byte) error {
	// Convert to string and validate
	return v.validateStringParameter(index, string(value))
}

func (v *DefaultQueryValidator) removeComments(query string) string {
	// Remove single-line comments (-- comment)
	lines := strings.Split(query, "\n")
	var result []string
	for _, line := range lines {
		if idx := strings.Index(line, "--"); idx != -1 {
			line = line[:idx]
		}
		result = append(result, line)
	}
	
	// Remove multi-line comments (/* comment */)
	cleaned := strings.Join(result, "\n")
	commentRegex := regexp.MustCompile(`/\*.*?\*/`)
	cleaned = commentRegex.ReplaceAllString(cleaned, "")
	
	return cleaned
}

func (v *DefaultQueryValidator) normalizeWhitespace(query string) string {
	// Replace multiple whitespace characters with single space
	whitespaceRegex := regexp.MustCompile(`\s+`)
	return strings.TrimSpace(whitespaceRegex.ReplaceAllString(query, " "))
}

// NoOpQueryValidator is a validator that performs no validation (for testing)
type NoOpQueryValidator struct{}

// NewNoOpQueryValidator creates a validator that doesn't validate anything
func NewNoOpQueryValidator() *NoOpQueryValidator {
	return &NoOpQueryValidator{}
}

func (n *NoOpQueryValidator) ValidateQuery(ctx context.Context, query string) error {
	return nil
}

func (n *NoOpQueryValidator) ValidateParameters(ctx context.Context, query string, params []interface{}) error {
	return nil
}

func (n *NoOpQueryValidator) SanitizeQuery(ctx context.Context, query string) (string, error) {
	return query, nil
}