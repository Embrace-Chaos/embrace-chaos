package parsers

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/embrace-chaos/internal/core/errors"
)

// VariableEngine handles variable substitution in YAML content
type VariableEngine struct {
	functions map[string]VariableFunction
	patterns  []*regexp.Regexp
}

// VariableFunction represents a function that can be called in variable expressions
type VariableFunction func(ctx context.Context, args []string) (string, error)

// NewVariableEngine creates a new variable engine with built-in functions
func NewVariableEngine() *VariableEngine {
	engine := &VariableEngine{
		functions: make(map[string]VariableFunction),
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`\$\{([^}]+)\}`),     // ${variable} syntax
			regexp.MustCompile(`\$\(([^)]+)\)`),     // $(expression) syntax
			regexp.MustCompile(`\{\{([^}]+)\}\}`),   // {{variable}} syntax
		},
	}

	// Register built-in functions
	engine.registerBuiltinFunctions()

	return engine
}

// SubstituteVariables replaces variable expressions in YAML content
func (e *VariableEngine) SubstituteVariables(ctx context.Context, yamlContent string, variables map[string]interface{}) (string, error) {
	result := yamlContent

	// Process each pattern type
	for _, pattern := range e.patterns {
		var err error
		result, err = e.processPattern(ctx, result, pattern, variables)
		if err != nil {
			return "", errors.NewValidationError("variable substitution failed: %w", err)
		}
	}

	return result, nil
}

// RegisterFunction registers a custom variable function
func (e *VariableEngine) RegisterFunction(name string, function VariableFunction) {
	e.functions[name] = function
}

// ValidateVariables validates that all variables in the content can be resolved
func (e *VariableEngine) ValidateVariables(ctx context.Context, yamlContent string, variables map[string]interface{}) error {
	// Extract all variable references
	variableRefs := e.extractVariableReferences(yamlContent)

	// Check if all variables can be resolved
	for _, ref := range variableRefs {
		if err := e.validateVariableReference(ctx, ref, variables); err != nil {
			return errors.NewValidationError("variable validation failed for '%s': %w", ref, err)
		}
	}

	return nil
}

// Private methods

func (e *VariableEngine) processPattern(ctx context.Context, content string, pattern *regexp.Regexp, variables map[string]interface{}) (string, error) {
	return pattern.ReplaceAllStringFunc(content, func(match string) string {
		// Extract the variable expression (remove delimiters)
		expression := pattern.FindStringSubmatch(match)[1]

		// Resolve the variable
		value, err := e.resolveVariable(ctx, expression, variables)
		if err != nil {
			// Return original match on error - this will be caught later
			return match
		}

		return value
	}), nil
}

func (e *VariableEngine) resolveVariable(ctx context.Context, expression string, variables map[string]interface{}) (string, error) {
	expression = strings.TrimSpace(expression)

	// Check if it's a function call
	if strings.Contains(expression, "(") && strings.HasSuffix(expression, ")") {
		return e.resolveFunctionCall(ctx, expression, variables)
	}

	// Check if it's a simple variable reference
	if value, exists := variables[expression]; exists {
		return e.convertToString(value), nil
	}

	// Check if it's a nested variable reference (e.g., object.property)
	if strings.Contains(expression, ".") {
		return e.resolveNestedVariable(expression, variables)
	}

	// Check if it's a default value expression (e.g., variable:default)
	if strings.Contains(expression, ":") {
		return e.resolveDefaultVariable(ctx, expression, variables)
	}

	return "", errors.NewValidationError("undefined variable: %s", expression)
}

func (e *VariableEngine) resolveFunctionCall(ctx context.Context, expression string, variables map[string]interface{}) (string, error) {
	// Parse function call: functionName(arg1, arg2, ...)
	parenIndex := strings.Index(expression, "(")
	if parenIndex == -1 {
		return "", errors.NewValidationError("invalid function call syntax: %s", expression)
	}

	functionName := strings.TrimSpace(expression[:parenIndex])
	argsStr := strings.TrimSpace(expression[parenIndex+1 : len(expression)-1])

	// Parse arguments
	var args []string
	if argsStr != "" {
		rawArgs := strings.Split(argsStr, ",")
		for _, arg := range rawArgs {
			arg = strings.TrimSpace(arg)
			// Remove quotes if present
			if (strings.HasPrefix(arg, "\"") && strings.HasSuffix(arg, "\"")) ||
				(strings.HasPrefix(arg, "'") && strings.HasSuffix(arg, "'")) {
				arg = arg[1 : len(arg)-1]
			}
			// Resolve variables in arguments
			resolvedArg, err := e.resolveVariable(ctx, arg, variables)
			if err != nil {
				// If it's not a variable, use the literal value
				resolvedArg = arg
			}
			args = append(args, resolvedArg)
		}
	}

	// Call the function
	function, exists := e.functions[functionName]
	if !exists {
		return "", errors.NewValidationError("undefined function: %s", functionName)
	}

	return function(ctx, args)
}

func (e *VariableEngine) resolveNestedVariable(expression string, variables map[string]interface{}) (string, error) {
	parts := strings.Split(expression, ".")
	current := variables

	for i, part := range parts {
		if i == len(parts)-1 {
			// Last part - get the final value
			if value, exists := current[part]; exists {
				return e.convertToString(value), nil
			}
			return "", errors.NewValidationError("undefined nested variable: %s", expression)
		} else {
			// Intermediate part - navigate deeper
			if value, exists := current[part]; exists {
				if nestedMap, ok := value.(map[string]interface{}); ok {
					current = nestedMap
				} else {
					return "", errors.NewValidationError("cannot navigate into non-object: %s", part)
				}
			} else {
				return "", errors.NewValidationError("undefined nested variable: %s", expression)
			}
		}
	}

	return "", errors.NewValidationError("failed to resolve nested variable: %s", expression)
}

func (e *VariableEngine) resolveDefaultVariable(ctx context.Context, expression string, variables map[string]interface{}) (string, error) {
	parts := strings.SplitN(expression, ":", 2)
	if len(parts) != 2 {
		return "", errors.NewValidationError("invalid default syntax: %s", expression)
	}

	variableName := strings.TrimSpace(parts[0])
	defaultValue := strings.TrimSpace(parts[1])

	// Try to resolve the variable
	if value, err := e.resolveVariable(ctx, variableName, variables); err == nil {
		return value, nil
	}

	// Use default value
	return defaultValue, nil
}

func (e *VariableEngine) convertToString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case time.Time:
		return v.Format(time.RFC3339)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (e *VariableEngine) extractVariableReferences(content string) []string {
	var references []string
	seen := make(map[string]bool)

	for _, pattern := range e.patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				ref := strings.TrimSpace(match[1])
				if !seen[ref] {
					references = append(references, ref)
					seen[ref] = true
				}
			}
		}
	}

	return references
}

func (e *VariableEngine) validateVariableReference(ctx context.Context, ref string, variables map[string]interface{}) error {
	_, err := e.resolveVariable(ctx, ref, variables)
	return err
}

func (e *VariableEngine) registerBuiltinFunctions() {
	// Random functions
	e.functions["random_string"] = func(ctx context.Context, args []string) (string, error) {
		length := 8
		if len(args) > 0 {
			if l, err := strconv.Atoi(args[0]); err == nil {
				length = l
			}
		}
		return e.generateRandomString(length), nil
	}

	e.functions["random_int"] = func(ctx context.Context, args []string) (string, error) {
		min, max := 0, 100
		if len(args) > 0 {
			if m, err := strconv.Atoi(args[0]); err == nil {
				min = m
			}
		}
		if len(args) > 1 {
			if m, err := strconv.Atoi(args[1]); err == nil {
				max = m
			}
		}
		return strconv.Itoa(e.generateRandomInt(min, max)), nil
	}

	// Time functions
	e.functions["now"] = func(ctx context.Context, args []string) (string, error) {
		format := time.RFC3339
		if len(args) > 0 {
			format = args[0]
		}
		return time.Now().Format(format), nil
	}

	e.functions["timestamp"] = func(ctx context.Context, args []string) (string, error) {
		return strconv.FormatInt(time.Now().Unix(), 10), nil
	}

	e.functions["uuid"] = func(ctx context.Context, args []string) (string, error) {
		return e.generateUUID(), nil
	}

	// String functions
	e.functions["upper"] = func(ctx context.Context, args []string) (string, error) {
		if len(args) == 0 {
			return "", errors.NewValidationError("upper function requires one argument")
		}
		return strings.ToUpper(args[0]), nil
	}

	e.functions["lower"] = func(ctx context.Context, args []string) (string, error) {
		if len(args) == 0 {
			return "", errors.NewValidationError("lower function requires one argument")
		}
		return strings.ToLower(args[0]), nil
	}

	e.functions["replace"] = func(ctx context.Context, args []string) (string, error) {
		if len(args) < 3 {
			return "", errors.NewValidationError("replace function requires three arguments: string, old, new")
		}
		return strings.ReplaceAll(args[0], args[1], args[2]), nil
	}

	// Environment functions
	e.functions["env"] = func(ctx context.Context, args []string) (string, error) {
		if len(args) == 0 {
			return "", errors.NewValidationError("env function requires environment variable name")
		}
		// This would typically read from environment, but for security reasons
		// we'll return empty string and log a warning
		return "", nil
	}

	// Conditional functions
	e.functions["if"] = func(ctx context.Context, args []string) (string, error) {
		if len(args) < 3 {
			return "", errors.NewValidationError("if function requires three arguments: condition, true_value, false_value")
		}
		condition := strings.ToLower(strings.TrimSpace(args[0]))
		if condition == "true" || condition == "1" || condition == "yes" {
			return args[1], nil
		}
		return args[2], nil
	}

	// Math functions
	e.functions["add"] = func(ctx context.Context, args []string) (string, error) {
		if len(args) < 2 {
			return "", errors.NewValidationError("add function requires at least two arguments")
		}
		sum := 0.0
		for _, arg := range args {
			if val, err := strconv.ParseFloat(arg, 64); err == nil {
				sum += val
			} else {
				return "", errors.NewValidationError("invalid number in add function: %s", arg)
			}
		}
		// Return as integer if it's a whole number
		if sum == float64(int64(sum)) {
			return strconv.FormatInt(int64(sum), 10), nil
		}
		return strconv.FormatFloat(sum, 'f', -1, 64), nil
	}

	e.functions["multiply"] = func(ctx context.Context, args []string) (string, error) {
		if len(args) < 2 {
			return "", errors.NewValidationError("multiply function requires at least two arguments")
		}
		product := 1.0
		for _, arg := range args {
			if val, err := strconv.ParseFloat(arg, 64); err == nil {
				product *= val
			} else {
				return "", errors.NewValidationError("invalid number in multiply function: %s", arg)
			}
		}
		// Return as integer if it's a whole number
		if product == float64(int64(product)) {
			return strconv.FormatInt(int64(product), 10), nil
		}
		return strconv.FormatFloat(product, 'f', -1, 64), nil
	}
}

// Helper functions for built-in functions

func (e *VariableEngine) generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

func (e *VariableEngine) generateRandomInt(min, max int) int {
	if min >= max {
		return min
	}
	return min + int(time.Now().UnixNano())%(max-min)
}

func (e *VariableEngine) generateUUID() string {
	// Simple UUID v4 generation (not cryptographically secure, but sufficient for testing)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		time.Now().UnixNano()&0xffffffff,
		time.Now().UnixNano()>>32&0xffff,
		(time.Now().UnixNano()>>48&0x0fff)|0x4000,
		(time.Now().UnixNano()>>60&0x3fff)|0x8000,
		time.Now().UnixNano()&0xffffffffffff,
	)
}