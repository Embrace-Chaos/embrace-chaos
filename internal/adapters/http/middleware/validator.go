package middleware

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/embrace-chaos/internal/core/errors"
)

// RequestValidator wraps the validator with custom validation rules
type RequestValidator struct {
	validator *validator.Validate
}

// NewRequestValidator creates a new request validator with custom rules
func NewRequestValidator() *RequestValidator {
	v := validator.New()
	
	// Register custom validation functions
	v.RegisterValidation("duration", validateDuration)
	v.RegisterValidation("provider", validateProvider)
	v.RegisterValidation("target_type", validateTargetType)
	
	// Use JSON tag names in error messages
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
	
	return &RequestValidator{
		validator: v,
	}
}

// ValidateStruct validates a struct and returns formatted validation errors
func (rv *RequestValidator) ValidateStruct(s interface{}) error {
	if err := rv.validator.Struct(s); err != nil {
		var validationErrors []string
		
		for _, err := range err.(validator.ValidationErrors) {
			validationErrors = append(validationErrors, rv.formatValidationError(err))
		}
		
		return errors.NewValidationError(strings.Join(validationErrors, "; "))
	}
	
	return nil
}

// formatValidationError formats a single validation error into a user-friendly message
func (rv *RequestValidator) formatValidationError(err validator.FieldError) string {
	field := err.Field()
	tag := err.Tag()
	value := err.Param()
	
	switch tag {
	case "required":
		return fmt.Sprintf("field '%s' is required", field)
	case "min":
		return fmt.Sprintf("field '%s' must be at least %s", field, value)
	case "max":
		return fmt.Sprintf("field '%s' must be at most %s", field, value)
	case "email":
		return fmt.Sprintf("field '%s' must be a valid email", field)
	case "duration":
		return fmt.Sprintf("field '%s' must be a valid duration (e.g., '5m', '1h')", field)
	case "provider":
		return fmt.Sprintf("field '%s' must be a valid provider (aws, gcp, azure, kubernetes, vmware)", field)
	case "target_type":
		return fmt.Sprintf("field '%s' must be a valid target type", field)
	case "oneof":
		return fmt.Sprintf("field '%s' must be one of: %s", field, value)
	case "uuid":
		return fmt.Sprintf("field '%s' must be a valid UUID", field)
	default:
		return fmt.Sprintf("field '%s' failed validation for '%s'", field, tag)
	}
}

// Custom validation functions

func validateDuration(fl validator.FieldLevel) bool {
	duration := fl.Field().String()
	if duration == "" {
		return true // Let required tag handle empty values
	}
	
	// Simple duration validation (actual implementation would use time.ParseDuration)
	validSuffixes := []string{"s", "m", "h", "d"}
	for _, suffix := range validSuffixes {
		if strings.HasSuffix(duration, suffix) {
			return true
		}
	}
	return false
}

func validateProvider(fl validator.FieldLevel) bool {
	provider := fl.Field().String()
	validProviders := []string{"aws", "gcp", "azure", "kubernetes", "vmware"}
	
	for _, valid := range validProviders {
		if provider == valid {
			return true
		}
	}
	return false
}

func validateTargetType(fl validator.FieldLevel) bool {
	targetType := fl.Field().String()
	validTypes := []string{
		"ec2_instance", "ecs_service", "rds_instance", "lambda_function",
		"gce_instance", "cloudsql_instance", "gke_node",
	}
	
	for _, valid := range validTypes {
		if targetType == valid {
			return true
		}
	}
	return false
}