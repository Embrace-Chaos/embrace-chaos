package errors

import (
	"fmt"
	"net/http"
	"strings"
)

// ErrorCode represents a unique error code
type ErrorCode string

// Error Categories
const (
	// Experiment errors (EXP001-EXP999)
	ErrExperimentNotFound          ErrorCode = "EXP001"
	ErrExperimentInvalidStatus     ErrorCode = "EXP002"
	ErrExperimentValidationFailed  ErrorCode = "EXP003"
	ErrExperimentAlreadyExists     ErrorCode = "EXP004"
	ErrExperimentCannotExecute     ErrorCode = "EXP005"
	ErrExperimentCannotCancel      ErrorCode = "EXP006"
	ErrExperimentCannotPause       ErrorCode = "EXP007"
	ErrExperimentCannotResume      ErrorCode = "EXP008"
	ErrExperimentInvalidTransition ErrorCode = "EXP009"
	ErrExperimentDuplicateName     ErrorCode = "EXP010"
	
	// Execution errors (EXE001-EXE999)
	ErrExecutionNotFound         ErrorCode = "EXE001"
	ErrExecutionInvalidStatus    ErrorCode = "EXE002"
	ErrExecutionAlreadyRunning   ErrorCode = "EXE003"
	ErrExecutionCannotStart      ErrorCode = "EXE004"
	ErrExecutionCannotStop       ErrorCode = "EXE005"
	ErrExecutionTimeout          ErrorCode = "EXE006"
	ErrExecutionFailed           ErrorCode = "EXE007"
	ErrExecutionSafetyViolation  ErrorCode = "EXE008"
	ErrExecutionRollbackFailed   ErrorCode = "EXE009"
	ErrExecutionInvalidPhase     ErrorCode = "EXE010"
	
	// Target errors (TGT001-TGT999)
	ErrTargetNotFound           ErrorCode = "TGT001"
	ErrTargetInvalidType        ErrorCode = "TGT002"
	ErrTargetUnhealthy          ErrorCode = "TGT003"
	ErrTargetNotAccessible      ErrorCode = "TGT004"
	ErrTargetInMaintenance      ErrorCode = "TGT005"
	ErrTargetSelectionFailed    ErrorCode = "TGT006"
	ErrTargetValidationFailed   ErrorCode = "TGT007"
	ErrTargetActionNotAllowed   ErrorCode = "TGT008"
	ErrTargetConcurrencyLimit   ErrorCode = "TGT009"
	ErrTargetDiscoveryFailed    ErrorCode = "TGT010"
	
	// Provider errors (PRV001-PRV999)
	ErrProviderNotFound         ErrorCode = "PRV001"
	ErrProviderNotAvailable     ErrorCode = "PRV002"
	ErrProviderConfigInvalid    ErrorCode = "PRV003"
	ErrProviderAuthFailed       ErrorCode = "PRV004"
	ErrProviderConnectionFailed ErrorCode = "PRV005"
	ErrProviderTimeout          ErrorCode = "PRV006"
	ErrProviderRateLimit        ErrorCode = "PRV007"
	ErrProviderCapabilityMissing ErrorCode = "PRV008"
	ErrProviderHealthCheck      ErrorCode = "PRV009"
	ErrProviderRegistration     ErrorCode = "PRV010"
	
	// Safety errors (SAF001-SAF999)
	ErrSafetyCheckFailed        ErrorCode = "SAF001"
	ErrSafetyThresholdExceeded  ErrorCode = "SAF002"
	ErrSafetyConfigInvalid      ErrorCode = "SAF003"
	ErrSafetyActionFailed       ErrorCode = "SAF004"
	ErrSafetyViolationCritical  ErrorCode = "SAF005"
	ErrSafetyRollbackRequired   ErrorCode = "SAF006"
	ErrSafetyMonitoringFailed   ErrorCode = "SAF007"
	ErrSafetyPreFlightFailed    ErrorCode = "SAF008"
	ErrSafetyEmergencyStop      ErrorCode = "SAF009"
	ErrSafetyConfigMissing      ErrorCode = "SAF010"
	
	// Validation errors (VAL001-VAL999)
	ErrValidationRequired       ErrorCode = "VAL001"
	ErrValidationInvalidFormat  ErrorCode = "VAL002"
	ErrValidationOutOfRange     ErrorCode = "VAL003"
	ErrValidationTooLong        ErrorCode = "VAL004"
	ErrValidationTooShort       ErrorCode = "VAL005"
	ErrValidationInvalidEmail   ErrorCode = "VAL006"
	ErrValidationInvalidURL     ErrorCode = "VAL007"
	ErrValidationInvalidJSON    ErrorCode = "VAL008"
	ErrValidationInvalidYAML    ErrorCode = "VAL009"
	ErrValidationDuplicateValue ErrorCode = "VAL010"
	
	// Storage errors (STO001-STO999)
	ErrStorageConnectionFailed  ErrorCode = "STO001"
	ErrStorageQueryFailed       ErrorCode = "STO002"
	ErrStorageConstraintViolation ErrorCode = "STO003"
	ErrStorageTransactionFailed ErrorCode = "STO004"
	ErrStorageNotFound          ErrorCode = "STO005"
	ErrStorageConflict          ErrorCode = "STO006"
	ErrStorageTimeout           ErrorCode = "STO007"
	ErrStorageMigrationFailed   ErrorCode = "STO008"
	ErrStorageCapacityExceeded  ErrorCode = "STO009"
	ErrStorageBackupFailed      ErrorCode = "STO010"
	
	// Authentication/Authorization errors (AUTH001-AUTH999)
	ErrAuthenticationFailed     ErrorCode = "AUTH001"
	ErrAuthorizationDenied      ErrorCode = "AUTH002"
	ErrAuthTokenInvalid         ErrorCode = "AUTH003"
	ErrAuthTokenExpired         ErrorCode = "AUTH004"
	ErrAuthPermissionDenied     ErrorCode = "AUTH005"
	ErrAuthRoleNotFound         ErrorCode = "AUTH006"
	ErrAuthUserNotFound         ErrorCode = "AUTH007"
	ErrAuthSessionExpired       ErrorCode = "AUTH008"
	ErrAuthMFARequired          ErrorCode = "AUTH009"
	ErrAuthInvalidCredentials   ErrorCode = "AUTH010"
	
	// Configuration errors (CFG001-CFG999)
	ErrConfigInvalid            ErrorCode = "CFG001"
	ErrConfigMissing            ErrorCode = "CFG002"
	ErrConfigParsingFailed      ErrorCode = "CFG003"
	ErrConfigValidationFailed   ErrorCode = "CFG004"
	ErrConfigEncryptionFailed   ErrorCode = "CFG005"
	ErrConfigSecretNotFound     ErrorCode = "CFG006"
	ErrConfigEnvironmentMissing ErrorCode = "CFG007"
	ErrConfigVersionMismatch    ErrorCode = "CFG008"
	ErrConfigReloadFailed       ErrorCode = "CFG009"
	ErrConfigBackupFailed       ErrorCode = "CFG010"
	
	// Network errors (NET001-NET999)
	ErrNetworkConnectionTimeout ErrorCode = "NET001"
	ErrNetworkConnectionRefused ErrorCode = "NET002"
	ErrNetworkDNSResolutionFailed ErrorCode = "NET003"
	ErrNetworkTLSHandshakeFailed ErrorCode = "NET004"
	ErrNetworkProxyError        ErrorCode = "NET005"
	ErrNetworkFirewallBlocked   ErrorCode = "NET006"
	ErrNetworkBandwidthExceeded ErrorCode = "NET007"
	ErrNetworkLatencyTooHigh    ErrorCode = "NET008"
	ErrNetworkPacketLoss        ErrorCode = "NET009"
	ErrNetworkPortUnavailable   ErrorCode = "NET010"
	
	// System errors (SYS001-SYS999)
	ErrSystemResourceExhausted  ErrorCode = "SYS001"
	ErrSystemMemoryExhausted    ErrorCode = "SYS002"
	ErrSystemDiskSpaceExhausted ErrorCode = "SYS003"
	ErrSystemCPUOverloaded      ErrorCode = "SYS004"
	ErrSystemFileNotFound       ErrorCode = "SYS005"
	ErrSystemPermissionDenied   ErrorCode = "SYS006"
	ErrSystemServiceUnavailable ErrorCode = "SYS007"
	ErrSystemMaintenanceMode    ErrorCode = "SYS008"
	ErrSystemVersionIncompatible ErrorCode = "SYS009"
	ErrSystemShuttingDown       ErrorCode = "SYS010"
)

// ErrorDefinition defines the properties of an error
type ErrorDefinition struct {
	Code        ErrorCode `json:"code"`
	Category    string    `json:"category"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	HTTPStatus  int       `json:"http_status"`
	Severity    string    `json:"severity"`
	Recoverable bool      `json:"recoverable"`
	UserMessage string    `json:"user_message"`
}

// ErrorCatalog holds all error definitions
type ErrorCatalog struct {
	definitions map[ErrorCode]ErrorDefinition
}

// NewErrorCatalog creates a new error catalog
func NewErrorCatalog() *ErrorCatalog {
	catalog := &ErrorCatalog{
		definitions: make(map[ErrorCode]ErrorDefinition),
	}
	catalog.initializeDefinitions()
	return catalog
}

// Get retrieves an error definition by code
func (ec *ErrorCatalog) Get(code ErrorCode) (ErrorDefinition, bool) {
	def, exists := ec.definitions[code]
	return def, exists
}

// GetByCategory returns all errors in a category
func (ec *ErrorCatalog) GetByCategory(category string) []ErrorDefinition {
	var errors []ErrorDefinition
	for _, def := range ec.definitions {
		if def.Category == category {
			errors = append(errors, def)
		}
	}
	return errors
}

// List returns all error definitions
func (ec *ErrorCatalog) List() []ErrorDefinition {
	var errors []ErrorDefinition
	for _, def := range ec.definitions {
		errors = append(errors, def)
	}
	return errors
}

// initializeDefinitions initializes all error definitions
func (ec *ErrorCatalog) initializeDefinitions() {
	// Experiment errors
	ec.add(ErrExperimentNotFound, "experiment", "Experiment Not Found", 
		"The requested experiment could not be found", http.StatusNotFound, "error", false,
		"The experiment you're looking for doesn't exist or you don't have permission to access it.")
		
	ec.add(ErrExperimentInvalidStatus, "experiment", "Experiment Invalid Status",
		"The experiment is in an invalid state for the requested operation", http.StatusBadRequest, "error", true,
		"The experiment cannot be modified in its current state.")
		
	ec.add(ErrExperimentValidationFailed, "experiment", "Experiment Validation Failed",
		"The experiment configuration failed validation", http.StatusBadRequest, "error", true,
		"Please check your experiment configuration and fix the validation errors.")
		
	ec.add(ErrExperimentAlreadyExists, "experiment", "Experiment Already Exists",
		"An experiment with this name already exists", http.StatusConflict, "error", true,
		"Please choose a different name for your experiment.")
		
	ec.add(ErrExperimentCannotExecute, "experiment", "Experiment Cannot Execute",
		"The experiment cannot be executed in its current state", http.StatusBadRequest, "error", true,
		"Please ensure the experiment is properly configured and in an active state.")
		
	// Execution errors
	ec.add(ErrExecutionNotFound, "execution", "Execution Not Found",
		"The requested execution could not be found", http.StatusNotFound, "error", false,
		"The execution you're looking for doesn't exist.")
		
	ec.add(ErrExecutionTimeout, "execution", "Execution Timeout",
		"The execution exceeded the maximum allowed duration", http.StatusRequestTimeout, "warning", true,
		"The experiment took longer than expected and was terminated.")
		
	ec.add(ErrExecutionSafetyViolation, "execution", "Execution Safety Violation",
		"A safety violation was detected during execution", http.StatusForbidden, "critical", false,
		"The experiment was stopped due to safety concerns.")
		
	// Target errors
	ec.add(ErrTargetNotFound, "target", "Target Not Found",
		"The specified target could not be found", http.StatusNotFound, "error", false,
		"The target resource doesn't exist or is not accessible.")
		
	ec.add(ErrTargetUnhealthy, "target", "Target Unhealthy",
		"The target is not in a healthy state", http.StatusServiceUnavailable, "warning", true,
		"The target resource is currently unhealthy and cannot be used.")
		
	ec.add(ErrTargetInMaintenance, "target", "Target In Maintenance",
		"The target is currently in maintenance mode", http.StatusServiceUnavailable, "info", true,
		"The target is temporarily unavailable due to maintenance.")
		
	// Provider errors
	ec.add(ErrProviderNotFound, "provider", "Provider Not Found",
		"The requested provider could not be found", http.StatusNotFound, "error", false,
		"The chaos provider is not available.")
		
	ec.add(ErrProviderAuthFailed, "provider", "Provider Authentication Failed",
		"Failed to authenticate with the provider", http.StatusUnauthorized, "error", true,
		"Please check your provider credentials.")
		
	ec.add(ErrProviderTimeout, "provider", "Provider Timeout",
		"The provider operation timed out", http.StatusRequestTimeout, "warning", true,
		"The provider is taking too long to respond.")
		
	// Safety errors
	ec.add(ErrSafetyCheckFailed, "safety", "Safety Check Failed",
		"A safety check failed during execution", http.StatusForbidden, "critical", false,
		"The experiment was stopped due to safety check failure.")
		
	ec.add(ErrSafetyThresholdExceeded, "safety", "Safety Threshold Exceeded",
		"A safety threshold was exceeded", http.StatusForbidden, "critical", false,
		"The experiment was stopped because safety limits were exceeded.")
		
	// Validation errors
	ec.add(ErrValidationRequired, "validation", "Required Field Missing",
		"A required field is missing", http.StatusBadRequest, "error", true,
		"Please provide all required fields.")
		
	ec.add(ErrValidationInvalidFormat, "validation", "Invalid Format",
		"The provided value has an invalid format", http.StatusBadRequest, "error", true,
		"Please check the format of your input.")
		
	// Storage errors
	ec.add(ErrStorageConnectionFailed, "storage", "Storage Connection Failed",
		"Failed to connect to the storage system", http.StatusServiceUnavailable, "critical", true,
		"Database connection failed. Please try again later.")
		
	ec.add(ErrStorageNotFound, "storage", "Storage Record Not Found",
		"The requested record was not found in storage", http.StatusNotFound, "error", false,
		"The requested data could not be found.")
		
	// Authentication errors
	ec.add(ErrAuthenticationFailed, "auth", "Authentication Failed",
		"User authentication failed", http.StatusUnauthorized, "error", true,
		"Please check your credentials and try again.")
		
	ec.add(ErrAuthorizationDenied, "auth", "Authorization Denied",
		"User does not have permission for this operation", http.StatusForbidden, "error", false,
		"You don't have permission to perform this action.")
		
	// System errors
	ec.add(ErrSystemResourceExhausted, "system", "System Resources Exhausted",
		"System resources are exhausted", http.StatusServiceUnavailable, "critical", true,
		"The system is currently overloaded. Please try again later.")
}

// add is a helper method to add error definitions
func (ec *ErrorCatalog) add(code ErrorCode, category, title, description string, httpStatus int, severity string, recoverable bool, userMessage string) {
	ec.definitions[code] = ErrorDefinition{
		Code:        code,
		Category:    category,
		Title:       title,
		Description: description,
		HTTPStatus:  httpStatus,
		Severity:    severity,
		Recoverable: recoverable,
		UserMessage: userMessage,
	}
}

// Global error catalog instance
var globalCatalog = NewErrorCatalog()

// GetErrorDefinition retrieves an error definition globally
func GetErrorDefinition(code ErrorCode) (ErrorDefinition, bool) {
	return globalCatalog.Get(code)
}

// GetErrorsByCategory retrieves errors by category globally
func GetErrorsByCategory(category string) []ErrorDefinition {
	return globalCatalog.GetByCategory(category)
}

// ListAllErrors lists all error definitions globally
func ListAllErrors() []ErrorDefinition {
	return globalCatalog.List()
}

// IsValidErrorCode checks if an error code is valid
func IsValidErrorCode(code ErrorCode) bool {
	_, exists := globalCatalog.Get(code)
	return exists
}

// GetCategoryFromCode extracts the category from an error code
func GetCategoryFromCode(code ErrorCode) string {
	codeStr := string(code)
	if len(codeStr) < 3 {
		return "unknown"
	}
	
	prefix := codeStr[:3]
	categoryMap := map[string]string{
		"EXP": "experiment",
		"EXE": "execution", 
		"TGT": "target",
		"PRV": "provider",
		"SAF": "safety",
		"VAL": "validation",
		"STO": "storage",
		"AUT": "auth",
		"CFG": "config",
		"NET": "network",
		"SYS": "system",
	}
	
	if category, exists := categoryMap[prefix]; exists {
		return category
	}
	
	return "unknown"
}

// FormatErrorCode formats an error code with proper spacing
func FormatErrorCode(code ErrorCode) string {
	codeStr := string(code)
	if len(codeStr) >= 6 {
		return fmt.Sprintf("%s-%s", codeStr[:3], codeStr[3:])
	}
	return codeStr
}

// SearchErrors searches for errors by title or description
func SearchErrors(query string) []ErrorDefinition {
	query = strings.ToLower(query)
	var results []ErrorDefinition
	
	for _, def := range globalCatalog.definitions {
		if strings.Contains(strings.ToLower(def.Title), query) ||
		   strings.Contains(strings.ToLower(def.Description), query) ||
		   strings.Contains(strings.ToLower(def.UserMessage), query) {
			results = append(results, def)
		}
	}
	
	return results
}