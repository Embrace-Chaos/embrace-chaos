package domain

import (
	"time"
)

// Result represents the overall result of an experiment execution
type Result struct {
	ID           string           `json:"id"`
	ExperimentID ExperimentID     `json:"experiment_id"`
	ExecutionID  ExecutionID      `json:"execution_id"`
	
	// Overall result
	Status       ResultStatus     `json:"status"`
	Success      bool             `json:"success"`
	
	// Timing
	StartTime    time.Time        `json:"start_time"`
	EndTime      time.Time        `json:"end_time"`
	Duration     Duration         `json:"duration"`
	
	// Execution summary
	Summary      ResultSummary    `json:"summary"`
	
	// Detailed results per target
	TargetResults []TargetResult  `json:"target_results"`
	
	// Safety information
	SafetySummary SafetySummary   `json:"safety_summary"`
	
	// Metrics and measurements
	Metrics      ResultMetrics    `json:"metrics"`
	
	// Impact analysis
	Impact       ImpactAnalysis   `json:"impact"`
	
	// Artifacts and outputs
	Artifacts    []Artifact       `json:"artifacts"`
	
	// Metadata
	CreatedAt    time.Time        `json:"created_at"`
	CreatedBy    string           `json:"created_by"`
}

// ResultStatus represents the status of an experiment result
type ResultStatus string

const (
	ResultStatusSuccess           ResultStatus = "success"
	ResultStatusPartialSuccess    ResultStatus = "partial_success"
	ResultStatusFailure           ResultStatus = "failure"
	ResultStatusCancelled         ResultStatus = "cancelled"
	ResultStatusSafetyViolation   ResultStatus = "safety_violation"
	ResultStatusTimeout           ResultStatus = "timeout"
)

// ResultSummary provides a high-level summary of the results
type ResultSummary struct {
	TotalTargets        int     `json:"total_targets"`
	SuccessfulTargets   int     `json:"successful_targets"`
	FailedTargets       int     `json:"failed_targets"`
	SkippedTargets      int     `json:"skipped_targets"`
	
	TotalActions        int     `json:"total_actions"`
	SuccessfulActions   int     `json:"successful_actions"`
	FailedActions       int     `json:"failed_actions"`
	
	SuccessRate         float64 `json:"success_rate"`
	
	// Safety
	SafetyViolations    int     `json:"safety_violations"`
	AutoRollbacks       int     `json:"auto_rollbacks"`
	
	// Error summary
	ErrorTypes          map[string]int `json:"error_types"`
	
	// Performance
	AverageExecutionTime Duration `json:"average_execution_time"`
	MaxExecutionTime     Duration `json:"max_execution_time"`
	MinExecutionTime     Duration `json:"min_execution_time"`
}

// TargetResult represents the result for a specific target
type TargetResult struct {
	TargetID     string           `json:"target_id"`
	TargetName   string           `json:"target_name"`
	TargetType   TargetType       `json:"target_type"`
	Provider     string           `json:"provider"`
	
	Status       ResultStatus     `json:"status"`
	Success      bool             `json:"success"`
	
	// Timing
	StartTime    time.Time        `json:"start_time"`
	EndTime      time.Time        `json:"end_time"`
	Duration     Duration         `json:"duration"`
	
	// Actions performed
	Actions      []ActionResult   `json:"actions"`
	
	// Error information
	Error        *ResultError     `json:"error,omitempty"`
	
	// Metrics for this target
	Metrics      map[string]interface{} `json:"metrics"`
	
	// State changes
	StateChanges []StateChange    `json:"state_changes"`
	
	// Recovery information
	Recovery     *RecoveryInfo    `json:"recovery,omitempty"`
}

// ActionResult represents the result of a single action
type ActionResult struct {
	ActionName   string                 `json:"action_name"`
	ActionType   string                 `json:"action_type"`
	Status       ResultStatus           `json:"status"`
	Success      bool                   `json:"success"`
	
	StartTime    time.Time              `json:"start_time"`
	EndTime      time.Time              `json:"end_time"`
	Duration     Duration               `json:"duration"`
	
	Parameters   map[string]interface{} `json:"parameters"`
	Output       string                 `json:"output"`
	Error        string                 `json:"error,omitempty"`
	
	// Provider-specific data
	ProviderData map[string]interface{} `json:"provider_data"`
	
	// Rollback information
	Rollback     *RollbackInfo          `json:"rollback,omitempty"`
}

// StateChange represents a change in target state
type StateChange struct {
	Timestamp    time.Time              `json:"timestamp"`
	Property     string                 `json:"property"`
	OldValue     interface{}            `json:"old_value"`
	NewValue     interface{}            `json:"new_value"`
	ActionName   string                 `json:"action_name"`
	Reversible   bool                   `json:"reversible"`
}

// RecoveryInfo holds information about target recovery
type RecoveryInfo struct {
	Required     bool                   `json:"required"`
	Attempted    bool                   `json:"attempted"`
	Success      bool                   `json:"success"`
	Method       string                 `json:"method"`
	Duration     Duration               `json:"duration"`
	Error        string                 `json:"error,omitempty"`
	Details      map[string]interface{} `json:"details"`
}

// RollbackInfo holds information about action rollback
type RollbackInfo struct {
	Required     bool                   `json:"required"`
	Attempted    bool                   `json:"attempted"`
	Success      bool                   `json:"success"`
	Method       string                 `json:"method"`
	Duration     Duration               `json:"duration"`
	Error        string                 `json:"error,omitempty"`
	Details      map[string]interface{} `json:"details"`
}

// ResultError represents an error in the result
type ResultError struct {
	Code         string                 `json:"code"`
	Message      string                 `json:"message"`
	Type         string                 `json:"type"`
	Category     string                 `json:"category"`
	Severity     string                 `json:"severity"`
	Recoverable  bool                   `json:"recoverable"`
	Context      map[string]interface{} `json:"context"`
	StackTrace   string                 `json:"stack_trace,omitempty"`
}

// SafetySummary provides safety-related result information
type SafetySummary struct {
	ChecksPerformed     int                `json:"checks_performed"`
	ViolationsDetected  int                `json:"violations_detected"`
	CriticalViolations  int                `json:"critical_violations"`
	AutoRollbacks       int                `json:"auto_rollbacks"`
	ManualInterventions int                `json:"manual_interventions"`
	
	ViolationDetails    []SafetyViolation  `json:"violation_details"`
	
	OverallRisk         string             `json:"overall_risk"`
	RiskScore           float64            `json:"risk_score"`
}

// SafetyViolation represents a safety violation
type SafetyViolation struct {
	CheckName    string                 `json:"check_name"`
	Severity     string                 `json:"severity"`
	Timestamp    time.Time              `json:"timestamp"`
	Value        float64                `json:"value"`
	Threshold    Threshold              `json:"threshold"`
	Message      string                 `json:"message"`
	ActionTaken  string                 `json:"action_taken"`
	Context      map[string]interface{} `json:"context"`
}

// ResultMetrics holds various metrics collected during execution
type ResultMetrics struct {
	// Performance metrics
	ResponseTimes       map[string]Duration    `json:"response_times"`
	Throughput          map[string]float64     `json:"throughput"`
	ErrorRates          map[string]float64     `json:"error_rates"`
	
	// Resource utilization
	CPUUsage            map[string]float64     `json:"cpu_usage"`
	MemoryUsage         map[string]float64     `json:"memory_usage"`
	NetworkIO           map[string]float64     `json:"network_io"`
	DiskIO              map[string]float64     `json:"disk_io"`
	
	// Application metrics
	RequestCount        map[string]int64       `json:"request_count"`
	ConnectionCount     map[string]int64       `json:"connection_count"`
	QueueDepth          map[string]int64       `json:"queue_depth"`
	
	// Custom metrics
	CustomMetrics       map[string]interface{} `json:"custom_metrics"`
	
	// Baseline comparison
	BaselineComparison  map[string]float64     `json:"baseline_comparison"`
}

// ImpactAnalysis provides analysis of the experiment's impact
type ImpactAnalysis struct {
	// Blast radius
	DirectlyAffected    []string           `json:"directly_affected"`
	IndirectlyAffected  []string           `json:"indirectly_affected"`
	
	// Service impact
	ServiceImpact       []ServiceImpact    `json:"service_impact"`
	
	// User impact
	UserImpact          UserImpact         `json:"user_impact"`
	
	// Business impact
	BusinessImpact      BusinessImpact     `json:"business_impact"`
	
	// Recovery time
	RecoveryTime        Duration           `json:"recovery_time"`
	
	// Lessons learned
	LessonsLearned      []string           `json:"lessons_learned"`
	
	// Recommendations
	Recommendations     []string           `json:"recommendations"`
}

// ServiceImpact represents impact on a service
type ServiceImpact struct {
	ServiceName         string             `json:"service_name"`
	ImpactLevel         string             `json:"impact_level"`
	Description         string             `json:"description"`
	Metrics             map[string]float64 `json:"metrics"`
	RecoveryTime        Duration           `json:"recovery_time"`
	MitigationActions   []string           `json:"mitigation_actions"`
}

// UserImpact represents impact on users
type UserImpact struct {
	AffectedUsers       int64              `json:"affected_users"`
	ImpactDuration      Duration           `json:"impact_duration"`
	SeverityLevel       string             `json:"severity_level"`
	Symptoms            []string           `json:"symptoms"`
	MitigationActions   []string           `json:"mitigation_actions"`
}

// BusinessImpact represents business impact
type BusinessImpact struct {
	EstimatedCost       float64            `json:"estimated_cost"`
	Currency            string             `json:"currency"`
	RevenueImpact       float64            `json:"revenue_impact"`
	SLAViolations       []string           `json:"sla_violations"`
	ComplianceIssues    []string           `json:"compliance_issues"`
	ReputationImpact    string             `json:"reputation_impact"`
}

// Artifact represents a file or data artifact generated during execution
type Artifact struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Path        string                 `json:"path"`
	URL         string                 `json:"url,omitempty"`
	Size        int64                  `json:"size"`
	Hash        string                 `json:"hash"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
}

// NewResult creates a new result
func NewResult(experimentID ExperimentID, executionID ExecutionID, createdBy string) *Result {
	now := time.Now()
	return &Result{
		ID:           generateID(),
		ExperimentID: experimentID,
		ExecutionID:  executionID,
		Status:       ResultStatusSuccess,
		Success:      true,
		StartTime:    now,
		Summary: ResultSummary{
			ErrorTypes: make(map[string]int),
		},
		TargetResults: make([]TargetResult, 0),
		SafetySummary: SafetySummary{
			ViolationDetails: make([]SafetyViolation, 0),
		},
		Metrics: ResultMetrics{
			ResponseTimes:      make(map[string]Duration),
			Throughput:         make(map[string]float64),
			ErrorRates:         make(map[string]float64),
			CPUUsage:           make(map[string]float64),
			MemoryUsage:        make(map[string]float64),
			NetworkIO:          make(map[string]float64),
			DiskIO:             make(map[string]float64),
			RequestCount:       make(map[string]int64),
			ConnectionCount:    make(map[string]int64),
			QueueDepth:         make(map[string]int64),
			CustomMetrics:      make(map[string]interface{}),
			BaselineComparison: make(map[string]float64),
		},
		Impact: ImpactAnalysis{
			DirectlyAffected:   make([]string, 0),
			IndirectlyAffected: make([]string, 0),
			ServiceImpact:      make([]ServiceImpact, 0),
			LessonsLearned:     make([]string, 0),
			Recommendations:    make([]string, 0),
		},
		Artifacts: make([]Artifact, 0),
		CreatedAt: now,
		CreatedBy: createdBy,
	}
}

// Complete completes the result
func (r *Result) Complete(endTime time.Time) {
	r.EndTime = endTime
	r.Duration = Duration(r.EndTime.Sub(r.StartTime))
	
	// Calculate summary metrics
	r.calculateSummary()
}

// AddTargetResult adds a target result
func (r *Result) AddTargetResult(targetResult TargetResult) {
	r.TargetResults = append(r.TargetResults, targetResult)
	
	// Update overall status based on target results
	r.updateOverallStatus()
}

// AddArtifact adds an artifact
func (r *Result) AddArtifact(artifact Artifact) {
	r.Artifacts = append(r.Artifacts, artifact)
}

// IsSuccessful checks if the result is successful
func (r *Result) IsSuccessful() bool {
	return r.Success && r.Status == ResultStatusSuccess
}

// HasFailures checks if there are any failures
func (r *Result) HasFailures() bool {
	return r.Summary.FailedTargets > 0 || r.Summary.FailedActions > 0
}

// HasSafetyViolations checks if there are safety violations
func (r *Result) HasSafetyViolations() bool {
	return r.SafetySummary.ViolationsDetected > 0
}

// calculateSummary calculates summary metrics
func (r *Result) calculateSummary() {
	r.Summary.TotalTargets = len(r.TargetResults)
	
	var totalExecutionTime Duration
	var maxTime Duration
	var minTime Duration = Duration(time.Hour * 24) // Initialize with a large value
	
	for _, targetResult := range r.TargetResults {
		if targetResult.Success {
			r.Summary.SuccessfulTargets++
		} else {
			r.Summary.FailedTargets++
		}
		
		r.Summary.TotalActions += len(targetResult.Actions)
		
		for _, action := range targetResult.Actions {
			if action.Success {
				r.Summary.SuccessfulActions++
			} else {
				r.Summary.FailedActions++
			}
		}
		
		// Track execution times
		totalExecutionTime += targetResult.Duration
		if targetResult.Duration > maxTime {
			maxTime = targetResult.Duration
		}
		if targetResult.Duration < minTime {
			minTime = targetResult.Duration
		}
		
		// Count error types
		if targetResult.Error != nil {
			r.Summary.ErrorTypes[targetResult.Error.Type]++
		}
	}
	
	// Calculate success rate
	if r.Summary.TotalTargets > 0 {
		r.Summary.SuccessRate = float64(r.Summary.SuccessfulTargets) / float64(r.Summary.TotalTargets)
	}
	
	// Calculate average execution time
	if r.Summary.TotalTargets > 0 {
		r.Summary.AverageExecutionTime = Duration(time.Duration(totalExecutionTime) / time.Duration(r.Summary.TotalTargets))
	}
	
	r.Summary.MaxExecutionTime = maxTime
	if minTime < Duration(time.Hour*24) {
		r.Summary.MinExecutionTime = minTime
	}
	
	// Update safety summary
	r.Summary.SafetyViolations = r.SafetySummary.ViolationsDetected
	r.Summary.AutoRollbacks = r.SafetySummary.AutoRollbacks
}

// updateOverallStatus updates the overall result status
func (r *Result) updateOverallStatus() {
	if r.Summary.FailedTargets == 0 && r.SafetySummary.CriticalViolations == 0 {
		r.Status = ResultStatusSuccess
		r.Success = true
	} else if r.Summary.SuccessfulTargets > 0 {
		r.Status = ResultStatusPartialSuccess
		r.Success = false
	} else if r.SafetySummary.CriticalViolations > 0 {
		r.Status = ResultStatusSafetyViolation
		r.Success = false
	} else {
		r.Status = ResultStatusFailure
		r.Success = false
	}
}