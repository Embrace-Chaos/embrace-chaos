package errors

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// ErrorMetricsCollector collects and reports error metrics
type ErrorMetricsCollector interface {
	// Record error occurrence
	RecordError(ctx context.Context, err error)
	RecordDomainError(ctx context.Context, domainErr *DomainError)
	
	// Record error with additional context
	RecordErrorWithContext(ctx context.Context, err error, labels map[string]string)
	RecordErrorRecovery(ctx context.Context, err error, recovered bool, recoveryDuration time.Duration)
	
	// Get metrics
	GetErrorMetrics(ctx context.Context) ErrorMetrics
	GetErrorMetricsByCode(ctx context.Context, code ErrorCode) *ErrorCodeMetrics
	GetErrorTrends(ctx context.Context, timeRange TimeRange) ErrorTrends
	
	// Reset metrics
	ResetMetrics(ctx context.Context) error
	ResetMetricsByCode(ctx context.Context, code ErrorCode) error
	
	// Export metrics
	ExportMetrics(ctx context.Context, format string) ([]byte, error)
}

// ErrorMetrics represents comprehensive error metrics
type ErrorMetrics struct {
	// Overall metrics
	TotalErrors         int64                          `json:"total_errors"`
	ErrorRate           float64                        `json:"error_rate"`
	ErrorsPerSecond     float64                        `json:"errors_per_second"`
	
	// Error breakdown
	ErrorsByCode        map[string]*ErrorCodeMetrics   `json:"errors_by_code"`
	ErrorsByCategory    map[string]*ErrorCategoryMetrics `json:"errors_by_category"`
	ErrorsBySeverity    map[string]*ErrorSeverityMetrics `json:"errors_by_severity"`
	
	// Recovery metrics
	RecoveryMetrics     RecoveryMetrics                `json:"recovery_metrics"`
	
	// Time-based metrics
	RecentErrors        []RecentErrorSample            `json:"recent_errors"`
	ErrorDistribution   ErrorDistribution              `json:"error_distribution"`
	
	// System health
	HealthScore         float64                        `json:"health_score"`
	AlertLevel          string                         `json:"alert_level"`
	
	// Collection metadata
	CollectionStartTime time.Time                      `json:"collection_start_time"`
	LastUpdated         time.Time                      `json:"last_updated"`
	SampleCount         int64                          `json:"sample_count"`
}

// ErrorCodeMetrics represents metrics for a specific error code
type ErrorCodeMetrics struct {
	Code                ErrorCode                      `json:"code"`
	Count               int64                          `json:"count"`
	Rate                float64                        `json:"rate"`
	FirstSeen           time.Time                      `json:"first_seen"`
	LastSeen            time.Time                      `json:"last_seen"`
	
	// Recovery information
	RecoveryAttempts    int64                          `json:"recovery_attempts"`
	SuccessfulRecoveries int64                         `json:"successful_recoveries"`
	RecoveryRate        float64                        `json:"recovery_rate"`
	
	// Context analysis
	CommonContexts      []ContextPattern               `json:"common_contexts"`
	AffectedComponents  []string                       `json:"affected_components"`
	
	// Trends
	HourlyDistribution  [24]int64                      `json:"hourly_distribution"`
	DailyTrend          []DailyErrorCount              `json:"daily_trend"`
	
	// Severity metrics
	CriticalCount       int64                          `json:"critical_count"`
	ErrorCount          int64                          `json:"error_count"`
	WarningCount        int64                          `json:"warning_count"`
}

// ErrorCategoryMetrics represents metrics for an error category
type ErrorCategoryMetrics struct {
	Category            string                         `json:"category"`
	Count               int64                          `json:"count"`
	Rate                float64                        `json:"rate"`
	TopErrorCodes       []ErrorCodeCount               `json:"top_error_codes"`
	AverageRecoveryTime time.Duration                  `json:"average_recovery_time"`
}

// ErrorSeverityMetrics represents metrics by severity level
type ErrorSeverityMetrics struct {
	Severity            string                         `json:"severity"`
	Count               int64                          `json:"count"`
	Rate                float64                        `json:"rate"`
	AverageImpact       float64                        `json:"average_impact"`
	EscalationRate      float64                        `json:"escalation_rate"`
}

// RecoveryMetrics represents error recovery metrics
type RecoveryMetrics struct {
	TotalRecoveryAttempts    int64         `json:"total_recovery_attempts"`
	SuccessfulRecoveries     int64         `json:"successful_recoveries"`
	FailedRecoveries         int64         `json:"failed_recoveries"`
	OverallRecoveryRate      float64       `json:"overall_recovery_rate"`
	AverageRecoveryTime      time.Duration `json:"average_recovery_time"`
	FastestRecovery          time.Duration `json:"fastest_recovery"`
	SlowestRecovery          time.Duration `json:"slowest_recovery"`
	RecoveryTimeP50          time.Duration `json:"recovery_time_p50"`
	RecoveryTimeP95          time.Duration `json:"recovery_time_p95"`
	RecoveryTimeP99          time.Duration `json:"recovery_time_p99"`
}

// RecentErrorSample represents a recent error sample
type RecentErrorSample struct {
	Timestamp   time.Time                      `json:"timestamp"`
	ErrorCode   ErrorCode                      `json:"error_code"`
	Category    string                         `json:"category"`
	Severity    string                         `json:"severity"`
	Component   string                         `json:"component"`
	Count       int64                          `json:"count"`
	Context     map[string]string              `json:"context,omitempty"`
}

// ErrorDistribution represents error distribution over time
type ErrorDistribution struct {
	TimeWindows         []TimeWindow                   `json:"time_windows"`
	PeakErrorTime       time.Time                      `json:"peak_error_time"`
	PeakErrorRate       float64                        `json:"peak_error_rate"`
	QuietPeriods        []TimeRange                    `json:"quiet_periods"`
	BusyPeriods         []TimeRange                    `json:"busy_periods"`
}

// TimeWindow represents an error count in a time window
type TimeWindow struct {
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	ErrorCount  int64     `json:"error_count"`
	ErrorRate   float64   `json:"error_rate"`
}

// TimeRange represents a time range
type TimeRange struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// ContextPattern represents a common context pattern
type ContextPattern struct {
	Pattern     map[string]string `json:"pattern"`
	Count       int64             `json:"count"`
	Percentage  float64           `json:"percentage"`
}

// DailyErrorCount represents daily error count
type DailyErrorCount struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// ErrorCodeCount represents error code with count
type ErrorCodeCount struct {
	Code  ErrorCode `json:"code"`
	Count int64     `json:"count"`
}

// ErrorTrends represents error trends over time
type ErrorTrends struct {
	TimeRange           TimeRange                      `json:"time_range"`
	OverallTrend        TrendDirection                 `json:"overall_trend"`
	TrendPercentage     float64                        `json:"trend_percentage"`
	TrendConfidence     float64                        `json:"trend_confidence"`
	
	// Code-specific trends
	CodeTrends          map[string]CodeTrend          `json:"code_trends"`
	
	// Category trends
	CategoryTrends      map[string]CategoryTrend      `json:"category_trends"`
	
	// Predictions
	Predictions         []ErrorPrediction             `json:"predictions"`
	
	// Anomalies
	Anomalies           []ErrorAnomaly                `json:"anomalies"`
}

// TrendDirection represents trend direction
type TrendDirection string

const (
	TrendUp       TrendDirection = "up"
	TrendDown     TrendDirection = "down"
	TrendStable   TrendDirection = "stable"
	TrendVolatile TrendDirection = "volatile"
)

// CodeTrend represents trend for a specific error code
type CodeTrend struct {
	Code            ErrorCode      `json:"code"`
	Trend           TrendDirection `json:"trend"`
	ChangeRate      float64        `json:"change_rate"`
	Confidence      float64        `json:"confidence"`
	PredictedImpact string         `json:"predicted_impact"`
}

// CategoryTrend represents trend for an error category
type CategoryTrend struct {
	Category        string         `json:"category"`
	Trend           TrendDirection `json:"trend"`
	ChangeRate      float64        `json:"change_rate"`
	DominantCodes   []ErrorCode    `json:"dominant_codes"`
}

// ErrorPrediction represents a prediction about future errors
type ErrorPrediction struct {
	TimeHorizon     time.Duration  `json:"time_horizon"`
	PredictedCount  int64          `json:"predicted_count"`
	Confidence      float64        `json:"confidence"`
	Factors         []string       `json:"factors"`
	Recommendations []string       `json:"recommendations"`
}

// ErrorAnomaly represents an anomaly in error patterns
type ErrorAnomaly struct {
	DetectedAt      time.Time                      `json:"detected_at"`
	Type            string                         `json:"type"`
	Severity        string                         `json:"severity"`
	Description     string                         `json:"description"`
	AffectedCodes   []ErrorCode                    `json:"affected_codes"`
	Metrics         map[string]float64             `json:"metrics"`
	Context         map[string]interface{}         `json:"context"`
}

// DefaultErrorMetricsCollector is the default implementation
type DefaultErrorMetricsCollector struct {
	mu                  sync.RWMutex
	
	// Counters
	totalErrors         int64
	errorCounts         map[ErrorCode]*int64
	categoryCounts      map[string]*int64
	severityCounts      map[string]*int64
	
	// Recovery tracking
	recoveryAttempts    map[ErrorCode]*int64
	successfulRecoveries map[ErrorCode]*int64
	recoveryTimes       map[ErrorCode][]time.Duration
	
	// Context tracking
	contextPatterns     map[ErrorCode]map[string]map[string]int64
	componentErrors     map[string]map[ErrorCode]int64
	
	// Time-based tracking
	recentErrors        []RecentErrorSample
	hourlyDistribution  map[ErrorCode][24]int64
	dailyTrend          map[ErrorCode][]DailyErrorCount
	
	// Collection metadata
	startTime           time.Time
	lastUpdate          time.Time
	
	// Configuration
	maxRecentErrors     int
	retentionDays       int
	alertThresholds     map[string]float64
	
	// External dependencies
	metricsBackend      MetricsBackend
	alertManager        AlertManager
}

// MetricsBackend defines the interface for metrics storage
type MetricsBackend interface {
	RecordCounter(name string, value int64, labels map[string]string) error
	RecordHistogram(name string, value float64, labels map[string]string) error
	RecordGauge(name string, value float64, labels map[string]string) error
	Query(query string, timeRange TimeRange) ([]MetricSample, error)
}

// AlertManager defines the interface for alerting
type AlertManager interface {
	TriggerAlert(ctx context.Context, alert Alert) error
	ResolveAlert(ctx context.Context, alertID string) error
	GetActiveAlerts(ctx context.Context) ([]Alert, error)
}

// Alert represents an alert
type Alert struct {
	ID          string                         `json:"id"`
	Type        string                         `json:"type"`
	Severity    string                         `json:"severity"`
	Title       string                         `json:"title"`
	Description string                         `json:"description"`
	Metrics     map[string]interface{}         `json:"metrics"`
	Context     map[string]string              `json:"context"`
	CreatedAt   time.Time                      `json:"created_at"`
	ResolvedAt  *time.Time                     `json:"resolved_at,omitempty"`
}

// MetricSample represents a metric sample
type MetricSample struct {
	Timestamp time.Time              `json:"timestamp"`
	Value     float64                `json:"value"`
	Labels    map[string]string      `json:"labels"`
}

// NewDefaultErrorMetricsCollector creates a new default error metrics collector
func NewDefaultErrorMetricsCollector(backend MetricsBackend, alertManager AlertManager) *DefaultErrorMetricsCollector {
	return &DefaultErrorMetricsCollector{
		errorCounts:          make(map[ErrorCode]*int64),
		categoryCounts:       make(map[string]*int64),
		severityCounts:       make(map[string]*int64),
		recoveryAttempts:     make(map[ErrorCode]*int64),
		successfulRecoveries: make(map[ErrorCode]*int64),
		recoveryTimes:        make(map[ErrorCode][]time.Duration),
		contextPatterns:      make(map[ErrorCode]map[string]map[string]int64),
		componentErrors:      make(map[string]map[ErrorCode]int64),
		recentErrors:         make([]RecentErrorSample, 0),
		hourlyDistribution:   make(map[ErrorCode][24]int64),
		dailyTrend:           make(map[ErrorCode][]DailyErrorCount),
		startTime:            time.Now(),
		lastUpdate:           time.Now(),
		maxRecentErrors:      1000,
		retentionDays:        30,
		alertThresholds: map[string]float64{
			"error_rate":           0.05, // 5% error rate
			"critical_errors":      10,   // 10 critical errors per minute
			"recovery_failure_rate": 0.1,  // 10% recovery failure rate
		},
		metricsBackend: backend,
		alertManager:   alertManager,
	}
}

// RecordError records an error occurrence
func (c *DefaultErrorMetricsCollector) RecordError(ctx context.Context, err error) {
	if domainErr, ok := err.(*DomainError); ok {
		c.RecordDomainError(ctx, domainErr)
		return
	}
	
	// Handle generic errors
	c.recordGenericError(ctx, err, nil)
}

// RecordDomainError records a domain error occurrence
func (c *DefaultErrorMetricsCollector) RecordDomainError(ctx context.Context, domainErr *DomainError) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Increment total errors
	atomic.AddInt64(&c.totalErrors, 1)
	
	// Increment error code counter
	if counter, exists := c.errorCounts[domainErr.Code]; exists {
		atomic.AddInt64(counter, 1)
	} else {
		counter := int64(1)
		c.errorCounts[domainErr.Code] = &counter
	}
	
	// Increment category counter
	category := GetCategoryFromCode(domainErr.Code)
	if counter, exists := c.categoryCounts[category]; exists {
		atomic.AddInt64(counter, 1)
	} else {
		counter := int64(1)
		c.categoryCounts[category] = &counter
	}
	
	// Increment severity counter
	severity := domainErr.GetSeverity()
	if counter, exists := c.severityCounts[severity]; exists {
		atomic.AddInt64(counter, 1)
	} else {
		counter := int64(1)
		c.severityCounts[severity] = &counter
	}
	
	// Record context patterns
	c.recordContextPatterns(domainErr.Code, domainErr.Context)
	
	// Add to recent errors
	c.addRecentError(RecentErrorSample{
		Timestamp: time.Now(),
		ErrorCode: domainErr.Code,
		Category:  category,
		Severity:  severity,
		Component: getComponentFromContext(ctx),
		Count:     1,
		Context:   domainErr.Context,
	})
	
	// Update time-based metrics
	c.updateTimeBasedMetrics(domainErr.Code)
	
	// Record to backend
	if c.metricsBackend != nil {
		labels := map[string]string{
			"error_code": string(domainErr.Code),
			"category":   category,
			"severity":   severity,
		}
		c.metricsBackend.RecordCounter("chaos_errors_total", 1, labels)
	}
	
	// Check for alerts
	c.checkAlerts(ctx, domainErr)
	
	c.lastUpdate = time.Now()
}

// RecordErrorWithContext records an error with additional context
func (c *DefaultErrorMetricsCollector) RecordErrorWithContext(ctx context.Context, err error, labels map[string]string) {
	// Implementation similar to RecordError but with additional labels
	c.RecordError(ctx, err)
	
	// Record additional context if backend is available
	if c.metricsBackend != nil {
		c.metricsBackend.RecordCounter("chaos_errors_with_context", 1, labels)
	}
}

// RecordErrorRecovery records an error recovery attempt
func (c *DefaultErrorMetricsCollector) RecordErrorRecovery(ctx context.Context, err error, recovered bool, recoveryDuration time.Duration) {
	domainErr, ok := err.(*DomainError)
	if !ok {
		return
	}
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Increment recovery attempts
	if counter, exists := c.recoveryAttempts[domainErr.Code]; exists {
		atomic.AddInt64(counter, 1)
	} else {
		counter := int64(1)
		c.recoveryAttempts[domainErr.Code] = &counter
	}
	
	// Increment successful recoveries if recovered
	if recovered {
		if counter, exists := c.successfulRecoveries[domainErr.Code]; exists {
			atomic.AddInt64(counter, 1)
		} else {
			counter := int64(1)
			c.successfulRecoveries[domainErr.Code] = &counter
		}
		
		// Record recovery time
		if times, exists := c.recoveryTimes[domainErr.Code]; exists {
			c.recoveryTimes[domainErr.Code] = append(times, recoveryDuration)
		} else {
			c.recoveryTimes[domainErr.Code] = []time.Duration{recoveryDuration}
		}
	}
	
	// Record to backend
	if c.metricsBackend != nil {
		labels := map[string]string{
			"error_code": string(domainErr.Code),
			"recovered":  fmt.Sprintf("%t", recovered),
		}
		c.metricsBackend.RecordCounter("chaos_error_recoveries_total", 1, labels)
		c.metricsBackend.RecordHistogram("chaos_error_recovery_duration_seconds", recoveryDuration.Seconds(), labels)
	}
}

// GetErrorMetrics returns comprehensive error metrics
func (c *DefaultErrorMetricsCollector) GetErrorMetrics(ctx context.Context) ErrorMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	metrics := ErrorMetrics{
		TotalErrors:         atomic.LoadInt64(&c.totalErrors),
		ErrorsByCode:        make(map[string]*ErrorCodeMetrics),
		ErrorsByCategory:    make(map[string]*ErrorCategoryMetrics),
		ErrorsBySeverity:    make(map[string]*ErrorSeverityMetrics),
		RecentErrors:        make([]RecentErrorSample, len(c.recentErrors)),
		CollectionStartTime: c.startTime,
		LastUpdated:         c.lastUpdate,
		SampleCount:         atomic.LoadInt64(&c.totalErrors),
	}
	
	// Calculate error rate and errors per second
	duration := time.Since(c.startTime)
	if duration.Seconds() > 0 {
		metrics.ErrorsPerSecond = float64(metrics.TotalErrors) / duration.Seconds()
	}
	
	// Build error code metrics
	for code, counter := range c.errorCounts {
		count := atomic.LoadInt64(counter)
		metrics.ErrorsByCode[string(code)] = &ErrorCodeMetrics{
			Code:  code,
			Count: count,
			Rate:  float64(count) / float64(metrics.TotalErrors),
		}
	}
	
	// Build category metrics
	for category, counter := range c.categoryCounts {
		count := atomic.LoadInt64(counter)
		metrics.ErrorsByCategory[category] = &ErrorCategoryMetrics{
			Category: category,
			Count:    count,
			Rate:     float64(count) / float64(metrics.TotalErrors),
		}
	}
	
	// Build severity metrics
	for severity, counter := range c.severityCounts {
		count := atomic.LoadInt64(counter)
		metrics.ErrorsBySeverity[severity] = &ErrorSeverityMetrics{
			Severity: severity,
			Count:    count,
			Rate:     float64(count) / float64(metrics.TotalErrors),
		}
	}
	
	// Copy recent errors
	copy(metrics.RecentErrors, c.recentErrors)
	
	// Calculate health score
	metrics.HealthScore = c.calculateHealthScore()
	metrics.AlertLevel = c.determineAlertLevel(metrics.HealthScore)
	
	return metrics
}

// GetErrorMetricsByCode returns metrics for a specific error code
func (c *DefaultErrorMetricsCollector) GetErrorMetricsByCode(ctx context.Context, code ErrorCode) *ErrorCodeMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	counter, exists := c.errorCounts[code]
	if !exists {
		return nil
	}
	
	count := atomic.LoadInt64(counter)
	totalErrors := atomic.LoadInt64(&c.totalErrors)
	
	metrics := &ErrorCodeMetrics{
		Code:  code,
		Count: count,
		Rate:  float64(count) / float64(totalErrors),
	}
	
	// Add recovery metrics if available
	if recoveryCounter, exists := c.recoveryAttempts[code]; exists {
		metrics.RecoveryAttempts = atomic.LoadInt64(recoveryCounter)
	}
	
	if successCounter, exists := c.successfulRecoveries[code]; exists {
		metrics.SuccessfulRecoveries = atomic.LoadInt64(successCounter)
		if metrics.RecoveryAttempts > 0 {
			metrics.RecoveryRate = float64(metrics.SuccessfulRecoveries) / float64(metrics.RecoveryAttempts)
		}
	}
	
	return metrics
}

// Additional helper methods

func (c *DefaultErrorMetricsCollector) recordGenericError(ctx context.Context, err error, labels map[string]string) {
	// Implementation for generic errors
	atomic.AddInt64(&c.totalErrors, 1)
	c.lastUpdate = time.Now()
}

func (c *DefaultErrorMetricsCollector) recordContextPatterns(code ErrorCode, context map[string]string) {
	if context == nil {
		return
	}
	
	if _, exists := c.contextPatterns[code]; !exists {
		c.contextPatterns[code] = make(map[string]map[string]int64)
	}
	
	for key, value := range context {
		if _, exists := c.contextPatterns[code][key]; !exists {
			c.contextPatterns[code][key] = make(map[string]int64)
		}
		c.contextPatterns[code][key][value]++
	}
}

func (c *DefaultErrorMetricsCollector) addRecentError(sample RecentErrorSample) {
	c.recentErrors = append(c.recentErrors, sample)
	
	// Keep only the most recent errors
	if len(c.recentErrors) > c.maxRecentErrors {
		c.recentErrors = c.recentErrors[len(c.recentErrors)-c.maxRecentErrors:]
	}
}

func (c *DefaultErrorMetricsCollector) updateTimeBasedMetrics(code ErrorCode) {
	now := time.Now()
	hour := now.Hour()
	
	// Update hourly distribution
	if dist, exists := c.hourlyDistribution[code]; exists {
		dist[hour]++
		c.hourlyDistribution[code] = dist
	} else {
		var dist [24]int64
		dist[hour] = 1
		c.hourlyDistribution[code] = dist
	}
}

func (c *DefaultErrorMetricsCollector) calculateHealthScore() float64 {
	// Simple health score calculation based on error rates and severity
	totalErrors := atomic.LoadInt64(&c.totalErrors)
	if totalErrors == 0 {
		return 100.0
	}
	
	duration := time.Since(c.startTime)
	errorRate := float64(totalErrors) / duration.Minutes()
	
	// Lower error rate = higher health score
	healthScore := 100.0 - (errorRate * 10)
	if healthScore < 0 {
		healthScore = 0
	}
	
	return healthScore
}

func (c *DefaultErrorMetricsCollector) determineAlertLevel(healthScore float64) string {
	switch {
	case healthScore >= 90:
		return "healthy"
	case healthScore >= 70:
		return "warning"
	case healthScore >= 50:
		return "critical"
	default:
		return "emergency"
	}
}

func (c *DefaultErrorMetricsCollector) checkAlerts(ctx context.Context, domainErr *DomainError) {
	if c.alertManager == nil {
		return
	}
	
	// Check for critical errors
	if domainErr.GetSeverity() == "critical" {
		alert := Alert{
			ID:          fmt.Sprintf("critical-error-%s-%d", domainErr.Code, time.Now().Unix()),
			Type:        "critical_error",
			Severity:    "critical",
			Title:       fmt.Sprintf("Critical Error: %s", domainErr.Code),
			Description: domainErr.Message,
			Metrics: map[string]interface{}{
				"error_code": string(domainErr.Code),
				"timestamp":  domainErr.Timestamp,
			},
			Context:   domainErr.Context,
			CreatedAt: time.Now(),
		}
		
		c.alertManager.TriggerAlert(ctx, alert)
	}
}

func getComponentFromContext(ctx context.Context) string {
	if component, ok := ctx.Value("component").(string); ok {
		return component
	}
	return "unknown"
}

// Implement remaining methods for completeness
func (c *DefaultErrorMetricsCollector) GetErrorTrends(ctx context.Context, timeRange TimeRange) ErrorTrends {
	// Implementation would analyze trends over the specified time range
	return ErrorTrends{
		TimeRange:    timeRange,
		OverallTrend: TrendStable,
	}
}

func (c *DefaultErrorMetricsCollector) ResetMetrics(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	atomic.StoreInt64(&c.totalErrors, 0)
	c.errorCounts = make(map[ErrorCode]*int64)
	c.categoryCounts = make(map[string]*int64)
	c.severityCounts = make(map[string]*int64)
	c.recentErrors = make([]RecentErrorSample, 0)
	c.startTime = time.Now()
	c.lastUpdate = time.Now()
	
	return nil
}

func (c *DefaultErrorMetricsCollector) ResetMetricsByCode(ctx context.Context, code ErrorCode) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if counter, exists := c.errorCounts[code]; exists {
		atomic.StoreInt64(counter, 0)
	}
	
	return nil
}

func (c *DefaultErrorMetricsCollector) ExportMetrics(ctx context.Context, format string) ([]byte, error) {
	metrics := c.GetErrorMetrics(ctx)
	
	switch format {
	case "json":
		return json.Marshal(metrics)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// Global metrics collector
var globalMetricsCollector ErrorMetricsCollector

// SetGlobalMetricsCollector sets the global metrics collector
func SetGlobalMetricsCollector(collector ErrorMetricsCollector) {
	globalMetricsCollector = collector
}

// GetGlobalMetricsCollector returns the global metrics collector
func GetGlobalMetricsCollector() ErrorMetricsCollector {
	return globalMetricsCollector
}

// Convenience functions
func RecordError(ctx context.Context, err error) {
	if globalMetricsCollector != nil {
		globalMetricsCollector.RecordError(ctx, err)
	}
}

func RecordDomainError(ctx context.Context, domainErr *DomainError) {
	if globalMetricsCollector != nil {
		globalMetricsCollector.RecordDomainError(ctx, domainErr)
	}
}