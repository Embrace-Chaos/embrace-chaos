package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
	"github.com/embrace-chaos/internal/core/ports"
	"github.com/embrace-chaos/internal/adapters/http/middleware"
)

// ExecutionHandler handles execution-related HTTP requests
type ExecutionHandler struct {
	executionService ports.ExecutionService
	validator        *middleware.RequestValidator
}

// NewExecutionHandler creates a new execution handler
func NewExecutionHandler(
	executionService ports.ExecutionService,
	validator *middleware.RequestValidator,
) *ExecutionHandler {
	return &ExecutionHandler{
		executionService: executionService,
		validator:        validator,
	}
}

// ListExecutions handles GET /executions
func (h *ExecutionHandler) ListExecutions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	filters, pagination, err := h.parseListParams(r)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	executions, total, err := h.executionService.ListExecutions(ctx, filters, pagination)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	response := ExecutionListResponse{
		Executions: executions,
		Pagination: PaginationInfo{
			Page:       pagination.Page,
			PageSize:   pagination.PageSize,
			Total:      total,
			TotalPages: (total + pagination.PageSize - 1) / pagination.PageSize,
		},
	}

	middleware.WriteJSONResponse(w, http.StatusOK, response)
}

// GetExecution handles GET /executions/{executionId}
func (h *ExecutionHandler) GetExecution(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	executionID := mux.Vars(r)["executionId"]

	execution, err := h.executionService.GetExecution(ctx, domain.ExecutionID(executionID))
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	middleware.WriteJSONResponse(w, http.StatusOK, execution)
}

// CancelExecution handles POST /executions/{executionId}/cancel
func (h *ExecutionHandler) CancelExecution(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	executionID := mux.Vars(r)["executionId"]
	userID := middleware.GetUserIDFromContext(ctx)

	execution, err := h.executionService.CancelExecution(ctx, domain.ExecutionID(executionID), userID)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	middleware.WriteJSONResponse(w, http.StatusOK, execution)
}

// GetExecutionLogs handles GET /executions/{executionId}/logs
func (h *ExecutionHandler) GetExecutionLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	executionID := mux.Vars(r)["executionId"]

	// Parse query parameters
	follow := r.URL.Query().Get("follow") == "true"
	tail := 100
	if t := r.URL.Query().Get("tail"); t != "" {
		if parsed, err := strconv.Atoi(t); err == nil && parsed > 0 && parsed <= 10000 {
			tail = parsed
		}
	}

	// Check Accept header for response format
	acceptHeader := r.Header.Get("Accept")
	if acceptHeader == "text/plain" {
		h.streamLogsAsText(w, r, domain.ExecutionID(executionID), follow, tail)
		return
	}

	// Default to JSON response
	logs, err := h.executionService.GetExecutionLogs(ctx, domain.ExecutionID(executionID), tail)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	response := LogResponse{
		Logs:  convertLogEntries(logs),
		Total: len(logs),
	}

	middleware.WriteJSONResponse(w, http.StatusOK, response)
}

// Helper methods

func (h *ExecutionHandler) parseListParams(r *http.Request) (ports.ExecutionFilters, ports.PaginationRequest, error) {
	query := r.URL.Query()
	
	// Parse pagination
	page := 1
	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	pageSize := 20
	if ps := query.Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	orderBy := query.Get("order_by")
	if orderBy == "" {
		orderBy = "created_at"
	}

	orderDir := query.Get("order_dir")
	if orderDir == "" {
		orderDir = "desc"
	}

	// Parse filters
	filters := ports.ExecutionFilters{
		OrderBy:  orderBy,
		OrderDir: orderDir,
	}

	if experimentID := query.Get("experiment_id"); experimentID != "" {
		filters.ExperimentID = domain.ExperimentID(experimentID)
	}

	if statuses := query["status"]; len(statuses) > 0 {
		statusEnums := make([]domain.ExecutionStatus, len(statuses))
		for i, status := range statuses {
			statusEnums[i] = domain.ExecutionStatus(status)
		}
		filters.Status = statusEnums
	}

	pagination := ports.PaginationRequest{
		Page:     page,
		PageSize: pageSize,
	}

	return filters, pagination, nil
}

func (h *ExecutionHandler) streamLogsAsText(w http.ResponseWriter, r *http.Request, executionID domain.ExecutionID, follow bool, tail int) {
	ctx := r.Context()

	// Set headers for streaming
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	if follow {
		// For streaming logs, we would implement Server-Sent Events or WebSocket
		// For now, just get the latest logs
		w.Header().Set("Transfer-Encoding", "chunked")
	}

	logs, err := h.executionService.GetExecutionLogs(ctx, executionID, tail)
	if err != nil {
		http.Error(w, "Failed to retrieve logs", http.StatusInternalServerError)
		return
	}

	// Write logs as plain text
	for _, log := range logs {
		line := formatLogAsText(log)
		if _, err := w.Write([]byte(line + "\n")); err != nil {
			return
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	if follow {
		// In a real implementation, this would stream new logs as they arrive
		// For now, just close the connection
		return
	}
}

func formatLogAsText(log domain.LogEntry) string {
	return log.Timestamp.Format("2006-01-02T15:04:05.000Z07:00") + " " +
		log.Level + " " + log.Message
}

func convertLogEntries(logs []domain.LogEntry) []LogEntry {
	result := make([]LogEntry, len(logs))
	for i, log := range logs {
		result[i] = LogEntry{
			Timestamp: log.Timestamp,
			Level:     string(log.Level),
			Message:   log.Message,
			Source:    log.Source,
			Metadata:  log.Metadata,
		}
	}
	return result
}