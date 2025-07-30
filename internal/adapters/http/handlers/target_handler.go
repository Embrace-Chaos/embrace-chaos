package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
	"github.com/embrace-chaos/internal/core/ports"
	"github.com/embrace-chaos/internal/adapters/http/middleware"
)

// TargetHandler handles target-related HTTP requests
type TargetHandler struct {
	targetService ports.TargetService
	validator     *middleware.RequestValidator
}

// NewTargetHandler creates a new target handler
func NewTargetHandler(
	targetService ports.TargetService,
	validator *middleware.RequestValidator,
) *TargetHandler {
	return &TargetHandler{
		targetService: targetService,
		validator:     validator,
	}
}

// ListTargets handles GET /targets
func (h *TargetHandler) ListTargets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	filters, pagination, err := h.parseListParams(r)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	targets, total, err := h.targetService.ListTargets(ctx, filters, pagination)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	response := TargetListResponse{
		Targets: convertTargetsToAPI(targets),
		Pagination: PaginationInfo{
			Page:       pagination.Page,
			PageSize:   pagination.PageSize,
			Total:      total,
			TotalPages: (total + pagination.PageSize - 1) / pagination.PageSize,
		},
	}

	middleware.WriteJSONResponse(w, http.StatusOK, response)
}

// DiscoverTargets handles POST /targets/discover
func (h *TargetHandler) DiscoverTargets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var request DiscoverTargetsRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		middleware.WriteErrorResponse(w, r, errors.NewValidationError("invalid request body"))
		return
	}

	// Validate request
	if err := h.validator.ValidateStruct(request); err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	// Convert request to domain model
	discoveryRequest := &domain.TargetDiscoveryRequest{
		Provider: domain.Provider(request.Provider),
		Region:   request.Region,
		Filters:  request.Filters,
	}

	targets, err := h.targetService.DiscoverTargets(ctx, discoveryRequest)
	if err != nil {
		middleware.WriteErrorResponse(w, r, err)
		return
	}

	response := DiscoverTargetsResponse{
		Targets: convertTargetsToAPI(targets),
		Total:   len(targets),
	}

	middleware.WriteJSONResponse(w, http.StatusOK, response)
}

// Helper methods

func (h *TargetHandler) parseListParams(r *http.Request) (ports.TargetFilters, ports.PaginationRequest, error) {
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

	// Parse filters
	filters := ports.TargetFilters{}

	if providers := query["provider"]; len(providers) > 0 {
		providerEnums := make([]domain.Provider, len(providers))
		for i, provider := range providers {
			providerEnums[i] = domain.Provider(provider)
		}
		filters.Providers = providerEnums
	}

	if types := query["type"]; len(types) > 0 {
		typeEnums := make([]domain.TargetType, len(types))
		for i, targetType := range types {
			typeEnums[i] = domain.TargetType(targetType)
		}
		filters.Types = typeEnums
	}

	if regions := query["region"]; len(regions) > 0 {
		filters.Regions = regions
	}

	pagination := ports.PaginationRequest{
		Page:     page,
		PageSize: pageSize,
	}

	return filters, pagination, nil
}

func convertTargetsToAPI(targets []domain.Target) []Target {
	result := make([]Target, len(targets))
	for i, target := range targets {
		result[i] = Target{
			ID:         target.ID,
			ResourceID: target.ResourceID,
			Name:       target.Name,
			Type:       string(target.Type),
			Provider:   string(target.Provider),
			Region:     target.Region,
			Tags:       target.Tags,
			Status:     string(target.Status),
			Metadata:   target.Metadata,
			CreatedAt:  target.CreatedAt,
			UpdatedAt:  target.UpdatedAt,
		}
	}
	return result
}