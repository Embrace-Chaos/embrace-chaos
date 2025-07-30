package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// ComputeHandler handles chaos operations for GCE instances
type ComputeHandler struct {
	client    *compute.InstancesClient
	projectID string
	config    ComputeConfig
}

// NewComputeHandler creates a new Compute Engine handler
func NewComputeHandler(client *compute.InstancesClient, projectID string, config ComputeConfig) *ComputeHandler {
	return &ComputeHandler{
		client:    client,
		projectID: projectID,
		config:    config,
	}
}

// DiscoverInstances discovers GCE instances based on criteria
func (h *ComputeHandler) DiscoverInstances(ctx context.Context, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target

	// Get zones to search
	zones, err := h.getZonesFromCriteria(ctx, criteria)
	if err != nil {
		return nil, err
	}

	// Search instances in each zone
	for _, zone := range zones {
		instances, err := h.listInstancesInZone(ctx, zone)
		if err != nil {
			continue // Log error but continue with other zones
		}

		for _, instance := range instances {
			if h.shouldIncludeInstance(instance, criteria) {
				target := h.instanceToTarget(instance, zone)
				targets = append(targets, target)
			}
		}
	}

	return targets, nil
}

// GetInstanceInfo gets detailed information about a GCE instance
func (h *ComputeHandler) GetInstanceInfo(ctx context.Context, target domain.Target) (*domain.TargetInfo, error) {
	// Parse zone and instance name from resource ID
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 2 {
		return nil, errors.NewValidationError("invalid GCE instance resource ID format: %s", target.ResourceID)
	}

	zone := parts[0]
	instanceName := parts[1]

	req := &computepb.GetInstanceRequest{
		Project:  h.projectID,
		Zone:     zone,
		Instance: instanceName,
	}

	instance, err := h.client.Get(ctx, req)
	if err != nil {
		return nil, errors.NewProviderError("gcp", "compute_info", err)
	}

	info := &domain.TargetInfo{
		ID:          target.ID,
		ResourceID:  target.ResourceID,
		Name:        target.Name,
		Type:        target.Type,
		Provider:    target.Provider,
		Region:      target.Region,
		Tags:        target.Tags,
		Status:      h.mapInstanceStatus(instance.GetStatus()),
		Metadata:    h.buildInstanceMetadata(instance),
		LastUpdated: time.Now(),
	}

	return info, nil
}

// ExecuteAction executes a chaos action on GCE instances
func (h *ComputeHandler) ExecuteAction(ctx context.Context, target domain.Target, action string, parameters map[string]any, dryRun bool) (map[string]any, error) {
	metadata := make(map[string]any)
	metadata["instance_id"] = target.ResourceID
	metadata["action"] = action
	metadata["dry_run"] = dryRun

	switch action {
	case "stop_instance":
		return h.stopInstance(ctx, target, parameters, dryRun)
	case "start_instance":
		return h.startInstance(ctx, target, parameters, dryRun)
	case "reset_instance":
		return h.resetInstance(ctx, target, parameters, dryRun)
	case "suspend_instance":
		return h.suspendInstance(ctx, target, parameters, dryRun)
	case "resume_instance":
		return h.resumeInstance(ctx, target, parameters, dryRun)
	default:
		return nil, errors.NewValidationError("unsupported GCE action: %s", action)
	}
}

// StartInstance starts a stopped GCE instance (rollback operation)
func (h *ComputeHandler) StartInstance(ctx context.Context, target domain.Target, metadata map[string]any) error {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 2 {
		return errors.NewValidationError("invalid instance resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	instanceName := parts[1]

	req := &computepb.StartInstanceRequest{
		Project:  h.projectID,
		Zone:     zone,
		Instance: instanceName,
	}

	op, err := h.client.Start(ctx, req)
	if err != nil {
		return errors.NewProviderError("gcp", "compute_start", err)
	}

	// Wait for operation to complete if configured
	if h.config.StartTimeout > 0 {
		return h.waitForOperation(ctx, op, h.config.StartTimeout)
	}

	return nil
}

// healthCheck performs a health check for the Compute service
func (h *ComputeHandler) healthCheck(ctx context.Context) error {
	// Try to list zones as a simple connectivity check
	_, err := h.listZones(ctx)
	return err
}

// listZones lists all available zones in the project
func (h *ComputeHandler) listZones(ctx context.Context) ([]string, error) {
	zonesClient, err := compute.NewZonesRESTClient(ctx)
	if err != nil {
		return nil, err
	}
	defer zonesClient.Close()

	req := &computepb.ListZonesRequest{
		Project: h.projectID,
	}

	var zones []string
	it := zonesClient.List(ctx, req)
	for {
		zone, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		zones = append(zones, zone.GetName())
	}

	return zones, nil
}

// Private methods

func (h *ComputeHandler) getZonesFromCriteria(ctx context.Context, criteria domain.DiscoveryCriteria) ([]string, error) {
	// Check if specific zones are specified in criteria
	var zones []string
	for _, filter := range criteria.Filters {
		if filter.Field == "zone" {
			zones = append(zones, filter.Value)
		}
	}

	// If no zones specified, get all available zones
	if len(zones) == 0 {
		allZones, err := h.listZones(ctx)
		if err != nil {
			return nil, err
		}
		zones = allZones
	}

	return zones, nil
}

func (h *ComputeHandler) listInstancesInZone(ctx context.Context, zone string) ([]*computepb.Instance, error) {
	req := &computepb.ListInstancesRequest{
		Project: h.projectID,
		Zone:    zone,
	}

	var instances []*computepb.Instance
	it := h.client.List(ctx, req)
	for {
		instance, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, errors.NewProviderError("gcp", "compute_list", err)
		}
		instances = append(instances, instance)
	}

	return instances, nil
}

func (h *ComputeHandler) stopInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 2 {
		return nil, errors.NewValidationError("invalid instance resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	instanceName := parts[1]

	metadata := map[string]any{
		"action":        "stop_instance",
		"instance_name": instanceName,
		"zone":          zone,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	req := &computepb.StopInstanceRequest{
		Project:  h.projectID,
		Zone:     zone,
		Instance: instanceName,
	}

	op, err := h.client.Stop(ctx, req)
	if err != nil {
		return nil, errors.NewProviderError("gcp", "compute_stop", err)
	}

	metadata["operation_id"] = op.GetName()

	// Wait for operation to complete if configured
	if h.config.StopTimeout > 0 {
		err = h.waitForOperation(ctx, op, h.config.StopTimeout)
		if err != nil {
			metadata["operation_error"] = err.Error()
		} else {
			metadata["operation_status"] = "completed"
		}
	}

	return metadata, nil
}

func (h *ComputeHandler) startInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 2 {
		return nil, errors.NewValidationError("invalid instance resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	instanceName := parts[1]

	metadata := map[string]any{
		"action":        "start_instance",
		"instance_name": instanceName,
		"zone":          zone,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	req := &computepb.StartInstanceRequest{
		Project:  h.projectID,
		Zone:     zone,
		Instance: instanceName,
	}

	op, err := h.client.Start(ctx, req)
	if err != nil {
		return nil, errors.NewProviderError("gcp", "compute_start", err)
	}

	metadata["operation_id"] = op.GetName()

	// Wait for operation to complete if configured
	if h.config.StartTimeout > 0 {
		err = h.waitForOperation(ctx, op, h.config.StartTimeout)
		if err != nil {
			metadata["operation_error"] = err.Error()
		} else {
			metadata["operation_status"] = "completed"
		}
	}

	return metadata, nil
}

func (h *ComputeHandler) resetInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 2 {
		return nil, errors.NewValidationError("invalid instance resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	instanceName := parts[1]

	metadata := map[string]any{
		"action":        "reset_instance",
		"instance_name": instanceName,
		"zone":          zone,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	req := &computepb.ResetInstanceRequest{
		Project:  h.projectID,
		Zone:     zone,
		Instance: instanceName,
	}

	op, err := h.client.Reset(ctx, req)
	if err != nil {
		return nil, errors.NewProviderError("gcp", "compute_reset", err)
	}

	metadata["operation_id"] = op.GetName()

	return metadata, nil
}

func (h *ComputeHandler) suspendInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 2 {
		return nil, errors.NewValidationError("invalid instance resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	instanceName := parts[1]

	metadata := map[string]any{
		"action":        "suspend_instance",
		"instance_name": instanceName,
		"zone":          zone,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	req := &computepb.SuspendInstanceRequest{
		Project:  h.projectID,
		Zone:     zone,
		Instance: instanceName,
	}

	op, err := h.client.Suspend(ctx, req)
	if err != nil {
		return nil, errors.NewProviderError("gcp", "compute_suspend", err)
	}

	metadata["operation_id"] = op.GetName()

	return metadata, nil
}

func (h *ComputeHandler) resumeInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 2 {
		return nil, errors.NewValidationError("invalid instance resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	instanceName := parts[1]

	metadata := map[string]any{
		"action":        "resume_instance",
		"instance_name": instanceName,
		"zone":          zone,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	req := &computepb.ResumeInstanceRequest{
		Project:  h.projectID,
		Zone:     zone,
		Instance: instanceName,
	}

	op, err := h.client.Resume(ctx, req)
	if err != nil {
		return nil, errors.NewProviderError("gcp", "compute_resume", err)
	}

	metadata["operation_id"] = op.GetName()

	return metadata, nil
}

func (h *ComputeHandler) shouldIncludeInstance(instance *computepb.Instance, criteria domain.DiscoveryCriteria) bool {
	instanceName := instance.GetName()
	machineType := h.extractMachineType(instance.GetMachineType())

	// Check allowed machine types
	if len(h.config.AllowedMachineTypes) > 0 {
		allowed := false
		for _, allowedType := range h.config.AllowedMachineTypes {
			if machineType == allowedType {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	// Check forbidden machine types
	for _, forbiddenType := range h.config.ForbiddenMachineTypes {
		if machineType == forbiddenType {
			return false
		}
	}

	// Check preemptible instances if not allowed
	if !h.config.AllowPreemptible && instance.GetScheduling().GetPreemptible() {
		return false
	}

	// Check required labels
	instanceLabels := instance.GetLabels()
	for key, value := range h.config.RequiredLabels {
		if instanceLabels[key] != value {
			return false
		}
	}

	return true
}

func (h *ComputeHandler) instanceToTarget(instance *computepb.Instance, zone string) domain.Target {
	instanceName := instance.GetName()
	resourceID := fmt.Sprintf("%s/%s", zone, instanceName)

	// Extract region from zone (e.g., "us-central1-a" -> "us-central1")
	region := h.extractRegionFromZone(zone)

	target := domain.Target{
		ID:         fmt.Sprintf("gcp-gce-%s", resourceID),
		ResourceID: resourceID,
		Name:       instanceName,
		Type:       domain.TargetTypeGCEInstance,
		Provider:   "gcp",
		Region:     region,
		Tags:       instance.GetLabels(),
		Metadata: map[string]any{
			"instance_name":  instanceName,
			"zone":           zone,
			"machine_type":   h.extractMachineType(instance.GetMachineType()),
			"status":         instance.GetStatus(),
			"creation_timestamp": instance.GetCreationTimestamp(),
			"preemptible":    instance.GetScheduling().GetPreemptible(),
			"can_ip_forward": instance.GetCanIpForward(),
		},
	}

	return target
}

func (h *ComputeHandler) extractMachineType(machineTypeURL string) string {
	// Extract machine type from URL (projects/PROJECT/zones/ZONE/machineTypes/TYPE)
	parts := strings.Split(machineTypeURL, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return machineTypeURL
}

func (h *ComputeHandler) extractRegionFromZone(zone string) string {
	// Extract region from zone (e.g., "us-central1-a" -> "us-central1")
	parts := strings.Split(zone, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[:len(parts)-1], "-")
	}
	return zone
}

func (h *ComputeHandler) mapInstanceStatus(status string) string {
	// Map GCE instance status to standard status
	switch status {
	case "RUNNING":
		return "running"
	case "STOPPED", "TERMINATED":
		return "stopped"
	case "STOPPING":
		return "stopping"
	case "STARTING":
		return "starting"
	case "SUSPENDED":
		return "suspended"
	case "SUSPENDING":
		return "suspending"
	default:
		return strings.ToLower(status)
	}
}

func (h *ComputeHandler) buildInstanceMetadata(instance *computepb.Instance) map[string]any {
	metadata := map[string]any{
		"instance_name":      instance.GetName(),
		"machine_type":       h.extractMachineType(instance.GetMachineType()),
		"status":             instance.GetStatus(),
		"creation_timestamp": instance.GetCreationTimestamp(),
		"description":        instance.GetDescription(),
		"hostname":           instance.GetHostname(),
		"can_ip_forward":     instance.GetCanIpForward(),
		"cpu_platform":       instance.GetCpuPlatform(),
		"min_cpu_platform":   instance.GetMinCpuPlatform(),
		"last_start_timestamp": instance.GetLastStartTimestamp(),
		"last_stop_timestamp":  instance.GetLastStopTimestamp(),
	}

	// Add scheduling information
	if scheduling := instance.GetScheduling(); scheduling != nil {
		metadata["scheduling"] = map[string]any{
			"automatic_restart":   scheduling.GetAutomaticRestart(),
			"on_host_maintenance": scheduling.GetOnHostMaintenance(),
			"preemptible":         scheduling.GetPreemptible(),
		}
	}

	// Add network interfaces
	if len(instance.GetNetworkInterfaces()) > 0 {
		networkInterfaces := make([]map[string]any, 0, len(instance.GetNetworkInterfaces()))
		for _, ni := range instance.GetNetworkInterfaces() {
			niInfo := map[string]any{
				"name":         ni.GetName(),
				"network":      ni.GetNetwork(),
				"network_ip":   ni.GetNetworkIP(),
				"subnetwork":   ni.GetSubnetwork(),
			}

			// Add access configs (external IPs)
			if len(ni.GetAccessConfigs()) > 0 {
				accessConfigs := make([]map[string]any, 0, len(ni.GetAccessConfigs()))
				for _, ac := range ni.GetAccessConfigs() {
					acInfo := map[string]any{
						"name":     ac.GetName(),
						"type":     ac.GetType(),
						"nat_ip":   ac.GetNatIP(),
					}
					accessConfigs = append(accessConfigs, acInfo)
				}
				niInfo["access_configs"] = accessConfigs
			}

			networkInterfaces = append(networkInterfaces, niInfo)
		}
		metadata["network_interfaces"] = networkInterfaces
	}

	// Add disks
	if len(instance.GetDisks()) > 0 {
		disks := make([]map[string]any, 0, len(instance.GetDisks()))
		for _, disk := range instance.GetDisks() {
			diskInfo := map[string]any{
				"device_name":  disk.GetDeviceName(),
				"source":       disk.GetSource(),
				"boot":         disk.GetBoot(),
				"auto_delete":  disk.GetAutoDelete(),
				"mode":         disk.GetMode(),
				"type":         disk.GetType(),
				"interface":    disk.GetInterface(),
			}
			disks = append(disks, diskInfo)
		}
		metadata["disks"] = disks
	}

	// Add service accounts
	if len(instance.GetServiceAccounts()) > 0 {
		serviceAccounts := make([]map[string]any, 0, len(instance.GetServiceAccounts()))
		for _, sa := range instance.GetServiceAccounts() {
			saInfo := map[string]any{
				"email":  sa.GetEmail(),
				"scopes": sa.GetScopes(),
			}
			serviceAccounts = append(serviceAccounts, saInfo)
		}
		metadata["service_accounts"] = serviceAccounts
	}

	// Add metadata
	if instanceMetadata := instance.GetMetadata(); instanceMetadata != nil {
		if len(instanceMetadata.GetItems()) > 0 {
			metadataItems := make(map[string]string)
			for _, item := range instanceMetadata.GetItems() {
				if item.GetValue() != nil {
					metadataItems[item.GetKey()] = *item.GetValue()
				}
			}
			metadata["instance_metadata"] = metadataItems
		}
	}

	// Add tags
	if tags := instance.GetTags(); tags != nil {
		metadata["tags"] = tags.GetItems()
	}

	return metadata
}

func (h *ComputeHandler) waitForOperation(ctx context.Context, op *computepb.Operation, timeout time.Duration) error {
	// Create zone operations client to check operation status
	zoneOpsClient, err := compute.NewZoneOperationsRESTClient(ctx)
	if err != nil {
		return err
	}
	defer zoneOpsClient.Close()

	// Extract zone from operation
	zone := h.extractZoneFromOperation(op.GetZone())

	// Wait for operation with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCtx.Done():
			return fmt.Errorf("operation timeout: %s", op.GetName())
		case <-ticker.C:
			req := &computepb.GetZoneOperationRequest{
				Project:   h.projectID,
				Zone:      zone,
				Operation: op.GetName(),
			}

			currentOp, err := zoneOpsClient.Get(ctx, req)
			if err != nil {
				return err
			}

			if currentOp.GetStatus() == "DONE" {
				if currentOp.GetError() != nil {
					return fmt.Errorf("operation failed: %v", currentOp.GetError())
				}
				return nil
			}
		}
	}
}

func (h *ComputeHandler) extractZoneFromOperation(zoneURL string) string {
	// Extract zone from URL (projects/PROJECT/zones/ZONE)
	parts := strings.Split(zoneURL, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return zoneURL
}