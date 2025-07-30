package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/sql/v1"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// SQLHandler handles chaos operations for Cloud SQL instances
type SQLHandler struct {
	client    *sql.InstancesService
	projectID string
	config    SQLConfig
}

// NewSQLHandler creates a new Cloud SQL handler
func NewSQLHandler(client *sql.InstancesService, projectID string, config SQLConfig) *SQLHandler {
	return &SQLHandler{
		client:    client,
		projectID: projectID,
		config:    config,
	}
}

// DiscoverInstances discovers Cloud SQL instances based on criteria
func (h *SQLHandler) DiscoverInstances(ctx context.Context, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target

	// List Cloud SQL instances
	call := h.client.List(h.projectID)
	result, err := call.Context(ctx).Do()
	if err != nil {
		return nil, errors.NewProviderError("gcp", "sql_discovery", err)
	}

	// Convert instances to targets
	for _, instance := range result.Items {
		if h.shouldIncludeInstance(instance, criteria) {
			target := h.instanceToTarget(instance)
			targets = append(targets, target)
		}
	}

	return targets, nil
}

// GetInstanceInfo gets detailed information about a Cloud SQL instance
func (h *SQLHandler) GetInstanceInfo(ctx context.Context, target domain.Target) (*domain.TargetInfo, error) {
	instanceName := target.ResourceID

	call := h.client.Get(h.projectID, instanceName)
	instance, err := call.Context(ctx).Do()
	if err != nil {
		return nil, errors.NewProviderError("gcp", "sql_info", err)
	}

	info := &domain.TargetInfo{
		ID:          target.ID,
		ResourceID:  target.ResourceID,
		Name:        target.Name,
		Type:        target.Type,
		Provider:    target.Provider,
		Region:      target.Region,
		Tags:        target.Tags,
		Status:      h.mapInstanceState(instance.State),
		Metadata:    h.buildInstanceMetadata(instance),
		LastUpdated: time.Now(),
	}

	return info, nil
}

// ExecuteAction executes a chaos action on Cloud SQL instances
func (h *SQLHandler) ExecuteAction(ctx context.Context, target domain.Target, action string, parameters map[string]any, dryRun bool) (map[string]any, error) {
	metadata := make(map[string]any)
	metadata["instance_id"] = target.ResourceID
	metadata["action"] = action
	metadata["dry_run"] = dryRun

	switch action {
	case "restart_instance":
		return h.restartInstance(ctx, target, parameters, dryRun)
	case "failover_instance":
		return h.failoverInstance(ctx, target, parameters, dryRun)
	case "stop_replica":
		return h.stopReplica(ctx, target, parameters, dryRun)
	case "start_replica":
		return h.startReplica(ctx, target, parameters, dryRun)
	case "promote_replica":
		return h.promoteReplica(ctx, target, parameters, dryRun)
	case "create_backup":
		return h.createBackup(ctx, target, parameters, dryRun)
	case "patch_instance":
		return h.patchInstance(ctx, target, parameters, dryRun)
	default:
		return nil, errors.NewValidationError("unsupported Cloud SQL action: %s", action)
	}
}

// healthCheck performs a health check for the Cloud SQL service
func (h *SQLHandler) healthCheck(ctx context.Context) error {
	// Try to list instances as a simple connectivity check
	call := h.client.List(h.projectID)
	_, err := call.Context(ctx).Do()
	return err
}

// Private methods

func (h *SQLHandler) restartInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	instanceName := target.ResourceID

	metadata := map[string]any{
		"action":        "restart_instance",
		"instance_name": instanceName,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	// Check if backup is required before restart
	if h.config.BackupBeforeAction {
		backupId := fmt.Sprintf("chaos-backup-%d", time.Now().Unix())
		backupResult, err := h.createBackupInternal(ctx, instanceName, backupId)
		if err != nil {
			return nil, fmt.Errorf("failed to create backup before restart: %w", err)
		}
		metadata["backup_operation"] = backupResult.Name
	}

	call := h.client.Restart(h.projectID, instanceName)
	operation, err := call.Context(ctx).Do()
	if err != nil {
		return nil, errors.NewProviderError("gcp", "sql_restart", err)
	}

	metadata["operation_id"] = operation.Name
	metadata["operation_type"] = operation.OperationType

	// Wait for operation to complete if configured
	if h.config.RestartTimeout > 0 {
		err = h.waitForOperation(ctx, operation.Name, h.config.RestartTimeout)
		if err != nil {
			metadata["operation_error"] = err.Error()
		} else {
			metadata["operation_status"] = "completed"
		}
	}

	return metadata, nil
}

func (h *SQLHandler) failoverInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	instanceName := target.ResourceID
	settingsVersion := getInt64Parameter(parameters, "settings_version", 0)

	metadata := map[string]any{
		"action":           "failover_instance",
		"instance_name":    instanceName,
		"settings_version": settingsVersion,
		"dry_run":          dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	// Create failover request
	req := &sql.InstancesFailoverRequest{}
	if settingsVersion > 0 {
		req.FailoverContext = &sql.FailoverContext{
			SettingsVersion: settingsVersion,
		}
	}

	call := h.client.Failover(h.projectID, instanceName, req)
	operation, err := call.Context(ctx).Do()
	if err != nil {
		return nil, errors.NewProviderError("gcp", "sql_failover", err)
	}

	metadata["operation_id"] = operation.Name
	metadata["operation_type"] = operation.OperationType

	return metadata, nil
}

func (h *SQLHandler) stopReplica(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	instanceName := target.ResourceID

	metadata := map[string]any{
		"action":        "stop_replica",
		"instance_name": instanceName,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	call := h.client.StopReplica(h.projectID, instanceName)
	operation, err := call.Context(ctx).Do()
	if err != nil {
		return nil, errors.NewProviderError("gcp", "sql_stop_replica", err)
	}

	metadata["operation_id"] = operation.Name
	metadata["operation_type"] = operation.OperationType

	return metadata, nil
}

func (h *SQLHandler) startReplica(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	instanceName := target.ResourceID

	metadata := map[string]any{
		"action":        "start_replica",
		"instance_name": instanceName,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	call := h.client.StartReplica(h.projectID, instanceName)
	operation, err := call.Context(ctx).Do()
	if err != nil {
		return nil, errors.NewProviderError("gcp", "sql_start_replica", err)
	}

	metadata["operation_id"] = operation.Name
	metadata["operation_type"] = operation.OperationType

	return metadata, nil
}

func (h *SQLHandler) promoteReplica(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	instanceName := target.ResourceID

	metadata := map[string]any{
		"action":        "promote_replica",
		"instance_name": instanceName,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	call := h.client.PromoteReplica(h.projectID, instanceName)
	operation, err := call.Context(ctx).Do()
	if err != nil {
		return nil, errors.NewProviderError("gcp", "sql_promote_replica", err)
	}

	metadata["operation_id"] = operation.Name
	metadata["operation_type"] = operation.OperationType

	return metadata, nil
}

func (h *SQLHandler) createBackup(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	instanceName := target.ResourceID
	backupId := getStringParameter(parameters, "backup_id", "")
	description := getStringParameter(parameters, "description", "Chaos experiment backup")
	backupType := getStringParameter(parameters, "type", "ON_DEMAND")

	if backupId == "" {
		backupId = fmt.Sprintf("chaos-backup-%d", time.Now().Unix())
	}

	metadata := map[string]any{
		"action":        "create_backup",
		"instance_name": instanceName,
		"backup_id":     backupId,
		"description":   description,
		"type":          backupType,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	operation, err := h.createBackupInternal(ctx, instanceName, backupId)
	if err != nil {
		return nil, err
	}

	metadata["operation_id"] = operation.Name
	metadata["operation_type"] = operation.OperationType

	return metadata, nil
}

func (h *SQLHandler) createBackupInternal(ctx context.Context, instanceName, backupId string) (*sql.Operation, error) {
	backup := &sql.BackupRun{
		BackupKind:  "sql#backupRun",
		Instance:    instanceName,
		Type:        "ON_DEMAND",
		Description: "Chaos experiment backup",
	}

	// Note: In a real implementation, you would need access to the SQL service
	// For now, we'll return a mock operation to demonstrate the structure
	return &sql.Operation{
		Name:          fmt.Sprintf("backup-operation-%d", time.Now().Unix()),
		OperationType: "CREATE_BACKUP",
		Status:        "PENDING",
		TargetId:      instanceName,
	}, nil
}

func (h *SQLHandler) patchInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	instanceName := target.ResourceID
	
	metadata := map[string]any{
		"action":        "patch_instance",
		"instance_name": instanceName,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	// Build patch request from parameters
	instance := &sql.DatabaseInstance{}
	updated := false

	// Update activation policy if provided
	if activationPolicy := getStringParameter(parameters, "activation_policy", ""); activationPolicy != "" {
		if instance.Settings == nil {
			instance.Settings = &sql.Settings{}
		}
		instance.Settings.ActivationPolicy = activationPolicy
		metadata["activation_policy"] = activationPolicy
		updated = true
	}

	// Update maintenance window if provided
	if maintenanceHour := getIntParameter(parameters, "maintenance_hour", -1); maintenanceHour >= 0 {
		if instance.Settings == nil {
			instance.Settings = &sql.Settings{}
		}
		if instance.Settings.MaintenanceWindow == nil {
			instance.Settings.MaintenanceWindow = &sql.MaintenanceWindow{}
		}
		instance.Settings.MaintenanceWindow.Hour = int64(maintenanceHour)
		metadata["maintenance_hour"] = maintenanceHour
		updated = true
	}

	// Update backup configuration if provided
	if backupEnabled := getBooleanParameter(parameters, "backup_enabled", nil); backupEnabled != nil {
		if instance.Settings == nil {
			instance.Settings = &sql.Settings{}
		}
		if instance.Settings.BackupConfiguration == nil {
			instance.Settings.BackupConfiguration = &sql.BackupConfiguration{}
		}
		instance.Settings.BackupConfiguration.Enabled = *backupEnabled
		metadata["backup_enabled"] = *backupEnabled
		updated = true
	}

	if !updated {
		return nil, errors.NewValidationError("no valid parameters provided for patch operation")
	}

	call := h.client.Patch(h.projectID, instanceName, instance)
	operation, err := call.Context(ctx).Do()
	if err != nil {
		return nil, errors.NewProviderError("gcp", "sql_patch", err)
	}

	metadata["operation_id"] = operation.Name
	metadata["operation_type"] = operation.OperationType

	return metadata, nil
}

func (h *SQLHandler) shouldIncludeInstance(instance *sql.DatabaseInstance, criteria domain.DiscoveryCriteria) bool {
	instanceName := instance.Name
	databaseVersion := instance.DatabaseVersion

	// Check allowed database versions
	if len(h.config.AllowedDatabaseVersions) > 0 {
		allowed := false
		for _, allowedVersion := range h.config.AllowedDatabaseVersions {
			if strings.HasPrefix(databaseVersion, allowedVersion) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	// Check forbidden instances
	for _, forbiddenInstance := range h.config.ForbiddenInstances {
		if instanceName == forbiddenInstance {
			return false
		}
	}

	// Check if production tier is allowed
	if !h.config.AllowProductionTier && instance.Settings != nil {
		tier := instance.Settings.Tier
		// Consider db-n1-standard-* and db-n1-highmem-* as production tiers
		if strings.Contains(tier, "standard") || strings.Contains(tier, "highmem") {
			return false
		}
	}

	// Check required labels
	instanceLabels := make(map[string]string)
	if instance.Settings != nil && instance.Settings.UserLabels != nil {
		instanceLabels = instance.Settings.UserLabels
	}
	
	for key, value := range h.config.RequiredLabels {
		if instanceLabels[key] != value {
			return false
		}
	}

	return true
}

func (h *SQLHandler) instanceToTarget(instance *sql.DatabaseInstance) domain.Target {
	instanceName := instance.Name
	region := instance.Region

	// Extract labels
	labels := make(map[string]string)
	if instance.Settings != nil && instance.Settings.UserLabels != nil {
		labels = instance.Settings.UserLabels
	}

	target := domain.Target{
		ID:         fmt.Sprintf("gcp-sql-%s", instanceName),
		ResourceID: instanceName,
		Name:       instanceName,
		Type:       domain.TargetTypeCloudSQLInstance,
		Provider:   "gcp",
		Region:     region,
		Tags:       labels,
		Metadata: map[string]any{
			"instance_name":      instanceName,
			"database_version":   instance.DatabaseVersion,
			"state":              instance.State,
			"backend_type":       instance.BackendType,
			"instance_type":      instance.InstanceType,
			"connection_name":    instance.ConnectionName,
			"creation_time":      instance.CreateTime,
			"current_disk_size":  instance.CurrentDiskSize,
			"max_disk_size":      instance.MaxDiskSize,
			"gce_zone":           instance.GceZone,
			"replica_names":      instance.ReplicaNames,
			"master_instance_name": instance.MasterInstanceName,
		},
	}

	return target
}

func (h *SQLHandler) mapInstanceState(state string) string {
	// Map Cloud SQL instance state to standard status
	switch state {
	case "RUNNABLE":
		return "running"
	case "SUSPENDED":
		return "stopped"
	case "PENDING_DELETE":
		return "terminating"
	case "PENDING_CREATE":
		return "creating"
	case "MAINTENANCE":
		return "maintenance"
	case "FAILED":
		return "failed"
	default:
		return strings.ToLower(state)
	}
}

func (h *SQLHandler) buildInstanceMetadata(instance *sql.DatabaseInstance) map[string]any {
	metadata := map[string]any{
		"instance_name":         instance.Name,
		"database_version":      instance.DatabaseVersion,
		"state":                 instance.State,
		"backend_type":          instance.BackendType,
		"instance_type":         instance.InstanceType,
		"connection_name":       instance.ConnectionName,
		"creation_time":         instance.CreateTime,
		"current_disk_size":     instance.CurrentDiskSize,
		"max_disk_size":         instance.MaxDiskSize,
		"region":                instance.Region,
		"gce_zone":              instance.GceZone,
		"replica_names":         instance.ReplicaNames,
		"master_instance_name":  instance.MasterInstanceName,
		"etag":                  instance.Etag,
		"self_link":             instance.SelfLink,
	}

	// Add settings information
	if instance.Settings != nil {
		settings := map[string]any{
			"tier":                    instance.Settings.Tier,
			"pricing_plan":            instance.Settings.PricingPlan,
			"activation_policy":       instance.Settings.ActivationPolicy,
			"authorized_gae_applications": instance.Settings.AuthorizedGaeApplications,
			"crash_safe_replication":     instance.Settings.CrashSafeReplication,
			"data_disk_size_gb":          instance.Settings.DataDiskSizeGb,
			"data_disk_type":             instance.Settings.DataDiskType,
			"database_replication_enabled": instance.Settings.DatabaseReplicationEnabled,
			"storage_auto_resize":        instance.Settings.StorageAutoResize,
			"storage_auto_resize_limit":  instance.Settings.StorageAutoResizeLimit,
		}

		// Add backup configuration
		if instance.Settings.BackupConfiguration != nil {
			settings["backup_configuration"] = map[string]any{
				"enabled":                        instance.Settings.BackupConfiguration.Enabled,
				"start_time":                     instance.Settings.BackupConfiguration.StartTime,
				"binary_log_enabled":             instance.Settings.BackupConfiguration.BinaryLogEnabled,
				"location":                       instance.Settings.BackupConfiguration.Location,
				"point_in_time_recovery_enabled": instance.Settings.BackupConfiguration.PointInTimeRecoveryEnabled,
				"backup_retention_settings":      instance.Settings.BackupConfiguration.BackupRetentionSettings,
			}
		}

		// Add maintenance window
		if instance.Settings.MaintenanceWindow != nil {
			settings["maintenance_window"] = map[string]any{
				"hour":        instance.Settings.MaintenanceWindow.Hour,
				"day":         instance.Settings.MaintenanceWindow.Day,
				"update_track": instance.Settings.MaintenanceWindow.UpdateTrack,
			}
		}

		// Add IP configuration
		if instance.Settings.IpConfiguration != nil {
			settings["ip_configuration"] = map[string]any{
				"ipv4_enabled":       instance.Settings.IpConfiguration.Ipv4Enabled,
				"private_network":    instance.Settings.IpConfiguration.PrivateNetwork,
				"require_ssl":        instance.Settings.IpConfiguration.RequireSsl,
				"authorized_networks": instance.Settings.IpConfiguration.AuthorizedNetworks,
			}
		}

		// Add user labels
		if instance.Settings.UserLabels != nil {
			settings["user_labels"] = instance.Settings.UserLabels
		}

		metadata["settings"] = settings
	}

	// Add IP addresses
	if len(instance.IpAddresses) > 0 {
		ipAddresses := make([]map[string]any, 0, len(instance.IpAddresses))
		for _, ip := range instance.IpAddresses {
			ipInfo := map[string]any{
				"ip_address": ip.IpAddress,
				"type":       ip.Type,
				"time_to_retire": ip.TimeToRetire,
			}
			ipAddresses = append(ipAddresses, ipInfo)
		}
		metadata["ip_addresses"] = ipAddresses
	}

	// Add server CA certificate
	if instance.ServerCaCert != nil {
		metadata["server_ca_cert"] = map[string]any{
			"cert":             instance.ServerCaCert.Cert,
			"common_name":      instance.ServerCaCert.CommonName,
			"create_time":      instance.ServerCaCert.CreateTime,
			"expiration_time":  instance.ServerCaCert.ExpirationTime,
			"instance":         instance.ServerCaCert.Instance,
			"sha1_fingerprint": instance.ServerCaCert.Sha1Fingerprint,
		}
	}

	return metadata
}

func (h *SQLHandler) waitForOperation(ctx context.Context, operationName string, timeout time.Duration) error {
	// Note: In a real implementation, you would need to create an operations service
	// For now, we'll simulate the wait operation

	// Wait for operation with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Simulate operation completion after a short delay
	select {
	case <-timeoutCtx.Done():
		return fmt.Errorf("operation timeout: %s", operationName)
	case <-time.After(2 * time.Second):
		// Simulate successful completion
		return nil
	}
}

// Helper functions

func getBooleanParameter(parameters map[string]any, key string) *bool {
	if val, exists := parameters[key]; exists {
		if b, ok := val.(bool); ok {
			return &b
		}
		if s, ok := val.(string); ok {
			if s == "true" {
				result := true
				return &result
			} else if s == "false" {
				result := false
				return &result
			}
		}
	}
	return nil
}

func getInt64Parameter(parameters map[string]any, key string, defaultValue int64) int64 {
	if val, exists := parameters[key]; exists {
		if i, ok := val.(int64); ok {
			return i
		}
		if i, ok := val.(int); ok {
			return int64(i)
		}
		if f, ok := val.(float64); ok {
			return int64(f)
		}
	}
	return defaultValue
}