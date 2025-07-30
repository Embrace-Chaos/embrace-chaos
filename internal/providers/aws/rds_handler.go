package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// RDSHandler handles chaos operations for RDS instances
type RDSHandler struct {
	client *rds.Client
	config RDSConfig
}

// NewRDSHandler creates a new RDS handler
func NewRDSHandler(client *rds.Client, config RDSConfig) *RDSHandler {
	return &RDSHandler{
		client: client,
		config: config,
	}
}

// DiscoverInstances discovers RDS instances based on criteria
func (h *RDSHandler) DiscoverInstances(ctx context.Context, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target

	// List RDS instances
	input := &rds.DescribeDBInstancesInput{}

	result, err := h.client.DescribeDBInstances(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "rds_discovery", err)
	}

	// Convert instances to targets
	for _, instance := range result.DBInstances {
		if h.shouldIncludeInstance(instance, criteria) {
			target := h.instanceToTarget(instance)
			targets = append(targets, target)
		}
	}

	return targets, nil
}

// GetInstanceInfo gets detailed information about an RDS instance
func (h *RDSHandler) GetInstanceInfo(ctx context.Context, target domain.Target) (*domain.TargetInfo, error) {
	input := &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(target.ResourceID),
	}

	result, err := h.client.DescribeDBInstances(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "rds_info", err)
	}

	if len(result.DBInstances) == 0 {
		return nil, errors.NewValidationError("RDS instance not found: %s", target.ResourceID)
	}

	instance := result.DBInstances[0]
	
	info := &domain.TargetInfo{
		ID:          target.ID,
		ResourceID:  target.ResourceID,
		Name:        target.Name,
		Type:        target.Type,
		Provider:    target.Provider,
		Region:      target.Region,
		Tags:        target.Tags,
		Status:      aws.ToString(instance.DBInstanceStatus),
		Metadata:    h.buildInstanceMetadata(instance),
		LastUpdated: time.Now(),
	}

	return info, nil
}

// ExecuteAction executes a chaos action on RDS instances
func (h *RDSHandler) ExecuteAction(ctx context.Context, target domain.Target, action string, parameters map[string]any, dryRun bool) (map[string]any, error) {
	metadata := make(map[string]any)
	metadata["instance_id"] = target.ResourceID
	metadata["action"] = action
	metadata["dry_run"] = dryRun

	switch action {
	case "reboot_db_instance":
		return h.rebootInstance(ctx, target, parameters, dryRun)
	case "stop_db_instance":
		return h.stopInstance(ctx, target, parameters, dryRun)
	case "start_db_instance":
		return h.startInstance(ctx, target, parameters, dryRun)
	case "modify_db_instance":
		return h.modifyInstance(ctx, target, parameters, dryRun)
	case "create_db_snapshot":
		return h.createSnapshot(ctx, target, parameters, dryRun)
	default:
		return nil, errors.NewValidationError("unsupported RDS action: %s", action)
	}
}

// Private methods

func (h *RDSHandler) rebootInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	forceFailover := getBoolParameter(parameters, "force_failover", false)

	metadata := map[string]any{
		"action":         "reboot_db_instance",
		"instance_id":    target.ResourceID,
		"force_failover": forceFailover,
		"dry_run":        dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	// Check if backup is required before action
	if h.config.BackupBeforeAction {
		snapshotId := fmt.Sprintf("%s-chaos-backup-%d", target.ResourceID, time.Now().Unix())
		_, err := h.createSnapshotInternal(ctx, target.ResourceID, snapshotId)
		if err != nil {
			return nil, fmt.Errorf("failed to create backup before reboot: %w", err)
		}
		metadata["backup_snapshot_id"] = snapshotId
	}

	input := &rds.RebootDBInstanceInput{
		DBInstanceIdentifier: aws.String(target.ResourceID),
		ForceFailover:        aws.Bool(forceFailover),
	}

	result, err := h.client.RebootDBInstance(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "rds_reboot", err)
	}

	if result.DBInstance != nil {
		metadata["previous_status"] = aws.ToString(result.DBInstance.DBInstanceStatus)
		metadata["engine"] = aws.ToString(result.DBInstance.Engine)
		metadata["multi_az"] = result.DBInstance.MultiAZ
	}

	return metadata, nil
}

func (h *RDSHandler) stopInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	createSnapshot := getBoolParameter(parameters, "create_snapshot", false)
	snapshotId := getStringParameter(parameters, "snapshot_id", "")

	metadata := map[string]any{
		"action":          "stop_db_instance",
		"instance_id":     target.ResourceID,
		"create_snapshot": createSnapshot,
		"dry_run":         dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	input := &rds.StopDBInstanceInput{
		DBInstanceIdentifier: aws.String(target.ResourceID),
	}

	if createSnapshot && snapshotId != "" {
		input.DBSnapshotIdentifier = aws.String(snapshotId)
		metadata["snapshot_id"] = snapshotId
	}

	result, err := h.client.StopDBInstance(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "rds_stop", err)
	}

	if result.DBInstance != nil {
		metadata["previous_status"] = aws.ToString(result.DBInstance.DBInstanceStatus)
		metadata["engine"] = aws.ToString(result.DBInstance.Engine)
	}

	return metadata, nil
}

func (h *RDSHandler) startInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	metadata := map[string]any{
		"action":      "start_db_instance",
		"instance_id": target.ResourceID,
		"dry_run":     dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	input := &rds.StartDBInstanceInput{
		DBInstanceIdentifier: aws.String(target.ResourceID),
	}

	result, err := h.client.StartDBInstance(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "rds_start", err)
	}

	if result.DBInstance != nil {
		metadata["previous_status"] = aws.ToString(result.DBInstance.DBInstanceStatus)
		metadata["engine"] = aws.ToString(result.DBInstance.Engine)
	}

	return metadata, nil
}

func (h *RDSHandler) modifyInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	instanceClass := getStringParameter(parameters, "db_instance_class", "")
	allocatedStorage := getIntParameter(parameters, "allocated_storage", 0)
	applyImmediately := getBoolParameter(parameters, "apply_immediately", false)

	metadata := map[string]any{
		"action":            "modify_db_instance",
		"instance_id":       target.ResourceID,
		"apply_immediately": applyImmediately,
		"dry_run":           dryRun,
	}

	if instanceClass != "" {
		metadata["new_instance_class"] = instanceClass
	}
	if allocatedStorage > 0 {
		metadata["new_allocated_storage"] = allocatedStorage
	}

	if dryRun {
		return metadata, nil
	}

	input := &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier: aws.String(target.ResourceID),
		ApplyImmediately:     aws.Bool(applyImmediately),
	}

	if instanceClass != "" {
		input.DBInstanceClass = aws.String(instanceClass)
	}
	if allocatedStorage > 0 {
		input.AllocatedStorage = aws.Int32(int32(allocatedStorage))
	}

	result, err := h.client.ModifyDBInstance(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "rds_modify", err)
	}

	if result.DBInstance != nil {
		metadata["current_status"] = aws.ToString(result.DBInstance.DBInstanceStatus)
		metadata["current_instance_class"] = aws.ToString(result.DBInstance.DBInstanceClass)
		metadata["current_allocated_storage"] = result.DBInstance.AllocatedStorage
	}

	return metadata, nil
}

func (h *RDSHandler) createSnapshot(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	snapshotId := getStringParameter(parameters, "snapshot_id", "")
	if snapshotId == "" {
		snapshotId = fmt.Sprintf("%s-chaos-%d", target.ResourceID, time.Now().Unix())
	}

	metadata := map[string]any{
		"action":      "create_db_snapshot",
		"instance_id": target.ResourceID,
		"snapshot_id": snapshotId,
		"dry_run":     dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	result, err := h.createSnapshotInternal(ctx, target.ResourceID, snapshotId)
	if err != nil {
		return nil, err
	}

	if result.DBSnapshot != nil {
		metadata["snapshot_status"] = aws.ToString(result.DBSnapshot.Status)
		metadata["snapshot_type"] = aws.ToString(result.DBSnapshot.SnapshotType)
		metadata["engine"] = aws.ToString(result.DBSnapshot.Engine)
		metadata["allocated_storage"] = result.DBSnapshot.AllocatedStorage
	}

	return metadata, nil
}

func (h *RDSHandler) createSnapshotInternal(ctx context.Context, instanceId, snapshotId string) (*rds.CreateDBSnapshotOutput, error) {
	input := &rds.CreateDBSnapshotInput{
		DBInstanceIdentifier: aws.String(instanceId),
		DBSnapshotIdentifier: aws.String(snapshotId),
	}

	result, err := h.client.CreateDBSnapshot(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "rds_create_snapshot", err)
	}

	return result, nil
}

func (h *RDSHandler) shouldIncludeInstance(instance types.DBInstance, criteria domain.DiscoveryCriteria) bool {
	engine := aws.ToString(instance.Engine)
	instanceId := aws.ToString(instance.DBInstanceIdentifier)

	// Check allowed engines
	if len(h.config.AllowedEngines) > 0 {
		allowed := false
		for _, allowedEngine := range h.config.AllowedEngines {
			if engine == allowedEngine {
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
		if instanceId == forbiddenInstance {
			return false
		}
	}

	// Check required tags
	instanceTags := h.extractTags(instance.TagList)
	for key, value := range h.config.RequiredTags {
		if instanceTags[key] != value {
			return false
		}
	}

	return true
}

func (h *RDSHandler) instanceToTarget(instance types.DBInstance) domain.Target {
	instanceId := aws.ToString(instance.DBInstanceIdentifier)
	name := instanceId

	// Try to get name from tags
	for _, tag := range instance.TagList {
		if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
			name = *tag.Value
			break
		}
	}

	target := domain.Target{
		ID:         fmt.Sprintf("aws-rds-%s", instanceId),
		ResourceID: instanceId,
		Name:       name,
		Type:       domain.TargetTypeRDSInstance,
		Provider:   "aws",
		Region:     h.extractRegion(aws.ToString(instance.DBInstanceArn)),
		Tags:       h.extractTags(instance.TagList),
		Metadata: map[string]any{
			"engine":              aws.ToString(instance.Engine),
			"engine_version":      aws.ToString(instance.EngineVersion),
			"db_instance_class":   aws.ToString(instance.DBInstanceClass),
			"db_instance_status":  aws.ToString(instance.DBInstanceStatus),
			"allocated_storage":   instance.AllocatedStorage,
			"storage_type":        aws.ToString(instance.StorageType),
			"multi_az":            instance.MultiAZ,
			"publicly_accessible": instance.PubliclyAccessible,
			"vpc_id":              aws.ToString(instance.DbInstancePort),
			"availability_zone":   aws.ToString(instance.AvailabilityZone),
			"backup_retention_period": instance.BackupRetentionPeriod,
			"instance_create_time":    instance.InstanceCreateTime,
		},
	}

	return target
}

func (h *RDSHandler) extractTags(tags []types.Tag) map[string]string {
	result := make(map[string]string)
	for _, tag := range tags {
		if tag.Key != nil && tag.Value != nil {
			result[*tag.Key] = *tag.Value
		}
	}
	return result
}

func (h *RDSHandler) extractRegion(arn string) string {
	// Extract region from ARN (arn:aws:rds:region:account:db:instance-id)
	parts := strings.Split(arn, ":")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

func (h *RDSHandler) buildInstanceMetadata(instance types.DBInstance) map[string]any {
	metadata := map[string]any{
		"db_instance_identifier": aws.ToString(instance.DBInstanceIdentifier),
		"engine":                 aws.ToString(instance.Engine),
		"engine_version":         aws.ToString(instance.EngineVersion),
		"db_instance_class":      aws.ToString(instance.DBInstanceClass),
		"db_instance_status":     aws.ToString(instance.DBInstanceStatus),
		"allocated_storage":      instance.AllocatedStorage,
		"storage_type":           aws.ToString(instance.StorageType),
		"storage_encrypted":      instance.StorageEncrypted,
		"multi_az":               instance.MultiAZ,
		"publicly_accessible":    instance.PubliclyAccessible,
		"backup_retention_period": instance.BackupRetentionPeriod,
		"preferred_backup_window":       aws.ToString(instance.PreferredBackupWindow),
		"preferred_maintenance_window":  aws.ToString(instance.PreferredMaintenanceWindow),
		"instance_create_time":          instance.InstanceCreateTime,
		"latest_restorable_time":        instance.LatestRestorableTime,
		"auto_minor_version_upgrade":    instance.AutoMinorVersionUpgrade,
		"deletion_protection":           instance.DeletionProtection,
	}

	if instance.Endpoint != nil {
		endpoint := map[string]any{
			"address": aws.ToString(instance.Endpoint.Address),
			"port":    instance.Endpoint.Port,
		}
		metadata["endpoint"] = endpoint
	}

	if instance.DBSubnetGroup != nil {
		subnetGroup := map[string]any{
			"name":        aws.ToString(instance.DBSubnetGroup.DBSubnetGroupName),
			"description": aws.ToString(instance.DBSubnetGroup.DBSubnetGroupDescription),
			"vpc_id":      aws.ToString(instance.DBSubnetGroup.VpcId),
			"status":      aws.ToString(instance.DBSubnetGroup.SubnetGroupStatus),
		}
		metadata["db_subnet_group"] = subnetGroup
	}

	// Add security groups
	if len(instance.VpcSecurityGroups) > 0 {
		securityGroups := make([]map[string]string, 0, len(instance.VpcSecurityGroups))
		for _, sg := range instance.VpcSecurityGroups {
			group := map[string]string{
				"vpc_security_group_id": aws.ToString(sg.VpcSecurityGroupId),
				"status":                aws.ToString(sg.Status),
			}
			securityGroups = append(securityGroups, group)
		}
		metadata["vpc_security_groups"] = securityGroups
	}

	// Add parameter groups
	if len(instance.DBParameterGroups) > 0 {
		parameterGroups := make([]map[string]string, 0, len(instance.DBParameterGroups))
		for _, pg := range instance.DBParameterGroups {
			group := map[string]string{
				"db_parameter_group_name": aws.ToString(pg.DBParameterGroupName),
				"parameter_apply_status":  aws.ToString(pg.ParameterApplyStatus),
			}
			parameterGroups = append(parameterGroups, group)
		}
		metadata["db_parameter_groups"] = parameterGroups
	}

	// Add option groups
	if len(instance.OptionGroupMemberships) > 0 {
		optionGroups := make([]map[string]string, 0, len(instance.OptionGroupMemberships))
		for _, og := range instance.OptionGroupMemberships {
			group := map[string]string{
				"option_group_name": aws.ToString(og.OptionGroupName),
				"status":            aws.ToString(og.Status),
			}
			optionGroups = append(optionGroups, group)
		}
		metadata["option_group_memberships"] = optionGroups
	}

	// Add read replicas
	if len(instance.ReadReplicaDBInstanceIdentifiers) > 0 {
		metadata["read_replica_db_instance_identifiers"] = instance.ReadReplicaDBInstanceIdentifiers
	}

	// Add master username
	if instance.MasterUsername != nil {
		metadata["master_username"] = aws.ToString(instance.MasterUsername)
	}

	// Add database name
	if instance.DBName != nil {
		metadata["db_name"] = aws.ToString(instance.DBName)
	}

	return metadata
}