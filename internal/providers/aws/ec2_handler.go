package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// EC2Handler handles chaos operations for EC2 instances
type EC2Handler struct {
	client *ec2.Client
	config EC2Config
}

// NewEC2Handler creates a new EC2 handler
func NewEC2Handler(client *ec2.Client, config EC2Config) *EC2Handler {
	return &EC2Handler{
		client: client,
		config: config,
	}
}

// DiscoverInstances discovers EC2 instances based on criteria
func (h *EC2Handler) DiscoverInstances(ctx context.Context, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target

	// Build filters from criteria
	filters := h.buildEC2Filters(criteria)

	// Describe instances
	input := &ec2.DescribeInstancesInput{
		Filters: filters,
	}

	result, err := h.client.DescribeInstances(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ec2_discovery", err)
	}

	// Process reservations and instances
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			// Skip terminated instances
			if instance.State != nil && instance.State.Name == types.InstanceStateNameTerminated {
				continue
			}

			target := h.instanceToTarget(instance)
			
			// Apply additional filters
			if h.shouldIncludeInstance(instance, criteria) {
				targets = append(targets, target)
			}
		}
	}

	return targets, nil
}

// GetInstanceInfo gets detailed information about an EC2 instance
func (h *EC2Handler) GetInstanceInfo(ctx context.Context, target domain.Target) (*domain.TargetInfo, error) {
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{target.ResourceID},
	}

	result, err := h.client.DescribeInstances(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ec2_info", err)
	}

	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		return nil, errors.NewValidationError("instance not found: %s", target.ResourceID)
	}

	instance := result.Reservations[0].Instances[0]
	
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

// ExecuteAction executes a chaos action on EC2 instances
func (h *EC2Handler) ExecuteAction(ctx context.Context, target domain.Target, action string, parameters map[string]any, dryRun bool) (map[string]any, error) {
	metadata := make(map[string]any)
	metadata["instance_id"] = target.ResourceID
	metadata["action"] = action
	metadata["dry_run"] = dryRun

	switch action {
	case "stop_instances":
		return h.stopInstance(ctx, target, parameters, dryRun)
	case "start_instances":
		return h.startInstance(ctx, target, parameters, dryRun)
	case "terminate_instances":
		return h.terminateInstance(ctx, target, parameters, dryRun)
	case "reboot_instances":
		return h.rebootInstance(ctx, target, parameters, dryRun)
	default:
		return nil, errors.NewValidationError("unsupported EC2 action: %s", action)
	}
}

// StartInstances starts stopped EC2 instances (rollback operation)
func (h *EC2Handler) StartInstances(ctx context.Context, target domain.Target, metadata map[string]any) error {
	input := &ec2.StartInstancesInput{
		InstanceIds: []string{target.ResourceID},
	}

	_, err := h.client.StartInstances(ctx, input)
	if err != nil {
		return errors.NewProviderError("aws", "ec2_start", err)
	}

	return nil
}

// Private methods

func (h *EC2Handler) stopInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	force := getBoolParameter(parameters, "force", false)

	input := &ec2.StopInstancesInput{
		InstanceIds: []string{target.ResourceID},
		Force:       aws.Bool(force),
		DryRun:      aws.Bool(dryRun),
	}

	result, err := h.client.StopInstances(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ec2_stop", err)
	}

	metadata := map[string]any{
		"action":      "stop_instances",
		"instance_id": target.ResourceID,
		"force":       force,
		"dry_run":     dryRun,
	}

	if len(result.StoppingInstances) > 0 {
		instance := result.StoppingInstances[0]
		metadata["previous_state"] = string(instance.PreviousState.Name)
		metadata["current_state"] = string(instance.CurrentState.Name)
	}

	return metadata, nil
}

func (h *EC2Handler) startInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	input := &ec2.StartInstancesInput{
		InstanceIds: []string{target.ResourceID},
		DryRun:      aws.Bool(dryRun),
	}

	result, err := h.client.StartInstances(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ec2_start", err)
	}

	metadata := map[string]any{
		"action":      "start_instances",
		"instance_id": target.ResourceID,
		"dry_run":     dryRun,
	}

	if len(result.StartingInstances) > 0 {
		instance := result.StartingInstances[0]
		metadata["previous_state"] = string(instance.PreviousState.Name)
		metadata["current_state"] = string(instance.CurrentState.Name)
	}

	return metadata, nil
}

func (h *EC2Handler) terminateInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	input := &ec2.TerminateInstancesInput{
		InstanceIds: []string{target.ResourceID},
		DryRun:      aws.Bool(dryRun),
	}

	result, err := h.client.TerminateInstances(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ec2_terminate", err)
	}

	metadata := map[string]any{
		"action":      "terminate_instances",
		"instance_id": target.ResourceID,
		"dry_run":     dryRun,
	}

	if len(result.TerminatingInstances) > 0 {
		instance := result.TerminatingInstances[0]
		metadata["previous_state"] = string(instance.PreviousState.Name)
		metadata["current_state"] = string(instance.CurrentState.Name)
	}

	return metadata, nil
}

func (h *EC2Handler) rebootInstance(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	input := &ec2.RebootInstancesInput{
		InstanceIds: []string{target.ResourceID},
		DryRun:      aws.Bool(dryRun),
	}

	_, err := h.client.RebootInstances(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ec2_reboot", err)
	}

	metadata := map[string]any{
		"action":      "reboot_instances",
		"instance_id": target.ResourceID,
		"dry_run":     dryRun,
	}

	return metadata, nil
}

func (h *EC2Handler) buildEC2Filters(criteria domain.DiscoveryCriteria) []types.Filter {
	var filters []types.Filter

	// Add state filter to exclude terminated instances
	filters = append(filters, types.Filter{
		Name:   aws.String("instance-state-name"),
		Values: []string{"pending", "running", "shutting-down", "stopping", "stopped"},
	})

	// Add filters from criteria
	for _, filter := range criteria.Filters {
		switch filter.Field {
		case "instance-type":
			filters = append(filters, types.Filter{
				Name:   aws.String("instance-type"),
				Values: []string{filter.Value},
			})
		case "vpc-id":
			filters = append(filters, types.Filter{
				Name:   aws.String("vpc-id"),
				Values: []string{filter.Value},
			})
		case "subnet-id":
			filters = append(filters, types.Filter{
				Name:   aws.String("subnet-id"),
				Values: []string{filter.Value},
			})
		case "availability-zone":
			filters = append(filters, types.Filter{
				Name:   aws.String("availability-zone"),
				Values: []string{filter.Value},
			})
		default:
			// Handle tag filters
			if strings.HasPrefix(filter.Field, "tag:") {
				filters = append(filters, types.Filter{
					Name:   aws.String(filter.Field),
					Values: []string{filter.Value},
				})
			}
		}
	}

	return filters
}

func (h *EC2Handler) shouldIncludeInstance(instance types.Instance, criteria domain.DiscoveryCriteria) bool {
	instanceType := ""
	if instance.InstanceType != "" {
		instanceType = string(instance.InstanceType)
	}

	// Check allowed instance types
	if len(h.config.AllowedInstanceTypes) > 0 {
		allowed := false
		for _, allowedType := range h.config.AllowedInstanceTypes {
			if instanceType == allowedType {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	// Check forbidden instance types
	for _, forbiddenType := range h.config.ForbiddenInstanceTypes {
		if instanceType == forbiddenType {
			return false
		}
	}

	// Check required tags
	instanceTags := h.extractTags(instance.Tags)
	for key, value := range h.config.RequiredTags {
		if instanceTags[key] != value {
			return false
		}
	}

	return true
}

func (h *EC2Handler) instanceToTarget(instance types.Instance) domain.Target {
	var name string
	if instance.InstanceId != nil {
		name = *instance.InstanceId
	}

	// Try to get name from tags
	for _, tag := range instance.Tags {
		if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
			name = *tag.Value
			break
		}
	}

	var resourceID string
	if instance.InstanceId != nil {
		resourceID = *instance.InstanceId
	}

	var region string
	if instance.Placement != nil && instance.Placement.AvailabilityZone != nil {
		// Extract region from AZ (e.g., "us-east-1a" -> "us-east-1")
		az := *instance.Placement.AvailabilityZone
		if len(az) > 0 {
			region = az[:len(az)-1]
		}
	}

	target := domain.Target{
		ID:         fmt.Sprintf("aws-ec2-%s", resourceID),
		ResourceID: resourceID,
		Name:       name,
		Type:       domain.TargetTypeEC2Instance,
		Provider:   "aws",
		Region:     region,
		Tags:       h.extractTags(instance.Tags),
		Metadata: map[string]any{
			"instance_type":     string(instance.InstanceType),
			"state":            h.mapInstanceState(instance.State),
			"vpc_id":           aws.ToString(instance.VpcId),
			"subnet_id":        aws.ToString(instance.SubnetId),
			"private_ip":       aws.ToString(instance.PrivateIpAddress),
			"public_ip":        aws.ToString(instance.PublicIpAddress),
			"launch_time":      instance.LaunchTime,
		},
	}

	return target
}

func (h *EC2Handler) extractTags(tags []types.Tag) map[string]string {
	result := make(map[string]string)
	for _, tag := range tags {
		if tag.Key != nil && tag.Value != nil {
			result[*tag.Key] = *tag.Value
		}
	}
	return result
}

func (h *EC2Handler) mapInstanceState(state *types.InstanceState) string {
	if state == nil {
		return "unknown"
	}
	return string(state.Name)
}

func (h *EC2Handler) buildInstanceMetadata(instance types.Instance) map[string]any {
	metadata := map[string]any{
		"instance_type":     string(instance.InstanceType),
		"state":            h.mapInstanceState(instance.State),
		"architecture":     string(instance.Architecture),
		"hypervisor":       string(instance.Hypervisor),
		"virtualization_type": string(instance.VirtualizationType),
		"root_device_type": string(instance.RootDeviceType),
	}

	if instance.VpcId != nil {
		metadata["vpc_id"] = *instance.VpcId
	}
	if instance.SubnetId != nil {
		metadata["subnet_id"] = *instance.SubnetId
	}
	if instance.PrivateIpAddress != nil {
		metadata["private_ip"] = *instance.PrivateIpAddress
	}
	if instance.PublicIpAddress != nil {
		metadata["public_ip"] = *instance.PublicIpAddress
	}
	if instance.LaunchTime != nil {
		metadata["launch_time"] = *instance.LaunchTime
	}
	if instance.Placement != nil {
		if instance.Placement.AvailabilityZone != nil {
			metadata["availability_zone"] = *instance.Placement.AvailabilityZone
		}
		if instance.Placement.Tenancy != "" {
			metadata["tenancy"] = string(instance.Placement.Tenancy)
		}
	}

	// Add security groups
	securityGroups := make([]map[string]string, 0, len(instance.SecurityGroups))
	for _, sg := range instance.SecurityGroups {
		group := map[string]string{}
		if sg.GroupId != nil {
			group["group_id"] = *sg.GroupId
		}
		if sg.GroupName != nil {
			group["group_name"] = *sg.GroupName
		}
		securityGroups = append(securityGroups, group)
	}
	metadata["security_groups"] = securityGroups

	// Add block device mappings
	blockDevices := make([]map[string]any, 0, len(instance.BlockDeviceMappings))
	for _, bdm := range instance.BlockDeviceMappings {
		device := map[string]any{}
		if bdm.DeviceName != nil {
			device["device_name"] = *bdm.DeviceName
		}
		if bdm.Ebs != nil {
			ebs := map[string]any{}
			if bdm.Ebs.VolumeId != nil {
				ebs["volume_id"] = *bdm.Ebs.VolumeId
			}
			if bdm.Ebs.Status != "" {
				ebs["status"] = string(bdm.Ebs.Status)
			}
			ebs["delete_on_termination"] = bdm.Ebs.DeleteOnTermination
			device["ebs"] = ebs
		}
		blockDevices = append(blockDevices, device)
	}
	metadata["block_device_mappings"] = blockDevices

	return metadata
}

// Helper functions

func getBoolParameter(parameters map[string]any, key string, defaultValue bool) bool {
	if val, exists := parameters[key]; exists {
		if b, ok := val.(bool); ok {
			return b
		}
		if s, ok := val.(string); ok {
			if parsed, err := strconv.ParseBool(s); err == nil {
				return parsed
			}
		}
	}
	return defaultValue
}

func getStringParameter(parameters map[string]any, key, defaultValue string) string {
	if val, exists := parameters[key]; exists {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return defaultValue
}

func getIntParameter(parameters map[string]any, key string, defaultValue int) int {
	if val, exists := parameters[key]; exists {
		if i, ok := val.(int); ok {
			return i
		}
		if f, ok := val.(float64); ok {
			return int(f)
		}
		if s, ok := val.(string); ok {
			if parsed, err := strconv.Atoi(s); err == nil {
				return parsed
			}
		}
	}
	return defaultValue
}