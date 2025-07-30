package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// ECSHandler handles chaos operations for ECS services and tasks
type ECSHandler struct {
	client *ecs.Client
	config ECSConfig
}

// NewECSHandler creates a new ECS handler
func NewECSHandler(client *ecs.Client, config ECSConfig) *ECSHandler {
	return &ECSHandler{
		client: client,
		config: config,
	}
}

// DiscoverServices discovers ECS services based on criteria
func (h *ECSHandler) DiscoverServices(ctx context.Context, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target

	// First, list all clusters
	clusters, err := h.listClusters(ctx)
	if err != nil {
		return nil, err
	}

	// For each cluster, list services
	for _, clusterArn := range clusters {
		clusterName := h.extractClusterName(clusterArn)
		
		// Check if cluster is allowed
		if !h.isClusterAllowed(clusterName) {
			continue
		}

		serviceTargets, err := h.discoverServicesInCluster(ctx, clusterArn, criteria)
		if err != nil {
			continue // Log error but continue with other clusters
		}
		targets = append(targets, serviceTargets...)
	}

	return targets, nil
}

// DiscoverTasks discovers ECS tasks based on criteria
func (h *ECSHandler) DiscoverTasks(ctx context.Context, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target

	// First, list all clusters
	clusters, err := h.listClusters(ctx)
	if err != nil {
		return nil, err
	}

	// For each cluster, list tasks
	for _, clusterArn := range clusters {
		clusterName := h.extractClusterName(clusterArn)
		
		// Check if cluster is allowed
		if !h.isClusterAllowed(clusterName) {
			continue
		}

		taskTargets, err := h.discoverTasksInCluster(ctx, clusterArn, criteria)
		if err != nil {
			continue // Log error but continue with other clusters
		}
		targets = append(targets, taskTargets...)
	}

	return targets, nil
}

// GetServiceInfo gets detailed information about an ECS service
func (h *ECSHandler) GetServiceInfo(ctx context.Context, target domain.Target) (*domain.TargetInfo, error) {
	// Parse cluster and service from resource ID
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 2 {
		return nil, errors.NewValidationError("invalid ECS service resource ID format: %s", target.ResourceID)
	}
	
	clusterName := parts[0]
	serviceName := parts[1]

	input := &ecs.DescribeServicesInput{
		Cluster:  aws.String(clusterName),
		Services: []string{serviceName},
	}

	result, err := h.client.DescribeServices(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ecs_service_info", err)
	}

	if len(result.Services) == 0 {
		return nil, errors.NewValidationError("service not found: %s", target.ResourceID)
	}

	service := result.Services[0]
	
	info := &domain.TargetInfo{
		ID:          target.ID,
		ResourceID:  target.ResourceID,
		Name:        target.Name,
		Type:        target.Type,
		Provider:    target.Provider,
		Region:      target.Region,
		Tags:        target.Tags,
		Status:      string(service.Status),
		Metadata:    h.buildServiceMetadata(service),
		LastUpdated: time.Now(),
	}

	return info, nil
}

// GetTaskInfo gets detailed information about an ECS task
func (h *ECSHandler) GetTaskInfo(ctx context.Context, target domain.Target) (*domain.TargetInfo, error) {
	// Parse cluster and task from resource ID
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 2 {
		return nil, errors.NewValidationError("invalid ECS task resource ID format: %s", target.ResourceID)
	}
	
	clusterName := parts[0]
	taskArn := parts[1]

	input := &ecs.DescribeTasksInput{
		Cluster: aws.String(clusterName),
		Tasks:   []string{taskArn},
	}

	result, err := h.client.DescribeTasks(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ecs_task_info", err)
	}

	if len(result.Tasks) == 0 {
		return nil, errors.NewValidationError("task not found: %s", target.ResourceID)
	}

	task := result.Tasks[0]
	
	info := &domain.TargetInfo{
		ID:          target.ID,
		ResourceID:  target.ResourceID,
		Name:        target.Name,
		Type:        target.Type,
		Provider:    target.Provider,
		Region:      target.Region,
		Tags:        target.Tags,
		Status:      string(task.LastStatus),
		Metadata:    h.buildTaskMetadata(task),
		LastUpdated: time.Now(),
	}

	return info, nil
}

// ExecuteAction executes a chaos action on ECS services or tasks
func (h *ECSHandler) ExecuteAction(ctx context.Context, target domain.Target, action string, parameters map[string]any, dryRun bool) (map[string]any, error) {
	metadata := make(map[string]any)
	metadata["resource_id"] = target.ResourceID
	metadata["action"] = action
	metadata["dry_run"] = dryRun

	switch target.Type {
	case domain.TargetTypeECSService:
		return h.executeServiceAction(ctx, target, action, parameters, dryRun)
	case domain.TargetTypeECSTask:
		return h.executeTaskAction(ctx, target, action, parameters, dryRun)
	default:
		return nil, errors.NewValidationError("unsupported ECS target type: %s", target.Type)
	}
}

// RollbackService rolls back an ECS service action
func (h *ECSHandler) RollbackService(ctx context.Context, target domain.Target, metadata map[string]any) error {
	// For service scaling, restore the original desired count
	if originalCount, exists := metadata["original_desired_count"]; exists {
		if count, ok := originalCount.(int32); ok {
			parts := strings.Split(target.ResourceID, "/")
			if len(parts) != 2 {
				return errors.NewValidationError("invalid service resource ID: %s", target.ResourceID)
			}

			_, err := h.client.UpdateService(ctx, &ecs.UpdateServiceInput{
				Cluster:      aws.String(parts[0]),
				Service:      aws.String(parts[1]),
				DesiredCount: aws.Int32(count),
			})
			return err
		}
	}
	return nil
}

// Private methods

func (h *ECSHandler) listClusters(ctx context.Context) ([]string, error) {
	input := &ecs.ListClustersInput{}
	result, err := h.client.ListClusters(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ecs_list_clusters", err)
	}

	return result.ClusterArns, nil
}

func (h *ECSHandler) discoverServicesInCluster(ctx context.Context, clusterArn string, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target

	// List services in cluster
	input := &ecs.ListServicesInput{
		Cluster: aws.String(clusterArn),
	}

	result, err := h.client.ListServices(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ecs_list_services", err)
	}

	if len(result.ServiceArns) == 0 {
		return targets, nil
	}

	// Describe services to get detailed information
	describeInput := &ecs.DescribeServicesInput{
		Cluster:  aws.String(clusterArn),
		Services: result.ServiceArns,
	}

	describeResult, err := h.client.DescribeServices(ctx, describeInput)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ecs_describe_services", err)
	}

	// Convert services to targets
	for _, service := range describeResult.Services {
		if h.shouldIncludeService(service, criteria) {
			target := h.serviceToTarget(service, clusterArn)
			targets = append(targets, target)
		}
	}

	return targets, nil
}

func (h *ECSHandler) discoverTasksInCluster(ctx context.Context, clusterArn string, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target

	// List tasks in cluster
	input := &ecs.ListTasksInput{
		Cluster: aws.String(clusterArn),
	}

	result, err := h.client.ListTasks(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ecs_list_tasks", err)
	}

	if len(result.TaskArns) == 0 {
		return targets, nil
	}

	// Describe tasks to get detailed information
	describeInput := &ecs.DescribeTasksInput{
		Cluster: aws.String(clusterArn),
		Tasks:   result.TaskArns,
	}

	describeResult, err := h.client.DescribeTasks(ctx, describeInput)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ecs_describe_tasks", err)
	}

	// Convert tasks to targets
	for _, task := range describeResult.Tasks {
		if h.shouldIncludeTask(task, criteria) {
			target := h.taskToTarget(task, clusterArn)
			targets = append(targets, target)
		}
	}

	return targets, nil
}

func (h *ECSHandler) executeServiceAction(ctx context.Context, target domain.Target, action string, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 2 {
		return nil, errors.NewValidationError("invalid service resource ID: %s", target.ResourceID)
	}

	clusterName := parts[0]
	serviceName := parts[1]

	switch action {
	case "update_service":
		return h.updateService(ctx, clusterName, serviceName, parameters, dryRun)
	case "stop_service":
		return h.stopService(ctx, clusterName, serviceName, parameters, dryRun)
	default:
		return nil, errors.NewValidationError("unsupported ECS service action: %s", action)
	}
}

func (h *ECSHandler) executeTaskAction(ctx context.Context, target domain.Target, action string, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 2 {
		return nil, errors.NewValidationError("invalid task resource ID: %s", target.ResourceID)
	}

	clusterName := parts[0]
	taskArn := parts[1]

	switch action {
	case "stop_tasks":
		return h.stopTask(ctx, clusterName, taskArn, parameters, dryRun)
	default:
		return nil, errors.NewValidationError("unsupported ECS task action: %s", action)
	}
}

func (h *ECSHandler) updateService(ctx context.Context, clusterName, serviceName string, parameters map[string]any, dryRun bool) (map[string]any, error) {
	desiredCount := getIntParameter(parameters, "desired_count", -1)
	if desiredCount < 0 {
		return nil, errors.NewValidationError("desired_count parameter is required for update_service action")
	}

	// Get current service state for rollback
	describeInput := &ecs.DescribeServicesInput{
		Cluster:  aws.String(clusterName),
		Services: []string{serviceName},
	}

	describeResult, err := h.client.DescribeServices(ctx, describeInput)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ecs_describe_service", err)
	}

	if len(describeResult.Services) == 0 {
		return nil, errors.NewValidationError("service not found: %s/%s", clusterName, serviceName)
	}

	currentService := describeResult.Services[0]
	originalDesiredCount := currentService.DesiredCount

	metadata := map[string]any{
		"action":                  "update_service",
		"cluster":                clusterName,
		"service":                serviceName,
		"original_desired_count": originalDesiredCount,
		"new_desired_count":      int32(desiredCount),
		"dry_run":                dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	// Update the service
	updateInput := &ecs.UpdateServiceInput{
		Cluster:      aws.String(clusterName),
		Service:      aws.String(serviceName),
		DesiredCount: aws.Int32(int32(desiredCount)),
	}

	updateResult, err := h.client.UpdateService(ctx, updateInput)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ecs_update_service", err)
	}

	if updateResult.Service != nil {
		metadata["task_definition"] = aws.ToString(updateResult.Service.TaskDefinition)
		metadata["status"] = string(updateResult.Service.Status)
	}

	return metadata, nil
}

func (h *ECSHandler) stopService(ctx context.Context, clusterName, serviceName string, parameters map[string]any, dryRun bool) (map[string]any, error) {
	// Get current service state for rollback
	describeInput := &ecs.DescribeServicesInput{
		Cluster:  aws.String(clusterName),
		Services: []string{serviceName},
	}

	describeResult, err := h.client.DescribeServices(ctx, describeInput)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ecs_describe_service", err)
	}

	if len(describeResult.Services) == 0 {
		return nil, errors.NewValidationError("service not found: %s/%s", clusterName, serviceName)
	}

	currentService := describeResult.Services[0]
	originalDesiredCount := currentService.DesiredCount

	metadata := map[string]any{
		"action":                  "stop_service",
		"cluster":                clusterName,
		"service":                serviceName,
		"original_desired_count": originalDesiredCount,
		"dry_run":                dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	// Scale service to 0 to stop all tasks
	updateInput := &ecs.UpdateServiceInput{
		Cluster:      aws.String(clusterName),
		Service:      aws.String(serviceName),
		DesiredCount: aws.Int32(0),
	}

	_, err = h.client.UpdateService(ctx, updateInput)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ecs_stop_service", err)
	}

	return metadata, nil
}

func (h *ECSHandler) stopTask(ctx context.Context, clusterName, taskArn string, parameters map[string]any, dryRun bool) (map[string]any, error) {
	reason := getStringParameter(parameters, "reason", "Chaos experiment")

	metadata := map[string]any{
		"action":  "stop_task",
		"cluster": clusterName,
		"task":    taskArn,
		"reason":  reason,
		"dry_run": dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	input := &ecs.StopTaskInput{
		Cluster: aws.String(clusterName),
		Task:    aws.String(taskArn),
		Reason:  aws.String(reason),
	}

	result, err := h.client.StopTask(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "ecs_stop_task", err)
	}

	if result.Task != nil {
		metadata["previous_status"] = aws.ToString(result.Task.LastStatus)
		metadata["desired_status"] = aws.ToString(result.Task.DesiredStatus)
	}

	return metadata, nil
}

func (h *ECSHandler) extractClusterName(clusterArn string) string {
	// Extract cluster name from ARN (arn:aws:ecs:region:account:cluster/cluster-name)
	parts := strings.Split(clusterArn, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return clusterArn
}

func (h *ECSHandler) isClusterAllowed(clusterName string) bool {
	// Check forbidden clusters
	for _, forbidden := range h.config.ForbiddenClusters {
		if clusterName == forbidden {
			return false
		}
	}

	// Check allowed cluster patterns
	if len(h.config.AllowedClusterPatterns) > 0 {
		for _, pattern := range h.config.AllowedClusterPatterns {
			if matched, _ := fmt.Sprintf(pattern, clusterName); matched == clusterName {
				return true
			}
			// Simple wildcard matching
			if strings.Contains(pattern, "*") {
				prefix := strings.Split(pattern, "*")[0]
				if strings.HasPrefix(clusterName, prefix) {
					return true
				}
			}
		}
		return false
	}

	return true
}

func (h *ECSHandler) shouldIncludeService(service types.Service, criteria domain.DiscoveryCriteria) bool {
	// Check required tags
	serviceTags := h.extractServiceTags(service.Tags)
	for key, value := range h.config.RequiredTags {
		if serviceTags[key] != value {
			return false
		}
	}

	return true
}

func (h *ECSHandler) shouldIncludeTask(task types.Task, criteria domain.DiscoveryCriteria) bool {
	// Check required tags
	taskTags := h.extractTaskTags(task.Tags)
	for key, value := range h.config.RequiredTags {
		if taskTags[key] != value {
			return false
		}
	}

	return true
}

func (h *ECSHandler) serviceToTarget(service types.Service, clusterArn string) domain.Target {
	clusterName := h.extractClusterName(clusterArn)
	serviceName := aws.ToString(service.ServiceName)
	resourceID := fmt.Sprintf("%s/%s", clusterName, serviceName)

	target := domain.Target{
		ID:         fmt.Sprintf("aws-ecs-service-%s", resourceID),
		ResourceID: resourceID,
		Name:       serviceName,
		Type:       domain.TargetTypeECSService,
		Provider:   "aws",
		Region:     h.extractRegionFromArn(aws.ToString(service.ServiceArn)),
		Tags:       h.extractServiceTags(service.Tags),
		Metadata: map[string]any{
			"cluster_name":     clusterName,
			"service_name":     serviceName,
			"task_definition":  aws.ToString(service.TaskDefinition),
			"desired_count":    service.DesiredCount,
			"running_count":    service.RunningCount,
			"pending_count":    service.PendingCount,
			"status":           string(service.Status),
			"launch_type":      string(service.LaunchType),
			"platform_version": aws.ToString(service.PlatformVersion),
		},
	}

	return target
}

func (h *ECSHandler) taskToTarget(task types.Task, clusterArn string) domain.Target {
	clusterName := h.extractClusterName(clusterArn)
	taskArn := aws.ToString(task.TaskArn)
	taskId := h.extractTaskId(taskArn)
	resourceID := fmt.Sprintf("%s/%s", clusterName, taskArn)

	target := domain.Target{
		ID:         fmt.Sprintf("aws-ecs-task-%s", taskId),
		ResourceID: resourceID,
		Name:       taskId,
		Type:       domain.TargetTypeECSTask,
		Provider:   "aws",
		Region:     h.extractRegionFromArn(taskArn),
		Tags:       h.extractTaskTags(task.Tags),
		Metadata: map[string]any{
			"cluster_name":     clusterName,
			"task_arn":         taskArn,
			"task_definition":  aws.ToString(task.TaskDefinitionArn),
			"last_status":      aws.ToString(task.LastStatus),
			"desired_status":   aws.ToString(task.DesiredStatus),
			"health_status":    string(task.HealthStatus),
			"launch_type":      string(task.LaunchType),
			"platform_version": aws.ToString(task.PlatformVersion),
			"cpu":              aws.ToString(task.Cpu),
			"memory":           aws.ToString(task.Memory),
			"created_at":       task.CreatedAt,
			"started_at":       task.StartedAt,
		},
	}

	return target
}

func (h *ECSHandler) extractTaskId(taskArn string) string {
	// Extract task ID from ARN (arn:aws:ecs:region:account:task/cluster-name/task-id)
	parts := strings.Split(taskArn, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return taskArn
}

func (h *ECSHandler) extractRegionFromArn(arn string) string {
	// Extract region from ARN (arn:aws:service:region:account:resource)
	parts := strings.Split(arn, ":")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

func (h *ECSHandler) extractServiceTags(tags []types.Tag) map[string]string {
	result := make(map[string]string)
	for _, tag := range tags {
		if tag.Key != nil && tag.Value != nil {
			result[*tag.Key] = *tag.Value
		}
	}
	return result
}

func (h *ECSHandler) extractTaskTags(tags []types.Tag) map[string]string {
	result := make(map[string]string)
	for _, tag := range tags {
		if tag.Key != nil && tag.Value != nil {
			result[*tag.Key] = *tag.Value
		}
	}
	return result
}

func (h *ECSHandler) buildServiceMetadata(service types.Service) map[string]any {
	metadata := map[string]any{
		"service_name":     aws.ToString(service.ServiceName),
		"task_definition":  aws.ToString(service.TaskDefinition),
		"desired_count":    service.DesiredCount,
		"running_count":    service.RunningCount,
		"pending_count":    service.PendingCount,
		"status":           string(service.Status),
		"launch_type":      string(service.LaunchType),
		"platform_version": aws.ToString(service.PlatformVersion),
		"created_at":       service.CreatedAt,
	}

	if service.LoadBalancers != nil {
		loadBalancers := make([]map[string]any, 0, len(service.LoadBalancers))
		for _, lb := range service.LoadBalancers {
			lbInfo := map[string]any{
				"target_group_arn": aws.ToString(lb.TargetGroupArn),
				"container_name":   aws.ToString(lb.ContainerName),
				"container_port":   lb.ContainerPort,
			}
			loadBalancers = append(loadBalancers, lbInfo)
		}
		metadata["load_balancers"] = loadBalancers
	}

	return metadata
}

func (h *ECSHandler) buildTaskMetadata(task types.Task) map[string]any {
	metadata := map[string]any{
		"task_arn":         aws.ToString(task.TaskArn),
		"task_definition":  aws.ToString(task.TaskDefinitionArn),
		"last_status":      aws.ToString(task.LastStatus),
		"desired_status":   aws.ToString(task.DesiredStatus),
		"health_status":    string(task.HealthStatus),
		"launch_type":      string(task.LaunchType),
		"platform_version": aws.ToString(task.PlatformVersion),
		"cpu":              aws.ToString(task.Cpu),
		"memory":           aws.ToString(task.Memory),
		"created_at":       task.CreatedAt,
		"started_at":       task.StartedAt,
		"stopped_at":       task.StoppedAt,
		"stopped_reason":   aws.ToString(task.StoppedReason),
	}

	// Add container information
	if len(task.Containers) > 0 {
		containers := make([]map[string]any, 0, len(task.Containers))
		for _, container := range task.Containers {
			containerInfo := map[string]any{
				"name":          aws.ToString(container.Name),
				"last_status":   aws.ToString(container.LastStatus),
				"exit_code":     container.ExitCode,
				"reason":        aws.ToString(container.Reason),
				"health_status": string(container.HealthStatus),
			}
			containers = append(containers, containerInfo)
		}
		metadata["containers"] = containers
	}

	return metadata
}