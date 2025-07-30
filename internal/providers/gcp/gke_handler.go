package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/container/apiv1"
	"cloud.google.com/go/container/apiv1/containerpb"
	"google.golang.org/api/iterator"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// GKEHandler handles chaos operations for GKE clusters and nodes
type GKEHandler struct {
	client    *container.ClusterManagerClient
	projectID string
	config    GKEConfig
}

// NewGKEHandler creates a new GKE handler
func NewGKEHandler(client *container.ClusterManagerClient, projectID string, config GKEConfig) *GKEHandler {
	return &GKEHandler{
		client:    client,
		projectID: projectID,
		config:    config,
	}
}

// DiscoverNodes discovers GKE nodes based on criteria
func (h *GKEHandler) DiscoverNodes(ctx context.Context, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target

	// Get clusters to search
	clusters, err := h.listClusters(ctx, criteria)
	if err != nil {
		return nil, err
	}

	// For each cluster, get node pools and nodes
	for _, cluster := range clusters {
		if !h.shouldIncludeCluster(cluster.Name, criteria) {
			continue
		}

		// Get node pools for this cluster
		nodeTargets, err := h.discoverNodesInCluster(ctx, cluster, criteria)
		if err != nil {
			continue // Log error but continue with other clusters
		}
		targets = append(targets, nodeTargets...)
	}

	return targets, nil
}

// GetNodeInfo gets detailed information about a GKE node
func (h *GKEHandler) GetNodeInfo(ctx context.Context, target domain.Target) (*domain.TargetInfo, error) {
	// Parse cluster, zone, and node from resource ID
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 3 {
		return nil, errors.NewValidationError("invalid GKE node resource ID format: %s", target.ResourceID)
	}

	zone := parts[0]
	clusterName := parts[1]
	nodeName := parts[2]

	// Get cluster information
	req := &containerpb.GetClusterRequest{
		Name: fmt.Sprintf("projects/%s/locations/%s/clusters/%s", h.projectID, zone, clusterName),
	}

	cluster, err := h.client.GetCluster(ctx, req)
	if err != nil {
		return nil, errors.NewProviderError("gcp", "gke_cluster_info", err)
	}

	// Find the node pool and node
	var nodePool *containerpb.NodePool
	for _, pool := range cluster.NodePools {
		for _, instance := range pool.InstanceGroupUrls {
			if strings.Contains(instance, nodeName) {
				nodePool = pool
				break
			}
		}
		if nodePool != nil {
			break
		}
	}

	info := &domain.TargetInfo{
		ID:          target.ID,
		ResourceID:  target.ResourceID,
		Name:        target.Name,
		Type:        target.Type,
		Provider:    target.Provider,
		Region:      target.Region,
		Tags:        target.Tags,
		Status:      h.mapNodeStatus(nodePool),
		Metadata:    h.buildNodeMetadata(cluster, nodePool, nodeName),
		LastUpdated: time.Now(),
	}

	return info, nil
}

// ExecuteAction executes a chaos action on GKE nodes
func (h *GKEHandler) ExecuteAction(ctx context.Context, target domain.Target, action string, parameters map[string]any, dryRun bool) (map[string]any, error) {
	metadata := make(map[string]any)
	metadata["node_id"] = target.ResourceID
	metadata["action"] = action
	metadata["dry_run"] = dryRun

	switch action {
	case "drain_node":
		return h.drainNode(ctx, target, parameters, dryRun)
	case "cordon_node":
		return h.cordonNode(ctx, target, parameters, dryRun)
	case "uncordon_node":
		return h.uncordonNode(ctx, target, parameters, dryRun)
	case "scale_node_pool":
		return h.scaleNodePool(ctx, target, parameters, dryRun)
	case "upgrade_node_pool":
		return h.upgradeNodePool(ctx, target, parameters, dryRun)
	case "set_node_pool_autoscaling":
		return h.setNodePoolAutoscaling(ctx, target, parameters, dryRun)
	case "restart_node_pool":
		return h.restartNodePool(ctx, target, parameters, dryRun)
	default:
		return nil, errors.NewValidationError("unsupported GKE action: %s", action)
	}
}

// UncordonNode uncordons a GKE node (rollback operation)
func (h *GKEHandler) UncordonNode(ctx context.Context, target domain.Target, metadata map[string]any) error {
	// This would typically use kubectl or the Kubernetes API
	// For now, we'll implement it as an uncordon action
	_, err := h.uncordonNode(ctx, target, make(map[string]any), false)
	if err != nil {
		return errors.NewProviderError("gcp", "gke_uncordon", err)
	}
	return nil
}

// healthCheck performs a health check for the GKE service
func (h *GKEHandler) healthCheck(ctx context.Context) error {
	// Try to list clusters as a simple connectivity check
	_, err := h.listClusters(ctx, domain.DiscoveryCriteria{})
	return err
}

// Private methods

func (h *GKEHandler) listClusters(ctx context.Context, criteria domain.DiscoveryCriteria) ([]*containerpb.Cluster, error) {
	var clusters []*containerpb.Cluster

	// Get zones from criteria or use all zones
	zones := h.getZonesFromCriteria(criteria)
	if len(zones) == 0 {
		zones = []string{"-"} // Use "-" to list all locations
	}

	for _, zone := range zones {
		req := &containerpb.ListClustersRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", h.projectID, zone),
		}

		result, err := h.client.ListClusters(ctx, req)
		if err != nil {
			continue // Skip zones that fail
		}

		clusters = append(clusters, result.Clusters...)
	}

	return clusters, nil
}

func (h *GKEHandler) discoverNodesInCluster(ctx context.Context, cluster *containerpb.Cluster, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target

	location := h.extractLocationFromCluster(cluster)
	
	// For each node pool in the cluster
	for _, nodePool := range cluster.NodePools {
		if !h.shouldIncludeNodePool(nodePool, criteria) {
			continue
		}

		// Create targets for each instance group (representing nodes)
		for i, instanceGroupUrl := range nodePool.InstanceGroupUrls {
			nodeName := h.extractNodeNameFromInstanceGroup(instanceGroupUrl, i)
			target := h.nodeToTarget(cluster, nodePool, nodeName, location)
			targets = append(targets, target)
		}
	}

	return targets, nil
}

func (h *GKEHandler) drainNode(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 3 {
		return nil, errors.NewValidationError("invalid node resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	clusterName := parts[1]
	nodeName := parts[2]
	timeout := getDurationParameter(parameters, "timeout", h.config.DrainTimeout)

	metadata := map[string]any{
		"action":       "drain_node",
		"cluster_name": clusterName,
		"zone":         zone,
		"node_name":    nodeName,
		"timeout":      timeout.String(),
		"dry_run":      dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	// Note: Draining a node typically requires Kubernetes API access
	// This is a simplified implementation that would need to be extended
	// with actual kubectl or Kubernetes client-go operations

	// For now, we simulate the drain operation
	metadata["operation_status"] = "simulated"
	metadata["drained_pods"] = 0 // Would contain actual pod count
	
	return metadata, nil
}

func (h *GKEHandler) cordonNode(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 3 {
		return nil, errors.NewValidationError("invalid node resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	clusterName := parts[1]
	nodeName := parts[2]

	metadata := map[string]any{
		"action":       "cordon_node",
		"cluster_name": clusterName,
		"zone":         zone,
		"node_name":    nodeName,
		"dry_run":      dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	// Note: Cordoning requires Kubernetes API access
	metadata["operation_status"] = "simulated"
	
	return metadata, nil
}

func (h *GKEHandler) uncordonNode(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 3 {
		return nil, errors.NewValidationError("invalid node resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	clusterName := parts[1]
	nodeName := parts[2]

	metadata := map[string]any{
		"action":       "uncordon_node",
		"cluster_name": clusterName,
		"zone":         zone,
		"node_name":    nodeName,
		"dry_run":      dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	// Note: Uncordoning requires Kubernetes API access
	metadata["operation_status"] = "simulated"
	
	return metadata, nil
}

func (h *GKEHandler) scaleNodePool(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 3 {
		return nil, errors.NewValidationError("invalid node resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	clusterName := parts[1]
	nodeCount := getIntParameter(parameters, "node_count", 0)

	if nodeCount <= 0 {
		return nil, errors.NewValidationError("node_count parameter is required and must be > 0")
	}

	metadata := map[string]any{
		"action":       "scale_node_pool",
		"cluster_name": clusterName,
		"zone":         zone,
		"node_count":   nodeCount,
		"dry_run":      dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	// Get the node pool name from the target
	nodePoolName := h.extractNodePoolNameFromTarget(target)
	if nodePoolName == "" {
		return nil, errors.NewValidationError("could not determine node pool name from target")
	}

	req := &containerpb.SetNodePoolSizeRequest{
		Name:     fmt.Sprintf("projects/%s/locations/%s/clusters/%s/nodePools/%s", h.projectID, zone, clusterName, nodePoolName),
		NodeCount: int32(nodeCount),
	}

	operation, err := h.client.SetNodePoolSize(ctx, req)
	if err != nil {
		return nil, errors.NewProviderError("gcp", "gke_scale_node_pool", err)
	}

	metadata["operation_id"] = operation.Name
	metadata["operation_type"] = operation.OperationType

	return metadata, nil
}

func (h *GKEHandler) upgradeNodePool(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 3 {
		return nil, errors.NewValidationError("invalid node resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	clusterName := parts[1]
	nodeVersion := getStringParameter(parameters, "node_version", "")

	if nodeVersion == "" {
		return nil, errors.NewValidationError("node_version parameter is required")
	}

	metadata := map[string]any{
		"action":       "upgrade_node_pool",
		"cluster_name": clusterName,
		"zone":         zone,
		"node_version": nodeVersion,
		"dry_run":      dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	nodePoolName := h.extractNodePoolNameFromTarget(target)
	if nodePoolName == "" {
		return nil, errors.NewValidationError("could not determine node pool name from target")
	}

	req := &containerpb.UpdateNodePoolRequest{
		Name:        fmt.Sprintf("projects/%s/locations/%s/clusters/%s/nodePools/%s", h.projectID, zone, clusterName, nodePoolName),
		NodeVersion: nodeVersion,
	}

	operation, err := h.client.UpdateNodePool(ctx, req)
	if err != nil {
		return nil, errors.NewProviderError("gcp", "gke_upgrade_node_pool", err)
	}

	metadata["operation_id"] = operation.Name
	metadata["operation_type"] = operation.OperationType

	return metadata, nil
}

func (h *GKEHandler) setNodePoolAutoscaling(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 3 {
		return nil, errors.NewValidationError("invalid node resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	clusterName := parts[1]
	enabled := getBoolParameter(parameters, "enabled", true)
	minNodeCount := getIntParameter(parameters, "min_node_count", 1)
	maxNodeCount := getIntParameter(parameters, "max_node_count", 10)

	metadata := map[string]any{
		"action":         "set_node_pool_autoscaling",
		"cluster_name":   clusterName,
		"zone":           zone,
		"enabled":        enabled,
		"min_node_count": minNodeCount,
		"max_node_count": maxNodeCount,
		"dry_run":        dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	nodePoolName := h.extractNodePoolNameFromTarget(target)
	if nodePoolName == "" {
		return nil, errors.NewValidationError("could not determine node pool name from target")
	}

	autoscaling := &containerpb.NodePoolAutoscaling{
		Enabled:      enabled,
		MinNodeCount: int32(minNodeCount),
		MaxNodeCount: int32(maxNodeCount),
	}

	req := &containerpb.SetNodePoolAutoscalingRequest{
		Name:        fmt.Sprintf("projects/%s/locations/%s/clusters/%s/nodePools/%s", h.projectID, zone, clusterName, nodePoolName),
		Autoscaling: autoscaling,
	}

	operation, err := h.client.SetNodePoolAutoscaling(ctx, req)
	if err != nil {
		return nil, errors.NewProviderError("gcp", "gke_set_autoscaling", err)
	}

	metadata["operation_id"] = operation.Name
	metadata["operation_type"] = operation.OperationType

	return metadata, nil
}

func (h *GKEHandler) restartNodePool(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	parts := strings.Split(target.ResourceID, "/")
	if len(parts) != 3 {
		return nil, errors.NewValidationError("invalid node resource ID: %s", target.ResourceID)
	}

	zone := parts[0]
	clusterName := parts[1]

	metadata := map[string]any{
		"action":       "restart_node_pool",
		"cluster_name": clusterName,
		"zone":         zone,
		"dry_run":      dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	// Note: GKE doesn't have a direct "restart" operation for node pools
	// This would typically involve rolling updates or node pool recreation
	// For now, we'll simulate this operation
	metadata["operation_status"] = "simulated"
	metadata["restart_method"] = "rolling_update"

	return metadata, nil
}

func (h *GKEHandler) getZonesFromCriteria(criteria domain.DiscoveryCriteria) []string {
	var zones []string
	for _, filter := range criteria.Filters {
		if filter.Field == "zone" || filter.Field == "location" {
			zones = append(zones, filter.Value)
		}
	}
	return zones
}

func (h *GKEHandler) shouldIncludeCluster(clusterName string, criteria domain.DiscoveryCriteria) bool {
	// Check allowed cluster names
	if len(h.config.AllowedClusterNames) > 0 {
		allowed := false
		for _, allowedName := range h.config.AllowedClusterNames {
			if clusterName == allowedName {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	// Check forbidden clusters
	for _, forbiddenCluster := range h.config.ForbiddenClusters {
		if clusterName == forbiddenCluster {
			return false
		}
	}

	return true
}

func (h *GKEHandler) shouldIncludeNodePool(nodePool *containerpb.NodePool, criteria domain.DiscoveryCriteria) bool {
	// Check if Autopilot clusters are allowed
	if nodePool.Config != nil && nodePool.Config.Preemptible && !h.config.AllowAutopilot {
		return false
	}

	// Check required labels
	nodeLabels := make(map[string]string)
	if nodePool.Config != nil && nodePool.Config.Labels != nil {
		nodeLabels = nodePool.Config.Labels
	}

	for key, value := range h.config.RequiredLabels {
		if nodeLabels[key] != value {
			return false
		}
	}

	return true
}

func (h *GKEHandler) nodeToTarget(cluster *containerpb.Cluster, nodePool *containerpb.NodePool, nodeName, location string) domain.Target {
	clusterName := cluster.Name
	resourceID := fmt.Sprintf("%s/%s/%s", location, clusterName, nodeName)

	// Extract labels
	labels := make(map[string]string)
	if nodePool.Config != nil && nodePool.Config.Labels != nil {
		labels = nodePool.Config.Labels
	}

	// Extract region from location
	region := h.extractRegionFromLocation(location)

	target := domain.Target{
		ID:         fmt.Sprintf("gcp-gke-node-%s", resourceID),
		ResourceID: resourceID,
		Name:       nodeName,
		Type:       domain.TargetTypeGKENode,
		Provider:   "gcp",
		Region:     region,
		Tags:       labels,
		Metadata: map[string]any{
			"cluster_name":     clusterName,
			"node_pool_name":   nodePool.Name,
			"location":         location,
			"node_name":        nodeName,
			"machine_type":     h.getMachineTypeFromNodePool(nodePool),
			"disk_size_gb":     h.getDiskSizeFromNodePool(nodePool),
			"preemptible":      h.getPreemptibleFromNodePool(nodePool),
			"node_pool_status": nodePool.Status,
			"node_count":       nodePool.InitialNodeCount,
		},
	}

	return target
}

func (h *GKEHandler) extractLocationFromCluster(cluster *containerpb.Cluster) string {
	if cluster.Location != "" {
		return cluster.Location
	}
	if cluster.Zone != "" {
		return cluster.Zone
	}
	return ""
}

func (h *GKEHandler) extractNodeNameFromInstanceGroup(instanceGroupUrl string, index int) string {
	// Extract node name from instance group URL
	// This is a simplified approach - in practice, you'd need to call the Compute API
	parts := strings.Split(instanceGroupUrl, "/")
	if len(parts) > 0 {
		return fmt.Sprintf("%s-node-%d", parts[len(parts)-1], index)
	}
	return fmt.Sprintf("node-%d", index)
}

func (h *GKEHandler) extractNodePoolNameFromTarget(target domain.Target) string {
	if metadata, ok := target.Metadata["node_pool_name"].(string); ok {
		return metadata
	}
	return ""
}

func (h *GKEHandler) extractRegionFromLocation(location string) string {
	// Extract region from location (e.g., "us-central1-a" -> "us-central1")
	parts := strings.Split(location, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[:len(parts)-1], "-")
	}
	return location
}

func (h *GKEHandler) mapNodeStatus(nodePool *containerpb.NodePool) string {
	if nodePool == nil {
		return "unknown"
	}

	switch nodePool.Status {
	case containerpb.NodePool_RUNNING:
		return "running"
	case containerpb.NodePool_PROVISIONING:
		return "provisioning"
	case containerpb.NodePool_RUNNING_WITH_ERROR:
		return "error"
	case containerpb.NodePool_RECONCILING:
		return "reconciling"
	case containerpb.NodePool_STOPPING:
		return "stopping"
	case containerpb.NodePool_ERROR:
		return "error"
	default:
		return "unknown"
	}
}

func (h *GKEHandler) getMachineTypeFromNodePool(nodePool *containerpb.NodePool) string {
	if nodePool.Config != nil {
		return nodePool.Config.MachineType
	}
	return ""
}

func (h *GKEHandler) getDiskSizeFromNodePool(nodePool *containerpb.NodePool) int32 {
	if nodePool.Config != nil {
		return nodePool.Config.DiskSizeGb
	}
	return 0
}

func (h *GKEHandler) getPreemptibleFromNodePool(nodePool *containerpb.NodePool) bool {
	if nodePool.Config != nil {
		return nodePool.Config.Preemptible
	}
	return false
}

func (h *GKEHandler) buildNodeMetadata(cluster *containerpb.Cluster, nodePool *containerpb.NodePool, nodeName string) map[string]any {
	metadata := map[string]any{
		"cluster_name":   cluster.Name,
		"node_name":      nodeName,
		"cluster_status": cluster.Status,
		"location":       cluster.Location,
		"zone":           cluster.Zone,
		"endpoint":       cluster.Endpoint,
		"cluster_version": cluster.CurrentMasterVersion,
	}

	if nodePool != nil {
		metadata["node_pool_name"] = nodePool.Name
		metadata["node_pool_status"] = nodePool.Status
		metadata["initial_node_count"] = nodePool.InitialNodeCount
		metadata["node_pool_version"] = nodePool.Version

		if nodePool.Config != nil {
			metadata["machine_type"] = nodePool.Config.MachineType
			metadata["disk_size_gb"] = nodePool.Config.DiskSizeGb
			metadata["disk_type"] = nodePool.Config.DiskType
			metadata["image_type"] = nodePool.Config.ImageType
			metadata["preemptible"] = nodePool.Config.Preemptible
			metadata["local_ssd_count"] = nodePool.Config.LocalSsdCount

			// Add OAuth scopes
			if len(nodePool.Config.OauthScopes) > 0 {
				metadata["oauth_scopes"] = nodePool.Config.OauthScopes
			}

			// Add service account
			if nodePool.Config.ServiceAccount != "" {
				metadata["service_account"] = nodePool.Config.ServiceAccount
			}

			// Add labels
			if nodePool.Config.Labels != nil {
				metadata["node_labels"] = nodePool.Config.Labels
			}

			// Add taints
			if len(nodePool.Config.Taints) > 0 {
				taints := make([]map[string]any, 0, len(nodePool.Config.Taints))
				for _, taint := range nodePool.Config.Taints {
					taintInfo := map[string]any{
						"key":    taint.Key,
						"value":  taint.Value,
						"effect": taint.Effect,
					}
					taints = append(taints, taintInfo)
				}
				metadata["taints"] = taints
			}
		}

		// Add autoscaling info
		if nodePool.Autoscaling != nil {
			metadata["autoscaling"] = map[string]any{
				"enabled":       nodePool.Autoscaling.Enabled,
				"min_node_count": nodePool.Autoscaling.MinNodeCount,
				"max_node_count": nodePool.Autoscaling.MaxNodeCount,
			}
		}

		// Add management info
		if nodePool.Management != nil {
			metadata["management"] = map[string]any{
				"auto_upgrade": nodePool.Management.AutoUpgrade,
				"auto_repair":  nodePool.Management.AutoRepair,
			}
		}
	}

	// Add network info
	if cluster.Network != "" {
		metadata["network"] = cluster.Network
	}
	if cluster.Subnetwork != "" {
		metadata["subnetwork"] = cluster.Subnetwork
	}

	// Add addon info
	if cluster.AddonsConfig != nil {
		addons := make(map[string]any)
		if cluster.AddonsConfig.HttpLoadBalancing != nil {
			addons["http_load_balancing"] = cluster.AddonsConfig.HttpLoadBalancing.Disabled
		}
		if cluster.AddonsConfig.HorizontalPodAutoscaling != nil {
			addons["horizontal_pod_autoscaling"] = cluster.AddonsConfig.HorizontalPodAutoscaling.Disabled
		}
		if cluster.AddonsConfig.KubernetesDashboard != nil {
			addons["kubernetes_dashboard"] = cluster.AddonsConfig.KubernetesDashboard.Disabled
		}
		if cluster.AddonsConfig.NetworkPolicyConfig != nil {
			addons["network_policy"] = cluster.AddonsConfig.NetworkPolicyConfig.Disabled
		}
		metadata["addons"] = addons
	}

	return metadata
}

// Helper function for duration parameters
func getDurationParameter(parameters map[string]any, key string, defaultValue time.Duration) time.Duration {
	if val, exists := parameters[key]; exists {
		if d, ok := val.(time.Duration); ok {
			return d
		}
		if s, ok := val.(string); ok {
			if duration, err := time.ParseDuration(s); err == nil {
				return duration
			}
		}
		if i, ok := val.(int); ok {
			return time.Duration(i) * time.Second
		}
		if f, ok := val.(float64); ok {
			return time.Duration(f) * time.Second
		}
	}
	return defaultValue
}