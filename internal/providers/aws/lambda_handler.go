package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// LambdaHandler handles chaos operations for Lambda functions
type LambdaHandler struct {
	client *lambda.Client
	config LambdaConfig
}

// NewLambdaHandler creates a new Lambda handler
func NewLambdaHandler(client *lambda.Client, config LambdaConfig) *LambdaHandler {
	return &LambdaHandler{
		client: client,
		config: config,
	}
}

// DiscoverFunctions discovers Lambda functions based on criteria
func (h *LambdaHandler) DiscoverFunctions(ctx context.Context, criteria domain.DiscoveryCriteria) ([]domain.Target, error) {
	var targets []domain.Target

	// List Lambda functions
	input := &lambda.ListFunctionsInput{}

	result, err := h.client.ListFunctions(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "lambda_discovery", err)
	}

	// Convert functions to targets
	for _, function := range result.Functions {
		if h.shouldIncludeFunction(function, criteria) {
			target := h.functionToTarget(function)
			targets = append(targets, target)
		}
	}

	return targets, nil
}

// GetFunctionInfo gets detailed information about a Lambda function
func (h *LambdaHandler) GetFunctionInfo(ctx context.Context, target domain.Target) (*domain.TargetInfo, error) {
	input := &lambda.GetFunctionInput{
		FunctionName: aws.String(target.ResourceID),
	}

	result, err := h.client.GetFunction(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "lambda_info", err)
	}

	if result.Configuration == nil {
		return nil, errors.NewValidationError("Lambda function not found: %s", target.ResourceID)
	}

	function := *result.Configuration
	
	info := &domain.TargetInfo{
		ID:          target.ID,
		ResourceID:  target.ResourceID,
		Name:        target.Name,
		Type:        target.Type,
		Provider:    target.Provider,
		Region:      target.Region,
		Tags:        target.Tags,
		Status:      string(function.State),
		Metadata:    h.buildFunctionMetadata(function, result.Code),
		LastUpdated: time.Now(),
	}

	return info, nil
}

// ExecuteAction executes a chaos action on Lambda functions
func (h *LambdaHandler) ExecuteAction(ctx context.Context, target domain.Target, action string, parameters map[string]any, dryRun bool) (map[string]any, error) {
	metadata := make(map[string]any)
	metadata["function_name"] = target.ResourceID
	metadata["action"] = action
	metadata["dry_run"] = dryRun

	switch action {
	case "invoke_function":
		return h.invokeFunction(ctx, target, parameters, dryRun)
	case "update_function_configuration":
		return h.updateFunctionConfiguration(ctx, target, parameters, dryRun)
	case "add_permission":
		return h.addPermission(ctx, target, parameters, dryRun)
	case "remove_permission":
		return h.removePermission(ctx, target, parameters, dryRun)
	case "update_function_code":
		return h.updateFunctionCode(ctx, target, parameters, dryRun)
	case "put_provisioned_concurrency":
		return h.putProvisionedConcurrency(ctx, target, parameters, dryRun)
	case "delete_provisioned_concurrency":
		return h.deleteProvisionedConcurrency(ctx, target, parameters, dryRun)
	default:
		return nil, errors.NewValidationError("unsupported Lambda action: %s", action)
	}
}

// Private methods

func (h *LambdaHandler) invokeFunction(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	invocationType := getStringParameter(parameters, "invocation_type", "RequestResponse")
	logType := getStringParameter(parameters, "log_type", "None")
	qualifier := getStringParameter(parameters, "qualifier", "$LATEST")
	
	// Get payload from parameters
	var payload []byte
	if payloadParam, exists := parameters["payload"]; exists {
		if payloadStr, ok := payloadParam.(string); ok {
			payload = []byte(payloadStr)
		} else {
			// Try to marshal as JSON
			payloadBytes, err := json.Marshal(payloadParam)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal payload: %w", err)
			}
			payload = payloadBytes
		}
	} else {
		// Default chaos payload
		chaosPayload := map[string]any{
			"chaos_experiment": true,
			"timestamp":        time.Now().Unix(),
			"source":           "embrace-chaos",
		}
		payloadBytes, _ := json.Marshal(chaosPayload)
		payload = payloadBytes
	}

	metadata := map[string]any{
		"action":          "invoke_function",
		"function_name":   target.ResourceID,
		"invocation_type": invocationType,
		"log_type":        logType,
		"qualifier":       qualifier,
		"payload_size":    len(payload),
		"dry_run":         dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	// Create invoke context with timeout
	invokeCtx, cancel := context.WithTimeout(ctx, h.config.InvocationTimeout)
	defer cancel()

	input := &lambda.InvokeInput{
		FunctionName:   aws.String(target.ResourceID),
		InvocationType: types.InvocationType(invocationType),
		LogType:        types.LogType(logType),
		Payload:        payload,
		Qualifier:      aws.String(qualifier),
	}

	result, err := h.client.Invoke(invokeCtx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "lambda_invoke", err)
	}

	metadata["status_code"] = result.StatusCode
	metadata["executed_version"] = aws.ToString(result.ExecutedVersion)
	
	if result.FunctionError != nil {
		metadata["function_error"] = aws.ToString(result.FunctionError)
	}
	
	if result.LogResult != nil {
		metadata["log_result"] = aws.ToString(result.LogResult)
	}
	
	if result.Payload != nil {
		metadata["response_payload_size"] = len(result.Payload)
		// Store first 1KB of response payload for debugging
		maxPayloadLog := 1024
		if len(result.Payload) > maxPayloadLog {
			metadata["response_payload_preview"] = string(result.Payload[:maxPayloadLog])
		} else {
			metadata["response_payload"] = string(result.Payload)
		}
	}

	return metadata, nil
}

func (h *LambdaHandler) updateFunctionConfiguration(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	timeout := getIntParameter(parameters, "timeout", 0)
	memorySize := getIntParameter(parameters, "memory_size", 0)
	description := getStringParameter(parameters, "description", "")

	metadata := map[string]any{
		"action":        "update_function_configuration",
		"function_name": target.ResourceID,
		"dry_run":       dryRun,
	}

	if timeout > 0 {
		metadata["new_timeout"] = timeout
	}
	if memorySize > 0 {
		metadata["new_memory_size"] = memorySize
	}
	if description != "" {
		metadata["new_description"] = description
	}

	if dryRun {
		return metadata, nil
	}

	input := &lambda.UpdateFunctionConfigurationInput{
		FunctionName: aws.String(target.ResourceID),
	}

	if timeout > 0 {
		input.Timeout = aws.Int32(int32(timeout))
	}
	if memorySize > 0 {
		input.MemorySize = aws.Int32(int32(memorySize))
	}
	if description != "" {
		input.Description = aws.String(description)
	}

	result, err := h.client.UpdateFunctionConfiguration(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "lambda_update_config", err)
	}

	metadata["function_arn"] = aws.ToString(result.FunctionArn)
	metadata["state"] = string(result.State)
	metadata["last_modified"] = aws.ToString(result.LastModified)
	metadata["version"] = aws.ToString(result.Version)

	return metadata, nil
}

func (h *LambdaHandler) addPermission(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	statementId := getStringParameter(parameters, "statement_id", "")
	principal := getStringParameter(parameters, "principal", "")
	action := getStringParameter(parameters, "action", "lambda:InvokeFunction")
	sourceArn := getStringParameter(parameters, "source_arn", "")

	if statementId == "" {
		statementId = fmt.Sprintf("chaos-experiment-%d", time.Now().Unix())
	}

	metadata := map[string]any{
		"action":        "add_permission",
		"function_name": target.ResourceID,
		"statement_id":  statementId,
		"principal":     principal,
		"action":        action,
		"dry_run":       dryRun,
	}

	if sourceArn != "" {
		metadata["source_arn"] = sourceArn
	}

	if dryRun {
		return metadata, nil
	}

	if principal == "" {
		return nil, errors.NewValidationError("principal parameter is required for add_permission action")
	}

	input := &lambda.AddPermissionInput{
		FunctionName: aws.String(target.ResourceID),
		StatementId:  aws.String(statementId),
		Principal:    aws.String(principal),
		Action:       aws.String(action),
	}

	if sourceArn != "" {
		input.SourceArn = aws.String(sourceArn)
	}

	result, err := h.client.AddPermission(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "lambda_add_permission", err)
	}

	if result.Statement != nil {
		metadata["statement"] = aws.ToString(result.Statement)
	}

	return metadata, nil
}

func (h *LambdaHandler) removePermission(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	statementId := getStringParameter(parameters, "statement_id", "")
	qualifier := getStringParameter(parameters, "qualifier", "")

	metadata := map[string]any{
		"action":        "remove_permission",
		"function_name": target.ResourceID,
		"statement_id":  statementId,
		"dry_run":       dryRun,
	}

	if qualifier != "" {
		metadata["qualifier"] = qualifier
	}

	if dryRun {
		return metadata, nil
	}

	if statementId == "" {
		return nil, errors.NewValidationError("statement_id parameter is required for remove_permission action")
	}

	input := &lambda.RemovePermissionInput{
		FunctionName: aws.String(target.ResourceID),
		StatementId:  aws.String(statementId),
	}

	if qualifier != "" {
		input.Qualifier = aws.String(qualifier)
	}

	_, err := h.client.RemovePermission(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "lambda_remove_permission", err)
	}

	return metadata, nil
}

func (h *LambdaHandler) updateFunctionCode(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	zipFile := getStringParameter(parameters, "zip_file", "")
	s3Bucket := getStringParameter(parameters, "s3_bucket", "")
	s3Key := getStringParameter(parameters, "s3_key", "")
	s3ObjectVersion := getStringParameter(parameters, "s3_object_version", "")
	imageUri := getStringParameter(parameters, "image_uri", "")

	metadata := map[string]any{
		"action":        "update_function_code",
		"function_name": target.ResourceID,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	input := &lambda.UpdateFunctionCodeInput{
		FunctionName: aws.String(target.ResourceID),
	}

	// Set the code source based on parameters
	if zipFile != "" {
		input.ZipFile = []byte(zipFile)
		metadata["code_source"] = "zip_file"
	} else if s3Bucket != "" && s3Key != "" {
		input.S3Bucket = aws.String(s3Bucket)
		input.S3Key = aws.String(s3Key)
		metadata["code_source"] = "s3"
		metadata["s3_bucket"] = s3Bucket
		metadata["s3_key"] = s3Key
		if s3ObjectVersion != "" {
			input.S3ObjectVersion = aws.String(s3ObjectVersion)
			metadata["s3_object_version"] = s3ObjectVersion
		}
	} else if imageUri != "" {
		input.ImageUri = aws.String(imageUri)
		metadata["code_source"] = "container_image"
		metadata["image_uri"] = imageUri
	} else {
		return nil, errors.NewValidationError("one of zip_file, s3_bucket+s3_key, or image_uri must be provided")
	}

	result, err := h.client.UpdateFunctionCode(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "lambda_update_code", err)
	}

	metadata["function_arn"] = aws.ToString(result.FunctionArn)
	metadata["state"] = string(result.State)
	metadata["last_modified"] = aws.ToString(result.LastModified)
	metadata["version"] = aws.ToString(result.Version)
	metadata["code_sha256"] = aws.ToString(result.CodeSha256)

	return metadata, nil
}

func (h *LambdaHandler) putProvisionedConcurrency(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	provisionedConcurrency := getIntParameter(parameters, "provisioned_concurrency", 0)
	qualifier := getStringParameter(parameters, "qualifier", "$LATEST")

	metadata := map[string]any{
		"action":                  "put_provisioned_concurrency",
		"function_name":           target.ResourceID,
		"provisioned_concurrency": provisionedConcurrency,
		"qualifier":               qualifier,
		"dry_run":                 dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	if provisionedConcurrency <= 0 {
		return nil, errors.NewValidationError("provisioned_concurrency must be greater than 0")
	}

	input := &lambda.PutProvisionedConcurrencyConfigInput{
		FunctionName:                 aws.String(target.ResourceID),
		ProvisionedConcurrencyAmount: aws.Int32(int32(provisionedConcurrency)),
		Qualifier:                    aws.String(qualifier),
	}

	result, err := h.client.PutProvisionedConcurrencyConfig(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "lambda_put_provisioned_concurrency", err)
	}

	metadata["requested_concurrency"] = result.RequestedProvisionedConcurrencyAmount
	metadata["available_concurrency"] = result.AvailableProvisionedConcurrencyAmount
	metadata["allocated_concurrency"] = result.AllocatedProvisionedConcurrencyAmount
	metadata["status"] = string(result.Status)

	return metadata, nil
}

func (h *LambdaHandler) deleteProvisionedConcurrency(ctx context.Context, target domain.Target, parameters map[string]any, dryRun bool) (map[string]any, error) {
	qualifier := getStringParameter(parameters, "qualifier", "$LATEST")

	metadata := map[string]any{
		"action":        "delete_provisioned_concurrency",
		"function_name": target.ResourceID,
		"qualifier":     qualifier,
		"dry_run":       dryRun,
	}

	if dryRun {
		return metadata, nil
	}

	input := &lambda.DeleteProvisionedConcurrencyConfigInput{
		FunctionName: aws.String(target.ResourceID),
		Qualifier:    aws.String(qualifier),
	}

	_, err := h.client.DeleteProvisionedConcurrencyConfig(ctx, input)
	if err != nil {
		return nil, errors.NewProviderError("aws", "lambda_delete_provisioned_concurrency", err)
	}

	return metadata, nil
}

func (h *LambdaHandler) shouldIncludeFunction(function types.FunctionConfiguration, criteria domain.DiscoveryCriteria) bool {
	functionName := aws.ToString(function.FunctionName)
	runtime := string(function.Runtime)

	// Check allowed runtimes
	if len(h.config.AllowedRuntimes) > 0 {
		allowed := false
		for _, allowedRuntime := range h.config.AllowedRuntimes {
			if runtime == allowedRuntime {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	// Check forbidden functions
	for _, forbiddenFunction := range h.config.ForbiddenFunctions {
		if functionName == forbiddenFunction {
			return false
		}
	}

	// Get function tags to check required tags
	// Note: We would need to call ListTags API here in a real implementation
	// For now, we'll skip the tag check as it requires an additional API call
	// In production, you might want to batch these calls or cache tag information

	return true
}

func (h *LambdaHandler) functionToTarget(function types.FunctionConfiguration) domain.Target {
	functionName := aws.ToString(function.FunctionName)
	
	target := domain.Target{
		ID:         fmt.Sprintf("aws-lambda-%s", functionName),
		ResourceID: functionName,
		Name:       functionName,
		Type:       domain.TargetTypeLambdaFunction,
		Provider:   "aws",
		Region:     h.extractRegionFromArn(aws.ToString(function.FunctionArn)),
		Tags:       make(map[string]string), // Would be populated from ListTags API call
		Metadata: map[string]any{
			"function_name":    functionName,
			"function_arn":     aws.ToString(function.FunctionArn),
			"runtime":          string(function.Runtime),
			"handler":          aws.ToString(function.Handler),
			"code_size":        function.CodeSize,
			"description":      aws.ToString(function.Description),
			"timeout":          function.Timeout,
			"memory_size":      function.MemorySize,
			"last_modified":    aws.ToString(function.LastModified),
			"code_sha256":      aws.ToString(function.CodeSha256),
			"version":          aws.ToString(function.Version),
			"state":            string(function.State),
			"state_reason":     aws.ToString(function.StateReason),
			"last_update_status": string(function.LastUpdateStatus),
			"package_type":     string(function.PackageType),
		},
	}

	return target
}

func (h *LambdaHandler) extractRegionFromArn(arn string) string {
	// Extract region from ARN (arn:aws:lambda:region:account:function:function-name)
	parts := strings.Split(arn, ":")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

func (h *LambdaHandler) buildFunctionMetadata(function types.FunctionConfiguration, code *types.FunctionCodeLocation) map[string]any {
	metadata := map[string]any{
		"function_name":         aws.ToString(function.FunctionName),
		"function_arn":          aws.ToString(function.FunctionArn),
		"runtime":               string(function.Runtime),
		"role":                  aws.ToString(function.Role),
		"handler":               aws.ToString(function.Handler),
		"code_size":             function.CodeSize,
		"description":           aws.ToString(function.Description),
		"timeout":               function.Timeout,
		"memory_size":           function.MemorySize,
		"last_modified":         aws.ToString(function.LastModified),
		"code_sha256":           aws.ToString(function.CodeSha256),
		"version":               aws.ToString(function.Version),
		"state":                 string(function.State),
		"state_reason":          aws.ToString(function.StateReason),
		"state_reason_code":     string(function.StateReasonCode),
		"last_update_status":    string(function.LastUpdateStatus),
		"last_update_status_reason": aws.ToString(function.LastUpdateStatusReason),
		"package_type":          string(function.PackageType),
		"architecture":          function.Architectures,
	}

	// Add VPC configuration if present
	if function.VpcConfig != nil {
		vpcConfig := map[string]any{
			"subnet_ids":         function.VpcConfig.SubnetIds,
			"security_group_ids": function.VpcConfig.SecurityGroupIds,
			"vpc_id":             aws.ToString(function.VpcConfig.VpcId),
		}
		metadata["vpc_config"] = vpcConfig
	}

	// Add environment variables if present
	if function.Environment != nil && function.Environment.Variables != nil {
		// Don't include actual values for security, just keys
		envKeys := make([]string, 0, len(function.Environment.Variables))
		for key := range function.Environment.Variables {
			envKeys = append(envKeys, key)
		}
		metadata["environment_variables"] = envKeys
		if function.Environment.Error != nil {
			metadata["environment_error"] = map[string]any{
				"error_code": aws.ToString(function.Environment.Error.ErrorCode),
				"message":    aws.ToString(function.Environment.Error.Message),
			}
		}
	}

	// Add dead letter config if present
	if function.DeadLetterConfig != nil && function.DeadLetterConfig.TargetArn != nil {
		metadata["dead_letter_config"] = map[string]any{
			"target_arn": aws.ToString(function.DeadLetterConfig.TargetArn),
		}
	}

	// Add KMS key ARN if present
	if function.KMSKeyArn != nil {
		metadata["kms_key_arn"] = aws.ToString(function.KMSKeyArn)
	}

	// Add tracing config if present
	if function.TracingConfig != nil {
		metadata["tracing_config"] = map[string]any{
			"mode": string(function.TracingConfig.Mode),
		}
	}

	// Add layers if present
	if len(function.Layers) > 0 {
		layers := make([]map[string]any, 0, len(function.Layers))
		for _, layer := range function.Layers {
			layerInfo := map[string]any{
				"arn":       aws.ToString(layer.Arn),
				"code_size": layer.CodeSize,
			}
			if layer.SigningProfileVersionArn != nil {
				layerInfo["signing_profile_version_arn"] = aws.ToString(layer.SigningProfileVersionArn)
			}
			if layer.SigningJobArn != nil {
				layerInfo["signing_job_arn"] = aws.ToString(layer.SigningJobArn)
			}
			layers = append(layers, layerInfo)
		}
		metadata["layers"] = layers
	}

	// Add code location information if available
	if code != nil {
		codeInfo := map[string]any{}
		if code.RepositoryType != nil {
			codeInfo["repository_type"] = aws.ToString(code.RepositoryType)
		}
		if code.Location != nil {
			codeInfo["location"] = aws.ToString(code.Location)
		}
		if code.ImageUri != nil {
			codeInfo["image_uri"] = aws.ToString(code.ImageUri)
		}
		if code.ResolvedImageUri != nil {
			codeInfo["resolved_image_uri"] = aws.ToString(code.ResolvedImageUri)
		}
		metadata["code"] = codeInfo
	}

	return metadata
}