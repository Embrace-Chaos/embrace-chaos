package git

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
	"github.com/embrace-chaos/internal/core/parsers"
	"github.com/embrace-chaos/internal/core/ports"
)

// GitOpsWorkflow handles GitOps-based experiment management
type GitOpsWorkflow struct {
	githubClient *GitHubClient
	parser       *parsers.YAMLParser
	store        ports.Store
	config       GitOpsConfig
}

// NewGitOpsWorkflow creates a new GitOps workflow manager
func NewGitOpsWorkflow(githubClient *GitHubClient, parser *parsers.YAMLParser, store ports.Store, config GitOpsConfig) *GitOpsWorkflow {
	return &GitOpsWorkflow{
		githubClient: githubClient,
		parser:       parser,
		store:        store,
		config:       config,
	}
}

// SyncExperiments syncs experiments from repository to database
func (g *GitOpsWorkflow) SyncExperiments(ctx context.Context, request *SyncRequest) (*SyncResult, error) {
	startTime := time.Now()
	result := &SyncResult{
		Repository:  request.Repository,
		Branch:      request.Branch,
		Path:        request.Path,
		StartedAt:   startTime,
		Errors:      make([]SyncError, 0),
		Metadata:    make(map[string]interface{}),
	}

	// Set defaults
	if request.Branch == "" {
		request.Branch = g.config.DefaultBranch
	}
	if request.Path == "" {
		request.Path = "."
	}

	// Parse repository owner and name
	repoParts := strings.Split(request.Repository, "/")
	if len(repoParts) != 2 {
		return nil, errors.NewValidationError("invalid repository format, expected 'owner/repo'")
	}
	owner, repo := repoParts[0], repoParts[1]

	// List experiment files in repository
	listRequest := &ListRequest{
		Owner:          owner,
		Repository:     repo,
		Path:           request.Path,
		Branch:         request.Branch,
		Pattern:        g.config.PathPattern,
		Page:           1,
		PageSize:       100, // Process in batches
		IncludeDetails: true,
	}

	experimentList, err := g.githubClient.ListExperiments(ctx, listRequest)
	if err != nil {
		return nil, errors.NewProviderError("github", "list_experiments", err)
	}

	result.TotalFiles = len(experimentList.Experiments)

	// Process each experiment file
	for _, expInfo := range experimentList.Experiments {
		if g.shouldSkipFile(expInfo.Path, request) {
			continue
		}

		syncErr := g.processSingleExperiment(ctx, owner, repo, &expInfo, request, result)
		if syncErr != nil {
			result.Errors = append(result.Errors, *syncErr)
			result.ErrorCount++
		}
		result.ProcessedFiles++
	}

	// Handle deletions if not dry run
	if !request.DryRun {
		deletedCount, err := g.handleDeletions(ctx, request, experimentList)
		if err != nil {
			result.Errors = append(result.Errors, SyncError{
				File:  "deletion_check",
				Error: err.Error(),
				Type:  "storage_error",
			})
			result.ErrorCount++
		} else {
			result.DeletedCount = deletedCount
		}
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	return result, nil
}

// ProcessWebhookEvent processes a webhook event and syncs affected experiments
func (g *GitOpsWorkflow) ProcessWebhookEvent(ctx context.Context, event *WebhookEvent) error {
	if !g.config.Enabled || !g.config.AutoSync {
		return nil // GitOps not enabled or auto-sync disabled
	}

	switch event.Type {
	case "push":
		return g.processPushEvent(ctx, event)
	case "pull_request":
		return g.processPullRequestEvent(ctx, event)
	default:
		// Ignore other event types
		return nil
	}
}

// CreatePullRequest creates a pull request for experiment changes
func (g *GitOpsWorkflow) CreatePullRequest(ctx context.Context, request *PRRequest) (*PRResponse, error) {
	// Parse repository owner and name
	repoParts := strings.Split(request.Repository, "/")
	if len(repoParts) != 2 {
		return nil, errors.NewValidationError("invalid repository format, expected 'owner/repo'")
	}
	owner, repo := repoParts[0], repoParts[1]

	// Create branch for changes
	branchName := fmt.Sprintf("%s-%d", g.config.ReviewBranch, time.Now().Unix())

	// Implementation would create branch, commit changes, and create PR
	// For now, return a mock response
	return &PRResponse{
		ID:         12345,
		Number:     42,
		Title:      request.Title,
		Body:       request.Body,
		State:      "open",
		HTMLURL:    fmt.Sprintf("https://github.com/%s/%s/pull/42", owner, repo),
		Head:       branchName,
		Base:       request.Base,
		Mergeable:  true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Repository: request.Repository,
	}, nil
}

// ValidateExperimentInRepo validates an experiment file in repository
func (g *GitOpsWorkflow) ValidateExperimentInRepo(ctx context.Context, owner, repo, path, branch string) (*ValidationResult, error) {
	// First validate file existence and format
	validateRequest := &ValidateRequest{
		Owner:      owner,
		Repository: repo,
		Path:       path,
		Branch:     branch,
	}

	result, err := g.githubClient.ValidateFile(ctx, validateRequest)
	if err != nil {
		return nil, err
	}

	if !result.Valid {
		return result, nil
	}

	// Fetch and parse content for deeper validation
	fetchRequest := &FetchRequest{
		Owner:      owner,
		Repository: repo,
		Path:       path,
		Branch:     branch,
	}

	experimentFile, err := g.githubClient.FetchExperiment(ctx, fetchRequest)
	if err != nil {
		return &ValidationResult{
			Valid:   false,
			Message: "Failed to fetch file content",
			Errors:  []string{err.Error()},
		}, nil
	}

	// Parse and validate experiment
	_, parseErr := g.parser.ParseExperiment(ctx, experimentFile.Content, nil)
	if parseErr != nil {
		return &ValidationResult{
			Valid:   false,
			Message: "Experiment parsing failed",
			Errors:  []string{parseErr.Error()},
		}, nil
	}

	result.Message = "Experiment is valid"
	return result, nil
}

// GetExperimentVersions gets version history for an experiment
func (g *GitOpsWorkflow) GetExperimentVersions(ctx context.Context, owner, repo, path string) (*VersionHistory, error) {
	// Implementation would get commit history for the file
	// For now, return a mock response
	return &VersionHistory{
		File: path,
		Versions: []VersionInfo{
			{
				Version:   "v1.0.0",
				SHA:       "abc123",
				Branch:    "main",
				Message:   "Initial experiment",
				IsLatest:  true,
				IsStable:  true,
				CreatedAt: time.Now().Add(-24 * time.Hour),
			},
		},
		Total: 1,
	}, nil
}

// Private methods

func (g *GitOpsWorkflow) shouldSkipFile(path string, request *SyncRequest) bool {
	// Check exclude patterns
	for _, pattern := range request.ExcludeFiles {
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
	}

	// Check GitOps exclude patterns
	for _, pattern := range g.config.ExcludePatterns {
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
	}

	// Check file patterns
	if len(g.config.FilePatterns) > 0 {
		matched := false
		for _, pattern := range g.config.FilePatterns {
			if m, _ := filepath.Match(pattern, filepath.Base(path)); m {
				matched = true
				break
			}
		}
		if !matched {
			return true
		}
	}

	return false
}

func (g *GitOpsWorkflow) processSingleExperiment(ctx context.Context, owner, repo string, expInfo *ExperimentInfo, request *SyncRequest, result *SyncResult) *SyncError {
	// Fetch experiment content
	fetchRequest := &FetchRequest{
		Owner:      owner,
		Repository: repo,
		Path:       expInfo.Path,
		Branch:     request.Branch,
	}

	experimentFile, err := g.githubClient.FetchExperiment(ctx, fetchRequest)
	if err != nil {
		return &SyncError{
			File:  expInfo.Path,
			Error: err.Error(),
			Type:  "fetch_error",
		}
	}

	// Parse experiment
	experiment, err := g.parser.ParseExperiment(ctx, experimentFile.Content, nil)
	if err != nil {
		return &SyncError{
			File:  expInfo.Path,
			Error: err.Error(),
			Type:  "parse_error",
		}
	}

	// Add metadata from Git
	if experiment.Metadata == nil {
		experiment.Metadata = make(map[string]interface{})
	}
	experiment.Metadata["git_repository"] = request.Repository
	experiment.Metadata["git_path"] = expInfo.Path
	experiment.Metadata["git_branch"] = request.Branch
	experiment.Metadata["git_sha"] = expInfo.SHA
	experiment.Metadata["git_commit_sha"] = expInfo.CommitSHA
	experiment.Metadata["git_last_modified"] = expInfo.LastModified
	experiment.Metadata["synced_at"] = time.Now()

	if !request.DryRun {
		// Check if experiment exists
		existing, err := g.store.GetExperimentByName(ctx, experiment.Name)
		if err != nil && !errors.IsNotFoundError(err) {
			return &SyncError{
				File:  expInfo.Path,
				Error: err.Error(),
				Type:  "storage_error",
			}
		}

		if existing != nil {
			// Update existing experiment
			experiment.ID = existing.ID
			experiment.CreatedAt = existing.CreatedAt
			experiment.CreatedBy = existing.CreatedBy
			experiment.Version = existing.Version + 1
			experiment.UpdatedAt = time.Now()

			if err := g.store.UpdateExperiment(ctx, experiment); err != nil {
				return &SyncError{
					File:  expInfo.Path,
					Error: err.Error(),
					Type:  "storage_error",
				}
			}
			result.UpdatedCount++
		} else {
			// Create new experiment
			experiment.CreatedAt = time.Now()
			experiment.UpdatedAt = time.Now()
			experiment.CreatedBy = "gitops-sync"
			experiment.Version = 1

			if err := g.store.SaveExperiment(ctx, experiment); err != nil {
				return &SyncError{
					File:  expInfo.Path,
					Error: err.Error(),
					Type:  "storage_error",
				}
			}
			result.CreatedCount++
		}
	}

	return nil
}

func (g *GitOpsWorkflow) handleDeletions(ctx context.Context, request *SyncRequest, experimentList *ExperimentList) (int, error) {
	// Get all experiments from database that were synced from this repository
	filters := ports.ExperimentFilters{
		// Implementation would filter by repository metadata
	}
	
	dbExperiments, _, err := g.store.ListExperiments(ctx, filters, ports.PaginationRequest{
		Page:     1,
		PageSize: 1000,
	})
	if err != nil {
		return 0, err
	}

	// Create map of current files
	currentFiles := make(map[string]bool)
	for _, exp := range experimentList.Experiments {
		currentFiles[exp.Path] = true
	}

	deletedCount := 0
	for _, dbExp := range dbExperiments {
		if metadata, ok := dbExp.Metadata["git_path"].(string); ok {
			if !currentFiles[metadata] {
				// File was deleted from repository, soft delete from database
				if err := g.store.DeleteExperiment(ctx, dbExp.ID); err != nil {
					return deletedCount, err
				}
				deletedCount++
			}
		}
	}

	return deletedCount, nil
}

func (g *GitOpsWorkflow) processPushEvent(ctx context.Context, event *WebhookEvent) error {
	// Filter files to only experiment files
	var experimentFiles []FileChangeInfo
	for _, file := range event.Files {
		if g.isExperimentFile(file.Path) {
			experimentFiles = append(experimentFiles, file)
		}
	}

	if len(experimentFiles) == 0 {
		return nil // No experiment files changed
	}

	// Create sync request
	syncRequest := &SyncRequest{
		Repository: event.Repository.FullName,
		Branch:     event.Branch,
		Path:       ".",
		Force:      false,
		DryRun:     false,
		Metadata: map[string]interface{}{
			"trigger":     "webhook",
			"webhook_event": "push",
			"commit_sha":  event.After,
		},
	}

	// Only sync changed files
	var changedPaths []string
	for _, file := range experimentFiles {
		changedPaths = append(changedPaths, file.Path)
	}
	syncRequest.ExcludeFiles = g.getExcludePatternForChangedFiles(changedPaths)

	// Execute sync
	_, err := g.SyncExperiments(ctx, syncRequest)
	return err
}

func (g *GitOpsWorkflow) processPullRequestEvent(ctx context.Context, event *WebhookEvent) error {
	// Handle pull request events if review workflow is enabled
	if !g.config.RequireReview {
		return nil
	}

	action := event.Action
	switch action {
	case "opened", "synchronize":
		// Validate experiments in PR
		return g.validatePullRequest(ctx, event)
	case "closed":
		// Handle merged PR
		if merged, ok := event.Metadata["pull_request"].(map[string]interface{})["merged"].(bool); ok && merged {
			return g.processPushEvent(ctx, event) // Treat as push event
		}
	}

	return nil
}

func (g *GitOpsWorkflow) validatePullRequest(ctx context.Context, event *WebhookEvent) error {
	// Implementation would validate all experiment files in the PR
	// For now, just return success
	return nil
}

func (g *GitOpsWorkflow) isExperimentFile(path string) bool {
	for _, format := range g.config.FilePatterns {
		if matched, _ := filepath.Match(format, filepath.Base(path)); matched {
			return true
		}
	}
	return false
}

func (g *GitOpsWorkflow) getExcludePatternForChangedFiles(changedPaths []string) []string {
	// Create exclude patterns for files that weren't changed
	// This is a simplified implementation
	var excludePatterns []string
	for _, path := range changedPaths {
		excludePatterns = append(excludePatterns, "!"+path)
	}
	return excludePatterns
}