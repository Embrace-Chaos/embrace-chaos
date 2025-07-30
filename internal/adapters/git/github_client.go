package git

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-github/v56/github"
	"golang.org/x/oauth2"

	"github.com/embrace-chaos/internal/core/domain"
	"github.com/embrace-chaos/internal/core/errors"
)

// GitHubClient provides integration with GitHub repositories
type GitHubClient struct {
	client   *github.Client
	config   GitHubConfig
	webhooks WebhookManager
}

// GitHubConfig contains GitHub client configuration
type GitHubConfig struct {
	Token             string            `json:"token"`
	AppID             int64             `json:"app_id,omitempty"`
	PrivateKey        string            `json:"private_key,omitempty"`
	WebhookSecret     string            `json:"webhook_secret"`
	DefaultBranch     string            `json:"default_branch"`
	AllowedOrgs       []string          `json:"allowed_orgs,omitempty"`
	AllowedRepos      []string          `json:"allowed_repos,omitempty"`
	MaxFileSizeMB     int               `json:"max_file_size_mb"`
	SupportedFormats  []string          `json:"supported_formats"`
	RateLimitBurst    int               `json:"rate_limit_burst"`
	RateLimitRefill   time.Duration     `json:"rate_limit_refill"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// NewGitHubClient creates a new GitHub client
func NewGitHubClient(config GitHubConfig) (*GitHubClient, error) {
	var client *github.Client

	if config.Token != "" {
		// Token-based authentication
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: config.Token},
		)
		tc := oauth2.NewClient(context.Background(), ts)
		client = github.NewClient(tc)
	} else if config.AppID > 0 && config.PrivateKey != "" {
		// GitHub App authentication
		// Implementation would use JWT-based authentication
		return nil, errors.NewValidationError("GitHub App authentication not yet implemented")
	} else {
		return nil, errors.NewValidationError("either token or GitHub App credentials must be provided")
	}

	// Set default values
	if config.DefaultBranch == "" {
		config.DefaultBranch = "main"
	}
	if config.MaxFileSizeMB == 0 {
		config.MaxFileSizeMB = 5 // 5MB default
	}
	if len(config.SupportedFormats) == 0 {
		config.SupportedFormats = []string{".yaml", ".yml", ".json"}
	}

	return &GitHubClient{
		client:   client,
		config:   config,
		webhooks: NewWebhookManager(config.WebhookSecret),
	}, nil
}

// FetchExperiment fetches an experiment file from a GitHub repository
func (g *GitHubClient) FetchExperiment(ctx context.Context, request *FetchRequest) (*ExperimentFile, error) {
	// Validate repository access
	if err := g.validateRepositoryAccess(request.Owner, request.Repository); err != nil {
		return nil, err
	}

	// Get file content
	file, _, resp, err := g.client.Repositories.GetContents(
		ctx,
		request.Owner,
		request.Repository,
		request.Path,
		&github.RepositoryContentGetOptions{
			Ref: request.Branch,
		},
	)

	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return nil, errors.NewNotFoundError("file not found: %s/%s/%s", request.Owner, request.Repository, request.Path)
		}
		return nil, errors.NewProviderError("github", "fetch_file", err)
	}

	if file == nil {
		return nil, errors.NewValidationError("file is a directory, not a file")
	}

	// Check file size
	if file.GetSize() > int64(g.config.MaxFileSizeMB*1024*1024) {
		return nil, errors.NewValidationError("file size %d bytes exceeds maximum %d MB", file.GetSize(), g.config.MaxFileSizeMB)
	}

	// Check file format
	if !g.isSupportedFormat(request.Path) {
		return nil, errors.NewValidationError("unsupported file format: %s", request.Path)
	}

	// Decode content
	content, err := base64.StdEncoding.DecodeString(file.GetContent())
	if err != nil {
		return nil, errors.NewProviderError("github", "decode_content", err)
	}

	// Get commit information for the file
	commit, err := g.getFileCommit(ctx, request.Owner, request.Repository, request.Path, request.Branch)
	if err != nil {
		return nil, err
	}

	experimentFile := &ExperimentFile{
		Repository:  fmt.Sprintf("%s/%s", request.Owner, request.Repository),
		Path:        request.Path,
		Branch:      request.Branch,
		Content:     string(content),
		SHA:         file.GetSHA(),
		Size:        file.GetSize(),
		LastModified: commit.Author.GetDate().Time,
		CommitSHA:   commit.GetSHA(),
		CommitMessage: commit.GetMessage(),
		Author: AuthorInfo{
			Name:  commit.Author.GetName(),
			Email: commit.Author.GetEmail(),
			Date:  commit.Author.GetDate().Time,
		},
		Metadata: map[string]interface{}{
			"file_sha":       file.GetSHA(),
			"commit_sha":     commit.GetSHA(),
			"repository_url": fmt.Sprintf("https://github.com/%s/%s", request.Owner, request.Repository),
			"file_url":       file.GetHTMLURL(),
			"download_url":   file.GetDownloadURL(),
		},
	}

	return experimentFile, nil
}

// ListExperiments lists experiment files in a repository directory
func (g *GitHubClient) ListExperiments(ctx context.Context, request *ListRequest) (*ExperimentList, error) {
	// Validate repository access
	if err := g.validateRepositoryAccess(request.Owner, request.Repository); err != nil {
		return nil, err
	}

	// Get directory contents
	_, contents, resp, err := g.client.Repositories.GetContents(
		ctx,
		request.Owner,
		request.Repository,
		request.Path,
		&github.RepositoryContentGetOptions{
			Ref: request.Branch,
		},
	)

	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return nil, errors.NewNotFoundError("directory not found: %s/%s/%s", request.Owner, request.Repository, request.Path)
		}
		return nil, errors.NewProviderError("github", "list_files", err)
	}

	var experiments []ExperimentInfo
	for _, content := range contents {
		if content.GetType() == "file" && g.isSupportedFormat(content.GetName()) {
			// Apply filters
			if request.Pattern != "" && !g.matchesPattern(content.GetName(), request.Pattern) {
				continue
			}

			// Get additional file information
			experimentInfo := ExperimentInfo{
				Name:         content.GetName(),
				Path:         content.GetPath(),
				SHA:          content.GetSHA(),
				Size:         content.GetSize(),
				DownloadURL:  content.GetDownloadURL(),
				HTMLURL:      content.GetHTMLURL(),
				LastModified: time.Time{}, // Will be populated if needed
				Metadata: map[string]interface{}{
					"file_sha": content.GetSHA(),
					"type":     content.GetType(),
				},
			}

			// Get commit info if detailed information is requested
			if request.IncludeDetails {
				commit, err := g.getFileCommit(ctx, request.Owner, request.Repository, content.GetPath(), request.Branch)
				if err == nil {
					experimentInfo.LastModified = commit.Author.GetDate().Time
					experimentInfo.Author = AuthorInfo{
						Name:  commit.Author.GetName(),
						Email: commit.Author.GetEmail(),
						Date:  commit.Author.GetDate().Time,
					}
					experimentInfo.CommitSHA = commit.GetSHA()
					experimentInfo.CommitMessage = commit.GetMessage()
				}
			}

			experiments = append(experiments, experimentInfo)
		}
	}

	// Apply pagination
	start := (request.Page - 1) * request.PageSize
	end := start + request.PageSize
	if start > len(experiments) {
		start = len(experiments)
	}
	if end > len(experiments) {
		end = len(experiments)
	}

	paginatedExperiments := experiments[start:end]

	return &ExperimentList{
		Repository:  fmt.Sprintf("%s/%s", request.Owner, request.Repository),
		Path:        request.Path,
		Branch:      request.Branch,
		Experiments: paginatedExperiments,
		Pagination: PaginationInfo{
			Page:       request.Page,
			PageSize:   request.PageSize,
			Total:      len(experiments),
			TotalPages: (len(experiments) + request.PageSize - 1) / request.PageSize,
		},
		Metadata: map[string]interface{}{
			"repository_url": fmt.Sprintf("https://github.com/%s/%s", request.Owner, request.Repository),
			"fetched_at":     time.Now(),
		},
	}, nil
}

// WatchRepository sets up webhook monitoring for a repository
func (g *GitHubClient) WatchRepository(ctx context.Context, request *WatchRequest) (*WatchResponse, error) {
	// Validate repository access
	if err := g.validateRepositoryAccess(request.Owner, request.Repository); err != nil {
		return nil, err
	}

	// Check if webhook already exists
	hooks, _, err := g.client.Repositories.ListHooks(ctx, request.Owner, request.Repository, nil)
	if err != nil {
		return nil, errors.NewProviderError("github", "list_hooks", err)
	}

	var existingHook *github.Hook
	for _, hook := range hooks {
		if hook.Config["url"] == request.WebhookURL {
			existingHook = hook
			break
		}
	}

	if existingHook != nil {
		return &WatchResponse{
			HookID:       existingHook.GetID(),
			WebhookURL:   request.WebhookURL,
			Events:       request.Events,
			Active:       existingHook.GetActive(),
			Repository:   fmt.Sprintf("%s/%s", request.Owner, request.Repository),
			CreatedAt:    existingHook.GetCreatedAt().Time,
			UpdatedAt:    existingHook.GetUpdatedAt().Time,
		}, nil
	}

	// Create new webhook
	hook := &github.Hook{
		Name:   github.String("web"),
		Events: request.Events,
		Active: github.Bool(true),
		Config: map[string]interface{}{
			"url":          request.WebhookURL,
			"content_type": "json",
			"secret":       g.config.WebhookSecret,
			"insecure_ssl": "0",
		},
	}

	createdHook, _, err := g.client.Repositories.CreateHook(ctx, request.Owner, request.Repository, hook)
	if err != nil {
		return nil, errors.NewProviderError("github", "create_hook", err)
	}

	return &WatchResponse{
		HookID:       createdHook.GetID(),
		WebhookURL:   request.WebhookURL,
		Events:       request.Events,
		Active:       createdHook.GetActive(),
		Repository:   fmt.Sprintf("%s/%s", request.Owner, request.Repository),
		CreatedAt:    createdHook.GetCreatedAt().Time,
		UpdatedAt:    createdHook.GetUpdatedAt().Time,
	}, nil
}

// UnwatchRepository removes webhook monitoring for a repository
func (g *GitHubClient) UnwatchRepository(ctx context.Context, owner, repository string, hookID int64) error {
	if err := g.validateRepositoryAccess(owner, repository); err != nil {
		return err
	}

	_, err := g.client.Repositories.DeleteHook(ctx, owner, repository, hookID)
	if err != nil {
		return errors.NewProviderError("github", "delete_hook", err)
	}

	return nil
}

// ValidateFile validates an experiment file without fetching its content
func (g *GitHubClient) ValidateFile(ctx context.Context, request *ValidateRequest) (*ValidationResult, error) {
	// Validate repository access
	if err := g.validateRepositoryAccess(request.Owner, request.Repository); err != nil {
		return nil, err
	}

	// Get file metadata
	file, _, resp, err := g.client.Repositories.GetContents(
		ctx,
		request.Owner,
		request.Repository,
		request.Path,
		&github.RepositoryContentGetOptions{
			Ref: request.Branch,
		},
	)

	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return &ValidationResult{
				Valid:   false,
				Message: "File not found",
				Errors:  []string{"File does not exist in the repository"},
			}, nil
		}
		return nil, errors.NewProviderError("github", "validate_file", err)
	}

	if file == nil {
		return &ValidationResult{
			Valid:   false,
			Message: "Path is a directory, not a file",
			Errors:  []string{"The specified path points to a directory, not a file"},
		}, nil
	}

	var validationErrors []string
	var warnings []string

	// Check file size
	if file.GetSize() > int64(g.config.MaxFileSizeMB*1024*1024) {
		validationErrors = append(validationErrors, fmt.Sprintf("File size %d bytes exceeds maximum %d MB", file.GetSize(), g.config.MaxFileSizeMB))
	}

	// Check file format
	if !g.isSupportedFormat(request.Path) {
		validationErrors = append(validationErrors, fmt.Sprintf("Unsupported file format: %s", request.Path))
	}

	// Additional validations can be added here
	// For example, syntax validation by attempting to parse the content

	valid := len(validationErrors) == 0
	message := "File is valid"
	if !valid {
		message = "File validation failed"
	} else if len(warnings) > 0 {
		message = "File is valid with warnings"
	}

	return &ValidationResult{
		Valid:    valid,
		Message:  message,
		Errors:   validationErrors,
		Warnings: warnings,
		Metadata: map[string]interface{}{
			"file_size": file.GetSize(),
			"file_sha":  file.GetSHA(),
		},
	}, nil
}

// GetBranches lists all branches in a repository
func (g *GitHubClient) GetBranches(ctx context.Context, owner, repository string) ([]BranchInfo, error) {
	if err := g.validateRepositoryAccess(owner, repository); err != nil {
		return nil, err
	}

	branches, _, err := g.client.Repositories.ListBranches(ctx, owner, repository, nil)
	if err != nil {
		return nil, errors.NewProviderError("github", "list_branches", err)
	}

	var branchInfos []BranchInfo
	for _, branch := range branches {
		branchInfo := BranchInfo{
			Name:      branch.GetName(),
			SHA:       branch.GetCommit().GetSHA(),
			Protected: branch.GetProtected(),
		}

		// Get additional commit information
		if commit := branch.GetCommit(); commit != nil {
			branchInfo.LastCommit = CommitInfo{
				SHA:     commit.GetSHA(),
				Message: "", // Would need additional API call to get full commit info
				Author: AuthorInfo{
					Name: "",  // Would need additional API call
					Date: time.Time{}, // Would need additional API call
				},
			}
		}

		branchInfos = append(branchInfos, branchInfo)
	}

	return branchInfos, nil
}

// ProcessWebhook processes incoming webhook events
func (g *GitHubClient) ProcessWebhook(ctx context.Context, headers http.Header, payload []byte) (*WebhookEvent, error) {
	return g.webhooks.ProcessWebhook(ctx, headers, payload)
}

// Private helper methods

func (g *GitHubClient) validateRepositoryAccess(owner, repository string) error {
	// Check allowed organizations
	if len(g.config.AllowedOrgs) > 0 {
		allowed := false
		for _, org := range g.config.AllowedOrgs {
			if org == owner {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.NewValidationError("organization '%s' is not allowed", owner)
		}
	}

	// Check allowed repositories
	if len(g.config.AllowedRepos) > 0 {
		repoFullName := fmt.Sprintf("%s/%s", owner, repository)
		allowed := false
		for _, repo := range g.config.AllowedRepos {
			if repo == repoFullName {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.NewValidationError("repository '%s' is not allowed", repoFullName)
		}
	}

	return nil
}

func (g *GitHubClient) isSupportedFormat(filename string) bool {
	for _, format := range g.config.SupportedFormats {
		if strings.HasSuffix(strings.ToLower(filename), format) {
			return true
		}
	}
	return false
}

func (g *GitHubClient) matchesPattern(filename, pattern string) bool {
	// Simple pattern matching - could be enhanced with regex
	return strings.Contains(strings.ToLower(filename), strings.ToLower(pattern))
}

func (g *GitHubClient) getFileCommit(ctx context.Context, owner, repository, path, branch string) (*github.RepositoryCommit, error) {
	commits, _, err := g.client.Repositories.ListCommits(ctx, owner, repository, &github.CommitsListOptions{
		Path: path,
		SHA:  branch,
		ListOptions: github.ListOptions{
			PerPage: 1,
		},
	})

	if err != nil {
		return nil, errors.NewProviderError("github", "get_file_commit", err)
	}

	if len(commits) == 0 {
		return nil, errors.NewNotFoundError("no commits found for file: %s", path)
	}

	return commits[0], nil
}