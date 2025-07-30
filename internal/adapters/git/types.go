package git

import (
	"time"
)

// FetchRequest represents a request to fetch an experiment file
type FetchRequest struct {
	Owner      string `json:"owner"`
	Repository string `json:"repository"`
	Path       string `json:"path"`
	Branch     string `json:"branch,omitempty"`
}

// ListRequest represents a request to list experiment files
type ListRequest struct {
	Owner          string `json:"owner"`
	Repository     string `json:"repository"`
	Path           string `json:"path,omitempty"`
	Branch         string `json:"branch,omitempty"`
	Pattern        string `json:"pattern,omitempty"`
	Page           int    `json:"page"`
	PageSize       int    `json:"page_size"`
	IncludeDetails bool   `json:"include_details,omitempty"`
}

// WatchRequest represents a request to watch a repository
type WatchRequest struct {
	Owner      string   `json:"owner"`
	Repository string   `json:"repository"`
	WebhookURL string   `json:"webhook_url"`
	Events     []string `json:"events"`
	Secret     string   `json:"secret,omitempty"`
}

// ValidateRequest represents a request to validate a file
type ValidateRequest struct {
	Owner      string `json:"owner"`
	Repository string `json:"repository"`
	Path       string `json:"path"`
	Branch     string `json:"branch,omitempty"`
}

// ExperimentFile represents an experiment file from GitHub
type ExperimentFile struct {
	Repository    string                 `json:"repository"`
	Path          string                 `json:"path"`
	Branch        string                 `json:"branch"`
	Content       string                 `json:"content"`
	SHA           string                 `json:"sha"`
	Size          int64                  `json:"size"`
	LastModified  time.Time              `json:"last_modified"`
	CommitSHA     string                 `json:"commit_sha"`
	CommitMessage string                 `json:"commit_message"`
	Author        AuthorInfo             `json:"author"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ExperimentInfo represents metadata about an experiment file
type ExperimentInfo struct {
	Name          string                 `json:"name"`
	Path          string                 `json:"path"`
	SHA           string                 `json:"sha"`
	Size          int64                  `json:"size"`
	DownloadURL   string                 `json:"download_url"`
	HTMLURL       string                 `json:"html_url"`
	LastModified  time.Time              `json:"last_modified"`
	CommitSHA     string                 `json:"commit_sha,omitempty"`
	CommitMessage string                 `json:"commit_message,omitempty"`
	Author        AuthorInfo             `json:"author,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ExperimentList represents a list of experiment files
type ExperimentList struct {
	Repository  string                 `json:"repository"`
	Path        string                 `json:"path"`
	Branch      string                 `json:"branch"`
	Experiments []ExperimentInfo       `json:"experiments"`
	Pagination  PaginationInfo         `json:"pagination"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AuthorInfo represents author information
type AuthorInfo struct {
	Name  string    `json:"name"`
	Email string    `json:"email"`
	Date  time.Time `json:"date"`
}

// PaginationInfo represents pagination information
type PaginationInfo struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// WatchResponse represents the response from watching a repository
type WatchResponse struct {
	HookID     int64     `json:"hook_id"`
	WebhookURL string    `json:"webhook_url"`
	Events     []string  `json:"events"`
	Active     bool      `json:"active"`
	Repository string    `json:"repository"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ValidationResult represents the result of file validation
type ValidationResult struct {
	Valid    bool                   `json:"valid"`
	Message  string                 `json:"message"`
	Errors   []string               `json:"errors,omitempty"`
	Warnings []string               `json:"warnings,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// BranchInfo represents information about a git branch
type BranchInfo struct {
	Name       string     `json:"name"`
	SHA        string     `json:"sha"`
	Protected  bool       `json:"protected"`
	LastCommit CommitInfo `json:"last_commit"`
}

// CommitInfo represents information about a git commit
type CommitInfo struct {
	SHA     string     `json:"sha"`
	Message string     `json:"message"`
	Author  AuthorInfo `json:"author"`
	Date    time.Time  `json:"date"`
}

// WebhookEvent represents a processed webhook event
type WebhookEvent struct {
	Type       string                 `json:"type"`
	Action     string                 `json:"action,omitempty"`
	Repository RepositoryInfo         `json:"repository"`
	Commits    []CommitInfo           `json:"commits,omitempty"`
	Branch     string                 `json:"branch,omitempty"`
	Ref        string                 `json:"ref,omitempty"`
	Before     string                 `json:"before,omitempty"`
	After      string                 `json:"after,omitempty"`
	Files      []FileChangeInfo       `json:"files,omitempty"`
	Sender     UserInfo               `json:"sender"`
	Timestamp  time.Time              `json:"timestamp"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// RepositoryInfo represents repository information from webhook
type RepositoryInfo struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Owner    string `json:"owner"`
	Private  bool   `json:"private"`
	HTMLURL  string `json:"html_url"`
	CloneURL string `json:"clone_url"`
}

// UserInfo represents user information from webhook
type UserInfo struct {
	ID       int64  `json:"id"`
	Login    string `json:"login"`
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	HTMLURL  string `json:"html_url"`
	AvatarURL string `json:"avatar_url"`
}

// FileChangeInfo represents information about changed files
type FileChangeInfo struct {
	Path     string `json:"path"`
	Status   string `json:"status"` // added, modified, removed
	Filename string `json:"filename"`
	SHA      string `json:"sha,omitempty"`
}

// GitOpsConfig represents GitOps workflow configuration
type GitOpsConfig struct {
	Enabled           bool              `json:"enabled"`
	AutoSync          bool              `json:"auto_sync"`
	SyncInterval      time.Duration     `json:"sync_interval"`
	RequireReview     bool              `json:"require_review"`
	ReviewBranch      string            `json:"review_branch"`
	DefaultBranch     string            `json:"default_branch"`
	PathPattern       string            `json:"path_pattern"`
	FilePatterns      []string          `json:"file_patterns"`
	ExcludePatterns   []string          `json:"exclude_patterns"`
	ConflictResolution string           `json:"conflict_resolution"` // merge, overwrite, manual
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// SyncRequest represents a request to sync experiments from repository
type SyncRequest struct {
	Repository    string            `json:"repository"`
	Branch        string            `json:"branch,omitempty"`
	Path          string            `json:"path,omitempty"`
	Force         bool              `json:"force,omitempty"`
	DryRun        bool              `json:"dry_run,omitempty"`
	FilterLabels  map[string]string `json:"filter_labels,omitempty"`
	ExcludeFiles  []string          `json:"exclude_files,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// SyncResult represents the result of a sync operation
type SyncResult struct {
	Repository     string                 `json:"repository"`
	Branch         string                 `json:"branch"`
	Path           string                 `json:"path"`
	TotalFiles     int                    `json:"total_files"`
	ProcessedFiles int                    `json:"processed_files"`
	CreatedCount   int                    `json:"created_count"`
	UpdatedCount   int                    `json:"updated_count"`
	DeletedCount   int                    `json:"deleted_count"`
	ErrorCount     int                    `json:"error_count"`
	Errors         []SyncError            `json:"errors,omitempty"`
	Duration       time.Duration          `json:"duration"`
	StartedAt      time.Time              `json:"started_at"`
	CompletedAt    time.Time              `json:"completed_at"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// SyncError represents an error during sync operation
type SyncError struct {
	File    string    `json:"file"`
	Error   string    `json:"error"`
	Type    string    `json:"type"` // parse_error, validation_error, storage_error
	Line    int       `json:"line,omitempty"`
	Column  int       `json:"column,omitempty"`
	Context string    `json:"context,omitempty"`
}

// PRConfig represents pull request configuration
type PRConfig struct {
	Enabled         bool              `json:"enabled"`
	AutoCreate      bool              `json:"auto_create"`
	BaseBranch      string            `json:"base_branch"`
	BranchPrefix    string            `json:"branch_prefix"`
	TitleTemplate   string            `json:"title_template"`
	BodyTemplate    string            `json:"body_template"`
	RequireReview   bool              `json:"require_review"`
	Reviewers       []string          `json:"reviewers,omitempty"`
	TeamReviewers   []string          `json:"team_reviewers,omitempty"`
	Labels          []string          `json:"labels,omitempty"`
	Assignees       []string          `json:"assignees,omitempty"`
	AutoMerge       bool              `json:"auto_merge"`
	DeleteBranch    bool              `json:"delete_branch"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// PRRequest represents a pull request creation request
type PRRequest struct {
	Repository    string                 `json:"repository"`
	Title         string                 `json:"title"`
	Body          string                 `json:"body"`
	Head          string                 `json:"head"` // source branch
	Base          string                 `json:"base"` // target branch
	Changes       []FileChange           `json:"changes"`
	Reviewers     []string               `json:"reviewers,omitempty"`
	TeamReviewers []string               `json:"team_reviewers,omitempty"`
	Labels        []string               `json:"labels,omitempty"`
	Assignees     []string               `json:"assignees,omitempty"`
	Draft         bool                   `json:"draft,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// FileChange represents a file change in a pull request
type FileChange struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Operation string `json:"operation"` // create, update, delete
	Message   string `json:"message,omitempty"`
}

// PRResponse represents the response from creating a pull request
type PRResponse struct {
	ID         int64     `json:"id"`
	Number     int       `json:"number"`
	Title      string    `json:"title"`
	Body       string    `json:"body"`
	State      string    `json:"state"`
	HTMLURL    string    `json:"html_url"`
	Head       string    `json:"head"`
	Base       string    `json:"base"`
	Mergeable  bool      `json:"mergeable"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Repository string    `json:"repository"`
}

// ConflictResolution represents conflict resolution options
type ConflictResolution struct {
	Strategy    string                 `json:"strategy"`    // merge, overwrite, manual
	AutoResolve bool                   `json:"auto_resolve"`
	NotifyUsers []string               `json:"notify_users,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// RepositoryTemplate represents a repository template configuration
type RepositoryTemplate struct {
	Name        string            `json:"name"`
	Repository  string            `json:"repository"`
	Path        string            `json:"path"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Tags        []string          `json:"tags,omitempty"`
	Variables   map[string]string `json:"variables,omitempty"`
	Requirements []string         `json:"requirements,omitempty"`
	Examples    []string          `json:"examples,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// TemplateRequest represents a request to use a template
type TemplateRequest struct {
	Template      string            `json:"template"`
	Name          string            `json:"name"`
	Description   string            `json:"description,omitempty"`
	Variables     map[string]string `json:"variables,omitempty"`
	TargetRepo    string            `json:"target_repo,omitempty"`
	TargetPath    string            `json:"target_path,omitempty"`
	CreatePR      bool              `json:"create_pr,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// VersionInfo represents version information for an experiment
type VersionInfo struct {
	Version     string    `json:"version"`
	SHA         string    `json:"sha"`
	Tag         string    `json:"tag,omitempty"`
	Branch      string    `json:"branch"`
	Message     string    `json:"message"`
	Author      AuthorInfo `json:"author"`
	CreatedAt   time.Time `json:"created_at"`
	IsLatest    bool      `json:"is_latest"`
	IsStable    bool      `json:"is_stable"`
}

// VersionHistory represents version history for an experiment
type VersionHistory struct {
	File     string        `json:"file"`
	Versions []VersionInfo `json:"versions"`
	Total    int           `json:"total"`
}

// WebhookManager defines the interface for webhook management
type WebhookManager interface {
	ProcessWebhook(ctx context.Context, headers map[string][]string, payload []byte) (*WebhookEvent, error)
	ValidateSignature(payload []byte, signature string) bool
	ParsePushEvent(payload []byte) (*WebhookEvent, error)
	ParsePullRequestEvent(payload []byte) (*WebhookEvent, error)
}