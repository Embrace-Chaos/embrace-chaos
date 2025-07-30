package git

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-github/v56/github"

	"github.com/embrace-chaos/internal/core/errors"
)

// DefaultWebhookManager implements WebhookManager interface
type DefaultWebhookManager struct {
	secret string
}

// NewWebhookManager creates a new webhook manager
func NewWebhookManager(secret string) WebhookManager {
	return &DefaultWebhookManager{
		secret: secret,
	}
}

// ProcessWebhook processes incoming webhook events
func (w *DefaultWebhookManager) ProcessWebhook(ctx context.Context, headers http.Header, payload []byte) (*WebhookEvent, error) {
	// Validate signature
	if signature := headers.Get("X-Hub-Signature-256"); signature != "" {
		if !w.ValidateSignature(payload, signature) {
			return nil, errors.NewValidationError("invalid webhook signature")
		}
	}

	// Get event type
	eventType := headers.Get("X-GitHub-Event")
	if eventType == "" {
		return nil, errors.NewValidationError("missing X-GitHub-Event header")
	}

	// Parse event based on type
	switch eventType {
	case "push":
		return w.ParsePushEvent(payload)
	case "pull_request":
		return w.ParsePullRequestEvent(payload)
	case "repository":
		return w.parseRepositoryEvent(payload)
	case "create":
		return w.parseCreateEvent(payload)
	case "delete":
		return w.parseDeleteEvent(payload)
	default:
		return &WebhookEvent{
			Type:      eventType,
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"raw_payload": string(payload),
			},
		}, nil
	}
}

// ValidateSignature validates the webhook signature
func (w *DefaultWebhookManager) ValidateSignature(payload []byte, signature string) bool {
	if w.secret == "" {
		return true // No secret configured, skip validation
	}

	// Remove "sha256=" prefix
	if strings.HasPrefix(signature, "sha256=") {
		signature = signature[7:]
	}

	// Calculate expected signature
	mac := hmac.New(sha256.New, []byte(w.secret))
	mac.Write(payload)
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	// Compare signatures
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

// ParsePushEvent parses a push event
func (w *DefaultWebhookManager) ParsePushEvent(payload []byte) (*WebhookEvent, error) {
	var pushEvent github.PushEvent
	if err := json.Unmarshal(payload, &pushEvent); err != nil {
		return nil, errors.NewValidationError("failed to parse push event: %w", err)
	}

	// Extract repository information
	repo := RepositoryInfo{
		ID:       pushEvent.Repo.GetID(),
		Name:     pushEvent.Repo.GetName(),
		FullName: pushEvent.Repo.GetFullName(),
		Owner:    pushEvent.Repo.GetOwner().GetLogin(),
		Private:  pushEvent.Repo.GetPrivate(),
		HTMLURL:  pushEvent.Repo.GetHTMLURL(),
		CloneURL: pushEvent.Repo.GetCloneURL(),
	}

	// Extract commits
	var commits []CommitInfo
	for _, commit := range pushEvent.Commits {
		commitInfo := CommitInfo{
			SHA:     commit.GetSHA(),
			Message: commit.GetMessage(),
			Author: AuthorInfo{
				Name:  commit.GetAuthor().GetName(),
				Email: commit.GetAuthor().GetEmail(),
			},
		}

		if timestamp := commit.GetTimestamp(); timestamp != nil {
			commitInfo.Date = timestamp.Time
		}

		commits = append(commits, commitInfo)
	}

	// Extract changed files
	var files []FileChangeInfo
	for _, commit := range pushEvent.Commits {
		for _, file := range commit.Added {
			files = append(files, FileChangeInfo{
				Path:     file,
				Status:   "added",
				Filename: getFilename(file),
			})
		}
		for _, file := range commit.Modified {
			files = append(files, FileChangeInfo{
				Path:     file,
				Status:   "modified",
				Filename: getFilename(file),
			})
		}
		for _, file := range commit.Removed {
			files = append(files, FileChangeInfo{
				Path:     file,
				Status:   "removed",
				Filename: getFilename(file),
			})
		}
	}

	// Extract branch name from ref
	branch := ""
	if ref := pushEvent.GetRef(); ref != "" {
		if strings.HasPrefix(ref, "refs/heads/") {
			branch = strings.TrimPrefix(ref, "refs/heads/")
		}
	}

	// Extract sender information
	sender := UserInfo{
		ID:        pushEvent.Sender.GetID(),
		Login:     pushEvent.Sender.GetLogin(),
		HTMLURL:   pushEvent.Sender.GetHTMLURL(),
		AvatarURL: pushEvent.Sender.GetAvatarURL(),
	}

	return &WebhookEvent{
		Type:       "push",
		Repository: repo,
		Commits:    commits,
		Branch:     branch,
		Ref:        pushEvent.GetRef(),
		Before:     pushEvent.GetBefore(),
		After:      pushEvent.GetAfter(),
		Files:      files,
		Sender:     sender,
		Timestamp:  time.Now(),
		Metadata: map[string]interface{}{
			"head_commit": pushEvent.GetHeadCommit(),
			"compare":     pushEvent.GetCompare(),
			"forced":      pushEvent.GetForced(),
			"created":     pushEvent.GetCreated(),
			"deleted":     pushEvent.GetDeleted(),
		},
	}, nil
}

// ParsePullRequestEvent parses a pull request event
func (w *DefaultWebhookManager) ParsePullRequestEvent(payload []byte) (*WebhookEvent, error) {
	var prEvent github.PullRequestEvent
	if err := json.Unmarshal(payload, &prEvent); err != nil {
		return nil, errors.NewValidationError("failed to parse pull request event: %w", err)
	}

	// Extract repository information
	repo := RepositoryInfo{
		ID:       prEvent.Repo.GetID(),
		Name:     prEvent.Repo.GetName(),
		FullName: prEvent.Repo.GetFullName(),
		Owner:    prEvent.Repo.GetOwner().GetLogin(),
		Private:  prEvent.Repo.GetPrivate(),
		HTMLURL:  prEvent.Repo.GetHTMLURL(),
		CloneURL: prEvent.Repo.GetCloneURL(),
	}

	// Extract sender information
	sender := UserInfo{
		ID:        prEvent.Sender.GetID(),
		Login:     prEvent.Sender.GetLogin(),
		HTMLURL:   prEvent.Sender.GetHTMLURL(),
		AvatarURL: prEvent.Sender.GetAvatarURL(),
	}

	return &WebhookEvent{
		Type:       "pull_request",
		Action:     prEvent.GetAction(),
		Repository: repo,
		Branch:     prEvent.PullRequest.GetHead().GetRef(),
		Sender:     sender,
		Timestamp:  time.Now(),
		Metadata: map[string]interface{}{
			"pull_request": map[string]interface{}{
				"id":       prEvent.PullRequest.GetID(),
				"number":   prEvent.PullRequest.GetNumber(),
				"title":    prEvent.PullRequest.GetTitle(),
				"body":     prEvent.PullRequest.GetBody(),
				"state":    prEvent.PullRequest.GetState(),
				"html_url": prEvent.PullRequest.GetHTMLURL(),
				"head":     prEvent.PullRequest.GetHead().GetRef(),
				"base":     prEvent.PullRequest.GetBase().GetRef(),
				"mergeable": prEvent.PullRequest.GetMergeable(),
			},
		},
	}, nil
}

// parseRepositoryEvent parses a repository event
func (w *DefaultWebhookManager) parseRepositoryEvent(payload []byte) (*WebhookEvent, error) {
	var repoEvent github.RepositoryEvent
	if err := json.Unmarshal(payload, &repoEvent); err != nil {
		return nil, errors.NewValidationError("failed to parse repository event: %w", err)
	}

	repo := RepositoryInfo{
		ID:       repoEvent.Repo.GetID(),
		Name:     repoEvent.Repo.GetName(),
		FullName: repoEvent.Repo.GetFullName(),
		Owner:    repoEvent.Repo.GetOwner().GetLogin(),
		Private:  repoEvent.Repo.GetPrivate(),
		HTMLURL:  repoEvent.Repo.GetHTMLURL(),
		CloneURL: repoEvent.Repo.GetCloneURL(),
	}

	sender := UserInfo{
		ID:        repoEvent.Sender.GetID(),
		Login:     repoEvent.Sender.GetLogin(),
		HTMLURL:   repoEvent.Sender.GetHTMLURL(),
		AvatarURL: repoEvent.Sender.GetAvatarURL(),
	}

	return &WebhookEvent{
		Type:       "repository",
		Action:     repoEvent.GetAction(),
		Repository: repo,
		Sender:     sender,
		Timestamp:  time.Now(),
		Metadata: map[string]interface{}{
			"changes": repoEvent.Changes,
		},
	}, nil
}

// parseCreateEvent parses a create event (branch/tag creation)
func (w *DefaultWebhookManager) parseCreateEvent(payload []byte) (*WebhookEvent, error) {
	var createEvent github.CreateEvent
	if err := json.Unmarshal(payload, &createEvent); err != nil {
		return nil, errors.NewValidationError("failed to parse create event: %w", err)
	}

	repo := RepositoryInfo{
		ID:       createEvent.Repo.GetID(),
		Name:     createEvent.Repo.GetName(),
		FullName: createEvent.Repo.GetFullName(),
		Owner:    createEvent.Repo.GetOwner().GetLogin(),
		Private:  createEvent.Repo.GetPrivate(),
		HTMLURL:  createEvent.Repo.GetHTMLURL(),
		CloneURL: createEvent.Repo.GetCloneURL(),
	}

	sender := UserInfo{
		ID:        createEvent.Sender.GetID(),
		Login:     createEvent.Sender.GetLogin(),
		HTMLURL:   createEvent.Sender.GetHTMLURL(),
		AvatarURL: createEvent.Sender.GetAvatarURL(),
	}

	return &WebhookEvent{
		Type:       "create",
		Repository: repo,
		Ref:        createEvent.GetRef(),
		Sender:     sender,
		Timestamp:  time.Now(),
		Metadata: map[string]interface{}{
			"ref_type":         createEvent.GetRefType(),
			"master_branch":    createEvent.GetMasterBranch(),
			"description":      createEvent.GetDescription(),
			"pusher_type":      createEvent.GetPusherType(),
		},
	}, nil
}

// parseDeleteEvent parses a delete event (branch/tag deletion)
func (w *DefaultWebhookManager) parseDeleteEvent(payload []byte) (*WebhookEvent, error) {
	var deleteEvent github.DeleteEvent
	if err := json.Unmarshal(payload, &deleteEvent); err != nil {
		return nil, errors.NewValidationError("failed to parse delete event: %w", err)
	}

	repo := RepositoryInfo{
		ID:       deleteEvent.Repo.GetID(),
		Name:     deleteEvent.Repo.GetName(),
		FullName: deleteEvent.Repo.GetFullName(),
		Owner:    deleteEvent.Repo.GetOwner().GetLogin(),
		Private:  deleteEvent.Repo.GetPrivate(),
		HTMLURL:  deleteEvent.Repo.GetHTMLURL(),
		CloneURL: deleteEvent.Repo.GetCloneURL(),
	}

	sender := UserInfo{
		ID:        deleteEvent.Sender.GetID(),
		Login:     deleteEvent.Sender.GetLogin(),
		HTMLURL:   deleteEvent.Sender.GetHTMLURL(),
		AvatarURL: deleteEvent.Sender.GetAvatarURL(),
	}

	return &WebhookEvent{
		Type:       "delete",
		Repository: repo,
		Ref:        deleteEvent.GetRef(),
		Sender:     sender,
		Timestamp:  time.Now(),
		Metadata: map[string]interface{}{
			"ref_type":      deleteEvent.GetRefType(),
			"pusher_type":   deleteEvent.GetPusherType(),
		},
	}, nil
}

// Helper functions

func getFilename(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return path
}