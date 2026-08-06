package admin

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/grepnest/grepnest/internal/audit"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/githubapp"
	"github.com/grepnest/grepnest/internal/repository"
)

var ErrForbidden = errors.New("administrator access required")

const jobsPageSize = 25

type Overview struct {
	Repositories  map[string]int64 `json:"repositories"`
	Jobs          map[string]int64 `json:"jobs"`
	Deliveries    map[string]int64 `json:"deliveries"`
	SCIPUploads   int64            `json:"scip_uploads"`
	Dependencies  int64            `json:"dependencies"`
	Installations int64            `json:"installations"`
}

type Repository struct {
	ID             int64      `json:"id"`
	GitHubID       int64      `json:"github_id"`
	InstallationID int64      `json:"installation_id"`
	Name           string     `json:"name"`
	DefaultBranch  string     `json:"default_branch"`
	DesiredSHA     string     `json:"desired_sha"`
	IndexedSHA     string     `json:"indexed_sha"`
	Status         string     `json:"status"`
	ErrorCode      string     `json:"error_code"`
	WebURL         string     `json:"web_url"`
	Enabled        bool       `json:"enabled"`
	Private        bool       `json:"private"`
	Archived       bool       `json:"archived"`
	LastIndexedAt  *time.Time `json:"last_indexed_at,omitempty"`
}

type JobCursor struct {
	UpdatedAt time.Time
	ID        int64
}

type Job struct {
	ID           int64     `json:"id"`
	RepositoryID int64     `json:"repository_id"`
	Repository   string    `json:"repository"`
	TargetSHA    string    `json:"target_sha"`
	TargetRef    string    `json:"target_ref"`
	Reason       string    `json:"reason"`
	State        string    `json:"state"`
	ErrorCode    string    `json:"error_code"`
	Attempt      int       `json:"attempt"`
	MaxAttempts  int       `json:"max_attempts"`
	Priority     int       `json:"priority"`
	RunAfter     time.Time `json:"run_after"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type SCIPUpload struct {
	ID             int64     `json:"id"`
	RepositoryID   int64     `json:"repository_id"`
	Repository     string    `json:"repository"`
	Commit         string    `json:"commit"`
	ProjectRoot    string    `json:"project_root"`
	IndexerName    string    `json:"indexer_name"`
	IndexerVersion string    `json:"indexer_version"`
	UploadedAt     time.Time `json:"uploaded_at"`
}

type SCIPDependency struct {
	RepositoryID int64  `json:"repository_id"`
	Repository   string `json:"repository"`
	Source       string `json:"source"`
	Relation     string `json:"relation"`
	PURL         string `json:"purl"`
	Manager      string `json:"manager"`
	Name         string `json:"name"`
	Version      string `json:"version"`
}

type Delivery struct {
	ID             int64      `json:"id"`
	DeliveryID     string     `json:"delivery_id"`
	Event          string     `json:"event"`
	State          string     `json:"state"`
	ErrorCode      string     `json:"error_code"`
	InstallationID int64      `json:"installation_id"`
	ReceivedAt     time.Time  `json:"received_at"`
	ProcessedAt    *time.Time `json:"processed_at,omitempty"`
}

type Installation struct {
	GitHubID     int64      `json:"github_id"`
	AccountLogin string     `json:"account_login"`
	AccountType  string     `json:"account_type"`
	Status       string     `json:"status"`
	SuspendedAt  *time.Time `json:"suspended_at,omitempty"`
}

type GitHub struct {
	AppID                   int64          `json:"app_id"`
	WebURL                  string         `json:"web_url"`
	APIURL                  string         `json:"api_url"`
	UploadURL               string         `json:"upload_url"`
	GitURL                  string         `json:"git_url"`
	APIVersion              string         `json:"api_version"`
	PrivateKeyConfigured    bool           `json:"private_key_configured"`
	WebhookSecretConfigured bool           `json:"webhook_secret_configured"`
	CAConfigured            bool           `json:"ca_configured"`
	Installations           []Installation `json:"installations"`
	Truncated               bool           `json:"truncated"`
}

type GitHubConfig struct {
	AppID                                                       int64
	WebURL, APIURL, UploadURL, GitURL, APIVersion               string
	PrivateKeyConfigured, WebhookSecretConfigured, CAConfigured bool
}

type IndexRequest struct {
	RepositoryID                 int64
	TargetSHA, TargetRef, Reason string
}

type Store interface {
	auditedIdentityStore
	AuditEvents(context.Context, int) ([]audit.Event, bool, error)
	AdminUsers(context.Context, int) ([]User, bool, error)
	AdminUser(context.Context, int64) (User, error)
	AdminGroups(context.Context, int) ([]Group, bool, error)
	AdminGroup(context.Context, int64) (Group, error)
	SuspendAdminUser(context.Context, int64, int64, bool) error
	ReplaceAdminUserAccess(context.Context, int64, int64, bool, []int64) error
	ReplaceAdminGroupAccess(context.Context, int64, int64, bool, []int64) error
	RevokeAdminUserCredentials(context.Context, int64) error
	AdminOverview(context.Context, int64, []int64) (Overview, error)
	AdminRepositories(context.Context, int64, []int64, int) ([]Repository, bool, error)
	AdminJobs(context.Context, int64, []int64, int, *JobCursor) ([]Job, bool, error)
	AdminSCIPUploads(context.Context, int64, []int64, int) ([]SCIPUpload, bool, error)
	AdminSCIPDependencies(context.Context, int64, []int64, int) ([]SCIPDependency, bool, error)
	AdminDeliveries(context.Context, int64, []int64, int) ([]Delivery, bool, error)
	AdminGitHub(context.Context, int64, []int64, GitHubConfig, int) (GitHub, error)
	AdminRepository(context.Context, int64, []int64, int64) (repository.Repository, error)
	AnyAuthorizedRepository(context.Context, int64) (repository.Repository, error)
	EnqueueAdminIndex(context.Context, IndexRequest) error
	RetryAdminJob(context.Context, int64, []int64, int64) error
	ReconcileAdminRepositories(context.Context, int64, []int64, []githubapp.Repository) error
}

type GitHubClient interface {
	DefaultBranchSHA(context.Context, int64, string, string, string) (string, error)
	InstallationRepositories(context.Context, int64) ([]githubapp.Repository, error)
}

type Service struct {
	Store        Store
	Audit        audit.Recorder
	GitHub       GitHubClient
	ReconcileAll func(context.Context) error
	Config       GitHubConfig
	MaxItems     int
}

func (service *Service) Overview(ctx context.Context, principal authn.Principal) (Overview, error) {
	if err := requireAdmin(principal); err != nil {
		return Overview{}, err
	}
	return service.Store.AdminOverview(ctx, principal.InstallationID, principal.RepositoryIDs)
}

func (service *Service) Repositories(ctx context.Context, principal authn.Principal) ([]Repository, bool, error) {
	if err := requireAdmin(principal); err != nil {
		return nil, false, err
	}
	return service.Store.AdminRepositories(ctx, principal.InstallationID, principal.RepositoryIDs, service.limit())
}

func (service *Service) Jobs(ctx context.Context, principal authn.Principal, cursor *JobCursor) ([]Job, bool, error) {
	if err := requireAdmin(principal); err != nil {
		return nil, false, err
	}
	return service.Store.AdminJobs(ctx, principal.InstallationID, principal.RepositoryIDs, jobsPageSize, cursor)
}

func (service *Service) SCIPUploads(ctx context.Context, principal authn.Principal) ([]SCIPUpload, bool, error) {
	if err := requireAdmin(principal); err != nil {
		return nil, false, err
	}
	return service.Store.AdminSCIPUploads(ctx, principal.InstallationID, principal.RepositoryIDs, service.limit())
}

func (service *Service) SCIPDependencies(ctx context.Context, principal authn.Principal) ([]SCIPDependency, bool, error) {
	if err := requireAdmin(principal); err != nil {
		return nil, false, err
	}
	return service.Store.AdminSCIPDependencies(ctx, principal.InstallationID, principal.RepositoryIDs, service.limit())
}

func (service *Service) Deliveries(ctx context.Context, principal authn.Principal) ([]Delivery, bool, error) {
	if err := requireAdmin(principal); err != nil {
		return nil, false, err
	}
	return service.Store.AdminDeliveries(ctx, principal.InstallationID, principal.RepositoryIDs, service.limit())
}

func (service *Service) GitHubInfo(ctx context.Context, principal authn.Principal) (GitHub, error) {
	if err := requireAdmin(principal); err != nil {
		return GitHub{}, err
	}
	return service.Store.AdminGitHub(ctx, principal.InstallationID, principal.RepositoryIDs, service.Config, service.limit())
}

func (service *Service) Reindex(ctx context.Context, principal authn.Principal, githubID int64) error {
	if err := requireAdmin(principal); err != nil {
		return err
	}
	var (
		repo repository.Repository
		err  error
	)
	if durableAdministrator(principal) {
		repo, err = service.Store.AnyAuthorizedRepository(ctx, githubID)
	} else {
		repo, err = service.Store.AdminRepository(ctx, principal.InstallationID, principal.RepositoryIDs, githubID)
	}
	if err != nil {
		return err
	}
	owner, name, ok := strings.Cut(repo.Name, "/")
	if !ok {
		return errors.New("repository name is invalid")
	}
	sha, err := service.GitHub.DefaultBranchSHA(ctx, repo.InstallationID, owner, name, repo.Branch)
	if err != nil {
		return err
	}
	return service.Store.EnqueueAdminIndex(ctx, IndexRequest{
		RepositoryID: repo.ID, TargetSHA: sha, TargetRef: "refs/heads/" + repo.Branch, Reason: "admin_reindex",
	})
}

func (service *Service) Reconcile(ctx context.Context, principal authn.Principal) error {
	if err := requireAdmin(principal); err != nil {
		return err
	}
	if principal.Method == "api_token" {
		return ErrForbidden
	}
	if durableAdministrator(principal) {
		return service.ReconcileAll(ctx)
	}
	upstream, err := service.GitHub.InstallationRepositories(ctx, principal.InstallationID)
	if err != nil {
		return err
	}
	allowed := make(map[int64]struct{}, len(principal.RepositoryIDs))
	for _, id := range principal.RepositoryIDs {
		allowed[id] = struct{}{}
	}
	scoped := make([]githubapp.Repository, 0, len(principal.RepositoryIDs))
	for _, repo := range upstream {
		if _, ok := allowed[repo.ID]; !ok {
			continue
		}
		repo.DefaultSHA, err = service.GitHub.DefaultBranchSHA(ctx, principal.InstallationID, repo.Owner, repo.Name, repo.DefaultBranch)
		if err != nil {
			return err
		}
		scoped = append(scoped, repo)
	}
	return service.Store.ReconcileAdminRepositories(ctx, principal.InstallationID, principal.RepositoryIDs, scoped)
}

func (service *Service) Retry(ctx context.Context, principal authn.Principal, id int64) error {
	if err := requireAdmin(principal); err != nil {
		return err
	}
	return service.Store.RetryAdminJob(ctx, principal.InstallationID, principal.RepositoryIDs, id)
}

func requireAdmin(principal authn.Principal) error {
	if !principal.Administrator {
		return ErrForbidden
	}
	return nil
}

func durableAdministrator(principal authn.Principal) bool {
	return principal.Administrator && (principal.Method == "oidc" || principal.Method == "local") &&
		principal.InstallationID == 0 && len(principal.RepositoryIDs) == 0
}

func (service *Service) limit() int {
	if service.MaxItems > 0 {
		return service.MaxItems
	}
	return 100
}
