package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/audit"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/githubapp"
	"github.com/grepnest/grepnest/internal/repository"
)

func TestServiceRejectsNonAdministrators(t *testing.T) {
	service := &Service{Store: &fakeStore{}, GitHub: fakeGitHub{}}
	for name, call := range map[string]func() error{
		"overview":  func() error { _, err := service.Overview(t.Context(), authn.Principal{}); return err },
		"reindex":   func() error { return service.Reindex(t.Context(), authn.Principal{}, 101) },
		"reconcile": func() error { return service.Reconcile(t.Context(), authn.Principal{}) },
		"retry":     func() error { return service.Retry(t.Context(), authn.Principal{}, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrForbidden) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestServiceResolvesReindexDefaultBranchSHA(t *testing.T) {
	store := &fakeStore{repository: repository.Repository{
		ID: 7, InstallationID: 10, GitHubID: 101, Name: "acme/one", Branch: "main", Enabled: true,
	}}
	service := &Service{Store: store, GitHub: fakeGitHub{sha: testSHA}}
	if err := service.Reindex(t.Context(), authn.Principal{Administrator: true, InstallationID: 10, RepositoryIDs: []int64{101}}, 101); err != nil {
		t.Fatal(err)
	}
	if store.enqueued.RepositoryID != 7 || store.enqueued.TargetSHA != testSHA ||
		store.enqueued.TargetRef != "refs/heads/main" || store.enqueued.Reason != "admin_reindex" {
		t.Fatalf("request = %#v", store.enqueued)
	}
}

func TestServiceDurableAdministratorReindexesGloballyAuthorizedRepository(t *testing.T) {
	store := &fakeStore{repository: repository.Repository{
		ID: 7, InstallationID: 20, GitHubID: 201, Name: "other/two", Branch: "main", Enabled: true,
	}}
	service := &Service{Store: store, GitHub: fakeGitHub{sha: testSHA}}
	principal := authn.Principal{Method: "oidc", Administrator: true}

	if err := service.Reindex(t.Context(), principal, 201); err != nil {
		t.Fatal(err)
	}
	if store.globalLookups != 1 || store.enqueued.RepositoryID != 7 {
		t.Fatalf("global lookups=%d request=%#v", store.globalLookups, store.enqueued)
	}
}

func TestServiceLocalAdministratorReindexesGloballyAuthorizedRepository(t *testing.T) {
	store := &fakeStore{repository: repository.Repository{
		ID: 7, InstallationID: 20, GitHubID: 201, Name: "other/two", Branch: "main", Enabled: true,
	}}
	service := &Service{Store: store, GitHub: fakeGitHub{sha: testSHA}}

	if err := service.Reindex(t.Context(), authn.Principal{Method: "local", Administrator: true}, 201); err != nil {
		t.Fatal(err)
	}
	if store.globalLookups != 1 || store.enqueued.RepositoryID != 7 {
		t.Fatalf("global lookups=%d request=%#v", store.globalLookups, store.enqueued)
	}
}

func TestServiceAdministratorAPITokenReindexesOnlyCeilingRepository(t *testing.T) {
	store := &fakeStore{repository: repository.Repository{
		ID: 7, InstallationID: 20, GitHubID: 201, Name: "other/two", Branch: "main", Enabled: true,
	}}
	service := &Service{Store: store, GitHub: fakeGitHub{sha: testSHA}}
	principal := authn.Principal{Method: "api_token", Administrator: true, RepositoryIDs: []int64{201}}

	if err := service.Reindex(t.Context(), principal, 201); err != nil {
		t.Fatal(err)
	}
	if store.globalLookups != 0 || store.enqueued.RepositoryID != 7 {
		t.Fatalf("global lookups=%d request=%#v", store.globalLookups, store.enqueued)
	}
}

func TestServiceDurableAdministratorReconcilesAllInstallations(t *testing.T) {
	called := false
	service := &Service{
		Store:  &fakeStore{},
		GitHub: fakeGitHub{},
		ReconcileAll: func(context.Context) error {
			called = true
			return nil
		},
	}
	if err := service.Reconcile(t.Context(), authn.Principal{Method: "oidc", Administrator: true}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("global reconciliation was not called")
	}
}

func TestServiceRejectsAdministratorAPITokenReconcile(t *testing.T) {
	service := &Service{Store: &fakeStore{}, GitHub: fakeGitHub{}}
	err := service.Reconcile(t.Context(), authn.Principal{
		Method: "api_token", Administrator: true, RepositoryIDs: []int64{101},
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("error=%v", err)
	}
}

func TestServiceJobsUsesFixedPageSizeAndForwardsCursor(t *testing.T) {
	cursor := &JobCursor{UpdatedAt: time.Unix(123, 0), ID: 42}
	store := &fakeStore{}
	service := &Service{Store: store, MaxItems: 100}
	principal := authn.Principal{Administrator: true, InstallationID: 10, RepositoryIDs: []int64{101}}

	if _, _, err := service.Jobs(t.Context(), principal, cursor); err != nil {
		t.Fatal(err)
	}
	if store.jobsLimit != 25 {
		t.Fatalf("limit = %d, want 25", store.jobsLimit)
	}
	if store.jobsCursor != cursor {
		t.Fatalf("cursor = %#v, want unchanged %#v", store.jobsCursor, cursor)
	}
}

func TestServiceScopesReconcileAndRetry(t *testing.T) {
	store := &fakeStore{}
	service := &Service{Store: store, GitHub: fakeGitHub{repositories: []githubapp.Repository{
		{ID: 101, InstallationID: 10, Owner: "acme", Name: "one", DefaultBranch: "main"},
		{ID: 102, InstallationID: 10, Owner: "acme", Name: "unscoped", DefaultBranch: "main"},
		{ID: 202, InstallationID: 20, Owner: "other", Name: "two", DefaultBranch: "main"},
	}}}
	admin := authn.Principal{Administrator: true, InstallationID: 10, RepositoryIDs: []int64{101}}
	if err := service.Reconcile(t.Context(), admin); err != nil {
		t.Fatal(err)
	}
	if err := service.Retry(t.Context(), admin, 42); err != nil {
		t.Fatal(err)
	}
	if len(store.reconciled) != 1 || store.reconciled[0].ID != 101 || store.retried != 42 ||
		store.retryInstallationID != 10 || len(store.retryRepositoryIDs) != 1 || store.retryRepositoryIDs[0] != 101 {
		t.Fatalf("reconciled=%#v retried=%d retry scope=(%d,%v)", store.reconciled, store.retried, store.retryInstallationID, store.retryRepositoryIDs)
	}
}

const testSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeStore struct {
	repository          repository.Repository
	enqueued            IndexRequest
	retried             int64
	retryInstallationID int64
	retryRepositoryIDs  []int64
	reconciled          []githubapp.Repository
	globalLookups       int
	jobsLimit           int
	jobsCursor          *JobCursor
}

func (*fakeStore) AuditEvents(context.Context, int) ([]audit.Event, bool, error) {
	return nil, false, nil
}

func (*fakeStore) AdminOverview(context.Context, int64, []int64) (Overview, error) {
	return Overview{}, nil
}
func (*fakeStore) AdminUsers(context.Context, int) ([]User, bool, error) {
	return nil, false, nil
}
func (*fakeStore) AdminUser(context.Context, int64) (User, error) {
	return User{}, nil
}
func (*fakeStore) AdminGroups(context.Context, int) ([]Group, bool, error) {
	return nil, false, nil
}
func (*fakeStore) AdminGroup(context.Context, int64) (Group, error) {
	return Group{}, nil
}
func (*fakeStore) SuspendAdminUser(context.Context, int64, int64, bool) error {
	return nil
}
func (*fakeStore) ReplaceAdminUserAccess(context.Context, int64, int64, bool, []int64) error {
	return nil
}
func (*fakeStore) ReplaceAdminGroupAccess(context.Context, int64, int64, bool, []int64) error {
	return nil
}
func (*fakeStore) RevokeAdminUserCredentials(context.Context, int64) error {
	return nil
}
func (store *fakeStore) SuspendAdminUserAudited(ctx context.Context, actorID, userID int64, suspended bool, _ audit.Event) error {
	return store.SuspendAdminUser(ctx, actorID, userID, suspended)
}
func (store *fakeStore) ReplaceAdminUserAccessAudited(ctx context.Context, actorID, userID int64, administrator bool, repositoryIDs []int64, _ audit.Event) error {
	return store.ReplaceAdminUserAccess(ctx, actorID, userID, administrator, repositoryIDs)
}
func (store *fakeStore) ReplaceAdminGroupAccessAudited(ctx context.Context, actorID, groupID int64, administrator bool, repositoryIDs []int64, _ audit.Event) error {
	return store.ReplaceAdminGroupAccess(ctx, actorID, groupID, administrator, repositoryIDs)
}
func (store *fakeStore) RevokeAdminUserCredentialsAudited(ctx context.Context, userID int64, _ audit.Event) error {
	return store.RevokeAdminUserCredentials(ctx, userID)
}
func (*fakeStore) AdminRepositories(context.Context, int64, []int64, int) ([]Repository, bool, error) {
	return nil, false, nil
}
func (store *fakeStore) AdminJobs(_ context.Context, _ int64, _ []int64, limit int, cursor *JobCursor) ([]Job, bool, error) {
	store.jobsLimit = limit
	store.jobsCursor = cursor
	return nil, false, nil
}
func (*fakeStore) AdminSCIPUploads(context.Context, int64, []int64, int) ([]SCIPUpload, bool, error) {
	return nil, false, nil
}
func (*fakeStore) AdminSCIPDependencies(context.Context, int64, []int64, int) ([]SCIPDependency, bool, error) {
	return nil, false, nil
}
func (*fakeStore) AdminDeliveries(context.Context, int64, []int64, int) ([]Delivery, bool, error) {
	return nil, false, nil
}
func (*fakeStore) AdminGitHub(context.Context, int64, []int64, GitHubConfig, int) (GitHub, error) {
	return GitHub{}, nil
}
func (store *fakeStore) AdminRepository(_ context.Context, installationID int64, repositoryIDs []int64, githubID int64) (repository.Repository, error) {
	if installationID != 0 && installationID != store.repository.InstallationID || len(repositoryIDs) != 1 ||
		repositoryIDs[0] != githubID || store.repository.GitHubID != githubID {
		return repository.Repository{}, errors.New("missing")
	}
	return store.repository, nil
}
func (store *fakeStore) AnyAuthorizedRepository(_ context.Context, githubID int64) (repository.Repository, error) {
	store.globalLookups++
	if store.repository.GitHubID != githubID {
		return repository.Repository{}, errors.New("missing")
	}
	return store.repository, nil
}
func (store *fakeStore) EnqueueAdminIndex(_ context.Context, request IndexRequest) error {
	store.enqueued = request
	return nil
}
func (store *fakeStore) RetryAdminJob(_ context.Context, installationID int64, repositoryIDs []int64, id int64) error {
	store.retried = id
	store.retryInstallationID = installationID
	store.retryRepositoryIDs = append([]int64(nil), repositoryIDs...)
	return nil
}
func (store *fakeStore) ReconcileAdminRepositories(_ context.Context, _ int64, _ []int64, repositories []githubapp.Repository) error {
	store.reconciled = append([]githubapp.Repository(nil), repositories...)
	return nil
}

type fakeGitHub struct {
	sha          string
	repositories []githubapp.Repository
}

func (github fakeGitHub) DefaultBranchSHA(context.Context, int64, string, string, string) (string, error) {
	return github.sha, nil
}
func (github fakeGitHub) InstallationRepositories(context.Context, int64) ([]githubapp.Repository, error) {
	return github.repositories, nil
}
