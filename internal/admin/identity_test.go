package admin

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/grepnest/grepnest/internal/audit"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/githubapp"
	"github.com/grepnest/grepnest/internal/repository"
)

func TestIdentityServiceListsAndLoadsEffectiveAccess(t *testing.T) {
	store := &identityStore{
		users: []User{{
			ID: 1, UserName: "ada", Administrator: true, RepositoryIDs: []int64{101},
			DirectAdministrator: false, DirectRepositoryIDs: []int64{},
		}},
		user: User{
			ID: 1, UserName: "ada", Administrator: true, RepositoryIDs: []int64{101},
			DirectAdministrator: false, DirectRepositoryIDs: []int64{},
		},
		groups: []Group{{ID: 2, DisplayName: "Engineering", Administrator: true, RepositoryIDs: []int64{101}}},
		group:  Group{ID: 2, DisplayName: "Engineering", Administrator: true, RepositoryIDs: []int64{101}},
	}
	service := &Service{Store: store, MaxItems: 3}
	principal := authn.Principal{Subject: "1", Method: "oidc", Administrator: true}

	users, usersTruncated, err := service.Users(t.Context(), principal)
	if err != nil || usersTruncated || !reflect.DeepEqual(users, store.users) || store.limit != 3 {
		t.Fatalf("users=%#v truncated=%v limit=%d err=%v", users, usersTruncated, store.limit, err)
	}
	user, err := service.User(t.Context(), principal, 1)
	if err != nil || !reflect.DeepEqual(user, store.user) {
		t.Fatalf("user=%#v err=%v", user, err)
	}
	groups, groupsTruncated, err := service.Groups(t.Context(), principal)
	if err != nil || groupsTruncated || !reflect.DeepEqual(groups, store.groups) || store.limit != 3 {
		t.Fatalf("groups=%#v truncated=%v limit=%d err=%v", groups, groupsTruncated, store.limit, err)
	}
	group, err := service.Group(t.Context(), principal, 2)
	if err != nil || !reflect.DeepEqual(group, store.group) {
		t.Fatalf("group=%#v err=%v", group, err)
	}
}

func TestIdentityServiceReplacesAccessAndRevokesCredentials(t *testing.T) {
	store := &identityStore{}
	service := &Service{Store: store}
	principal := authn.Principal{Subject: "7", Method: "oidc", Administrator: true}

	if err := service.ReplaceUserAccess(t.Context(), principal, 8, true, []int64{101}); err != nil {
		t.Fatal(err)
	}
	if store.actorID != 7 || store.userID != 8 || !store.administrator || !reflect.DeepEqual(store.repositoryIDs, []int64{101}) {
		t.Fatalf("user access actor=%d user=%d admin=%v repositories=%v", store.actorID, store.userID, store.administrator, store.repositoryIDs)
	}
	if err := service.ReplaceGroupAccess(t.Context(), principal, 9, true, []int64{102}); err != nil {
		t.Fatal(err)
	}
	if store.actorID != 7 || store.groupID != 9 || !store.administrator || !reflect.DeepEqual(store.repositoryIDs, []int64{102}) {
		t.Fatalf("group access actor=%d group=%d admin=%v repositories=%v", store.actorID, store.groupID, store.administrator, store.repositoryIDs)
	}
	if err := service.RevokeUserCredentials(t.Context(), principal, 8); err != nil || store.revokedUserID != 8 {
		t.Fatalf("revoked=%d err=%v", store.revokedUserID, err)
	}
}

func TestIdentityServiceRejectsSelfSuspensionButForwardsDirectAccess(t *testing.T) {
	store := &identityStore{}
	service := &Service{Store: store}
	principal := authn.Principal{Subject: "7", Method: "oidc", Administrator: true}

	if err := service.SuspendUser(t.Context(), principal, 7, true); !errors.Is(err, ErrSelfAdministration) {
		t.Fatalf("self suspension error=%v", err)
	}
	if err := service.ReplaceUserAccess(t.Context(), principal, 7, false, []int64{101}); err != nil {
		t.Fatalf("self direct access error=%v", err)
	}
	if store.userID != 7 || store.administrator || !reflect.DeepEqual(store.repositoryIDs, []int64{101}) {
		t.Fatalf("self direct user=%d admin=%v repositories=%v", store.userID, store.administrator, store.repositoryIDs)
	}
	if err := service.SuspendUser(t.Context(), principal, 8, true); err != nil || store.userID != 8 || !store.suspended {
		t.Fatalf("suspend user=%d suspended=%v err=%v", store.userID, store.suspended, err)
	}
}

func TestIdentityServiceRequiresAdministrator(t *testing.T) {
	service := &Service{Store: &identityStore{}}
	for name, call := range map[string]func() error{
		"users":        func() error { _, _, err := service.Users(t.Context(), authn.Principal{}); return err },
		"user":         func() error { _, err := service.User(t.Context(), authn.Principal{}, 1); return err },
		"groups":       func() error { _, _, err := service.Groups(t.Context(), authn.Principal{}); return err },
		"group":        func() error { _, err := service.Group(t.Context(), authn.Principal{}, 1); return err },
		"suspend":      func() error { return service.SuspendUser(t.Context(), authn.Principal{}, 1, true) },
		"user access":  func() error { return service.ReplaceUserAccess(t.Context(), authn.Principal{}, 1, true, nil) },
		"group access": func() error { return service.ReplaceGroupAccess(t.Context(), authn.Principal{}, 1, true, nil) },
		"revoke":       func() error { return service.RevokeUserCredentials(t.Context(), authn.Principal{}, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrForbidden) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestIdentityServiceRejectsAdministratorAPITokens(t *testing.T) {
	service := &Service{Store: &identityStore{}}
	principal := authn.Principal{Subject: "7", Method: "api_token", Administrator: true, RepositoryIDs: []int64{101}}
	for name, call := range map[string]func() error{
		"users":        func() error { _, _, err := service.Users(t.Context(), principal); return err },
		"user":         func() error { _, err := service.User(t.Context(), principal, 1); return err },
		"groups":       func() error { _, _, err := service.Groups(t.Context(), principal); return err },
		"group":        func() error { _, err := service.Group(t.Context(), principal, 1); return err },
		"suspend":      func() error { return service.SuspendUser(t.Context(), principal, 1, true) },
		"user access":  func() error { return service.ReplaceUserAccess(t.Context(), principal, 1, true, nil) },
		"group access": func() error { return service.ReplaceGroupAccess(t.Context(), principal, 1, true, nil) },
		"revoke":       func() error { return service.RevokeUserCredentials(t.Context(), principal, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrForbidden) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

type identityStore struct {
	users         []User
	user          User
	groups        []Group
	group         Group
	limit         int
	actorID       int64
	userID        int64
	groupID       int64
	administrator bool
	suspended     bool
	repositoryIDs []int64
	revokedUserID int64
	mutationErr   error
}

type deniedAuditRecorder struct{ events []audit.Event }

func (r *deniedAuditRecorder) Record(_ context.Context, event audit.Event) error {
	r.events = append(r.events, event)
	return errors.New("audit unavailable")
}

func TestDeniedMutationIgnoresAuditFailure(t *testing.T) {
	recorder := &deniedAuditRecorder{}
	service := &Service{Store: &identityStore{}, Audit: recorder}
	err := service.SuspendUser(t.Context(), authn.Principal{
		Subject: "7", Method: "api_token", Administrator: true,
	}, 8, true)
	if !errors.Is(err, ErrForbidden) || len(recorder.events) != 1 ||
		recorder.events[0].Operation != audit.OperationAdminMutationDenied {
		t.Fatalf("error=%v events=%#v", err, recorder.events)
	}
}

func (*identityStore) AuditEvents(context.Context, int) ([]audit.Event, bool, error) {
	return nil, false, nil
}

func (store *identityStore) AdminUsers(_ context.Context, limit int) ([]User, bool, error) {
	store.limit = limit
	return store.users, false, nil
}
func (store *identityStore) AdminUser(context.Context, int64) (User, error) {
	return store.user, nil
}
func (store *identityStore) AdminGroups(_ context.Context, limit int) ([]Group, bool, error) {
	store.limit = limit
	return store.groups, false, nil
}
func (store *identityStore) AdminGroup(context.Context, int64) (Group, error) {
	return store.group, nil
}
func (store *identityStore) SuspendAdminUser(_ context.Context, actorID, userID int64, suspended bool) error {
	store.actorID, store.userID, store.suspended = actorID, userID, suspended
	return store.mutationErr
}
func (store *identityStore) ReplaceAdminUserAccess(_ context.Context, actorID, userID int64, administrator bool, repositoryIDs []int64) error {
	store.actorID, store.userID, store.administrator = actorID, userID, administrator
	store.repositoryIDs = append([]int64(nil), repositoryIDs...)
	return store.mutationErr
}
func (store *identityStore) ReplaceAdminGroupAccess(_ context.Context, actorID, groupID int64, administrator bool, repositoryIDs []int64) error {
	store.actorID, store.groupID, store.administrator = actorID, groupID, administrator
	store.repositoryIDs = append([]int64(nil), repositoryIDs...)
	return store.mutationErr
}

func TestFinalAdministratorDenialIsAuditedAndPreserved(t *testing.T) {
	recorder := &deniedAuditRecorder{}
	service := &Service{Store: &identityStore{mutationErr: ErrFinalAdministrator}, Audit: recorder}
	ctx := audit.WithRequestID(t.Context(), "request-42")
	principal := authn.Principal{Subject: "7", Method: "oidc", Administrator: true}
	if err := service.ReplaceUserAccess(ctx, principal, 8, false, nil); !errors.Is(err, ErrFinalAdministrator) {
		t.Fatalf("error=%v", err)
	}
	if len(recorder.events) != 1 || recorder.events[0].TargetID != "8" ||
		recorder.events[0].RequestID != "request-42" {
		t.Fatalf("events=%#v", recorder.events)
	}
}
func (store *identityStore) RevokeAdminUserCredentials(_ context.Context, userID int64) error {
	store.revokedUserID = userID
	return nil
}
func (store *identityStore) SuspendAdminUserAudited(ctx context.Context, actorID, userID int64, suspended bool, _ audit.Event) error {
	return store.SuspendAdminUser(ctx, actorID, userID, suspended)
}
func (store *identityStore) ReplaceAdminUserAccessAudited(ctx context.Context, actorID, userID int64, administrator bool, repositoryIDs []int64, _ audit.Event) error {
	return store.ReplaceAdminUserAccess(ctx, actorID, userID, administrator, repositoryIDs)
}
func (store *identityStore) ReplaceAdminGroupAccessAudited(ctx context.Context, actorID, groupID int64, administrator bool, repositoryIDs []int64, _ audit.Event) error {
	return store.ReplaceAdminGroupAccess(ctx, actorID, groupID, administrator, repositoryIDs)
}
func (store *identityStore) RevokeAdminUserCredentialsAudited(ctx context.Context, userID int64, _ audit.Event) error {
	return store.RevokeAdminUserCredentials(ctx, userID)
}

func (*identityStore) AdminOverview(context.Context, int64, []int64) (Overview, error) {
	return Overview{}, nil
}
func (*identityStore) AdminRepositories(context.Context, int64, []int64, int) ([]Repository, bool, error) {
	return nil, false, nil
}
func (*identityStore) AdminJobs(context.Context, int64, []int64, int, *JobCursor) ([]Job, bool, error) {
	return nil, false, nil
}
func (*identityStore) AdminSCIPUploads(context.Context, int64, []int64, int) ([]SCIPUpload, bool, error) {
	return nil, false, nil
}
func (*identityStore) AdminSCIPDependencies(context.Context, int64, []int64, int) ([]SCIPDependency, bool, error) {
	return nil, false, nil
}
func (*identityStore) AdminDeliveries(context.Context, int64, []int64, int) ([]Delivery, bool, error) {
	return nil, false, nil
}
func (*identityStore) AdminGitHub(context.Context, int64, []int64, GitHubConfig, int) (GitHub, error) {
	return GitHub{}, nil
}
func (*identityStore) AdminRepository(context.Context, int64, []int64, int64) (repository.Repository, error) {
	return repository.Repository{}, nil
}
func (*identityStore) AnyAuthorizedRepository(context.Context, int64) (repository.Repository, error) {
	return repository.Repository{}, nil
}
func (*identityStore) EnqueueAdminIndex(context.Context, IndexRequest) error { return nil }
func (*identityStore) RetryAdminJob(context.Context, int64, []int64, int64) error {
	return nil
}
func (*identityStore) ReconcileAdminRepositories(context.Context, int64, []int64, []githubapp.Repository) error {
	return nil
}
