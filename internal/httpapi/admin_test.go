package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/admin"
	"github.com/grepnest/grepnest/internal/audit"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/githubapp"
	"github.com/grepnest/grepnest/internal/repository"
	"github.com/jackc/pgx/v5"
)

func TestAdminRoutesRequireAdministrator(t *testing.T) {
	mux := http.NewServeMux()
	RegisterAdmin(mux, requestAuthenticator(authn.NewStatic(map[string]authn.Principal{
		"user":  {Subject: "user"},
		"admin": {Subject: "admin", Administrator: true, InstallationID: 10, RepositoryIDs: []int64{101}},
	})), &admin.Service{Store: &adminHTTPStore{}, GitHub: adminHTTPGitHub{}}, 2, 1024, 4096)

	for _, token := range []string{"", "user"} {
		request := httptest.NewRequest(http.MethodGet, "/v1/admin/overview", nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		want := http.StatusUnauthorized
		if token == "user" {
			want = http.StatusForbidden
		}
		if response.Code != want || strings.Contains(response.Body.String(), "secret") {
			t.Fatalf("token=%q status=%d body=%q", token, response.Code, response.Body.String())
		}
	}
}

func TestAdminRouteAcceptsAdministratorSession(t *testing.T) {
	mux := http.NewServeMux()
	RegisterAdmin(mux, authn.RequestAuthenticator{Session: httpSession{principal: authn.Principal{Administrator: true, InstallationID: 10, RepositoryIDs: []int64{101}}}}, &admin.Service{Store: &adminHTTPStore{}, GitHub: adminHTTPGitHub{}}, 2, 1024, 4096)
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/overview", nil)
	request.AddCookie(&http.Cookie{Name: authn.SessionCookieName, Value: "session"})
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAdminJobsPaginatesWithOpaqueCursor(t *testing.T) {
	store := &adminHTTPStore{jobPages: true}
	mux := http.NewServeMux()
	RegisterAdmin(mux, requestAuthenticator(authn.NewStatic(map[string]authn.Principal{
		"admin": {Administrator: true, InstallationID: 10, RepositoryIDs: []int64{101}},
	})), &admin.Service{Store: store, GitHub: adminHTTPGitHub{}}, 100, 1024, 64<<10)

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/jobs", nil)
	request.Header.Set("Authorization", "Bearer admin")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	var first struct {
		Jobs       []admin.Job `json:"jobs"`
		Truncated  bool        `json:"truncated"`
		NextCursor string      `json:"next_cursor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(first.Jobs) != 25 || !first.Truncated || first.NextCursor == "" {
		t.Fatalf("status=%d response=%#v body=%s", response.Code, first, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/admin/jobs?cursor="+first.NextCursor, nil)
	request.Header.Set("Authorization", "Bearer admin")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	var final map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &final); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || string(final["truncated"]) != "false" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, ok := final["next_cursor"]; ok {
		t.Fatalf("final response contains next_cursor: %s", response.Body.String())
	}
	last := first.Jobs[len(first.Jobs)-1]
	if store.jobsCursor == nil || store.jobsCursor.ID != last.ID || !store.jobsCursor.UpdatedAt.Equal(last.UpdatedAt) {
		t.Fatalf("cursor=%#v last=%#v", store.jobsCursor, last)
	}
}

func TestAdminJobsRejectsInvalidCursors(t *testing.T) {
	validTime := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	encode := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	for name, cursor := range map[string]string{
		"not base64":          "not-base64",
		"unsupported version": encode(`{"v":2,"updated_at":"` + validTime + `","id":1}`),
		"malformed timestamp": encode(`{"v":1,"updated_at":"not-a-timestamp","id":1}`),
		"zero timestamp":      encode(`{"v":1,"updated_at":"0001-01-01T00:00:00Z","id":1}`),
		"zero ID":             encode(`{"v":1,"updated_at":"` + validTime + `","id":0}`),
		"second JSON value":   encode(`{"v":1,"updated_at":"` + validTime + `","id":1} {}`),
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			RegisterAdmin(mux, requestAuthenticator(authn.NewStatic(map[string]authn.Principal{
				"admin": {Administrator: true},
			})), &admin.Service{Store: &adminHTTPStore{}, GitHub: adminHTTPGitHub{}}, 100, 1024, 4096)
			request := httptest.NewRequest(http.MethodGet, "/v1/admin/jobs?cursor="+cursor, nil)
			request.Header.Set("Authorization", "Bearer admin")
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestAdminReconcileRejectsAdministratorAPIToken(t *testing.T) {
	mux := http.NewServeMux()
	RegisterAdmin(mux, requestAuthenticator(authn.NewStatic(map[string]authn.Principal{
		"token": {Method: "api_token", Administrator: true, RepositoryIDs: []int64{101}},
	})), &admin.Service{Store: &adminHTTPStore{}, GitHub: adminHTTPGitHub{}}, 2, 1024, 4096)
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/reconcile", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAdminRoutesExposeBoundedDataAndActions(t *testing.T) {
	store := &adminHTTPStore{}
	service := &admin.Service{Store: store, GitHub: adminHTTPGitHub{}}
	mux := http.NewServeMux()
	RegisterAdmin(mux, requestAuthenticator(authn.NewStatic(map[string]authn.Principal{
		"admin": {Administrator: true, InstallationID: 10, RepositoryIDs: []int64{101}},
	})), service, 2, 1024, 4096)

	for _, path := range []string{
		"/v1/admin/overview", "/v1/admin/repositories", "/v1/admin/jobs",
		"/v1/admin/scip/uploads", "/v1/admin/scip/dependencies",
		"/v1/admin/webhook-deliveries", "/v1/admin/github",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer admin")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Body.Len() > 4096 {
			t.Fatalf("%s status=%d bytes=%d body=%q", path, response.Code, response.Body.Len(), response.Body.String())
		}
		if path == "/v1/admin/overview" && strings.Contains(response.Body.String(), "search_nodes") {
			t.Fatalf("overview exposed unsupported search-node metrics: %q", response.Body.String())
		}
		if path == "/v1/admin/github" && (strings.Contains(response.Body.String(), "private_key_file") ||
			strings.Contains(response.Body.String(), "webhook_secret_file")) {
			t.Fatalf("GitHub response exposed secret: %q", response.Body.String())
		}
	}

	for _, path := range []string{
		"/v1/admin/repositories/101/reindex",
		"/v1/admin/reconcile",
		"/v1/admin/jobs/42/retry",
	} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		request.Header.Set("Authorization", "Bearer admin")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s status=%d body=%q", path, response.Code, response.Body.String())
		}
	}
	if store.reindexed != 7 || store.retried != 42 {
		t.Fatalf("reindexed=%d retried=%d", store.reindexed, store.retried)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/admin/repositories/202/reindex", nil)
	request.Header.Set("Authorization", "Bearer admin")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-scope reindex status=%d body=%q", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/admin/jobs/99/retry", nil)
	request.Header.Set("Authorization", "Bearer admin")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-scope retry status=%d body=%q", response.Code, response.Body.String())
	}
}

type adminHTTPStore struct {
	reindexed       int64
	retried         int64
	identityErr     error
	identityActorID int64
	identityUserID  int64
	identityGroupID int64
	administrator   bool
	suspended       bool
	repositoryIDs   []int64
	revokedUserID   int64
	auditEvents     []audit.Event
	jobPages        bool
	jobsCursor      *admin.JobCursor
}

func (store *adminHTTPStore) AuditEvents(context.Context, int) ([]audit.Event, bool, error) {
	return store.auditEvents, true, store.identityErr
}

func (adminHTTPStore) AdminOverview(context.Context, int64, []int64) (admin.Overview, error) {
	return admin.Overview{Repositories: map[string]int64{"ready": 1}}, nil
}
func (adminHTTPStore) AdminRepositories(context.Context, int64, []int64, int) ([]admin.Repository, bool, error) {
	return []admin.Repository{{GitHubID: 101, Name: "acme/one"}}, false, nil
}
func (store *adminHTTPStore) AdminJobs(_ context.Context, _ int64, _ []int64, limit int, cursor *admin.JobCursor) ([]admin.Job, bool, error) {
	if !store.jobPages {
		return []admin.Job{{ID: 42, RepositoryID: 101}}, false, nil
	}
	store.jobsCursor = cursor
	if cursor != nil {
		return []admin.Job{{ID: 1, RepositoryID: 101}}, false, nil
	}
	jobs := make([]admin.Job, limit)
	for i := range jobs {
		jobs[i] = admin.Job{ID: int64(limit - i), RepositoryID: 101, UpdatedAt: time.Date(2026, 8, 5, 12, 0, i, 0, time.UTC)}
	}
	return jobs, true, nil
}
func (adminHTTPStore) AdminSCIPUploads(context.Context, int64, []int64, int) ([]admin.SCIPUpload, bool, error) {
	return []admin.SCIPUpload{}, false, nil
}
func (adminHTTPStore) AdminSCIPDependencies(context.Context, int64, []int64, int) ([]admin.SCIPDependency, bool, error) {
	return []admin.SCIPDependency{}, false, nil
}
func (adminHTTPStore) AdminDeliveries(context.Context, int64, []int64, int) ([]admin.Delivery, bool, error) {
	return []admin.Delivery{}, false, nil
}
func (adminHTTPStore) AdminGitHub(context.Context, int64, []int64, admin.GitHubConfig, int) (admin.GitHub, error) {
	return admin.GitHub{AppID: 7, PrivateKeyConfigured: true, WebhookSecretConfigured: true}, nil
}
func (adminHTTPStore) AdminRepository(_ context.Context, installationID int64, repositoryIDs []int64, githubID int64) (repository.Repository, error) {
	if installationID != 10 || len(repositoryIDs) != 1 || repositoryIDs[0] != 101 || githubID != 101 {
		return repository.Repository{}, pgx.ErrNoRows
	}
	return repository.Repository{ID: 7, InstallationID: 10, GitHubID: 101, Name: "acme/one", Branch: "main", Enabled: true}, nil
}
func (adminHTTPStore) AnyAuthorizedRepository(_ context.Context, githubID int64) (repository.Repository, error) {
	return repository.Repository{ID: 7, InstallationID: 10, GitHubID: githubID, Name: "acme/one", Branch: "main", Enabled: true}, nil
}
func (store *adminHTTPStore) EnqueueAdminIndex(_ context.Context, request admin.IndexRequest) error {
	store.reindexed = request.RepositoryID
	return nil
}
func (store *adminHTTPStore) RetryAdminJob(_ context.Context, installationID int64, repositoryIDs []int64, id int64) error {
	if installationID != 10 || len(repositoryIDs) != 1 || repositoryIDs[0] != 101 || id != 42 {
		return pgx.ErrNoRows
	}
	store.retried = id
	return nil
}
func (*adminHTTPStore) ReconcileAdminRepositories(context.Context, int64, []int64, []githubapp.Repository) error {
	return nil
}

type adminHTTPGitHub struct{}

func (adminHTTPGitHub) DefaultBranchSHA(context.Context, int64, string, string, string) (string, error) {
	return strings.Repeat("a", 40), nil
}
func (adminHTTPGitHub) InstallationRepositories(context.Context, int64) ([]githubapp.Repository, error) {
	return []githubapp.Repository{{ID: 101, InstallationID: 10, Owner: "acme", Name: "one", DefaultBranch: "main"}}, nil
}
