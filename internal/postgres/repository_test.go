//go:build integration

package postgres

import (
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/admin"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/githubapp"
)

func migratedStore(t *testing.T) *Store {
	t.Helper()
	pool := testPool(t)
	if err := Migrate(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	return New(pool)
}

func TestRepositoryStorePreservesDurableIDs(t *testing.T) {
	store := migratedStore(t)
	if err := store.UpsertInstallation(t.Context(), InstallationUpdate{GitHubID: 10, AccountLogin: "acme", AccountType: "Organization", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	got, err := store.UpsertRepository(t.Context(), RepositoryUpdate{GitHubID: 101, InstallationID: 10, Owner: "acme", Name: "one", CloneURL: "https://example.invalid/acme/one.git", WebURL: "https://example.invalid/acme/one", DefaultBranch: "main", SizeBytes: 123456, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.InstallationID != 10 || got.GitHubID != 101 || got.Name != "acme/one" || got.ZoektID == 0 || got.SizeBytes != 123456 {
		t.Fatalf("got %#v", got)
	}
	for _, check := range []struct {
		name string
		fn   func() (string, error)
	}{
		{"index lookup", func() (string, error) {
			repository, err := store.RepositoryForIndex(t.Context(), got.ID)
			if err == nil && repository.SizeBytes != 123456 {
				t.Fatalf("repository size = %d", repository.SizeBytes)
			}
			return repository.Name, err
		}},
		{"desired sha", func() (string, error) { return store.DesiredSHA(t.Context(), got.ID) }},
	} {
		value, err := check.fn()
		if check.name == "desired sha" && value != "" || err != nil || check.name == "index lookup" && value != "acme/one" {
			t.Fatalf("%s: value=%q err=%v", check.name, value, err)
		}
	}
	if err := store.UpsertSearchNode(t.Context(), "node-a", "http://zoekt.invalid"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertSearchNode(t.Context(), "node-b", "http://zoekt-b.invalid"); err != nil {
		t.Fatal(err)
	}
	authorized, err := store.AuthorizedRepository(t.Context(), 10, []int64{101}, 101)
	if err != nil || authorized.SearchNode != "node-b" {
		t.Fatalf("authorized repository = %#v, err=%v", authorized, err)
	}
	var nodes int
	var nodeID, baseURL string
	if err := store.pool.QueryRow(t.Context(), "select count(*), min(node_id), min(base_url) from search_nodes").Scan(&nodes, &nodeID, &baseURL); err != nil || nodes != 1 || nodeID != "node-b" || baseURL != "http://zoekt-b.invalid" {
		t.Fatalf("nodes=%d nodeID=%q baseURL=%q err=%v", nodes, nodeID, baseURL, err)
	}
}

func TestReconcileInstallationCoalescesQuietDefaultHeads(t *testing.T) {
	store := migratedStore(t)
	installation := githubapp.Installation{ID: 10, AccountLogin: "acme", AccountType: "Organization", Status: "active"}
	repository := githubapp.Repository{ID: 101, InstallationID: 10, Owner: "acme", Name: "one", CloneURL: "clone", HTMLURL: "web", DefaultBranch: "main", DefaultSHA: testSHA('a')}

	if err := store.ReconcileInstallation(t.Context(), installation, []githubapp.Repository{repository}); err != nil {
		t.Fatal(err)
	}
	firstID, firstZoektID := reconciledRepositoryIDs(t, store, 101)
	assertReconciledRepository(t, store, 101, "acme", "one", "main", testSHA('a'), true, false, 1)

	repository.Owner, repository.Name = "renamed", "quiet"
	replacement := githubapp.Repository{ID: 102, InstallationID: 10, Owner: "acme", Name: "one", CloneURL: "replacement-clone", HTMLURL: "replacement-web", DefaultBranch: "main", DefaultSHA: testSHA('d')}
	if err := store.ReconcileInstallation(t.Context(), installation, []githubapp.Repository{replacement, repository}); err != nil {
		t.Fatal(err)
	}
	assertReconciledRepository(t, store, 101, "renamed", "quiet", "main", testSHA('a'), true, false, 1)
	assertReconciledRepository(t, store, 102, "acme", "one", "main", testSHA('d'), true, false, 1)

	repository.DefaultBranch, repository.DefaultSHA = "trunk", testSHA('b')
	if err := store.ReconcileInstallation(t.Context(), installation, []githubapp.Repository{repository}); err != nil {
		t.Fatal(err)
	}
	assertReconciledRepository(t, store, 101, "renamed", "quiet", "trunk", testSHA('b'), true, false, 1)

	repository.DefaultSHA = testSHA('c')
	if err := store.ReconcileInstallation(t.Context(), installation, []githubapp.Repository{repository}); err != nil {
		t.Fatal(err)
	}
	assertReconciledRepository(t, store, 101, "renamed", "quiet", "trunk", testSHA('c'), true, false, 1)
	if id, zoektID := reconciledRepositoryIDs(t, store, 101); id != firstID || zoektID != firstZoektID {
		t.Fatalf("IDs changed from (%d,%d) to (%d,%d)", firstID, firstZoektID, id, zoektID)
	}

	repository.Archived = true
	if err := store.ReconcileInstallation(t.Context(), installation, []githubapp.Repository{repository}); err != nil {
		t.Fatal(err)
	}
	assertReconciledRepository(t, store, 101, "renamed", "quiet", "trunk", testSHA('c'), false, true, 0)
	assertUnavailableJobs(t, store, 101, 1)
	repository.Archived = false
	if err := store.ReconcileInstallation(t.Context(), installation, []githubapp.Repository{repository}); err != nil {
		t.Fatal(err)
	}
	assertRepositoryState(t, store, 101, "pending", "")

	if err := store.ReconcileInstallation(t.Context(), installation, nil); err != nil {
		t.Fatal(err)
	}
	assertReconciledRepository(t, store, 101, "renamed", "quiet", "trunk", testSHA('c'), false, false, 0)
	assertUnavailableJobs(t, store, 101, 2)
	recreated := githubapp.Repository{ID: 103, InstallationID: 10, Owner: "acme", Name: "one", CloneURL: "recreated-clone", HTMLURL: "recreated-web", DefaultBranch: "main", DefaultSHA: testSHA('e')}
	if err := store.ReconcileInstallation(t.Context(), installation, []githubapp.Repository{recreated}); err != nil {
		t.Fatal(err)
	}
	assertReconciledRepository(t, store, 103, "acme", "one", "main", testSHA('e'), true, false, 1)

	installation.Status = "suspended"
	repository.Archived = false
	if err := store.ReconcileInstallation(t.Context(), installation, []githubapp.Repository{repository}); err != nil {
		t.Fatal(err)
	}
	assertReconciledRepository(t, store, 101, "renamed", "quiet", "trunk", testSHA('c'), false, false, 0)
	assertUnavailableJobs(t, store, 101, 2)

	ids, err := store.InstallationIDs(t.Context())
	if err != nil || len(ids) != 1 || ids[0] != 10 {
		t.Fatalf("installation IDs = %v, err = %v", ids, err)
	}
	if err := store.DisableInstallation(t.Context(), 10, "deleted"); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := store.pool.QueryRow(t.Context(), "select status from installations where github_id=10").Scan(&status); err != nil || status != "deleted" {
		t.Fatalf("status = %q, err = %v", status, err)
	}
}

func reconciledRepositoryIDs(t *testing.T, store *Store, githubID int64) (int64, int64) {
	t.Helper()
	var id, zoektID int64
	if err := store.pool.QueryRow(t.Context(), "select id, zoekt_repo_id from repositories where github_id=$1", githubID).Scan(&id, &zoektID); err != nil {
		t.Fatal(err)
	}
	return id, zoektID
}

func assertReconciledRepository(t *testing.T, store *Store, githubID int64, owner, name, branch, desiredSHA string, enabled, archived bool, jobs int) {
	t.Helper()
	var gotOwner, gotName, gotBranch, gotSHA string
	var gotEnabled, gotArchived bool
	if err := store.pool.QueryRow(t.Context(), `select owner, name, default_branch, coalesce(desired_sha, ''), enabled, archived from repositories where github_id=$1`, githubID).Scan(&gotOwner, &gotName, &gotBranch, &gotSHA, &gotEnabled, &gotArchived); err != nil {
		t.Fatal(err)
	}
	var gotJobs int
	if err := store.pool.QueryRow(t.Context(), `select count(*) from index_jobs where repository_id=(select id from repositories where github_id=$1) and state='queued'`, githubID).Scan(&gotJobs); err != nil {
		t.Fatal(err)
	}
	if gotOwner != owner || gotName != name || gotBranch != branch || gotSHA != desiredSHA || gotEnabled != enabled || gotArchived != archived || gotJobs != jobs {
		t.Fatalf("metadata=(%q,%q,%q,%q,%v,%v) jobs=%d", gotOwner, gotName, gotBranch, gotSHA, gotEnabled, gotArchived, gotJobs)
	}
}

func assertRepositoryState(t *testing.T, store *Store, githubID int64, status, errorCode string) {
	t.Helper()
	var gotStatus, gotError string
	if err := store.pool.QueryRow(t.Context(), `select status, coalesce(error_code, '') from repositories where github_id=$1`, githubID).Scan(&gotStatus, &gotError); err != nil {
		t.Fatal(err)
	}
	if gotStatus != status || gotError != errorCode {
		t.Fatalf("status=%q error=%q", gotStatus, gotError)
	}
}

func assertUnavailableJobs(t *testing.T, store *Store, githubID int64, want int) {
	t.Helper()
	var got int
	if err := store.pool.QueryRow(t.Context(), `select count(*) from index_jobs
		where repository_id=(select id from repositories where github_id=$1)
		and state='superseded' and error_code='repository_unavailable'`, githubID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("unavailable jobs=%d want=%d", got, want)
	}
}

func testSHA(character byte) string {
	result := make([]byte, 40)
	for index := range result {
		result[index] = character
	}
	return string(result)
}

func TestAuthorizedRepositoriesExcludeInactiveStates(t *testing.T) {
	store := migratedStore(t)
	for _, update := range []InstallationUpdate{
		{GitHubID: 10, AccountLogin: "active", AccountType: "Organization", Status: "active"},
		{GitHubID: 20, AccountLogin: "disabled", AccountType: "Organization", Status: "suspended", SuspendedAt: timePtr(time.Now())},
	} {
		if err := store.UpsertInstallation(t.Context(), update); err != nil {
			t.Fatal(err)
		}
	}
	for _, update := range []RepositoryUpdate{
		{GitHubID: 101, InstallationID: 10, Owner: "acme", Name: "enabled", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true},
		{GitHubID: 102, InstallationID: 10, Owner: "acme", Name: "disabled", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: false},
		{GitHubID: 103, InstallationID: 10, Owner: "acme", Name: "archived", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true, Archived: true},
		{GitHubID: 201, InstallationID: 20, Owner: "other", Name: "suspended", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true},
	} {
		if _, err := store.UpsertRepository(t.Context(), update); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.AuthorizedRepositories(t.Context(), 10, []int64{101, 102, 103, 201}, nil)
	if err != nil || len(got) != 1 || got[0].GitHubID != 101 {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if got, err := store.AuthorizedRepositories(t.Context(), 10, nil, nil); err != nil || len(got) != 0 {
		t.Fatalf("empty IDs: got=%#v err=%v", got, err)
	}
}

func TestGraphRepositoriesEnforcePrincipalEligibility(t *testing.T) {
	store := migratedStore(t)
	for _, installation := range []InstallationUpdate{
		{GitHubID: 10, AccountLogin: "active", AccountType: "Organization", Status: "active"},
		{GitHubID: 20, AccountLogin: "other", AccountType: "Organization", Status: "active"},
		{GitHubID: 30, AccountLogin: "suspended", AccountType: "Organization", Status: "suspended"},
	} {
		if err := store.UpsertInstallation(t.Context(), installation); err != nil {
			t.Fatal(err)
		}
	}
	for _, update := range []RepositoryUpdate{
		{GitHubID: 101, InstallationID: 10, Owner: "Acme", Name: "One", DefaultBranch: "main", Enabled: true},
		{GitHubID: 102, InstallationID: 10, Owner: "acme", Name: "disabled", DefaultBranch: "main"},
		{GitHubID: 103, InstallationID: 10, Owner: "acme", Name: "archived", DefaultBranch: "main", Enabled: true, Archived: true},
		{GitHubID: 201, InstallationID: 20, Owner: "other", Name: "two", DefaultBranch: "main", Enabled: true},
		{GitHubID: 202, InstallationID: 20, Owner: "Acme", Name: "One", DefaultBranch: "main", Enabled: true},
		{GitHubID: 301, InstallationID: 30, Owner: "other", Name: "suspended", DefaultBranch: "main", Enabled: true},
	} {
		if _, err := store.UpsertRepository(t.Context(), update); err != nil {
			t.Fatal(err)
		}
	}
	user, err := store.GraphRepositories(t.Context(), authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101, 201}})
	if err != nil || len(user) != 1 || user[0].GitHubID != 101 || user[0].Name != "Acme/One" {
		t.Fatalf("user repositories = %#v, %v", user, err)
	}
	for _, repositoryIDs := range [][]int64{nil, {}} {
		got, err := store.GraphRepositories(t.Context(), authn.Principal{InstallationID: 10, RepositoryIDs: repositoryIDs})
		if err != nil || len(got) != 0 {
			t.Fatalf("empty repository IDs = %#v, %v", got, err)
		}
	}
	admin, err := store.GraphRepositories(t.Context(), authn.Principal{Administrator: true})
	if err != nil || len(admin) != 3 || admin[0].GitHubID != 101 || admin[1].GitHubID != 202 || admin[2].GitHubID != 201 {
		t.Fatalf("admin repositories = %#v, %v", admin, err)
	}
}

func timePtr(value time.Time) *time.Time { return &value }

func TestAdminJobsPaginatesAuthorizedJobs(t *testing.T) {
	store := migratedStore(t)
	repositoryID := queueRepository(t, store)
	if err := store.UpsertInstallation(t.Context(), InstallationUpdate{GitHubID: 20, AccountLogin: "other", AccountType: "Organization", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	other, err := store.UpsertRepository(t.Context(), RepositoryUpdate{GitHubID: 202, InstallationID: 20, Owner: "other", Name: "two", DefaultBranch: "main", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(t.Context(), `insert into index_jobs(repository_id,target_sha,state,updated_at)
		select $1,$2,'succeeded',$3::timestamptz+series*interval '1 second' from generate_series(1,27) series`,
		repositoryID, shaA, time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	var unauthorizedID int64
	if err := store.pool.QueryRow(t.Context(), `insert into index_jobs(repository_id,target_sha,state,updated_at)
		values($1,$2,'succeeded',$3) returning id`, other.ID, shaB, time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC)).Scan(&unauthorizedID); err != nil {
		t.Fatal(err)
	}

	first, more, err := store.AdminJobs(t.Context(), 10, []int64{101}, 25, nil)
	if err != nil || len(first) != 25 || !more {
		t.Fatalf("first page length=%d more=%v err=%v", len(first), more, err)
	}
	cursor := &admin.JobCursor{UpdatedAt: first[len(first)-1].UpdatedAt, ID: first[len(first)-1].ID}
	second, more, err := store.AdminJobs(t.Context(), 10, []int64{101}, 25, cursor)
	if err != nil || len(second) != 2 || more {
		t.Fatalf("second page=%#v more=%v err=%v", second, more, err)
	}
	seen := make(map[int64]bool, len(first))
	for _, job := range first {
		seen[job.ID] = true
		if job.ID == unauthorizedID {
			t.Fatal("unauthorized job appeared on first page")
		}
	}
	for _, job := range second {
		if seen[job.ID] {
			t.Fatalf("job %d appears on both pages", job.ID)
		}
		if job.ID == unauthorizedID {
			t.Fatal("unauthorized job appeared on second page")
		}
	}
}

func TestAdminDataIsBoundedAndSanitized(t *testing.T) {
	store := migratedStore(t)
	repositoryID := queueRepository(t, store)
	if err := store.UpsertInstallation(t.Context(), InstallationUpdate{GitHubID: 20, AccountLogin: "other", AccountType: "Organization", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	other, err := store.UpsertRepository(t.Context(), RepositoryUpdate{GitHubID: 202, InstallationID: 20, Owner: "other", Name: "two", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnqueueIndex(t.Context(), IndexRequest{RepositoryID: repositoryID, TargetSHA: shaA}); err != nil {
		t.Fatal(err)
	}
	if err := store.EnqueueIndex(t.Context(), IndexRequest{RepositoryID: other.ID, TargetSHA: shaB}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertRepository(t.Context(), RepositoryUpdate{GitHubID: 102, InstallationID: 10, Owner: "acme", Name: "unscoped", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(t.Context(), `insert into scip_uploads(repository_id, commit, project_root, indexer_name, indexer_version)
		values($1,$2,'','scip-go','1')`, repositoryID, shaA); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(t.Context(), `insert into repository_packages(repository_id,source,relation,purl,manager,name,version)
		values($1,'manual','depends_on','pkg:golang/example.com/dep@v1','golang','example.com/dep','v1')`, repositoryID); err != nil {
		t.Fatal(err)
	}
	repositories, truncated, err := store.AdminRepositories(t.Context(), 10, []int64{101}, 10)
	if err != nil || len(repositories) != 1 || truncated {
		t.Fatalf("repositories=%#v truncated=%v err=%v", repositories, truncated, err)
	}
	jobs, _, err := store.AdminJobs(t.Context(), 10, []int64{101}, 10, nil)
	if err != nil || len(jobs) != 1 || jobs[0].RepositoryID != 101 {
		t.Fatalf("jobs=%#v err=%v", jobs, err)
	}
	uploads, _, err := store.AdminSCIPUploads(t.Context(), 10, []int64{101}, 10)
	if err != nil || len(uploads) != 1 || uploads[0].RepositoryID != 101 {
		t.Fatalf("uploads=%#v err=%v", uploads, err)
	}
	dependencies, _, err := store.AdminSCIPDependencies(t.Context(), 10, []int64{101}, 10)
	if err != nil || len(dependencies) != 1 || dependencies[0].PURL != "pkg:golang/example.com/dep@v1" {
		t.Fatalf("dependencies=%#v err=%v", dependencies, err)
	}
	overview, err := store.AdminOverview(t.Context(), 10, []int64{101})
	if err != nil || overview.Repositories["pending"] != 1 || overview.Jobs["queued"] != 1 ||
		overview.SCIPUploads != 1 || overview.Dependencies != 1 || overview.Installations != 1 ||
		len(overview.Deliveries) != 0 {
		t.Fatalf("overview=%#v err=%v", overview, err)
	}
	github, err := store.AdminGitHub(t.Context(), 10, []int64{101}, admin.GitHubConfig{
		AppID: 7, WebURL: "https://github.example", PrivateKeyConfigured: true, WebhookSecretConfigured: true,
	}, 1)
	if err != nil || github.AppID != 7 || len(github.Installations) != 1 ||
		github.Installations[0].GitHubID != 10 || !github.PrivateKeyConfigured || !github.WebhookSecretConfigured {
		t.Fatalf("github=%#v err=%v", github, err)
	}
	if _, err := store.AdminRepository(t.Context(), 10, []int64{101}, 202); err == nil {
		t.Fatal("cross-scope repository was accessible")
	}
	if _, err := store.AdminRepository(t.Context(), 10, []int64{101}, 102); err == nil {
		t.Fatal("same-installation unscoped repository was accessible")
	}
}

func TestDurableAdministratorInventoryUsesGlobalEligibleRepositories(t *testing.T) {
	store := migratedStore(t)
	for _, installation := range []InstallationUpdate{
		{GitHubID: 10, AccountLogin: "acme", AccountType: "Organization", Status: "active"},
		{GitHubID: 20, AccountLogin: "other", AccountType: "Organization", Status: "active"},
		{GitHubID: 30, AccountLogin: "inactive", AccountType: "Organization", Status: "suspended"},
	} {
		if err := store.UpsertInstallation(t.Context(), installation); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []RepositoryUpdate{
		{GitHubID: 101, InstallationID: 10, Owner: "acme", Name: "one", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true},
		{GitHubID: 201, InstallationID: 20, Owner: "other", Name: "two", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true},
		{GitHubID: 202, InstallationID: 20, Owner: "other", Name: "disabled", CloneURL: "clone", WebURL: "web", DefaultBranch: "main"},
		{GitHubID: 203, InstallationID: 20, Owner: "other", Name: "archived", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true, Archived: true},
		{GitHubID: 301, InstallationID: 30, Owner: "inactive", Name: "three", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true},
	} {
		if _, err := store.UpsertRepository(t.Context(), item); err != nil {
			t.Fatal(err)
		}
	}

	repositories, truncated, err := store.AdminRepositories(t.Context(), 0, nil, 10)
	if err != nil || truncated || len(repositories) != 2 ||
		repositories[0].GitHubID != 101 || repositories[1].GitHubID != 201 {
		t.Fatalf("repositories=%#v truncated=%v err=%v", repositories, truncated, err)
	}
	if repository, err := store.AdminRepository(t.Context(), 0, nil, 201); err != nil || repository.GitHubID != 201 {
		t.Fatalf("repository=%#v err=%v", repository, err)
	}
	overview, err := store.AdminOverview(t.Context(), 0, nil)
	if err != nil || overview.Repositories["pending"] != 2 || overview.Installations != 2 {
		t.Fatalf("overview=%#v err=%v", overview, err)
	}
}

func TestAdministratorAPITokenInventoryUsesOnlyRepositoryCeiling(t *testing.T) {
	store := migratedStore(t)
	for _, installation := range []InstallationUpdate{
		{GitHubID: 10, AccountLogin: "acme", AccountType: "Organization", Status: "active"},
		{GitHubID: 20, AccountLogin: "other", AccountType: "Organization", Status: "active"},
	} {
		if err := store.UpsertInstallation(t.Context(), installation); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []RepositoryUpdate{
		{GitHubID: 101, InstallationID: 10, Owner: "acme", Name: "one", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true},
		{GitHubID: 201, InstallationID: 20, Owner: "other", Name: "two", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true},
	} {
		if _, err := store.UpsertRepository(t.Context(), item); err != nil {
			t.Fatal(err)
		}
	}

	repositories, _, err := store.AdminRepositories(t.Context(), 0, []int64{201}, 10)
	if err != nil || len(repositories) != 1 || repositories[0].GitHubID != 201 {
		t.Fatalf("repositories=%#v err=%v", repositories, err)
	}
	if _, err := store.AdminRepository(t.Context(), 0, []int64{201}, 101); err == nil {
		t.Fatal("repository outside API token ceiling was accessible")
	}
	overview, err := store.AdminOverview(t.Context(), 0, []int64{201})
	if err != nil || overview.Repositories["pending"] != 1 || overview.Installations != 1 {
		t.Fatalf("overview=%#v err=%v", overview, err)
	}
	github, err := store.AdminGitHub(t.Context(), 0, []int64{201}, admin.GitHubConfig{}, 10)
	if err != nil || len(github.Installations) != 1 || github.Installations[0].GitHubID != 20 {
		t.Fatalf("github=%#v err=%v", github, err)
	}
}

func TestAdminReconcileOnlyChangesScopedRepositories(t *testing.T) {
	store := migratedStore(t)
	queueRepository(t, store)
	if err := store.UpsertInstallation(t.Context(), InstallationUpdate{GitHubID: 20, AccountLogin: "other", AccountType: "Organization", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertRepository(t.Context(), RepositoryUpdate{GitHubID: 202, InstallationID: 20, Owner: "other", Name: "two", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertRepository(t.Context(), RepositoryUpdate{GitHubID: 102, InstallationID: 10, Owner: "acme", Name: "unscoped", CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileAdminRepositories(t.Context(), 10, []int64{101}, []githubapp.Repository{{
		ID: 101, InstallationID: 10, Owner: "renamed", Name: "one", CloneURL: "new-clone",
		HTMLURL: "new-web", DefaultBranch: "trunk", DefaultSHA: shaA,
	}}); err != nil {
		t.Fatal(err)
	}
	var owner, branch string
	if err := store.pool.QueryRow(t.Context(), "select owner,default_branch from repositories where github_id=101").Scan(&owner, &branch); err != nil || owner != "renamed" || branch != "trunk" {
		t.Fatalf("scoped repository owner=%q branch=%q err=%v", owner, branch, err)
	}
	if err := store.pool.QueryRow(t.Context(), "select owner,default_branch from repositories where github_id=202").Scan(&owner, &branch); err != nil || owner != "other" || branch != "main" {
		t.Fatalf("cross-scope repository owner=%q branch=%q err=%v", owner, branch, err)
	}
	if err := store.pool.QueryRow(t.Context(), "select owner,default_branch from repositories where github_id=102").Scan(&owner, &branch); err != nil || owner != "acme" || branch != "main" {
		t.Fatalf("same-installation unscoped repository owner=%q branch=%q err=%v", owner, branch, err)
	}
}
