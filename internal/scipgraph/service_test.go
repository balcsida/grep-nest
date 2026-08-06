package scipgraph

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/githubapp"
	"github.com/grepnest/grepnest/internal/repository"
	"github.com/grepnest/grepnest/pkg/api"
	"github.com/scip-code/scip/bindings/go/scip"
)

var (
	serviceSHA        = strings.Repeat("a", 40)
	userPrincipal     = authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101}}
	adminPrincipal    = authn.Principal{Administrator: true, InstallationID: 10, RepositoryIDs: []int64{101}}
	serviceRepository = repository.Repository{ID: 1, GitHubID: 101, IndexedSHA: serviceSHA}
)

func TestUploadRequiresScopedAdministratorAndCurrentCommit(t *testing.T) {
	store := &fakeStore{repositories: map[int64]repository.Repository{101: serviceRepository}}
	service := Service{Store: store}
	data := marshalIndex(t, &scip.Index{Metadata: &scip.Metadata{ToolInfo: &scip.ToolInfo{Name: "test"}}})

	if err := service.Upload(t.Context(), userPrincipal, 101, serviceSHA, data); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ordinary Upload() error = %v", err)
	}
	if err := service.Upload(t.Context(), adminPrincipal, 102, serviceSHA, data); !errors.Is(err, errUnauthorizedRepository) {
		t.Fatalf("unscoped administrator Upload() error = %v", err)
	}
	if err := service.Upload(t.Context(), adminPrincipal, 101, strings.Repeat("b", 40), data); !errors.Is(err, ErrNotIndexed) {
		t.Fatalf("stale Upload() error = %v", err)
	}
	if err := service.Upload(t.Context(), adminPrincipal, 101, serviceSHA, []byte("bad")); !errors.Is(err, ErrInvalidIndex) {
		t.Fatalf("invalid Upload() error = %v", err)
	}
	if err := service.Upload(t.Context(), adminPrincipal, 101, serviceSHA, data); err != nil {
		t.Fatal(err)
	}
	if store.replacedRepositoryID != 1 || store.replacedCommit != serviceSHA {
		t.Fatalf("ReplaceSCIP() = repository %d commit %q", store.replacedRepositoryID, store.replacedCommit)
	}
}

func TestUploadAllowsDurableAdministratorWithoutLegacyScope(t *testing.T) {
	store := &fakeStore{repositories: map[int64]repository.Repository{201: {
		ID: 2, InstallationID: 20, GitHubID: 201, IndexedSHA: serviceSHA,
	}}}
	data := marshalIndex(t, &scip.Index{Metadata: &scip.Metadata{ToolInfo: &scip.ToolInfo{Name: "test"}}})

	if err := (&Service{Store: store}).Upload(t.Context(), authn.Principal{
		Method: "oidc", Administrator: true,
	}, 201, serviceSHA, data); err != nil {
		t.Fatal(err)
	}
	if store.globalAuthorizationCalls != 1 || len(store.authorizationCalls) != 0 || store.replacedRepositoryID != 2 {
		t.Fatalf("global calls=%d scoped calls=%#v replaced=%d", store.globalAuthorizationCalls, store.authorizationCalls, store.replacedRepositoryID)
	}
}

func TestUploadAllowsLocalAdministratorWithoutLegacyScope(t *testing.T) {
	store := &fakeStore{repositories: map[int64]repository.Repository{201: {
		ID: 2, InstallationID: 20, GitHubID: 201, IndexedSHA: serviceSHA,
	}}}
	data := marshalIndex(t, &scip.Index{Metadata: &scip.Metadata{ToolInfo: &scip.ToolInfo{Name: "test"}}})

	if err := (&Service{Store: store}).Upload(t.Context(), authn.Principal{
		Method: "local", Administrator: true,
	}, 201, serviceSHA, data); err != nil {
		t.Fatal(err)
	}
	if store.globalAuthorizationCalls != 1 || len(store.authorizationCalls) != 0 || store.replacedRepositoryID != 2 {
		t.Fatalf("global calls=%d scoped calls=%#v replaced=%d", store.globalAuthorizationCalls, store.authorizationCalls, store.replacedRepositoryID)
	}
}

func TestUploadMapsStaleReplacementOnly(t *testing.T) {
	backendError := errors.New("backend unavailable")
	data := marshalIndex(t, &scip.Index{Metadata: &scip.Metadata{ToolInfo: &scip.ToolInfo{Name: "test"}}})
	for _, test := range []struct {
		name     string
		storeErr error
		wantErr  error
	}{
		{name: "indexed SHA changed", storeErr: ErrStaleIndex, wantErr: ErrNotIndexed},
		{name: "backend failure", storeErr: backendError, wantErr: backendError},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{repositories: map[int64]repository.Repository{101: serviceRepository}, replaceErr: test.storeErr}
			err := (&Service{Store: store}).Upload(t.Context(), adminPrincipal, 101, serviceSHA, data)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Upload() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestNavigateValidatesRequestAndUsesZeroBasedStorageLine(t *testing.T) {
	store := &fakeStore{repositories: map[int64]repository.Repository{101: serviceRepository}, origin: StoredOccurrence{RepositoryID: 1, Commit: serviceSHA}}
	service := Service{Store: store, MaxResults: 7}
	utf8, utf16, utf32 := 5, 4, 3
	request := api.SCIPNavigationRequest{
		RepositoryID: 101, Path: "a.go", Commit: serviceSHA, Line: 3,
		CharacterUTF8: &utf8, CharacterUTF16: &utf16, CharacterUTF32: &utf32,
		Operation: "definitions",
	}

	if _, err := service.Navigate(t.Context(), userPrincipal, request); err != nil {
		t.Fatal(err)
	}
	if store.occurrenceRepositoryID != 1 || store.occurrenceCommit != serviceSHA || store.occurrenceLine != 2 ||
		store.occurrencePosition != (OccurrencePosition{UTF8: 5, UTF16: 4, UTF32: 3}) || store.locationsMax != 7 {
		t.Fatalf("storage request = %#v", store)
	}

	for _, invalid := range []api.SCIPNavigationRequest{
		{RepositoryID: 101, Path: "a.go", Line: 0, Operation: "definitions"},
		{RepositoryID: 101, Path: "a.go", Line: 1 << 31, Operation: "definitions"},
		{RepositoryID: 101, Path: "../a.go", Line: 1, Operation: "definitions"},
		{RepositoryID: 101, Path: "a.go", Line: 1, Character: -1, Operation: "definitions"},
		{RepositoryID: 101, Path: "a.go", Line: 1, Character: 1 << 31, Operation: "definitions"},
		{RepositoryID: 101, Path: "a.go", Line: 1, Character: -1, CharacterUTF8: intPointer(0), CharacterUTF16: intPointer(0), CharacterUTF32: intPointer(0), Operation: "definitions"},
		{RepositoryID: 101, Path: "a.go", Line: 1, CharacterUTF8: intPointer(-1), CharacterUTF16: intPointer(0), CharacterUTF32: intPointer(0), Operation: "definitions"},
		{RepositoryID: 101, Path: "a.go", Line: 1, CharacterUTF8: intPointer(1 << 31), CharacterUTF16: intPointer(0), CharacterUTF32: intPointer(0), Operation: "definitions"},
		{RepositoryID: 101, Path: "a.go", Line: 1, CharacterUTF8: intPointer(0), CharacterUTF16: intPointer(1 << 31), CharacterUTF32: intPointer(0), Operation: "definitions"},
		{RepositoryID: 101, Path: "a.go", Line: 1, CharacterUTF8: intPointer(0), CharacterUTF16: intPointer(0), CharacterUTF32: intPointer(1 << 31), Operation: "definitions"},
		{RepositoryID: 101, Path: "a.go", Line: 1, CharacterUTF8: intPointer(0), Operation: "definitions"},
		{RepositoryID: 101, Path: "a.go", Commit: strings.Repeat("A", 40), Line: 1, Operation: "definitions"},
		{RepositoryID: 101, Path: "a.go", Line: 1, Operation: "unknown"},
	} {
		if _, err := service.Navigate(t.Context(), userPrincipal, invalid); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Navigate(%#v) error = %v", invalid, err)
		}
	}
}

func TestNavigateRejectsSuppliedStaleCommit(t *testing.T) {
	store := &fakeStore{repositories: map[int64]repository.Repository{101: serviceRepository}}
	_, err := (&Service{Store: store}).Navigate(t.Context(), userPrincipal, api.SCIPNavigationRequest{
		RepositoryID: 101,
		Path:         "a.go",
		Commit:       strings.Repeat("b", 40),
		Line:         1,
		Operation:    "definitions",
	})
	if !errors.Is(err, ErrStaleCommit) {
		t.Fatalf("Navigate() error = %v", err)
	}
	if store.occurrenceRepositoryID != 0 {
		t.Fatal("stale navigation reached occurrence lookup")
	}
}

func intPointer(value int) *int {
	return &value
}

func TestNavigateAuthorizesEveryLocationAndConvertsLines(t *testing.T) {
	principal := userPrincipal
	principal.RepositoryNames = []string{"acme/one"}
	target := serviceRepository
	target.Branch = "release/2026"
	store := &fakeStore{
		repositories: map[int64]repository.Repository{101: target},
		origin:       StoredOccurrence{RepositoryID: 1, Commit: serviceSHA},
		locations: []Location{
			{RepositoryID: 101, RepositoryName: "acme/one", WebURL: "https://github.example/acme/one", Commit: serviceSHA, Path: "allowed.go", StartLine: 2, EndLine: 3, PositionEncoding: 2, Approximate: true},
			{RepositoryID: 102, RepositoryName: "acme/two", Commit: serviceSHA, Path: "forbidden.go"},
			{RepositoryID: 101, RepositoryName: "acme/one", Commit: strings.Repeat("b", 40), Path: "stale.go"},
		},
		locationsTruncated: true,
	}
	service := Service{Store: store, MaxResults: 100}

	got, err := service.Navigate(t.Context(), principal, api.SCIPNavigationRequest{RepositoryID: 101, Path: "a.go", Line: 3, Character: 4, Operation: "definitions"})
	if err != nil || len(got.Locations) != 1 || got.Locations[0].RepositoryID != 101 || got.Locations[0].StartLine != 3 || got.Locations[0].EndLine != 4 ||
		got.Locations[0].WebURL != "https://github.example/acme/one" ||
		got.Locations[0].Branch != "release/2026" ||
		got.Locations[0].PositionEncoding != "UTF16CodeUnitOffsetFromLineStart" || !got.Locations[0].Approximate || !got.Truncated {
		t.Fatalf("Navigate() = %#v, %v", got, err)
	}
	if len(store.authorizationCalls) != 4 {
		t.Fatalf("AuthorizedRepository() calls = %#v", store.authorizationCalls)
	}
	for index, call := range store.authorizationCalls {
		if call.installationID != principal.InstallationID || len(call.repositoryIDs) != 1 || call.repositoryIDs[0] != 101 {
			t.Fatalf("AuthorizedRepository() call = %#v", call)
		}
		if want := []int64{101, 101, 102, 101}[index]; call.repositoryID != want {
			t.Fatalf("AuthorizedRepository() call %d repository = %d, want %d", index, call.repositoryID, want)
		}
	}
	if store.locationsPrincipal.InstallationID != principal.InstallationID || len(store.locationsPrincipal.RepositoryIDs) != 1 || store.locationsPrincipal.RepositoryIDs[0] != 101 || len(store.locationsPrincipal.RepositoryNames) != 1 || store.locationsPrincipal.RepositoryNames[0] != "acme/one" {
		t.Fatalf("Locations() principal = %#v", store.locationsPrincipal)
	}
}

func TestNavigateMapsOnlyMissingOccurrence(t *testing.T) {
	backendError := errors.New("backend unavailable")
	for _, test := range []struct {
		name     string
		storeErr error
		wantErr  error
	}{
		// This fake reports no SCIP upload, so a missing occurrence means the index is absent.
		{name: "missing occurrence", storeErr: ErrOccurrenceNotFound, wantErr: ErrSCIPUnavailable},
		{name: "canceled", storeErr: context.Canceled, wantErr: context.Canceled},
		{name: "deadline", storeErr: context.DeadlineExceeded, wantErr: context.DeadlineExceeded},
		{name: "backend failure", storeErr: backendError, wantErr: backendError},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{repositories: map[int64]repository.Repository{101: serviceRepository}, occurrenceErr: test.storeErr}
			_, err := (&Service{Store: store}).Navigate(t.Context(), userPrincipal, api.SCIPNavigationRequest{RepositoryID: 101, Path: "a.go", Line: 1, Operation: "definitions"})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Navigate() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestNavigateReportsNotIndexed(t *testing.T) {
	store := &fakeStore{repositories: map[int64]repository.Repository{101: {ID: 1, GitHubID: 101}}}
	if _, err := (&Service{Store: store}).Navigate(t.Context(), userPrincipal, api.SCIPNavigationRequest{RepositoryID: 101, Path: "a.go", Line: 1, Operation: "references"}); !errors.Is(err, ErrNotIndexed) {
		t.Fatalf("Navigate() error = %v", err)
	}
}

func TestSetDependenciesRequiresScopedAdministratorAndMapsPURLs(t *testing.T) {
	store := &fakeStore{repositories: map[int64]repository.Repository{101: serviceRepository}}
	service := Service{Store: store}
	purls := api.RepositoryPackages{Provides: []string{"pkg:golang/example.com/acme/app@v1"}, DependsOn: []string{"pkg:npm/acme@1.0.0"}}

	if err := service.SetDependencies(t.Context(), userPrincipal, 101, purls); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ordinary SetDependencies() error = %v", err)
	}
	if err := service.SetDependencies(t.Context(), adminPrincipal, 102, purls); !errors.Is(err, errUnauthorizedRepository) {
		t.Fatalf("unscoped administrator SetDependencies() error = %v", err)
	}
	if err := service.SetDependencies(t.Context(), adminPrincipal, 101, api.RepositoryPackages{Provides: []string{"bad"}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid SetDependencies() error = %v", err)
	}
	if err := service.SetDependencies(t.Context(), adminPrincipal, 101, purls); err != nil {
		t.Fatal(err)
	}
	if store.packagesRepositoryID != 1 || store.packagesSource != "manual" || len(store.packages) != 2 || store.packages[0].Relation != "provides" || store.packages[1].Relation != "depends_on" {
		t.Fatalf("ReplacePackages() = repository %d source %q mappings %#v", store.packagesRepositoryID, store.packagesSource, store.packages)
	}
}

func TestSetDependenciesDeduplicatesCanonicalPURLs(t *testing.T) {
	store := &fakeStore{repositories: map[int64]repository.Repository{101: serviceRepository}}
	err := (&Service{Store: store}).SetDependencies(t.Context(), adminPrincipal, 101, api.RepositoryPackages{
		Provides: []string{
			"pkg:PyPI/acme%2Dlib@V1",
			"pkg:pypi/acme-lib@V1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(store.packages) != 1 || store.packages[0].Package.PURL != "pkg:pypi/acme-lib@V1" {
		t.Fatalf("packages = %#v", store.packages)
	}
}

func TestRefreshGitHubDependenciesAuthorizesAndMapsSBOM(t *testing.T) {
	repo := serviceRepository
	repo.InstallationID, repo.Name = 10, "acme/repo"
	store := &fakeStore{repositories: map[int64]repository.Repository{101: repo}}
	reader := &dependencyReader{sbom: githubapp.SBOM{
		DocumentSPDXID:    "SPDXRef-DOCUMENT",
		DocumentDescribes: []string{"SPDXRef-root"},
		Packages: []githubapp.SBOMPackage{
			{SPDXID: "SPDXRef-root", PURLs: []string{"pkg:golang/example.com/acme/app@v1", "bad"}},
			{SPDXID: "SPDXRef-dep", PURLs: []string{"pkg:npm/acme@1.0.0", "pkg:npm/acme@1.0.0"}},
		},
		Relationships: []githubapp.SBOMRelationship{{SPDXElementID: "SPDXRef-root", Type: "DEPENDS_ON", RelatedSPDXElement: "SPDXRef-dep"}},
	}, available: true}
	service := Service{Store: store, GitHub: reader}

	if _, err := service.RefreshGitHubDependencies(t.Context(), userPrincipal, 101); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ordinary refresh error = %v", err)
	}
	if _, err := service.RefreshGitHubDependencies(t.Context(), adminPrincipal, 102); !errors.Is(err, errUnauthorizedRepository) {
		t.Fatalf("unscoped refresh error = %v", err)
	}
	response, err := service.RefreshGitHubDependencies(t.Context(), adminPrincipal, 101)
	if err != nil || !response.Available || response.Packages != 2 {
		t.Fatalf("RefreshGitHubDependencies() = %#v, %v", response, err)
	}
	if reader.installationID != 10 || reader.owner != "acme" || reader.name != "repo" {
		t.Fatalf("DependencySBOM() = installation %d %q/%q", reader.installationID, reader.owner, reader.name)
	}
	if store.packagesRepositoryID != 1 || store.packagesSource != "github" || len(store.packages) != 2 || store.packages[0].Relation != "provides" || store.packages[1].Relation != "depends_on" {
		t.Fatalf("ReplacePackages() = repository %d source %q mappings %#v", store.packagesRepositoryID, store.packagesSource, store.packages)
	}
}

func TestRefreshGitHubDependenciesPreservesRowsWhenUnavailable(t *testing.T) {
	repo := serviceRepository
	repo.InstallationID, repo.Name = 10, "acme/repo"
	store := &fakeStore{repositories: map[int64]repository.Repository{101: repo}}
	response, err := (&Service{Store: store, GitHub: &dependencyReader{}}).RefreshGitHubDependencies(t.Context(), adminPrincipal, 101)
	if err != nil || response.Available || response.Packages != 0 {
		t.Fatalf("RefreshGitHubDependencies() = %#v, %v", response, err)
	}
	if store.replacePackagesCalls != 0 {
		t.Fatalf("ReplacePackages() calls = %d", store.replacePackagesCalls)
	}
}

func TestRefreshGitHubDependenciesPreservesRowsOnGitHubError(t *testing.T) {
	repo := serviceRepository
	repo.InstallationID, repo.Name = 10, "acme/repo"
	store := &fakeStore{repositories: map[int64]repository.Repository{101: repo}}
	githubError := errors.New("GitHub unavailable")
	_, err := (&Service{Store: store, GitHub: &dependencyReader{err: githubError}}).RefreshGitHubDependencies(t.Context(), adminPrincipal, 101)
	if !errors.Is(err, githubError) || store.replacePackagesCalls != 0 {
		t.Fatalf("error = %v, ReplacePackages() calls = %d", err, store.replacePackagesCalls)
	}
}

type dependencyReader struct {
	sbom           githubapp.SBOM
	available      bool
	err            error
	installationID int64
	owner, name    string
}

func (reader *dependencyReader) DependencySBOM(_ context.Context, installationID int64, owner, name string) (githubapp.SBOM, bool, error) {
	reader.installationID, reader.owner, reader.name = installationID, owner, name
	return reader.sbom, reader.available, reader.err
}

var errUnauthorizedRepository = errors.New("unauthorized repository")

type fakeStore struct {
	repositories                 map[int64]repository.Repository
	origin                       StoredOccurrence
	locations                    []Location
	locationsTruncated           bool
	replacedRepositoryID         int64
	replacedCommit               string
	occurrenceRepositoryID       int64
	occurrenceCommit             string
	occurrenceLine, locationsMax int
	occurrencePosition           OccurrencePosition
	packagesRepositoryID         int64
	packagesSource               string
	packages                     []PackageMapping
	replaceErr, occurrenceErr    error
	scipCommit                   string
	scipCommitErr                error
	authorizationCalls           []authorizationCall
	globalAuthorizationCalls     int
	locationsPrincipal           authn.Principal
	replacePackagesCalls         int
}

type authorizationCall struct {
	installationID int64
	repositoryIDs  []int64
	repositoryID   int64
}

func (store *fakeStore) AuthorizedRepository(_ context.Context, installationID int64, repositoryIDs []int64, repositoryID int64) (repository.Repository, error) {
	store.authorizationCalls = append(store.authorizationCalls, authorizationCall{installationID, append([]int64(nil), repositoryIDs...), repositoryID})
	item, ok := store.repositories[repositoryID]
	if !ok {
		return repository.Repository{}, errUnauthorizedRepository
	}
	return item, nil
}

func (store *fakeStore) SCIPIndexCommit(_ context.Context, _ int64) (string, error) {
	return store.scipCommit, store.scipCommitErr
}

func (store *fakeStore) AnyAuthorizedRepository(_ context.Context, repositoryID int64) (repository.Repository, error) {
	store.globalAuthorizationCalls++
	item, ok := store.repositories[repositoryID]
	if !ok {
		return repository.Repository{}, errUnauthorizedRepository
	}
	return item, nil
}

func (store *fakeStore) ReplaceSCIP(_ context.Context, repositoryID int64, commit string, _ Upload) error {
	store.replacedRepositoryID, store.replacedCommit = repositoryID, commit
	return store.replaceErr
}

func (store *fakeStore) OccurrenceAt(_ context.Context, repositoryID int64, commit, _ string, line int, position OccurrencePosition) (StoredOccurrence, error) {
	store.occurrenceRepositoryID, store.occurrenceCommit = repositoryID, commit
	store.occurrenceLine, store.occurrencePosition = line, position
	return store.origin, store.occurrenceErr
}

func (store *fakeStore) Locations(_ context.Context, principal authn.Principal, _ StoredOccurrence, _ string, max int) ([]Location, bool, error) {
	store.locationsMax = max
	store.locationsPrincipal = principal
	return store.locations, store.locationsTruncated, nil
}

func (store *fakeStore) ReplacePackages(_ context.Context, repositoryID int64, source string, packages []PackageMapping) error {
	store.replacePackagesCalls++
	store.packagesRepositoryID, store.packagesSource = repositoryID, source
	store.packages = packages
	return nil
}

// Navigate used to answer ErrNotIndexed for every one of these, which told the caller a
// search-indexed repository was unindexed and hid the real cause.
func TestNavigateDistinguishesMissingOccurrenceCauses(t *testing.T) {
	staleSHA := strings.Repeat("b", 40)
	request := api.SCIPNavigationRequest{RepositoryID: 101, Path: "src/schema/getSchema.ts", Line: 29, Character: 16, Operation: "definitions"}

	for _, testCase := range []struct {
		name       string
		repository repository.Repository
		scipCommit string
		commit     string
		want       error
	}{
		{"no indexed revision", repository.Repository{ID: 1, GitHubID: 101}, "", "", ErrNotIndexed},
		{"caller asked for another commit", serviceRepository, serviceSHA, staleSHA, ErrStaleCommit},
		{"no SCIP upload at all", serviceRepository, "", "", ErrSCIPUnavailable},
		{"SCIP built for an earlier commit", serviceRepository, staleSHA, "", ErrSCIPStale},
		{"SCIP current, nothing at this position", serviceRepository, serviceSHA, "", ErrSymbolNotFound},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			store := &fakeStore{
				repositories:  map[int64]repository.Repository{101: testCase.repository},
				occurrenceErr: ErrOccurrenceNotFound,
				scipCommit:    testCase.scipCommit,
			}
			navigation := request
			navigation.Commit = testCase.commit
			_, err := (&Service{Store: store}).Navigate(t.Context(), userPrincipal, navigation)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("Navigate() error = %v, want %v", err, testCase.want)
			}
		})
	}
}
