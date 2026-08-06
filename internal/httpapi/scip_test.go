package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/githubapp"
	"github.com/grepnest/grepnest/internal/repository"
	"github.com/grepnest/grepnest/internal/scipgraph"
	"github.com/grepnest/grepnest/pkg/api"
	"github.com/jackc/pgx/v5"
	"github.com/scip-code/scip/bindings/go/scip"
	"google.golang.org/protobuf/proto"
)

const scipTestSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestSCIPUploadContract(t *testing.T) {
	store := &scipStoreStub{repository: scipRepository()}
	handler := scipHandler(store, 8)

	tests := []struct {
		name, method, target, token, contentType string
		body                                     []byte
		want                                     int
	}{
		{"administrator required", http.MethodPost, "/v1/scip/uploads?repository_id=101&commit=" + scipTestSHA, "user", "application/vnd.scip+protobuf", []byte("index"), http.StatusForbidden},
		{"exact method", http.MethodPut, "/v1/scip/uploads?repository_id=101&commit=" + scipTestSHA, "admin", "application/vnd.scip+protobuf", []byte("index"), http.StatusMethodNotAllowed},
		{"exact content type", http.MethodPost, "/v1/scip/uploads?repository_id=101&commit=" + scipTestSHA, "admin", "application/octet-stream", []byte("index"), http.StatusUnsupportedMediaType},
		{"missing repository", http.MethodPost, "/v1/scip/uploads?commit=" + scipTestSHA, "admin", "application/vnd.scip+protobuf", []byte("index"), http.StatusBadRequest},
		{"duplicate repository", http.MethodPost, "/v1/scip/uploads?repository_id=101&repository_id=101&commit=" + scipTestSHA, "admin", "application/vnd.scip+protobuf", []byte("index"), http.StatusBadRequest},
		{"unknown query", http.MethodPost, "/v1/scip/uploads?repository_id=101&commit=" + scipTestSHA + "&extra=1", "admin", "application/vnd.scip+protobuf", []byte("index"), http.StatusBadRequest},
		{"uppercase commit", http.MethodPost, "/v1/scip/uploads?repository_id=101&commit=" + strings.ToUpper(scipTestSHA), "admin", "application/vnd.scip+protobuf", []byte("index"), http.StatusBadRequest},
		{"bounded upload", http.MethodPost, "/v1/scip/uploads?repository_id=101&commit=" + scipTestSHA, "admin", "application/vnd.scip+protobuf", []byte("123456789"), http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := scipRequest(handler, test.method, test.target, test.body, test.token, test.contentType)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d, body = %q", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestSCIPUploadAcceptsValidIndex(t *testing.T) {
	store := &scipStoreStub{repository: scipRepository()}
	data, err := proto.Marshal(&scip.Index{Metadata: &scip.Metadata{ProjectRoot: "file:///workspace", ToolInfo: &scip.ToolInfo{Name: "scip-go", Version: "1"}}})
	if err != nil {
		t.Fatal(err)
	}
	response := scipRequest(scipHandler(store, 1<<20), http.MethodPost, "/v1/scip/uploads?repository_id=101&commit="+scipTestSHA, data, "admin", "application/vnd.scip+protobuf")
	if response.Code != http.StatusNoContent || store.replacedCommit != scipTestSHA {
		t.Fatalf("status = %d, commit = %q, body = %q", response.Code, store.replacedCommit, response.Body.String())
	}
}

func TestSCIPUploadRejectsNonAdministratorWithoutReadingBody(t *testing.T) {
	reader := &recordingReader{}
	request := httptest.NewRequest(http.MethodPost, "/v1/scip/uploads?repository_id=101&commit="+scipTestSHA, reader)
	request.Header.Set("Authorization", "Bearer user")
	request.Header.Set("Content-Type", "application/vnd.scip+protobuf")
	response := httptest.NewRecorder()
	scipHandler(&scipStoreStub{repository: scipRepository()}, 64).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || reader.reads != 0 {
		t.Fatalf("status = %d, body reads = %d", response.Code, reader.reads)
	}
}

func TestSCIPJSONRouteContracts(t *testing.T) {
	store := &scipStoreStub{repository: scipRepository(), locations: []scipgraph.Location{{
		RepositoryID: 101, RepositoryName: "acme/one", Commit: scipTestSHA, Path: "target.go", Symbol: "sym", StartLine: 4,
	}}}
	reader := &scipDependencyReader{}
	handler := newSCIPHandler(store, reader, 256, 64)
	routes := []struct {
		name, path, method, token, valid, unknown string
		want                                      int
	}{
		{"navigation", "/v1/scip/navigation", http.MethodPost, "user", `{"repository_id":101,"path":"main.go","line":1,"character":0,"operation":"definitions"}`, `{"repository_id":101,"path":"main.go","line":1,"character":0,"operation":"definitions","extra":true}`, http.StatusOK},
		{"manual dependencies", "/v1/scip/dependencies", http.MethodPut, "admin", `{"repository_id":101,"provides":[],"depends_on":[]}`, `{"repository_id":101,"provides":[],"depends_on":[],"extra":true}`, http.StatusNoContent},
		{"GitHub dependencies", "/v1/scip/dependencies/github", http.MethodPost, "admin", `{"repository_id":101}`, `{"repository_id":101,"extra":true}`, http.StatusOK},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			for _, test := range []struct {
				name, method, token, contentType, body string
				want                                   int
			}{
				{"allowed method", route.method, route.token, "application/json", route.valid, route.want},
				{"rejected method", alternateMethod(route.method), route.token, "application/json", route.valid, http.StatusMethodNotAllowed},
				{"exact content type", route.method, route.token, "application/json; charset=utf-8", route.valid, http.StatusUnsupportedMediaType},
				{"unknown JSON", route.method, route.token, "application/json", route.unknown, http.StatusBadRequest},
				{"trailing JSON", route.method, route.token, "application/json", route.valid + ` {}`, http.StatusBadRequest},
				{"body cap", route.method, route.token, "application/json", strings.Repeat(" ", 257), http.StatusRequestEntityTooLarge},
			} {
				t.Run(test.name, func(t *testing.T) {
					response := scipRequest(handler, test.method, route.path, []byte(test.body), test.token, test.contentType)
					if response.Code != test.want {
						t.Fatalf("status = %d, want %d, body = %q", response.Code, test.want, response.Body.String())
					}
					if test.want == http.StatusMethodNotAllowed && response.Header().Get("Allow") != route.method {
						t.Fatalf("Allow = %q, want %q", response.Header().Get("Allow"), route.method)
					}
				})
			}
		})
	}
	if store.replacePackagesCalls != 2 || reader.calls != 1 {
		t.Fatalf("metadata writes = %d, GitHub reads = %d", store.replacePackagesCalls, reader.calls)
	}
	for _, route := range routes[1:] {
		response := scipRequest(handler, route.method, route.path, []byte(`{`), "user", "application/json")
		if response.Code != http.StatusForbidden {
			t.Fatalf("non-admin %s status = %d", route.name, response.Code)
		}
	}
}

func TestSCIPNavigationReturnsPositionEncoding(t *testing.T) {
	store := &scipStoreStub{repository: scipRepository(), locations: []scipgraph.Location{{
		RepositoryID: 101, RepositoryName: "acme/one", WebURL: "https://github.example/acme/target", Commit: scipTestSHA,
		Path: "target.go", PositionEncoding: 3,
	}}}
	response := scipRequest(
		newSCIPHandler(store, nil, 1024, 1024),
		http.MethodPost,
		"/v1/scip/navigation",
		[]byte(`{"repository_id":101,"path":"main.go","commit":"`+scipTestSHA+`","line":1,"character_utf8":5,"character_utf16":4,"character_utf32":3,"operation":"definitions"}`),
		"user",
		"application/json",
	)
	var got api.SCIPNavigationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(got.Locations) != 1 ||
		got.Locations[0].WebURL != "https://github.example/acme/target" ||
		got.Locations[0].PositionEncoding != "UTF32CodeUnitOffsetFromLineStart" {
		t.Fatalf("status = %d, response = %#v", response.Code, got)
	}
}

func TestSCIPNavigationRejectsInvalidDatabasePositions(t *testing.T) {
	handler := newSCIPHandler(&scipStoreStub{repository: scipRepository()}, nil, 1024, 1024)
	for _, body := range []string{
		`{"repository_id":101,"path":"main.go","line":2147483648,"character":0,"operation":"definitions"}`,
		`{"repository_id":101,"path":"main.go","line":1,"character":2147483648,"operation":"definitions"}`,
		`{"repository_id":101,"path":"main.go","line":1,"character":-1,"character_utf8":0,"character_utf16":0,"character_utf32":0,"operation":"definitions"}`,
		`{"repository_id":101,"path":"main.go","line":1,"character_utf8":2147483648,"character_utf16":0,"character_utf32":0,"operation":"definitions"}`,
		`{"repository_id":101,"path":"main.go","line":1,"character_utf8":0,"character_utf16":2147483648,"character_utf32":0,"operation":"definitions"}`,
		`{"repository_id":101,"path":"main.go","line":1,"character_utf8":0,"character_utf16":0,"character_utf32":2147483648,"operation":"definitions"}`,
	} {
		response := scipRequest(handler, http.MethodPost, "/v1/scip/navigation", []byte(body), "user", "application/json")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body = %s, status = %d, response = %q", body, response.Code, response.Body.String())
		}
	}
}

func TestSCIPNavigationRejectsStaleSuppliedCommit(t *testing.T) {
	response := scipRequest(
		newSCIPHandler(&scipStoreStub{repository: scipRepository()}, nil, 1024, 1024),
		http.MethodPost,
		"/v1/scip/navigation",
		[]byte(`{"repository_id":101,"path":"main.go","commit":"`+strings.Repeat("b", 40)+`","line":1,"character":0,"operation":"definitions"}`),
		"user",
		"application/json",
	)
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestSCIPNavigationResponseIsBounded(t *testing.T) {
	store := &scipStoreStub{repository: scipRepository(), locations: []scipgraph.Location{{
		RepositoryID: 101, RepositoryName: "acme/one", Commit: scipTestSHA, Path: "target.go",
	}}}
	mux := http.NewServeMux()
	RegisterSCIP(mux, requestAuthenticator(authn.NewStatic(map[string]authn.Principal{"user": {
		InstallationID: 10, RepositoryIDs: []int64{101},
	}})), &scipgraph.Service{Store: store}, 1024, 1024, 1)
	response := scipRequest(mux, http.MethodPost, "/v1/scip/navigation", []byte(`{"repository_id":101,"path":"main.go","line":1,"character":0,"operation":"definitions"}`), "user", "application/json")
	if response.Code != http.StatusInternalServerError || response.Body.Len() != 0 {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestSCIPErrorClassification(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		want      int
		code      string
		message   string
		retryable bool
	}{
		{"forbidden", scipgraph.ErrForbidden, http.StatusForbidden, "forbidden", "administrator access required", false},
		{"invalid request", scipgraph.ErrInvalidRequest, http.StatusBadRequest, "invalid_request", "request is invalid", false},
		{"invalid index", scipgraph.ErrInvalidIndex, http.StatusBadRequest, "invalid_request", "request is invalid", false},
		{"not indexed", scipgraph.ErrNotIndexed, http.StatusConflict, "not_indexed", "repository is not indexed", false},
		{"stale index", scipgraph.ErrStaleIndex, http.StatusConflict, "not_indexed", "repository is not indexed", true},
		{"missing repository", pgx.ErrNoRows, http.StatusNotFound, "not_found", "repository not found", false},
		{"backend", errors.New("secret backend"), http.StatusServiceUnavailable, "unavailable", "SCIP service is unavailable", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeSCIPError(response, test.err)
			assertSafeError(t, response.Body.String(), "secret", test.code, test.message, test.retryable)
			if response.Code != test.want {
				t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
			}
		})
	}
}

func scipHandler(store *scipStoreStub, maxUpload int64) http.Handler {
	return newSCIPHandler(store, &scipDependencyReader{}, 1024, maxUpload)
}

func newSCIPHandler(store *scipStoreStub, reader *scipDependencyReader, maxJSON, maxUpload int64) http.Handler {
	mux := http.NewServeMux()
	RegisterSCIP(mux, requestAuthenticator(authn.NewStatic(map[string]authn.Principal{
		"user":  {InstallationID: 10, RepositoryIDs: []int64{101}},
		"admin": {InstallationID: 10, RepositoryIDs: []int64{101}, Administrator: true},
	})), &scipgraph.Service{Store: store, GitHub: reader}, maxJSON, maxUpload, 1024)
	return mux
}

func alternateMethod(method string) string {
	if method == http.MethodPost {
		return http.MethodPut
	}
	return http.MethodPost
}

type recordingReader struct{ reads int }

func (reader *recordingReader) Read([]byte) (int, error) {
	reader.reads++
	return 0, errors.New("body must not be read")
}

func scipRequest(handler http.Handler, method, target string, body []byte, token, contentType string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", contentType)
	handler.ServeHTTP(response, request)
	return response
}

func scipRepository() repository.Repository {
	return repository.Repository{ID: 1, GitHubID: 101, InstallationID: 10, Name: "acme/one", IndexedSHA: scipTestSHA}
}

type scipStoreStub struct {
	repository           repository.Repository
	locations            []scipgraph.Location
	replacedCommit       string
	replacePackagesCalls int
	scipCommit           string
}

func (store *scipStoreStub) SCIPIndexCommit(context.Context, int64) (string, error) {
	return store.scipCommit, nil
}

func (store *scipStoreStub) AuthorizedRepository(_ context.Context, _ int64, ids []int64, id int64) (repository.Repository, error) {
	if id == store.repository.GitHubID && len(ids) == 1 && ids[0] == id {
		return store.repository, nil
	}
	return repository.Repository{}, pgx.ErrNoRows
}
func (store *scipStoreStub) AnyAuthorizedRepository(_ context.Context, id int64) (repository.Repository, error) {
	if id == store.repository.GitHubID {
		return store.repository, nil
	}
	return repository.Repository{}, pgx.ErrNoRows
}
func (store *scipStoreStub) ReplaceSCIP(_ context.Context, _ int64, commit string, _ scipgraph.Upload) error {
	store.replacedCommit = commit
	return nil
}
func (*scipStoreStub) OccurrenceAt(context.Context, int64, string, string, int, scipgraph.OccurrencePosition) (scipgraph.StoredOccurrence, error) {
	return scipgraph.StoredOccurrence{RepositoryID: 101}, nil
}
func (store *scipStoreStub) Locations(context.Context, authn.Principal, scipgraph.StoredOccurrence, string, int) ([]scipgraph.Location, bool, error) {
	return store.locations, false, nil
}

func (store *scipStoreStub) ReplacePackages(context.Context, int64, string, []scipgraph.PackageMapping) error {
	store.replacePackagesCalls++
	return nil
}

type scipDependencyReader struct{ calls int }

func (reader *scipDependencyReader) DependencySBOM(context.Context, int64, string, string) (githubapp.SBOM, bool, error) {
	reader.calls++
	return githubapp.SBOM{}, true, nil
}
