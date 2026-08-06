package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/authz"
	"github.com/grepnest/grepnest/internal/githubapp"
	"github.com/grepnest/grepnest/internal/graphprotocol"
	"github.com/grepnest/grepnest/internal/graphservice"
	"github.com/grepnest/grepnest/internal/httpapi"
	"github.com/grepnest/grepnest/internal/observability"
	"github.com/grepnest/grepnest/internal/repository"
	"github.com/grepnest/grepnest/internal/scipgraph"
	"github.com/grepnest/grepnest/internal/search"
	"github.com/grepnest/grepnest/internal/zoekt"
	"github.com/grepnest/grepnest/pkg/api"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestGraphMCPMatchesService(t *testing.T) {
	principal := authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101}}
	store := &mcpGraphStore{repository: repository.Repository{ID: 1, InstallationID: 10, GitHubID: 101, Name: "acme/one", Branch: "main", IndexedSHA: strings.Repeat("a", 40)}}
	backend := &mcpGraphBackend{}
	graphService := &graphservice.Service{
		Store:   store,
		Backend: backend,
	}
	request := api.GraphImpactRequest{Repo: api.GraphRepositorySelector{Name: "acme/one"}, Branch: "main", TargetUID: "symbol:a", Direction: "downstream"}
	want, err := graphService.Impact(t.Context(), principal, request)
	if err != nil {
		t.Fatal(err)
	}
	budget := mcpResultSize(t, want)
	server := NewWithLimits(Services{Search: testService(t, &recordingBackend{}), Graph: graphService}, Limits{MaxOutputBytes: int64(budget), GraphMaxOutputBytes: int64(budget)})
	handler := httpapi.AuthenticateBearer(authn.NewStatic(map[string]authn.Principal{
		"secret": principal,
		"admin":  {InstallationID: 10, RepositoryIDs: []int64{101}, Administrator: true},
	}), mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil))
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: httpServer.URL, HTTPClient: bearerClient(httpServer.Client(), "secret"), DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	tools, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, description := range map[string]string{
		"context": "Inspect a symbol's incoming and outgoing code relationships.",
		"impact":  "Analyze the upstream or downstream impact of a code symbol.",
		"trace":   "Trace code relationships between two symbols.",
		"cypher":  "Run an administrator-only read query against the code graph.",
	} {
		schema := repositoryToolSchema(t, tools.Tools, name)
		if schema["additionalProperties"] != false {
			t.Fatalf("%s schema = %#v", name, schema)
		}
		for _, tool := range tools.Tools {
			if tool.Name == name && tool.Description != description {
				t.Fatalf("%s description = %q", name, tool.Description)
			}
		}
	}
	impactSchema := repositoryToolSchema(t, tools.Tools, "impact")
	impactProperties := impactSchema["properties"].(map[string]any)
	if impactProperties["repo"].(map[string]any)["oneOf"] == nil || impactProperties["branch"].(map[string]any)["minLength"] != float64(1) {
		t.Fatalf("impact schema = %#v", impactSchema)
	}
	for field, want := range map[string]string{
		"max_depth": "default: 3; values above 32 are capped",
		"limit":     "default: 100; values above 100 are capped",
	} {
		property := impactProperties[field].(map[string]any)
		if property["default"] == nil || !strings.Contains(property["description"].(string), want) {
			t.Fatalf("impact.%s schema = %#v", field, property)
		}
	}
	traceProperties := repositoryToolSchema(t, tools.Tools, "trace")["properties"].(map[string]any)
	if property := traceProperties["max_depth"].(map[string]any); property["default"] == nil || !strings.Contains(property["description"].(string), "default: 10; values above 30 are capped") {
		t.Fatalf("trace.max_depth schema = %#v", property)
	}
	cypherProperties := repositoryToolSchema(t, tools.Tools, "cypher")["properties"].(map[string]any)
	for field, want := range map[string]string{
		"max_rows":  "default: 100; values above 100 are capped",
		"max_bytes": "default: 262144; values above 262144 are capped",
	} {
		property := cypherProperties[field].(map[string]any)
		if property["default"] == nil || !strings.Contains(property["description"].(string), want) {
			t.Fatalf("cypher.%s schema = %#v", field, property)
		}
	}
	contextSchema := repositoryToolSchema(t, tools.Tools, "context")
	if contextSchema["properties"].(map[string]any)["uid"] == nil || contextSchema["properties"].(map[string]any)["name"] == nil {
		t.Fatalf("context schema = %#v", contextSchema)
	}
	if contextSchema["oneOf"] == nil || contextSchema["anyOf"] != nil {
		t.Fatalf("context selector schema = %#v", contextSchema)
	}
	contextLimit := contextSchema["properties"].(map[string]any)["per_category_limit"].(map[string]any)
	if contextLimit["minimum"] != float64(0) || contextLimit["default"] != float64(100) || !strings.Contains(contextLimit["description"].(string), "default: 100; values above 100 are capped") {
		t.Fatalf("context.per_category_limit schema = %#v", contextLimit)
	}
	for _, properties := range []map[string]any{impactProperties, traceProperties, cypherProperties} {
		for _, property := range properties {
			schema, ok := property.(map[string]any)
			if ok && schema["default"] != nil && schema["minimum"] != float64(0) {
				t.Fatalf("capped integer schema = %#v", schema)
			}
		}
	}

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "impact", Arguments: map[string]any{"repo": "acme/one", "branch": "main", "target_uid": "symbol:a", "direction": "downstream"}})
	if err != nil {
		t.Fatal(err)
	}
	assertMCPResultBudget(t, "impact", result, budget)
	var got api.GraphImpactResponse
	decodeStructured(t, result.StructuredContent, &got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
	if store.principal.InstallationID != principal.InstallationID || !slices.Equal(store.principal.RepositoryIDs, principal.RepositoryIDs) {
		t.Fatalf("principal=%#v want=%#v", store.principal, principal)
	}

	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "cypher", Arguments: map[string]any{"repo": 101, "statement": "RETURN 1"}})
	if err != nil || !result.IsError || backend.cypherCalls != 0 {
		t.Fatalf("non-admin cypher result=%#v err=%v calls=%d", result, err, backend.cypherCalls)
	}

	adminSession, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: httpServer.URL, HTTPClient: bearerClient(httpServer.Client(), "admin"), DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adminSession.Close()
	result, err = adminSession.CallTool(t.Context(), &mcp.CallToolParams{Name: "cypher", Arguments: map[string]any{"repo": 101, "statement": "RETURN 1", "max_rows": 999, "max_bytes": 999 << 10}})
	if err != nil || result.IsError || backend.cypherCalls != 1 || backend.cypherRequest.MaxRows != 100 || backend.cypherRequest.MaxBytes != 256<<10 {
		t.Fatalf("admin cypher result=%#v err=%v request=%#v calls=%d", result, err, backend.cypherRequest, backend.cypherCalls)
	}
}

func TestGraphOutputBudgetIsSmallerWithoutChangingOtherTools(t *testing.T) {
	limits := normalizeLimits(Limits{MaxOutputBytes: 100, GraphMaxOutputBytes: 50})
	if limits.MaxOutputBytes != 100 || limits.GraphMaxOutputBytes != 50 {
		t.Fatalf("limits=%#v", limits)
	}
	if _, _, err := graphResult(strings.Repeat("x", 51), nil, limits.GraphMaxOutputBytes); !errors.Is(err, errOutputBudget) {
		t.Fatalf("graph output error=%v", err)
	}
	if _, _, err := graphResult(strings.Repeat("x", 51), nil, limits.MaxOutputBytes); err != nil {
		t.Fatalf("existing output budget error=%v", err)
	}
}

type mcpGraphStore struct {
	repository repository.Repository
	principal  authn.Principal
}

func (store *mcpGraphStore) GraphRepositories(_ context.Context, principal authn.Principal) ([]repository.Repository, error) {
	store.principal = principal
	if principal.InstallationID != store.repository.InstallationID || !slices.Contains(principal.RepositoryIDs, store.repository.GitHubID) {
		return nil, nil
	}
	return []repository.Repository{store.repository}, nil
}

type mcpGraphBackend struct {
	cypherCalls   int
	cypherRequest graphprotocol.CypherRequest
}

func (mcpGraphBackend) Context(context.Context, graphprotocol.ContextRequest) (graphprotocol.ContextResponse, error) {
	return graphprotocol.ContextResponse{}, nil
}
func (mcpGraphBackend) Impact(_ context.Context, request graphprotocol.ImpactRequest) (graphprotocol.ImpactResponse, error) {
	symbol := graphprotocol.Symbol{UID: "symbol:b", Name: "b", Kind: "function", FilePath: "b.go", Language: "go", RepositoryID: 1}
	relation := graphprotocol.Relationship{SourceRepositoryID: 1, TargetRepositoryID: 1, SourceUID: "symbol:a", TargetUID: "symbol:b", Kind: "calls", Confidence: 1}
	return graphprotocol.ImpactResponse{Status: graphprotocol.StatusFound, ByDepth: map[int][]graphprotocol.Symbol{1: {symbol}}, Edges: []graphprotocol.Relationship{relation}, Boundaries: []graphprotocol.Boundary{{Repository: "acme/one", Reason: "depth_limit", Depth: 1}}, Commits: map[string]string{"acme/one": request.Scope.Repositories[0].Commit}, Partial: true}, nil
}
func (mcpGraphBackend) Trace(context.Context, graphprotocol.TraceRequest) (graphprotocol.TraceResponse, error) {
	return graphprotocol.TraceResponse{}, nil
}
func (backend *mcpGraphBackend) Cypher(_ context.Context, request graphprotocol.CypherRequest) (graphprotocol.CypherResponse, error) {
	backend.cypherCalls++
	backend.cypherRequest = request
	return graphprotocol.CypherResponse{Columns: []string{"value"}, Rows: [][]any{{1}}, Commits: map[string]string{"acme/one": request.Scope.Repositories[0].Commit}}, nil
}

func TestRepositoryToolsUseAuthenticatedService(t *testing.T) {
	repositoryService := mcpRepositoryService()
	principal := authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101}}
	wantList, err := repositoryService.List(t.Context(), principal)
	if err != nil {
		t.Fatal(err)
	}
	listBudget := mcpResultSize(t, repositoryListOutput{Repositories: wantList})
	server := NewWithLimits(Services{Search: testService(t, &recordingBackend{}), Repositories: repositoryService}, Limits{MaxOutputBytes: int64(listBudget)})
	handler := httpapi.AuthenticateBearer(
		authn.NewStatic(map[string]authn.Principal{"secret": {InstallationID: 10, RepositoryIDs: []int64{101}}}),
		mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil),
	)
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(
		t.Context(),
		&mcp.StreamableClientTransport{Endpoint: httpServer.URL, HTTPClient: bearerClient(httpServer.Client(), "secret"), DisableStandaloneSSE: true},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	tools, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(tools.Tools))
	for index, tool := range tools.Tools {
		names[index] = tool.Name
	}
	for _, name := range []string{"list_repositories", "get_repository_status", "read_file"} {
		if !slices.Contains(names, name) {
			t.Fatalf("tools = %v", names)
		}
	}
	for toolName, fields := range map[string][]string{
		"list_repositories":     {"limit", "max_output_bytes"},
		"get_repository_status": {"repository_id", "max_output_bytes"},
		"read_file":             {"repository_id", "start_line", "end_line", "max_output_bytes"},
	} {
		schema := repositoryToolSchema(t, tools.Tools, toolName)
		properties := schema["properties"].(map[string]any)
		for _, field := range fields {
			if properties[field].(map[string]any)["minimum"] != float64(1) {
				t.Fatalf("%s.%s schema = %#v", toolName, field, properties[field])
			}
		}
	}
	readSchema := repositoryToolSchema(t, tools.Tools, "read_file")
	if readSchema["properties"].(map[string]any)["path"].(map[string]any)["minLength"] != float64(1) {
		t.Fatalf("read_file.path schema = %#v", readSchema["properties"])
	}

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_repositories", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	assertMCPResultBudget(t, "list_repositories configured", result, listBudget)
	var list struct {
		Repositories []api.RepositorySummary `json:"repositories"`
	}
	decodeStructured(t, result.StructuredContent, &list)
	if !slices.EqualFunc(list.Repositories, wantList, func(a, b api.RepositorySummary) bool { return a == b }) {
		t.Fatalf("list = %#v, want %#v, err %v", list.Repositories, wantList, err)
	}

	wantStatus, err := repositoryService.Status(t.Context(), principal, 101)
	if err != nil {
		t.Fatal(err)
	}
	statusBudget := mcpResultSize(t, wantStatus)
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_repository_status", Arguments: map[string]any{"repository_id": 101, "max_output_bytes": statusBudget}})
	if err != nil {
		t.Fatal(err)
	}
	assertMCPResultBudget(t, "get_repository_status per-call", result, statusBudget)
	var status api.RepositorySummary
	decodeStructured(t, result.StructuredContent, &status)
	if status.GitHubID != 101 || status.Status != "ready" || status.SearchNode != "node-a" {
		t.Fatalf("status = %#v", status)
	}

	wantFile, err := repositoryService.ReadFile(t.Context(), principal, api.ReadFileRequest{RepositoryID: 101, Path: "main.go", StartLine: 2, EndLine: 99})
	if err != nil {
		t.Fatal(err)
	}
	fileBudget := mcpResultSize(t, wantFile)
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "read_file", Arguments: map[string]any{
		"repository_id": 101, "path": "main.go", "start_line": 2, "end_line": 99, "max_output_bytes": fileBudget,
	}})
	if err != nil {
		t.Fatal(err)
	}
	assertMCPResultBudget(t, "read_file per-call", result, fileBudget)
	var file api.ReadFileResponse
	decodeStructured(t, result.StructuredContent, &file)
	if file.Content != "two\nthree" || file.StartLine != 2 || file.EndLine != 3 || file.IndexedSHA != strings.Repeat("a", 40) {
		t.Fatalf("file = %#v", file)
	}

	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "read_file", Arguments: map[string]any{
		"repository_id": 101, "path": "main.go", "max_output_bytes": 1,
	}})
	if err != nil || !result.IsError || marshaledSize(t, result) <= 1 {
		t.Fatalf("tiny-budget result = %#v, size = %d, err = %v", result, marshaledSize(t, result), err)
	}
	var content *mcp.TextContent
	ok := false
	if len(result.Content) == 1 {
		content, ok = result.Content[0].(*mcp.TextContent)
	}
	if !ok || content.Text != errOutputBudget.Error() {
		t.Fatalf("tiny-budget content = %#v", result.Content)
	}

	store := repositoryService.Store.(*mcpRepositoryStore)
	store.calls = 0
	for _, call := range []*mcp.CallToolParams{
		{Name: "get_repository_status", Arguments: map[string]any{"repository_id": 0}},
		{Name: "read_file", Arguments: map[string]any{"repository_id": 101, "path": ""}},
		{Name: "read_file", Arguments: map[string]any{"repository_id": 101, "path": "main.go", "start_line": 0}},
	} {
		result, err := session.CallTool(t.Context(), call)
		if err != nil || !result.IsError {
			t.Fatalf("invalid %s result = %#v, err = %v", call.Name, result, err)
		}
	}
	if store.calls != 0 {
		t.Fatalf("invalid tool service calls = %d", store.calls)
	}
}

func TestNavigateSymbolMatchesSCIPServiceResponse(t *testing.T) {
	store := &mcpSCIPStore{repository: repository.Repository{ID: 1, GitHubID: 101, InstallationID: 10, Name: "acme/one", IndexedSHA: strings.Repeat("a", 40)}}
	store.locations = []scipgraph.Location{{
		RepositoryID: 101, RepositoryName: "acme/one", Commit: store.repository.IndexedSHA,
		Path: "target.go", Symbol: "sym", StartLine: 2, PositionEncoding: 2,
	}}
	scipService := &scipgraph.Service{Store: store}
	principal := authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101}}
	request := api.SCIPNavigationRequest{RepositoryID: 101, Path: "main.go", Line: 1, Character: 0, Operation: "definitions"}
	want, err := scipService.Navigate(t.Context(), principal, request)
	if err != nil {
		t.Fatal(err)
	}
	budget := mcpResultSize(t, want)
	server := NewWithLimits(Services{Search: testService(t, &recordingBackend{}), SCIP: scipService}, Limits{MaxOutputBytes: int64(budget)})
	handler := httpapi.AuthenticateBearer(authn.NewStatic(map[string]authn.Principal{"secret": principal}), mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil))
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: httpServer.URL, HTTPClient: bearerClient(httpServer.Client(), "secret"), DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(tools.Tools))
	for index, tool := range tools.Tools {
		names[index] = tool.Name
	}
	if !slices.Contains(names, "navigate_symbol") || slices.Contains(names, "scip_upload") || slices.Contains(names, "set_dependencies") {
		t.Fatalf("tools = %v", names)
	}
	schema := repositoryToolSchema(t, tools.Tools, "navigate_symbol")
	properties := schema["properties"].(map[string]any)
	if properties["repository_id"].(map[string]any)["minimum"] != float64(1) || properties["line"].(map[string]any)["minimum"] != float64(1) || properties["character"].(map[string]any)["minimum"] != float64(0) || properties["path"].(map[string]any)["minLength"] != float64(1) {
		t.Fatalf("navigate_symbol schema = %#v", schema)
	}
	if !slices.Equal(properties["operation"].(map[string]any)["enum"].([]any), []any{"definitions", "references", "implementations"}) {
		t.Fatalf("operation schema = %#v", properties["operation"])
	}
	invalid, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "navigate_symbol", Arguments: map[string]any{
		"repository_id": 101, "path": "main.go", "line": 1, "character": 0, "operation": "unknown",
	}})
	if err != nil || !invalid.IsError {
		t.Fatalf("invalid operation result = %#v, err = %v", invalid, err)
	}

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "navigate_symbol", Arguments: map[string]any{
		"repository_id": 101, "path": "main.go", "line": 1, "character": 0, "operation": "definitions",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var got api.SCIPNavigationResponse
	decodeStructured(t, result.StructuredContent, &got)
	if !slices.Equal(got.Locations, want.Locations) || got.Truncated != want.Truncated || len(result.Content) != 0 || marshaledSize(t, result) > budget {
		t.Fatalf("output = %#v, want %#v", got, want)
	}
	if got.Locations[0].PositionEncoding != "UTF16CodeUnitOffsetFromLineStart" {
		t.Fatalf("position encoding = %q", got.Locations[0].PositionEncoding)
	}

	store.occurrenceErr = errors.New("secret backend")
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "navigate_symbol", Arguments: map[string]any{
		"repository_id": 101, "path": "main.go", "line": 1, "character": 0, "operation": "definitions",
	}})
	content, ok := result.Content[0].(*mcp.TextContent)
	if err != nil || !result.IsError || len(result.Content) != 1 || !ok || content.Text != "SCIP service is unavailable" || strings.Contains(content.Text, "secret") {
		t.Fatalf("service error result = %#v, err = %v", result, err)
	}
	store.occurrenceErr = nil

	tinyServer := NewWithLimits(Services{Search: testService(t, &recordingBackend{}), SCIP: scipService}, Limits{MaxOutputBytes: int64(budget - 1)})
	tinyHTTPServer := httptest.NewServer(httpapi.AuthenticateBearer(authn.NewStatic(map[string]authn.Principal{"secret": principal}), mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return tinyServer }, nil)))
	defer tinyHTTPServer.Close()
	tinySession, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: tinyHTTPServer.URL, HTTPClient: bearerClient(tinyHTTPServer.Client(), "secret"), DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tinySession.Close()
	result, err = tinySession.CallTool(t.Context(), &mcp.CallToolParams{Name: "navigate_symbol", Arguments: map[string]any{
		"repository_id": 101, "path": "main.go", "line": 1, "character": 0, "operation": "definitions",
	}})
	if err != nil || !result.IsError {
		t.Fatalf("bounded result = %#v, err = %v", result, err)
	}

	nilServer := NewWithLimits(Services{Search: testService(t, &recordingBackend{}), SCIP: nil}, Limits{})
	nilHTTPServer := httptest.NewServer(httpapi.AuthenticateBearer(authn.NewStatic(map[string]authn.Principal{"secret": principal}), mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return nilServer }, nil)))
	defer nilHTTPServer.Close()
	nilSession, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: nilHTTPServer.URL, HTTPClient: bearerClient(nilHTTPServer.Client(), "secret"), DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nilSession.Close()
	nilTools, err := nilSession.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range nilTools.Tools {
		if tool.Name == "navigate_symbol" {
			t.Fatal("navigate_symbol registered without SCIP service")
		}
	}
}

type mcpSCIPStore struct {
	repository    repository.Repository
	locations     []scipgraph.Location
	occurrenceErr error
	scipCommit    string
}

func (store *mcpSCIPStore) SCIPIndexCommit(context.Context, int64) (string, error) {
	return store.scipCommit, nil
}

func (store *mcpSCIPStore) AuthorizedRepository(_ context.Context, _ int64, _ []int64, _ int64) (repository.Repository, error) {
	return store.repository, nil
}
func (store *mcpSCIPStore) AnyAuthorizedRepository(_ context.Context, _ int64) (repository.Repository, error) {
	return store.repository, nil
}
func (*mcpSCIPStore) ReplaceSCIP(context.Context, int64, string, scipgraph.Upload) error { return nil }
func (store *mcpSCIPStore) OccurrenceAt(context.Context, int64, string, string, int, scipgraph.OccurrencePosition) (scipgraph.StoredOccurrence, error) {
	return scipgraph.StoredOccurrence{}, store.occurrenceErr
}
func (store *mcpSCIPStore) Locations(context.Context, authn.Principal, scipgraph.StoredOccurrence, string, int) ([]scipgraph.Location, bool, error) {
	return store.locations, false, nil
}
func (*mcpSCIPStore) ReplacePackages(context.Context, int64, string, []scipgraph.PackageMapping) error {
	return nil
}

func TestRepositoryToolBudgetsBoundActualCallToolResult(t *testing.T) {
	items := []api.RepositorySummary{
		{GitHubID: 101, Name: strings.Repeat("a", 80)},
		{GitHubID: 102, Name: strings.Repeat("b", 80)},
		{GitHubID: 103, Name: strings.Repeat("c", 80)},
	}
	list, err := limitRepositoryList(items, listInput{Limit: 2, MaxOutputBytes: 400}, Limits{MaxItems: 100, MaxOutputBytes: 256 << 10})
	if err != nil || len(list.Repositories) != 1 || !list.Truncated || mcpResultSize(t, list) > 400 {
		t.Fatalf("list=%#v size=%d err=%v", list, mcpResultSize(t, list), err)
	}

	file := api.ReadFileResponse{RepositoryID: 101, Path: "main.go", IndexedSHA: strings.Repeat("a", 40), BlobSHA: "blob", Content: "one\ntwo\n" + strings.Repeat("x", 400), StartLine: 1, EndLine: 3}
	wantFile := filePrefix(file, strings.Split(file.Content, "\n"), 2)
	fileBudget := mcpResultSize(t, wantFile)
	limited, err := limitReadFile(file, int64(fileBudget), Limits{MaxOutputBytes: 256 << 10})
	if err != nil || limited != wantFile || mcpResultSize(t, limited) > fileBudget {
		t.Fatalf("file=%#v size=%d err=%v", limited, mcpResultSize(t, limited), err)
	}
	if _, err := limitReadFile(file, 1, Limits{MaxOutputBytes: 256 << 10}); !errors.Is(err, errOutputBudget) {
		t.Fatalf("tiny budget error=%v", err)
	}
	configured, err := limitReadFile(file, 0, Limits{MaxOutputBytes: int64(fileBudget)})
	if err != nil || mcpResultSize(t, configured) > fileBudget || !configured.Truncated {
		t.Fatalf("configured file=%#v size=%d err=%v", configured, mcpResultSize(t, configured), err)
	}
	list, err = limitRepositoryList(items, listInput{}, Limits{MaxItems: 2, MaxOutputBytes: 256 << 10})
	if err != nil || len(list.Repositories) != 2 || !list.Truncated {
		t.Fatalf("configured item limit list=%#v err=%v", list, err)
	}
}

func TestReadFileBudgetFindsLargestWholeLinePrefix(t *testing.T) {
	lines := make([]string, 1000)
	for index := range lines {
		lines[index] = "x"
	}
	file := api.ReadFileResponse{RepositoryID: 101, Path: "main.go", IndexedSHA: strings.Repeat("a", 40), BlobSHA: "blob", Content: strings.Join(lines, "\n"), StartLine: 1, EndLine: len(lines)}
	want := file
	want.Content = strings.Join(lines[:537], "\n")
	want.EndLine = 537
	want.Truncated = true

	got, err := limitReadFile(file, int64(mcpResultSize(t, want)), Limits{MaxOutputBytes: 256 << 10})
	if err != nil || got.Content != want.Content || got.EndLine != want.EndLine || !got.Truncated {
		t.Fatalf("lines=%d end=%d size=%d err=%v", strings.Count(got.Content, "\n")+1, got.EndLine, mcpResultSize(t, got), err)
	}
}

func TestRepositoryToolErrorsAreSafe(t *testing.T) {
	const secret = "upstream-token"
	service := mcpRepositoryService()
	service.GitHub = mcpContentReader{err: errors.New(secret)}
	server := New(testService(t, &recordingBackend{}), service)
	handler := httpapi.AuthenticateBearer(
		authn.NewStatic(map[string]authn.Principal{"secret": {InstallationID: 10, RepositoryIDs: []int64{101}}}),
		mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil),
	)
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(
		t.Context(), &mcp.StreamableClientTransport{Endpoint: httpServer.URL, HTTPClient: bearerClient(httpServer.Client(), "secret"), DisableStandaloneSSE: true}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	for _, test := range []struct {
		name, tool, message string
		arguments           map[string]any
	}{
		{"unknown repository", "get_repository_status", "repository not found", map[string]any{"repository_id": 999}},
		{"invalid path", "read_file", "file request is invalid", map[string]any{"repository_id": 101, "path": "../secret"}},
		{"upstream failure", "read_file", "repository service is unavailable", map[string]any{"repository_id": 101, "path": "main.go"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: test.tool, Arguments: test.arguments})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), secret) || !result.IsError || len(result.Content) != 1 {
				t.Fatalf("result = %s", encoded)
			}
			content, ok := result.Content[0].(*mcp.TextContent)
			if !ok || content.Text != test.message {
				t.Fatalf("content = %#v", result.Content)
			}
		})
	}
}

func mcpRepositoryService() *repository.Service {
	sha := strings.Repeat("a", 40)
	return &repository.Service{
		Store: &mcpRepositoryStore{repository: repository.Repository{
			ID: 1, InstallationID: 10, GitHubID: 101, Name: "acme/one", Branch: "main",
			DesiredSHA: sha, IndexedSHA: sha, Status: "ready", SearchNode: "node-a",
		}},
		GitHub: mcpContentReader{content: githubapp.Content{
			Type: "file", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("one\ntwo\nthree")), SHA: "blob", Size: 13,
		}},
		MaxLines: 2,
	}
}

type mcpRepositoryStore struct {
	repository repository.Repository
	calls      int
}

func (store *mcpRepositoryStore) AuthorizedRepositories(_ context.Context, _ int64, ids []int64, _ []string) ([]repository.Repository, error) {
	store.calls++
	if len(ids) == 1 && ids[0] == store.repository.GitHubID {
		return []repository.Repository{store.repository}, nil
	}
	return []repository.Repository{}, nil
}

func (store *mcpRepositoryStore) AuthorizedRepository(_ context.Context, _ int64, ids []int64, id int64) (repository.Repository, error) {
	store.calls++
	if id == store.repository.GitHubID && len(ids) == 1 && ids[0] == id {
		return store.repository, nil
	}
	return repository.Repository{}, pgx.ErrNoRows
}

func (*mcpRepositoryStore) AllAuthorizedRepositories(context.Context, []string) ([]repository.Repository, error) {
	return nil, nil
}

func (*mcpRepositoryStore) AnyAuthorizedRepository(context.Context, int64) (repository.Repository, error) {
	return repository.Repository{}, pgx.ErrNoRows
}

type mcpContentReader struct {
	content githubapp.Content
	err     error
}

func (reader mcpContentReader) ReadContents(context.Context, int64, string, string, string, string, int64) (githubapp.Content, error) {
	return reader.content, reader.err
}

func repositoryToolSchema(t *testing.T, tools []*mcp.Tool, name string) map[string]any {
	t.Helper()
	for _, tool := range tools {
		if tool.Name == name {
			data, err := json.Marshal(tool.InputSchema)
			if err != nil {
				t.Fatal(err)
			}
			var schema map[string]any
			if err := json.Unmarshal(data, &schema); err != nil {
				t.Fatal(err)
			}
			return schema
		}
	}
	t.Fatalf("tool %q not found", name)
	return nil
}

func TestSearchToolsUseAuthenticatedService(t *testing.T) {
	backend := &recordingBackend{response: api.SearchResponse{Matches: []api.SearchMatch{{
		Path: "main.go", SHA: "abc123", Branches: []string{"main"}, LineNumber: 3, Preview: "needle\n", ZoektID: 7,
	}}}}
	service := testService(t, backend)
	server := New(service)
	handler := httpapi.AuthenticateBearer(
		authn.NewStatic(map[string]authn.Principal{"secret": {Subject: "user", RepositoryNames: []string{"acme/one"}}}),
		mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil),
	)
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()

	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(
		t.Context(),
		&mcp.StreamableClientTransport{Endpoint: httpServer.URL, HTTPClient: bearerClient(httpServer.Client(), "secret"), DisableStandaloneSSE: true},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	tools, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(tools.Tools))
	for index, tool := range tools.Tools {
		names[index] = tool.Name
	}
	if !slices.Equal(names, []string{"find_files", "search_code"}) {
		t.Fatalf("tools = %v", names)
	}

	wantOutput := output{Matches: []api.SearchMatch{{
		Repository: api.Repository{ID: 1, Name: "acme/one", Branch: "main", IndexedSHA: "abc123"},
		Path:       "main.go", SHA: "abc123", LineNumber: 3, Preview: "needle\n",
	}}}
	searchBudget := mcpResultSize(t, wantOutput)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "search_code",
		Arguments: map[string]any{"query": "needle", "repositories": []string{"acme/one"}, "max_output_bytes": searchBudget},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMCPResultBudget(t, "search_code per-call", result, searchBudget)
	var output struct {
		Matches   []api.SearchMatch `json:"matches"`
		Truncated bool              `json:"truncated"`
	}
	decodeStructured(t, result.StructuredContent, &output)
	if len(output.Matches) != 1 || output.Matches[0].Repository.Name != "acme/one" || output.Matches[0].Path != "main.go" || output.Truncated {
		t.Fatalf("output = %#v", output)
	}
	backend.calls = 0
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "search_code", Arguments: map[string]any{"query": "needle", "repositories": []string{"acme/two"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	decodeStructured(t, result.StructuredContent, &output)
	if len(output.Matches) != 0 || backend.calls != 0 {
		t.Fatalf("matches = %d, backend calls = %d", len(output.Matches), backend.calls)
	}

	backend.response.Truncated = true
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "search_code", Arguments: map[string]any{"query": "needle", "repositories": []string{"acme/one"}, "limit": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	decodeStructured(t, result.StructuredContent, &output)
	if !output.Truncated {
		t.Fatalf("search_code truncated = %v, want true", output.Truncated)
	}

	wantOutput.Truncated = true
	findBudget := mcpResultSize(t, wantOutput)
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "find_files", Arguments: map[string]any{"pattern": "\\.go$", "repositories": []string{"acme/one"}, "limit": 5, "max_output_bytes": findBudget},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMCPResultBudget(t, "find_files per-call", result, findBudget)
	decodeStructured(t, result.StructuredContent, &output)
	if !output.Truncated {
		t.Fatalf("find_files truncated = %v, want true", output.Truncated)
	}
	if backend.request.Query != `file:\.go$` || backend.request.Limit != 5 {
		t.Fatalf("backend request = %#v", backend.request)
	}
}

func TestSearchToolErrorsAreSafe(t *testing.T) {
	const secret = "https://token@zoekt.internal.invalid/search"
	backend := &recordingBackend{err: errors.New(secret)}
	server := New(testService(t, backend))
	handler := httpapi.AuthenticateBearer(
		authn.NewStatic(map[string]authn.Principal{"secret": {Subject: "user", RepositoryNames: []string{"acme/one"}}}),
		mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil),
	)
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(
		t.Context(),
		&mcp.StreamableClientTransport{Endpoint: httpServer.URL, HTTPClient: bearerClient(httpServer.Client(), "secret"), DisableStandaloneSSE: true},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	for _, test := range []struct {
		name, query, message string
	}{
		{"invalid query", " ", "search query is invalid"},
		{"backend failure", "needle", "search service is unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "search_code", Arguments: map[string]any{"query": test.query}})
			if err != nil {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("protocol error leaked backend detail: %v", err)
				}
				t.Fatalf("protocol error = %v", err)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("tool result leaked backend detail: %s", encoded)
			}
			if !result.IsError || len(result.Content) != 1 {
				t.Fatalf("result = %#v", result)
			}
			content, ok := result.Content[0].(*mcp.TextContent)
			if !ok || content.Text != test.message {
				t.Fatalf("content = %#v, want %q", result.Content, test.message)
			}
		})
	}
}

func TestSearchCodeLimitsCanonicalOutputThroughZoekt(t *testing.T) {
	preview := "needle with enough surrounding source to make each match material"
	wireBody, err := json.Marshal(map[string]any{"Result": map[string]any{"Files": []any{map[string]any{
		"FileName": "main.go", "Version": "abc", "Branches": []string{"main"}, "RepositoryID": 7,
		"LineMatches": []any{
			map[string]any{"Line": base64.StdEncoding.EncodeToString([]byte(preview)), "LineNumber": 1},
			map[string]any{"Line": base64.StdEncoding.EncodeToString([]byte(preview)), "LineNumber": 2},
		},
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	zoektServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write(wireBody) }))
	defer zoektServer.Close()
	backend, err := zoekt.New(zoektServer.URL, zoektServer.Client(), 256<<10, observability.New())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := repository.NewStatic([]repository.Repository{{ID: 1, ZoektID: 7, Name: "acme/one", Branch: "main", IndexedSHA: "abc"}})
	if err != nil {
		t.Fatal(err)
	}
	service := search.NewService(backend, authz.NewStatic(registry), search.Limits{MaxResults: 100, MaxResponseBytes: 256 << 10})
	expected := api.SearchResponse{Matches: []api.SearchMatch{{
		Repository: api.Repository{ID: 1, Name: "acme/one", Branch: "main", IndexedSHA: "abc"}, Path: "main.go", SHA: "abc", LineNumber: 1, Preview: preview,
	}}, Truncated: true}
	budget := mcpResultSize(t, expected)
	if len(wireBody) <= budget {
		t.Fatalf("wire body = %d, output budget = %d", len(wireBody), budget)
	}

	server := New(service)
	handler := httpapi.AuthenticateBearer(
		authn.NewStatic(map[string]authn.Principal{"secret": {Subject: "user", RepositoryNames: []string{"acme/one"}}}),
		mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil),
	)
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(
		t.Context(),
		&mcp.StreamableClientTransport{Endpoint: httpServer.URL, HTTPClient: bearerClient(httpServer.Client(), "secret"), DisableStandaloneSSE: true},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "search_code", Arguments: map[string]any{
		"query": "needle", "repositories": []string{"acme/one"}, "limit": 1, "max_output_bytes": 256 << 10,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var output api.SearchResponse
	decodeStructured(t, result.StructuredContent, &output)
	if len(output.Matches) != 1 || !output.Truncated {
		t.Fatalf("limited normalized output = %#v", output)
	}

	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "search_code", Arguments: map[string]any{
		"query": "needle", "repositories": []string{"acme/one"}, "max_output_bytes": budget,
	}})
	if err != nil {
		t.Fatal(err)
	}
	decodeStructured(t, result.StructuredContent, &output)
	if len(output.Matches) != 1 || !output.Truncated || len(result.Content) != 0 || marshaledSize(t, result) > budget {
		t.Fatalf("output = %#v, content = %#v, size = %d, budget = %d", output, result.Content, marshaledSize(t, result), budget)
	}
}

func mcpResultSize(t *testing.T, value any) int {
	t.Helper()
	return marshaledSize(t, &mcp.CallToolResult{Content: []mcp.Content{}, StructuredContent: value})
}

func assertMCPResultBudget(t *testing.T, tool string, result *mcp.CallToolResult, budget int) {
	t.Helper()
	size := marshaledSize(t, result)
	t.Logf("%s CallTool result size = %d, budget = %d", tool, size, budget)
	if len(result.Content) != 0 || size > budget {
		t.Fatalf("content = %#v, size = %d, budget = %d", result.Content, size, budget)
	}
}

func marshaledSize(t *testing.T, value any) int {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return len(data)
}

func testService(t *testing.T, backend *recordingBackend) *search.Service {
	t.Helper()
	registry, err := repository.NewStatic([]repository.Repository{
		{ID: 1, ZoektID: 7, Name: "acme/one", Branch: "main", IndexedSHA: "abc123"}, {ID: 2, ZoektID: 8, Name: "acme/two", Branch: "main", IndexedSHA: "def456"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return search.NewService(backend, authz.NewStatic(registry), search.Limits{MaxResults: 100, MaxResponseBytes: 256 << 10})
}

func decodeStructured(t *testing.T, value any, target any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (transport bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	request.Header.Set("Authorization", "Bearer "+transport.token)
	return transport.base.RoundTrip(request)
}

func bearerClient(client *http.Client, token string) *http.Client {
	copy := *client
	copy.Transport = bearerTransport{token: token, base: client.Transport}
	return &copy
}

type recordingBackend struct {
	calls    int
	request  search.BackendRequest
	response api.SearchResponse
	err      error
}

func (backend *recordingBackend) Search(_ context.Context, request search.BackendRequest) (api.SearchResponse, error) {
	backend.calls++
	backend.request = request
	return backend.response, backend.err
}

func (*recordingBackend) Health(context.Context) error { return nil }
