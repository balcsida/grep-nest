package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/observability"
)

func TestClientRecordsBoundedRequestMetrics(t *testing.T) {
	now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[]`)
	}))
	defer server.Close()
	metrics := observability.New()
	client := testClient(t, server, &now, 1024, metrics)
	if _, err := client.Installations(t.Context()); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if want := `grepnest_github_requests_total{operation="installations",result="success"} 1`; !strings.Contains(recorder.Body.String(), want) {
		t.Fatalf("metrics missing %q:\n%s", want, recorder.Body.String())
	}
}

func TestClientRecordsEveryFixedOperationResultOnce(t *testing.T) {
	for _, operation := range []string{"installation_token", "installations", "repositories", "default_branch", "contents", "dependency_sbom"} {
		for _, result := range []string{"success", "error"} {
			t.Run(operation+" "+result, func(t *testing.T) {
				now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requestOperation := githubRequestOperation(r.URL.EscapedPath())
					if requestOperation == operation && result == "error" {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					switch requestOperation {
					case "installation_token":
						fmt.Fprintf(w, `{"token":"opaque","expires_at":%q}`, now.Add(10*time.Minute).Format(time.RFC3339))
					case "installations":
						fmt.Fprint(w, `[]`)
					case "repositories":
						fmt.Fprint(w, `{"repositories":[]}`)
					case "default_branch":
						fmt.Fprint(w, `{"commit":{"sha":"abc"}}`)
					case "contents":
						fmt.Fprint(w, `{"type":"file","encoding":"base64","content":"YQ==","sha":"blob","size":1}`)
					case "dependency_sbom":
						fmt.Fprint(w, `{"sbom":{"SPDXID":"SPDXRef-DOCUMENT"}}`)
					default:
						t.Fatalf("unexpected path %q", r.URL.EscapedPath())
					}
				}))
				defer server.Close()
				metrics := observability.New()
				client := testClient(t, server, &now, 4096, metrics)
				err := callGitHubOperation(t.Context(), client, operation)
				if (err == nil) != (result == "success") {
					t.Fatalf("error = %v", err)
				}

				body := scrapeClientMetrics(t, metrics)
				want := fmt.Sprintf(`grepnest_github_requests_total{operation=%q,result=%q} 1`, operation, result)
				if strings.Count(body, want) != 1 {
					t.Fatalf("metric %q not recorded exactly once:\n%s", want, body)
				}
				other := map[string]string{"success": "error", "error": "success"}[result]
				if strings.Contains(body, fmt.Sprintf(`operation=%q,result=%q`, operation, other)) {
					t.Fatalf("operation recorded with both results:\n%s", body)
				}
			})
		}
	}
}

func githubRequestOperation(path string) string {
	switch {
	case strings.HasSuffix(path, "/access_tokens"):
		return "installation_token"
	case strings.HasSuffix(path, "/app/installations"):
		return "installations"
	case strings.HasSuffix(path, "/installation/repositories"):
		return "repositories"
	case strings.Contains(path, "/branches/"):
		return "default_branch"
	case strings.Contains(path, "/contents/"):
		return "contents"
	case strings.HasSuffix(path, "/dependency-graph/sbom"):
		return "dependency_sbom"
	default:
		return ""
	}
}

func callGitHubOperation(ctx context.Context, client *Client, operation string) error {
	switch operation {
	case "installation_token":
		_, err := client.InstallationToken(ctx, 9, nil)
		return err
	case "installations":
		_, err := client.Installations(ctx)
		return err
	case "repositories":
		_, err := client.InstallationRepositories(ctx, 9)
		return err
	case "default_branch":
		_, err := client.DefaultBranchSHA(ctx, 9, "owner", "repo", "main")
		return err
	case "contents":
		_, err := client.ReadContents(ctx, 9, "owner", "repo", "README.md", "abc", 1024)
		return err
	case "dependency_sbom":
		_, _, err := client.DependencySBOM(ctx, 9, "owner", "repo")
		return err
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
}

func scrapeClientMetrics(t *testing.T, metrics *observability.Metrics) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return recorder.Body.String()
}

func TestInstallationTokenCachesSortedRestrictionsAndRefreshes(t *testing.T) {
	now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	requests := 0
	var client *Client
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		if r.Method != http.MethodPost || r.URL.EscapedPath() != "/api/v3/app/installations/42/access_tokens" {
			t.Errorf("request = %s %s", r.Method, r.URL.EscapedPath())
		}
		assertRequest(t, r, http.MethodPost, signerAuthorization(t, client.signer))
		var body struct {
			RepositoryIDs []int64 `json:"repository_ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(body.RepositoryIDs, []int64{2, 7}) {
			t.Errorf("repository_ids = %v", body.RepositoryIDs)
		}
		fmt.Fprintf(w, `{"token":"opaque-token-%d","expires_at":%q}`, requests, now.Add(10*time.Minute).Format(time.RFC3339))
	}))
	defer server.Close()
	client = testClient(t, server, &now, 1024)

	first, err := client.InstallationToken(context.Background(), 42, []int64{7, 2})
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.InstallationToken(context.Background(), 42, []int64{2, 7})
	if err != nil {
		t.Fatal(err)
	}
	if first.Value != "opaque-token-1" || second != first || len(first.Value) != 14 || requests != 1 {
		t.Fatalf("tokens = %#v %#v, requests = %d", first, second, requests)
	}
	now = now.Add(9 * time.Minute)
	if _, err := client.InstallationToken(context.Background(), 42, []int64{2, 7}); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestClientPaginatesRetries401AndEscapesSegments(t *testing.T) {
	var server *httptest.Server
	var repositoryRequests int
	var tokenRequests int
	var client *Client
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.EscapedPath() {
		case "/api/v3/app/installations":
			assertRequest(t, r, http.MethodGet, signerAuthorization(t, client.signer))
			if r.URL.Query().Get("page") == "2" {
				fmt.Fprint(w, `[{"id":2,"account":{"login":"two","type":"Organization"},"status":"active"}]`)
				return
			}
			w.Header().Set("Link", "<"+server.URL+"/api/v3/app/installations?page=2>; rel=\"next\"")
			fmt.Fprint(w, `[{"id":1,"account":{"login":"one","type":"User"},"status":"active"}]`)
		case "/api/v3/app/installations/9/access_tokens":
			assertRequest(t, r, http.MethodPost, signerAuthorization(t, client.signer))
			tokenRequests++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if _, ok := body["repository_ids"]; ok {
				t.Errorf("unexpected repository_ids: %v", body)
			}
			fmt.Fprintf(w, `{"token":"installation-secret-%d","expires_at":"2026-07-18T13:00:00Z"}`, tokenRequests)
		case "/api/v3/installation/repositories":
			repositoryRequests++
			assertRequest(t, r, http.MethodGet, fmt.Sprintf("Bearer installation-secret-%d", repositoryRequests))
			if repositoryRequests == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"repositories":[{"id":22,"full_name":"o/r","owner":{"login":"o"},"name":"r","clone_url":"https://example/r.git","html_url":"https://example/r","default_branch":"main","private":true,"size":123}]}`)
		case "/api/v3/repos/space%20owner/repo%2Fname/branches/main%2Fbranch":
			assertRequest(t, r, http.MethodGet, "Bearer installation-secret-2")
			fmt.Fprint(w, `{"commit":{"sha":"abc123"}}`)
		case "/api/v3/repos/space%20owner/repo%2Fname/contents/dir/file%20name":
			assertRequest(t, r, http.MethodGet, "Bearer installation-secret-2")
			if got := r.URL.Query().Get("ref"); got != "refs/heads/main & exact" {
				t.Errorf("ref = %q", got)
			}
			fmt.Fprint(w, `{"type":"file","encoding":"base64","content":"YQ==","sha":"blob","size":1}`)
		default:
			t.Errorf("unexpected path %q", r.URL.EscapedPath())
			w.WriteHeader(http.StatusNotFound)
		}
	})
	server = httptest.NewTLSServer(handler)
	defer server.Close()
	now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	client = testClient(t, server, &now, 4096)

	installations, err := client.Installations(context.Background())
	if err != nil || len(installations) != 2 || installations[1].AccountLogin != "two" {
		t.Fatalf("installations = %#v, err = %v", installations, err)
	}
	repositories, err := client.InstallationRepositories(context.Background(), 9)
	if err != nil || len(repositories) != 1 || repositories[0].ID != 22 || repositories[0].InstallationID != 9 || repositories[0].SizeBytes != 123*1024 {
		t.Fatalf("repositories = %#v, err = %v", repositories, err)
	}
	if repositoryRequests != 2 || tokenRequests != 2 {
		t.Fatalf("repository requests = %d, token requests = %d", repositoryRequests, tokenRequests)
	}
	sha, err := client.DefaultBranchSHA(context.Background(), 9, "space owner", "repo/name", "main/branch")
	if err != nil || sha != "abc123" {
		t.Fatalf("sha = %q, err = %v", sha, err)
	}
	content, err := client.ReadContents(context.Background(), 9, "space owner", "repo/name", "dir/file name", "refs/heads/main & exact", 256)
	if err != nil || content.SHA != "blob" {
		t.Fatalf("content = %#v, err = %v", content, err)
	}
}

func TestClientNextPageParsesRFC5988Links(t *testing.T) {
	api, err := url.Parse("https://github.example/api/v3")
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(Endpoints{API: api}, nil, nil, "", 0, nil)
	tests := []struct {
		name string
		link string
		want string
	}{
		{"URI delimiters", `<https://github.example/api/v3/items?cursor=a,b;c>; rel=next`, "https://github.example/api/v3/items?cursor=a,b;c"},
		{"unquoted relation", `<https://github.example/api/v3/items?page=2>; rel=next`, "https://github.example/api/v3/items?page=2"},
		{"multiple relations", `<https://github.example/api/v3/items?page=2>; rel="prev next"`, "https://github.example/api/v3/items?page=2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			next, err := client.nextPage(test.link)
			if err != nil || next == nil || next.String() != test.want {
				t.Fatalf("next = %v, err = %v", next, err)
			}
		})
	}
}

func TestClientNextPageRejectsDotSegments(t *testing.T) {
	api, err := url.Parse("https://github.example/api/v3")
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(Endpoints{API: api}, nil, nil, "", 0, nil)
	for _, link := range []string{
		`<https://github.example/api/v3/../outside>; rel="next"`,
		`<https://github.example/api/v3/%2e%2e/outside>; rel="next"`,
	} {
		if next, err := client.nextPage(link); err == nil || next != nil {
			t.Fatalf("next = %v, err = %v", next, err)
		}
	}
}

func TestClientBoundsResponsesAndKeepsErrorsSafe(t *testing.T) {
	secret := "installation-secret"
	bodySecret := "private-response-body"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access_tokens") {
			fmt.Fprintf(w, `{"token":%q,"expires_at":"2026-07-18T13:00:00Z"}`, secret)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, bodySecret+strings.Repeat("x", 100))
	}))
	defer server.Close()
	now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	client := testClient(t, server, &now, 1024)
	_, err := client.DefaultBranchSHA(context.Background(), 9, "o", "r", "main")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), bodySecret) {
		t.Fatalf("unsafe error = %q", err)
	}
	var statusError HTTPStatusError
	if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusForbidden || err.Error() != "GitHub API status 403" {
		t.Fatalf("status error = %#v, %v", statusError, err)
	}

	large := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 34))
	}))
	defer large.Close()
	client = testClient(t, large, &now, 32)
	_, err = client.Installations(context.Background())
	if err == nil || !strings.Contains(err.Error(), "response too large") {
		t.Fatalf("error = %v", err)
	}

	trailing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[] []`)
	}))
	defer trailing.Close()
	client = testClient(t, trailing, &now, 32)
	_, err = client.Installations(context.Background())
	if err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("error = %v", err)
	}
}

func testClient(t *testing.T, server *httptest.Server, now *time.Time, maxBytes int64, metrics ...*observability.Metrics) *Client {
	t.Helper()
	endpoint, err := url.Parse(server.URL + "/api/v3")
	if err != nil {
		t.Fatal(err)
	}
	httpClient, err := NewHTTPClient(pemCertificate(t, server.Certificate()), Endpoints{Web: endpoint, API: endpoint, Upload: endpoint, Git: endpoint}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(1, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return NewClient(Endpoints{Web: endpoint, API: endpoint, Upload: endpoint, Git: endpoint}, httpClient, signer, "2022-11-28", maxBytes, func() time.Time { return *now }, metrics...)
}

func assertRequest(t *testing.T, r *http.Request, method, authorization string) {
	t.Helper()
	if r.Method != method {
		t.Errorf("method = %q, want %q", r.Method, method)
	}
	if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
		t.Errorf("Accept = %q", got)
	}
	if got := r.Header.Get("X-GitHub-Api-Version"); got != "2022-11-28" {
		t.Errorf("version = %q", got)
	}
	if got := r.Header.Get("Authorization"); got != authorization {
		t.Errorf("authorization = %q", r.Header.Get("Authorization"))
	}
}

func TestSharedAPIHelpersPreserveBasePathAndHeaders(t *testing.T) {
	base, err := url.Parse("https://github.example/api/v3/")
	if err != nil {
		t.Fatal(err)
	}
	if got := EndpointURL(base, "repos", "a/b"); got != "https://github.example/api/v3/repos/a%2Fb" {
		t.Fatalf("EndpointURL = %q", got)
	}
	header := make(http.Header)
	SetAPIHeaders(header, "2022-11-28")
	if header.Get("Accept") != "application/vnd.github+json" || header.Get("User-Agent") != "GrepNest" || header.Get("X-GitHub-Api-Version") != "2022-11-28" {
		t.Fatalf("headers = %#v", header)
	}
}

func signerAuthorization(t *testing.T, signer *Signer) string {
	t.Helper()
	jwt, err := signer.JWT()
	if err != nil {
		t.Fatal(err)
	}
	return "Bearer " + jwt
}
