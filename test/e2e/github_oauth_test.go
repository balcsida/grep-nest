//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/authz"
	"github.com/grepnest/grepnest/internal/githubapp"
	"github.com/grepnest/grepnest/internal/httpapi"
	"github.com/grepnest/grepnest/internal/mcpserver"
	"github.com/grepnest/grepnest/internal/postgres"
	"github.com/grepnest/grepnest/internal/repository"
	"github.com/grepnest/grepnest/internal/search"
	"github.com/grepnest/grepnest/internal/sso"
	"github.com/grepnest/grepnest/internal/sso/githuboauth"
	oidcclient "github.com/grepnest/grepnest/internal/sso/oidc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestGitHubOAuthCrossReplicaPreservesCredentialBoundaries(t *testing.T) {
	database := newMilestoneDatabase(t)
	idp := newGitHubOAuthTestProvider(t)
	seedOIDCAuthorization(t, database)
	seedGitHubOAuthAuthorization(t, database, idp.linkID())
	public := newOIDCPublicServer(t)
	oidc := newOIDCTestProvider(t)
	a := newGitHubOAuthReplica(t, database, idp, oidc, public.URL)
	b := newGitHubOAuthReplica(t, database, idp, oidc, public.URL)
	public.Config.Handler = replicaHandler(a, b)

	oidcJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	oidcBrowser := public.Client()
	oidcBrowser.Jar = oidcJar
	oidcBrowser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	assertGitHubOAuthConfig(t, oidcBrowser, public.URL)

	oidcLogin := startBrowserLogin(t, oidcBrowser, public.URL+"/auth/oidc/login", "A")
	assertBrowserCallbackFails(t, oidcBrowser, public.URL+"/auth/oauth/github/callback", oidcLogin.state, "B")
	completeOIDCLogin(t, oidcBrowser, oidcLogin.authorize, "B")
	assertOIDCRepositoryStatus(t, oidcBrowser, public.URL, "B", http.StatusOK)

	githubJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	githubBrowser := public.Client()
	githubBrowser.Jar = githubJar
	githubBrowser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	assertNoCookie(t, githubJar, public.URL, authn.SessionCookieName)

	githubLogin := startBrowserLogin(t, githubBrowser, public.URL+"/auth/oauth/github/login", "A")
	githubCookie := loginCookie(t, githubJar, public.URL, "__Host-grepnest_oauth_github_login")
	assertGitHubOAuthFlowPersistence(t, database, githubLogin.state, githubCookie)
	assertBrowserCallbackFails(t, githubBrowser, public.URL+"/auth/oidc/callback", githubLogin.state, "B")
	githubCallback := completeGitHubOAuthLogin(t, githubBrowser, githubLogin.authorize, "B")
	assertOIDCRepositoryStatus(t, githubBrowser, public.URL, "B", http.StatusOK)
	assertCallbackReplayFails(t, public.Client(), githubCallback, githubCookie)

	session := sessionCookie(t, githubJar, public.URL)
	assertMCPStatus(t, githubBrowser, public.URL, http.StatusUnauthorized)
	bearer := newGitHubOAuthBearer(t, database)
	assertBearerStatus(t, public.Client(), public.URL, bearer, "/v1/repositories/101", http.StatusOK)
	assertMCPRepositoryAccess(t, public, bearer)
	assertMixedCredentialsRejected(t, githubBrowser, public.URL, bearer)
	logout(t, githubBrowser, public.URL, "B")
	assertOIDCSessionStatus(t, githubBrowser, public.URL, "B", http.StatusUnauthorized)
	assertSessionReplayFails(t, public.Client(), public.URL, session)
	assertGitHubOAuthFailureHidesCanaries(t, public, idp)
}

type githubOAuthTestProvider struct {
	server       *httptest.Server
	failExchange bool
}

const (
	githubOAuthCodeCanary    = "github-oauth-code-canary"
	githubOAuthTokenCanary   = "github-oauth-token-canary"
	githubOAuthSecretCanary  = "github-oauth-secret-canary"
	githubOAuthStateCanary   = "github-oauth-state-canary-000001"
	githubOAuthBrowserCanary = "github-oauth-browser-canary-0000"
	githubOAuthNonceCanary   = "github-oauth-nonce-canary-000001"
)

func newGitHubOAuthTestProvider(t *testing.T) *githubOAuthTestProvider {
	t.Helper()
	provider := &githubOAuthTestProvider{}
	provider.server = httptest.NewTLSServer(http.HandlerFunc(provider.serveHTTP))
	t.Cleanup(provider.server.Close)
	return provider
}

func (provider *githubOAuthTestProvider) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.server.Certificate().Raw})
}

func (provider *githubOAuthTestProvider) linkID() string {
	return "github:" + provider.server.URL + ":42"
}

func (provider *githubOAuthTestProvider) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/login/oauth/authorize":
		if _, present := request.URL.Query()["scope"]; present {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		callback, _ := url.Parse(request.URL.Query().Get("redirect_uri"))
		query := callback.Query()
		query.Set("code", githubOAuthCodeCanary)
		query.Set("state", request.URL.Query().Get("state"))
		callback.RawQuery = query.Encode()
		http.Redirect(writer, request, callback.String(), http.StatusSeeOther)
	case "/login/oauth/access_token":
		if provider.failExchange {
			writer.WriteHeader(http.StatusBadGateway)
			_, _ = writer.Write([]byte(githubOAuthCodeCanary + githubOAuthTokenCanary + githubOAuthSecretCanary))
			return
		}
		if err := request.ParseForm(); err != nil || request.Form.Get("client_secret") != githubOAuthSecretCanary || request.Form.Get("code") != githubOAuthCodeCanary || request.Form.Get("code_verifier") == "" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{"access_token": githubOAuthTokenCanary, "token_type": "bearer", "scope": ""})
	case "/user":
		if request.Header.Get("Authorization") != "Bearer "+githubOAuthTokenCanary {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"id": 42, "login": "ada"})
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func newGitHubOAuthReplica(t *testing.T, database milestoneDatabase, github *githubOAuthTestProvider, oidcProvider *oidcTestProvider, publicURL string) http.Handler {
	t.Helper()
	public, err := url.Parse(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	endpoints := githubapp.Endpoints{Web: mustURL(t, github.server.URL), API: mustURL(t, github.server.URL), Upload: mustURL(t, github.server.URL), Git: mustURL(t, github.server.URL)}
	httpClient, err := githubapp.NewHTTPClient(github.caPEM(), endpoints, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client, err := githuboauth.NewClient(endpoints, public, "github-e2e", []byte(githubOAuthSecretCanary), "2022-11-28", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	sessions := &authn.SessionManager{Store: database.store, IdleTTL: time.Hour, TTL: 2 * time.Hour}
	tokens := authn.TokenManager{Store: database.store}
	requestAuth := authn.RequestAuthenticator{Bearer: tokens, Session: sessions, PublicOrigin: publicURL}
	repositories := &repository.Service{Store: database.store}
	searchService := search.NewService(oidcSearchBackend{}, authz.NewPostgres(database.store), search.Limits{MaxResults: 10, MaxResponseBytes: 64 << 10})
	mux := http.NewServeMux()
	oidc := newOIDCClient(t, oidcProvider, publicURL)
	githubProvider := githuboauth.NewProvider(client, database.store, sessions, nil, time.Minute)
	flowRandom := []byte(githubOAuthStateCanary + githubOAuthBrowserCanary + githubOAuthNonceCanary)
	githubProvider.Rand = bytes.NewReader(append(flowRandom, flowRandom...))
	providers := []sso.Provider{
		oidcclient.NewProvider(oidc, database.store, sessions, nil, time.Minute),
		githubProvider,
	}
	httpapi.RegisterAuth(mux, false, false, true, providers, requestAuth, sessions, nil)
	httpapi.RegisterRepositories(mux, requestAuth, repositories, 64<<10, 10, 64<<10)
	httpapi.RegisterSearch(mux, requestAuth, searchService, 64<<10, 64<<10)
	mux.Handle("/mcp", httpapi.AuthenticateBearer(tokens, mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return mcpserver.New(searchService, repositories)
	}, nil)))
	return mux
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func replicaHandler(a, b http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Replica") == "A" {
			a.ServeHTTP(writer, request)
			return
		}
		b.ServeHTTP(writer, request)
	})
}

func seedGitHubOAuthAuthorization(t *testing.T, database milestoneDatabase, linkID string) {
	t.Helper()
	if err := database.store.UpsertSearchNode(t.Context(), "github-oauth-e2e", "http://127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	if err := database.store.UpsertInstallation(t.Context(), postgres.InstallationUpdate{GitHubID: 10, AccountLogin: "acme", AccountType: "Organization", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.store.UpsertRepository(t.Context(), postgres.RepositoryUpdate{GitHubID: 101, InstallationID: 10, Owner: "acme", Name: "source", CloneURL: "https://example.invalid/acme/source.git", WebURL: "https://example.invalid/acme/source", DefaultBranch: "main", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := database.pool.QueryRow(t.Context(), `insert into users (external_id,user_name,source) values ($1,'ada','scim') returning id`, linkID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `insert into user_repository_grants (user_id,repository_id) values ($1,101)`, userID); err != nil {
		t.Fatal(err)
	}
}

type browserLogin struct{ authorize, state string }

func startBrowserLogin(t *testing.T, client *http.Client, endpoint, replica string) browserLogin {
	t.Helper()
	response := browserRequest(t, client, endpoint, replica)
	defer response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") == "" {
		t.Fatalf("login status = %d", response.StatusCode)
	}
	authorize := response.Header.Get("Location")
	parsed, err := url.Parse(authorize)
	if err != nil || parsed.Query().Get("state") == "" {
		t.Fatal("login did not issue state")
	}
	return browserLogin{authorize: authorize, state: parsed.Query().Get("state")}
}

func completeOIDCLogin(t *testing.T, client *http.Client, authorize, replica string) {
	t.Helper()
	response, err := client.Get(authorize)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") == "" {
		t.Fatalf("OIDC authorize status = %d", response.StatusCode)
	}
	response = browserRequest(t, client, response.Header.Get("Location"), replica)
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("OIDC callback status = %d", response.StatusCode)
	}
}

func completeGitHubOAuthLogin(t *testing.T, client *http.Client, authorize, replica string) string {
	t.Helper()
	response, err := client.Get(authorize)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") == "" {
		t.Fatalf("GitHub authorize status = %d", response.StatusCode)
	}
	response = browserRequest(t, client, response.Header.Get("Location"), replica)
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("GitHub callback status = %d", response.StatusCode)
	}
	return response.Request.URL.String()
}

func assertBrowserCallbackFails(t *testing.T, client *http.Client, endpoint, state, replica string) {
	t.Helper()
	response := browserRequest(t, client, endpoint+"?code=unused&state="+url.QueryEscape(state), replica)
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("cross-provider callback status = %d", response.StatusCode)
	}
}

func browserRequest(t *testing.T, client *http.Client, endpoint, replica string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Replica", replica)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertGitHubOAuthConfig(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	response, err := client.Get(baseURL + "/v1/auth/config")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("auth config status = %d", response.StatusCode)
	}
	var config struct {
		Providers []sso.Metadata `json:"providers"`
	}
	if err := json.NewDecoder(response.Body).Decode(&config); err != nil {
		t.Fatal(err)
	}
	if len(config.Providers) != 2 || config.Providers[0].ID != "oidc" || config.Providers[1].ID != "github" {
		t.Fatalf("auth providers = %#v", config.Providers)
	}
}

func sessionCookie(t *testing.T, jar http.CookieJar, baseURL string) *http.Cookie {
	return loginCookie(t, jar, baseURL, authn.SessionCookieName)
}

func loginCookie(t *testing.T, jar http.CookieJar, baseURL, name string) *http.Cookie {
	t.Helper()
	endpoint, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range jar.Cookies(endpoint) {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatal("expected cookie is missing")
	return nil
}

func assertNoCookie(t *testing.T, jar http.CookieJar, baseURL, name string) {
	t.Helper()
	endpoint, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range jar.Cookies(endpoint) {
		if cookie.Name == name {
			t.Fatal("unexpected session cookie")
		}
	}
}

func assertGitHubOAuthFlowPersistence(t *testing.T, database milestoneDatabase, state string, browser *http.Cookie) {
	t.Helper()
	stateRaw, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		t.Fatal(err)
	}
	browserRaw, err := base64.RawURLEncoding.DecodeString(browser.Value)
	if err != nil {
		t.Fatal(err)
	}
	if string(stateRaw) != githubOAuthStateCanary || string(browserRaw) != githubOAuthBrowserCanary {
		t.Fatal("GitHub flow did not use deterministic state/browser canaries")
	}
	var stateHash, browserHash []byte
	var nonce, verifier, returnTo string
	if err := database.pool.QueryRow(t.Context(), `select state_hash,browser_hash,nonce,code_verifier,return_to from auth_login_flows where provider='github'`).Scan(&stateHash, &browserHash, &nonce, &verifier, &returnTo); err != nil {
		t.Fatal(err)
	}
	wantState, wantBrowser := sha256.Sum256(stateRaw), sha256.Sum256(browserRaw)
	if !bytes.Equal(stateHash, wantState[:]) || !bytes.Equal(browserHash, wantBrowser[:]) || nonce != base64.RawURLEncoding.EncodeToString([]byte(githubOAuthNonceCanary)) || verifier == "" || returnTo != "/" {
		t.Fatal("GitHub login flow persistence is invalid")
	}
	credentialHashes := make([][]byte, 0, 3)
	for _, credential := range []string{githubOAuthCodeCanary, githubOAuthTokenCanary, githubOAuthSecretCanary} {
		hash := sha256.Sum256([]byte(credential))
		credentialHashes = append(credentialHashes, hash[:])
	}
	var count int
	if err := database.pool.QueryRow(t.Context(), `select count(*) from auth_login_flows where state_hash=any($1) or browser_hash=any($1) or nonce=any($2) or code_verifier=any($2) or return_to=any($2)`, credentialHashes, []string{githubOAuthCodeCanary, githubOAuthTokenCanary, githubOAuthSecretCanary}).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("OAuth credential canary persisted")
	}
}

func assertCallbackReplayFails(t *testing.T, client *http.Client, callback string, cookie *http.Cookie) {
	t.Helper()
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, callback, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(cookie)
	response, err := copyClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("replayed callback status = %d", response.StatusCode)
	}
}

func assertMCPStatus(t *testing.T, client *http.Client, baseURL string, want int) {
	t.Helper()
	response, err := client.Get(baseURL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("MCP session status = %d, want %d", response.StatusCode, want)
	}
}

func newGitHubOAuthBearer(t *testing.T, database milestoneDatabase) string {
	t.Helper()
	var userID int64
	if err := database.pool.QueryRow(t.Context(), `select id from users where external_id like 'github:%'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	_, token, err := (authn.TokenManager{Store: database.store}).CreateWithMethod(t.Context(), userID, authn.ProviderOAuth, []int64{101}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func assertMixedCredentialsRejected(t *testing.T, client *http.Client, baseURL, token string) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/v1/repositories/101", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("mixed credentials status = %d", response.StatusCode)
	}
}

func logout(t *testing.T, client *http.Client, baseURL, replica string) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/auth/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", baseURL)
	request.Header.Set("X-Replica", replica)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d", response.StatusCode)
	}
}

func assertSessionReplayFails(t *testing.T, client *http.Client, baseURL string, session *http.Cookie) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/v1/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(session)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed session status = %d", response.StatusCode)
	}
}

func assertGitHubOAuthFailureHidesCanaries(t *testing.T, public *httptest.Server, provider *githubOAuthTestProvider) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := public.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	login := startBrowserLogin(t, client, public.URL+"/auth/oauth/github/login", "A")
	provider.failExchange = true
	t.Cleanup(func() { provider.failExchange = false })
	response, err := client.Get(login.authorize)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	response = browserRequest(t, client, response.Header.Get("Location"), "B")
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	output := string(body) + response.Header.Get("Location") + response.Header.Get("Set-Cookie")
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/?auth_error=authentication_failed" {
		t.Fatalf("OAuth failure response status = %d", response.StatusCode)
	}
	for _, credential := range []string{githubOAuthCodeCanary, githubOAuthTokenCanary, githubOAuthSecretCanary} {
		if strings.Contains(output, credential) {
			t.Fatal("OAuth failure response leaked credential canary")
		}
	}
}
