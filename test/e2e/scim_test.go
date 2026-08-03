//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/account"
	"github.com/grepnest/grepnest/internal/admin"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/authz"
	"github.com/grepnest/grepnest/internal/config"
	"github.com/grepnest/grepnest/internal/httpapi"
	"github.com/grepnest/grepnest/internal/mcpserver"
	"github.com/grepnest/grepnest/internal/postgres"
	"github.com/grepnest/grepnest/internal/repository"
	"github.com/grepnest/grepnest/internal/scim"
	"github.com/grepnest/grepnest/internal/search"
	"github.com/grepnest/grepnest/internal/sso"
	oidcclient "github.com/grepnest/grepnest/internal/sso/oidc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	scimToken = "directory-token-32-bytes-exactly!"
	entraUser = `{
	  "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
	  "externalId":"directory-42",
	  "userName":"ada@example.test",
	  "displayName":"Ada Lovelace",
	  "active":true,
	  "name":{"givenName":"Ada","familyName":"Lovelace"},
	  "emails":[{"value":"ada@example.test","type":"work","primary":true}]
	}`
	oktaGroup = `{
	  "schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
	  "externalId":"00gdevelopers",
	  "displayName":"developers"
	}`
)

func TestSCIMProvisioningAndImmediateDeprovisioning(t *testing.T) {
	database := newMilestoneDatabase(t)
	seedSCIMRepositoryAndAdministrator(t, database)
	idp := newOIDCTestProvider(t)
	public := newOIDCPublicServer(t)
	public.Config.Handler = newSCIME2EHandler(t, database, idp, public.URL)

	var before scim.ListResponse[scim.User]
	scimJSON(t, public.Client(), http.MethodGet, public.URL+"/scim/v2/Users?filter="+url.QueryEscape(`externalId eq "directory-42"`), nil, &before, http.StatusOK)
	if before.TotalResults != 0 {
		t.Fatalf("pre-create filter returned %d users", before.TotalResults)
	}

	var user scim.User
	scimJSON(t, public.Client(), http.MethodPost, public.URL+"/scim/v2/Users", []byte(entraUser), &user, http.StatusCreated)
	var group scim.Group
	scimJSON(t, public.Client(), http.MethodPost, public.URL+"/scim/v2/Groups", []byte(oktaGroup), &group, http.StatusCreated)
	addMember := []byte(fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Add","path":"members","value":[{"value":%q}]}]}`, user.ID))
	scimJSON(t, public.Client(), http.MethodPatch, public.URL+"/scim/v2/Groups/"+group.ID, addMember, &group, http.StatusOK)
	adminJSON(t, adminSessionClient(t, database, public), http.MethodPut, public.URL+"/v1/admin/groups/"+group.ID+"/access", []byte(`{"administrator":false,"repository_ids":[101]}`), http.StatusNoContent)

	browser := loginSCIMOIDC(t, public)
	assertClientStatus(t, browser, public.URL+"/v1/repositories/101", http.StatusOK)
	var created struct {
		Token string `json:"token"`
	}
	sessionJSON(t, browser, http.MethodPost, public.URL+"/v1/account/api-tokens", []byte(`{"repository_ids":[101]}`), &created, http.StatusCreated)
	if len(created.Token) != 47 {
		t.Fatalf("created API token length = %d", len(created.Token))
	}
	if _, err := (authn.TokenManager{Store: database.store}).Authenticate(t.Context(), created.Token); err != nil {
		t.Fatalf("authenticate created API token: %v", err)
	}
	assertBearerStatus(t, public.Client(), public.URL, created.Token, "/v1/repositories/101", http.StatusOK)
	assertMCPRepositoryAccess(t, public, created.Token)

	patch := []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":false}]}`)
	scimJSON(t, public.Client(), http.MethodPatch, public.URL+"/scim/v2/Users/"+user.ID, patch, nil, http.StatusOK)
	assertClientStatus(t, browser, public.URL+"/v1/auth/session", http.StatusUnauthorized)
	assertBearerStatus(t, public.Client(), public.URL, created.Token, "/v1/repositories/101", http.StatusUnauthorized)

	var adminID int64
	if err := database.pool.QueryRow(t.Context(), `select id from users where external_id='directory-admin'`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	scimJSON(t, public.Client(), http.MethodPatch, fmt.Sprintf("%s/scim/v2/Users/%d", public.URL, adminID), patch, nil, http.StatusConflict)
}

func newSCIME2EHandler(t *testing.T, database milestoneDatabase, idp *oidcTestProvider, publicURL string) http.Handler {
	t.Helper()
	public, err := url.Parse(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := oidcclient.New(t.Context(), config.OIDC{IssuerURL: idp.server.URL, ClientID: "grepnest-e2e", Scopes: []string{"openid"}, LinkClaim: "directory_id", DisplayNameClaim: "name"}, public, []byte("oidc-e2e-secret"), idp.caPEM())
	if err != nil {
		t.Fatal(err)
	}
	sessions := &authn.SessionManager{Store: database.store, IdleTTL: time.Hour, TTL: 2 * time.Hour}
	tokens := authn.TokenManager{Store: database.store}
	bearer := tokens
	requestAuth := authn.RequestAuthenticator{Bearer: bearer, Session: sessions, PublicOrigin: publicURL}
	authorizer := authz.NewPostgres(database.store)
	repositories := &repository.Service{Store: database.store}
	searchService := search.NewService(oidcSearchBackend{}, authorizer, search.Limits{MaxResults: 10, MaxResponseBytes: 64 << 10})
	mux := http.NewServeMux()
	httpapi.RegisterAuth(mux, false, false, true, []sso.Provider{&oidcclient.Provider{Client: client, Store: database.store, Sessions: sessions, LoginTTL: time.Minute}}, requestAuth, sessions, nil)
	httpapi.RegisterRepositories(mux, requestAuth, repositories, 64<<10, 10, 64<<10)
	httpapi.RegisterSearch(mux, requestAuth, searchService, 64<<10, 64<<10)
	httpapi.RegisterAccount(mux, requestAuth, &account.Service{Manager: tokens, Authorizer: authorizer}, 64<<10, 64<<10)
	httpapi.RegisterAdmin(mux, requestAuth, &admin.Service{Store: database.store}, 10, 64<<10, 64<<10)
	mux.Handle("/mcp", httpapi.AuthenticateBearer(bearer, mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return mcpserver.New(searchService, repositories)
	}, nil)))
	provisioning, err := authn.NewProvisioningAuthenticator([]byte(scimToken))
	if err != nil {
		t.Fatal(err)
	}
	return httpapi.GuardSCIMV2(mux, provisioning, &scim.Service{Store: database.store, BaseURL: publicURL, MaxResults: 10})
}

func seedSCIMRepositoryAndAdministrator(t *testing.T, database milestoneDatabase) {
	t.Helper()
	if err := database.store.UpsertSearchNode(t.Context(), "scim-e2e", "http://127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	if err := database.store.UpsertInstallation(t.Context(), postgres.InstallationUpdate{GitHubID: 10, AccountLogin: "acme", AccountType: "Organization", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.store.UpsertRepository(t.Context(), postgres.RepositoryUpdate{GitHubID: 101, InstallationID: 10, Owner: "acme", Name: "source", CloneURL: "https://example.invalid/acme/source.git", WebURL: "https://example.invalid/acme/source", DefaultBranch: "main", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := database.pool.QueryRow(t.Context(), `insert into users (external_id,user_name,source) values ('directory-admin','admin','scim') returning id`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `insert into user_roles (user_id, administrator) values ($1, true)`, userID); err != nil {
		t.Fatal(err)
	}
}

func adminSessionClient(t *testing.T, database milestoneDatabase, server *httptest.Server) *http.Client {
	t.Helper()
	token, _, err := (authn.SessionManager{Store: database.store, IdleTTL: time.Hour, TTL: 2 * time.Hour}).Create(t.Context(), authn.Identity{
		Provider: "oidc", Issuer: "https://admin.example", Subject: "admin", LinkID: "directory-admin",
	}, audit.OperationOIDCLoginSucceeded)
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse(server.URL)
	jar.SetCookies(origin, []*http.Cookie{{Name: authn.SessionCookieName, Value: token, Path: "/", Secure: true}})
	client := server.Client()
	client.Jar = jar
	return client
}

func loginSCIMOIDC(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(server.URL + "/auth/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	location := response.Header.Get("Location")
	response.Body.Close()
	response, err = client.Get(location)
	if err != nil {
		t.Fatal(err)
	}
	location = response.Header.Get("Location")
	response.Body.Close()
	response, err = client.Get(location)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("OIDC callback = %d", response.StatusCode)
	}
	return client
}

func scimJSON(t *testing.T, client *http.Client, method, endpoint string, body []byte, output any, want int) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+scimToken)
	if body != nil {
		request.Header.Set("Content-Type", "application/scim+json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("%s %s = %d, want %d: %s", method, endpoint, response.StatusCode, want, data)
	}
	if output != nil {
		if err := json.NewDecoder(response.Body).Decode(output); err != nil {
			t.Fatal(err)
		}
	}
}

func adminJSON(t *testing.T, client *http.Client, method, endpoint string, body []byte, want int) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("admin request = %d, want %d: %s", response.StatusCode, want, data)
	}
}

func sessionJSON(t *testing.T, client *http.Client, method, endpoint string, body []byte, output any, want int) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", endpoint[:len(endpoint)-len("/v1/account/api-tokens")])
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("session request = %d, want %d: %s", response.StatusCode, want, data)
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		t.Fatal(err)
	}
}

func assertBearerStatus(t *testing.T, client *http.Client, baseURL, token, path string, want int) {
	t.Helper()
	copyClient := *client
	copyClient.Jar = nil
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := copyClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("bearer %s = %d, want %d", path, response.StatusCode, want)
	}
}

func assertClientStatus(t *testing.T, client *http.Client, endpoint string, want int) {
	t.Helper()
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("GET %s = %d, want %d", endpoint, response.StatusCode, want)
	}
}

func assertMCPRepositoryAccess(t *testing.T, server *httptest.Server, token string) {
	t.Helper()
	client := *server.Client()
	client.Jar = nil
	client.Transport = scimBearerTransport{base: client.Transport, token: token}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "scim-e2e", Version: "1"}, nil).Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint: server.URL + "/mcp", HTTPClient: &client, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_repositories", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Repositories []struct {
			ID int64 `json:"id"`
		} `json:"repositories"`
	}
	decode(t, result.StructuredContent, &list)
	if len(list.Repositories) != 1 || list.Repositories[0].ID != 101 {
		t.Fatalf("MCP repositories = %#v", list.Repositories)
	}
}

type scimBearerTransport struct {
	base  http.RoundTripper
	token string
}

func (transport scimBearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header.Set("Authorization", "Bearer "+transport.token)
	return transport.base.RoundTrip(copy)
}
