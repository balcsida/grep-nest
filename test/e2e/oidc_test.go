//go:build e2e

package e2e

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/authz"
	"github.com/grepnest/grepnest/internal/config"
	"github.com/grepnest/grepnest/internal/httpapi"
	"github.com/grepnest/grepnest/internal/postgres"
	"github.com/grepnest/grepnest/internal/repository"
	"github.com/grepnest/grepnest/internal/search"
	"github.com/grepnest/grepnest/internal/sso"
	oidcclient "github.com/grepnest/grepnest/internal/sso/oidc"
	"github.com/grepnest/grepnest/pkg/api"
)

const oidcDirectoryID = "directory-42"

func TestOIDCCrossReplicaSessionUsesLiveAuthorization(t *testing.T) {
	database := newMilestoneDatabase(t)
	seedOIDCAuthorization(t, database)
	idp := newOIDCTestProvider(t)
	public := newOIDCPublicServer(t)
	a := newOIDCReplica(t, database, idp, public.URL)
	b := newOIDCReplica(t, database, idp, public.URL)
	public.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Replica") == "A" {
			a.ServeHTTP(writer, request)
			return
		}
		b.ServeHTTP(writer, request)
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := public.Client()
	browser.Jar = jar
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	login, err := http.NewRequestWithContext(t.Context(), http.MethodGet, public.URL+"/auth/oidc/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	login.Header.Set("X-Replica", "A")
	response, err := browser.Do(login)
	if err != nil {
		t.Fatal(err)
	}
	authorize := response.Header.Get("Location")
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || authorize == "" {
		t.Fatalf("login = %d %q", response.StatusCode, authorize)
	}

	response, err = browser.Get(authorize)
	if err != nil {
		t.Fatal(err)
	}
	callback := response.Header.Get("Location")
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || callback == "" {
		t.Fatalf("authorize = %d %q", response.StatusCode, callback)
	}
	response, err = browser.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback = %d", response.StatusCode)
	}
	assertOIDCRepositoryStatus(t, browser, public.URL, "B", http.StatusOK)
	if _, err := database.pool.Exec(t.Context(), `delete from user_repository_grants using users where user_repository_grants.user_id=users.id and users.external_id=$1 and user_repository_grants.repository_id=101`, oidcDirectoryID); err != nil {
		t.Fatal(err)
	}
	assertOIDCRepositoryStatus(t, browser, public.URL, "B", http.StatusNotFound)
	if _, err := database.pool.Exec(t.Context(), `update users set suspended_at=now() where external_id=$1`, oidcDirectoryID); err != nil {
		t.Fatal(err)
	}
	assertOIDCSessionStatus(t, browser, public.URL, "B", http.StatusUnauthorized)
}

func newOIDCPublicServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.NotFoundHandler())
}

func newOIDCReplica(t *testing.T, database milestoneDatabase, idp *oidcTestProvider, publicURL string) http.Handler {
	t.Helper()
	client := newOIDCClient(t, idp, publicURL)
	sessions := &authn.SessionManager{Store: database.store, IdleTTL: time.Hour, TTL: 2 * time.Hour}
	authenticator := authn.RequestAuthenticator{Session: sessions, PublicOrigin: publicURL}
	mux := http.NewServeMux()
	httpapi.RegisterAuth(mux, false, false, true, []sso.Provider{oidcclient.NewProvider(client, database.store, sessions, nil, time.Minute)}, authenticator, sessions, nil)
	httpapi.RegisterRepositories(mux, authenticator, &repository.Service{Store: database.store}, 64<<10, 10, 64<<10)
	httpapi.RegisterSearch(mux, authenticator, search.NewService(oidcSearchBackend{}, authz.NewPostgres(database.store), search.Limits{MaxResults: 10, MaxResponseBytes: 64 << 10}), 64<<10, 64<<10)
	return mux
}

func newOIDCClient(t *testing.T, idp *oidcTestProvider, publicURL string) *oidcclient.Client {
	t.Helper()
	public, err := url.Parse(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := oidcclient.New(t.Context(), config.OIDC{IssuerURL: idp.server.URL, ClientID: "grepnest-e2e", Scopes: []string{"openid"}, LinkClaim: "directory_id", DisplayNameClaim: "name"}, public, []byte("oidc-e2e-secret"), idp.caPEM())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func seedOIDCAuthorization(t *testing.T, database milestoneDatabase) {
	t.Helper()
	if err := database.store.UpsertSearchNode(t.Context(), "oidc-e2e", "http://127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	if err := database.store.UpsertInstallation(t.Context(), postgres.InstallationUpdate{GitHubID: 10, AccountLogin: "acme", AccountType: "Organization", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.store.UpsertRepository(t.Context(), postgres.RepositoryUpdate{GitHubID: 101, InstallationID: 10, Owner: "acme", Name: "source", CloneURL: "https://example.invalid/acme/source.git", WebURL: "https://example.invalid/acme/source", DefaultBranch: "main", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := database.pool.QueryRow(t.Context(), `insert into users (external_id,user_name,source) values ($1,'ada','scim') returning id`, oidcDirectoryID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `insert into user_repository_grants (user_id,repository_id) values ($1,101)`, userID); err != nil {
		t.Fatal(err)
	}
}

func assertOIDCRepositoryStatus(t *testing.T, client *http.Client, baseURL, replica string, want int) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/v1/repositories/101", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Replica", replica)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("repository status = %d, want %d: %s", response.StatusCode, want, body)
	}
}

func assertOIDCSessionStatus(t *testing.T, client *http.Client, baseURL, replica string, want int) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/v1/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Replica", replica)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("session status = %d, want %d", response.StatusCode, want)
	}
}

type oidcSearchBackend struct{}

func (oidcSearchBackend) Search(context.Context, search.BackendRequest) (api.SearchResponse, error) {
	return api.SearchResponse{}, nil
}
func (oidcSearchBackend) Health(context.Context) error { return nil }

type oidcTestProvider struct {
	server      *httptest.Server
	key         *rsa.PrivateKey
	displayName string
}

func newOIDCTestProvider(t *testing.T) *oidcTestProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := &oidcTestProvider{key: key, displayName: "Ada"}
	provider.server = httptest.NewTLSServer(http.HandlerFunc(provider.serveHTTP))
	t.Cleanup(provider.server.Close)
	return provider
}

func (provider *oidcTestProvider) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.server.Certificate().Raw})
}

func (provider *oidcTestProvider) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	issuer := provider.server.URL
	switch request.URL.Path {
	case "/app/installations":
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte("[]"))
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(writer).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys"})
	case "/authorize":
		callback, _ := url.Parse(request.URL.Query().Get("redirect_uri"))
		query := callback.Query()
		query.Set("code", request.URL.Query().Get("nonce"))
		query.Set("state", request.URL.Query().Get("state"))
		callback.RawQuery = query.Encode()
		http.Redirect(writer, request, callback.String(), http.StatusSeeOther)
	case "/keys":
		n := base64.RawURLEncoding.EncodeToString(provider.key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(provider.key.E)).Bytes())
		_ = json.NewEncoder(writer).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "e2e", "alg": "RS256", "use": "sig", "n": n, "e": e}}})
	case "/token":
		_ = request.ParseForm()
		idToken, err := provider.token(issuer, request.Form.Get("code"))
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{"access_token": "unused", "token_type": "Bearer", "id_token": idToken})
	}
}

func (provider *oidcTestProvider) token(issuer, nonce string) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "e2e", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{"iss": issuer, "sub": "subject-42", "aud": "grepnest-e2e", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce, "directory_id": oidcDirectoryID, "name": provider.displayName})
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	hash := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, provider.key, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
