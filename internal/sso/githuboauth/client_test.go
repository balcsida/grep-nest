package githuboauth

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/githubapp"
	"golang.org/x/oauth2"
)

const (
	testCode   = "code-canary"
	testSecret = "secret-canary"
	testToken  = "token-canary"
	bodyCanary = "body-canary"
)

func TestNewClientValidatesAndCanonicalizesWebOrigin(t *testing.T) {
	invalid := []string{
		"http://github.example", "https://user@github.example", "https://github.example/?q=1",
		"https://github.example/#fragment", "https://github.example/enterprise",
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			endpoints := endpointsFor(t, raw, "https://api.github.example")
			if _, err := NewClient(endpoints, mustURL(t, "https://grepnest.example"), "client", []byte(testSecret), "v1", http.DefaultClient); err == nil {
				t.Fatal("NewClient accepted invalid web origin")
			}
		})
	}

	for _, test := range []struct{ raw, issuer string }{
		{"https://GITHUB.EXAMPLE/", "https://github.example"},
		{"https://GITHUB.EXAMPLE:443", "https://github.example"},
		{"https://GITHUB.EXAMPLE:8443/", "https://github.example:8443"},
	} {
		t.Run(test.raw, func(t *testing.T) {
			client, err := NewClient(endpointsFor(t, test.raw, "https://api.github.example"), mustURL(t, "https://grepnest.example"), "client", []byte(testSecret), "v1", http.DefaultClient)
			if err != nil {
				t.Fatal(err)
			}
			if client.issuer != test.issuer {
				t.Fatalf("issuer = %q, want %q", client.issuer, test.issuer)
			}
		})
	}
}

func TestAuthorizationURLUsesFixedEndpointCallbackAndPKCEWithoutScope(t *testing.T) {
	fixture := newFixture(t, nil)
	got, err := url.Parse(fixture.client.AuthorizationURL("exact-state", "ignored-nonce", "exact-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	query := got.Query()
	wantChallenge := oauth2.S256ChallengeFromVerifier("exact-verifier")
	if got.Path != "/login/oauth/authorize" || query.Get("state") != "exact-state" || query.Get("redirect_uri") != "https://grepnest.example/auth/oauth/github/callback" || query.Get("code_challenge") != wantChallenge || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL = %q", got.String())
	}
	if _, exists := query["scope"]; exists {
		t.Fatalf("scope present in %q", got.String())
	}
}

func TestExchangePostsExactValuesAndResolvesIdentityOnce(t *testing.T) {
	tokenCalls, userCalls := 0, 0
	fixture := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			tokenCalls++
			if r.Method != http.MethodPost || r.Header.Get("Accept") != "application/json" {
				t.Errorf("token request = %s accept %q", r.Method, r.Header.Get("Accept"))
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			want := map[string]string{"client_id": "client-id", "client_secret": testSecret, "code": testCode, "redirect_uri": "https://grepnest.example/auth/oauth/github/callback", "code_verifier": "exact-verifier"}
			for key, value := range want {
				if r.Form.Get(key) != value {
					t.Errorf("%s = %q", key, r.Form.Get(key))
				}
			}
			fmt.Fprintf(w, `{"access_token":%q,"token_type":"bEaReR","scope":""}`, testToken)
		case "/api/v3/user":
			userCalls++
			if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("User-Agent") != "GrepNest" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
				t.Errorf("user headers = %#v", r.Header)
			}
			fmt.Fprint(w, `{"id":42,"login":"ada","name":"  Ada Lovelace  "}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	})
	identity, err := fixture.client.Exchange(t.Context(), testCode, "exact-verifier", "ignored-nonce")
	if err != nil {
		t.Fatal(err)
	}
	if tokenCalls != 1 || userCalls != 1 || identity.Provider != "oauth" || identity.Issuer != fixture.server.URL || identity.Subject != "42" || identity.LinkID != "github:"+fixture.server.URL+":42" || identity.DisplayName != "Ada Lovelace" {
		t.Fatalf("calls = %d/%d, identity = %#v", tokenCalls, userCalls, identity)
	}
}

func TestExchangeNeverFollowsTokenRedirect(t *testing.T) {
	redirected := false
	fixture := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/oauth/access_token" {
			http.Redirect(w, r, "/redirect-canary", http.StatusFound)
			return
		}
		redirected = true
	})
	if _, err := fixture.client.Exchange(t.Context(), testCode, "verifier", ""); err == nil {
		t.Fatal("redirecting token endpoint succeeded")
	}
	if redirected {
		t.Fatal("token redirect was followed")
	}
}

func TestExchangeStatusErrorsExcludeResponseBodiesAndCredentials(t *testing.T) {
	for _, failedPath := range []string{"/login/oauth/access_token", "/api/v3/user"} {
		t.Run(failedPath, func(t *testing.T) {
			fixture := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == failedPath {
					w.WriteHeader(http.StatusBadGateway)
					fmt.Fprint(w, bodyCanary+testToken+testSecret+testCode)
					return
				}
				fmt.Fprint(w, validToken())
			})
			_, err := fixture.client.Exchange(t.Context(), testCode, "verifier", "")
			if err == nil {
				t.Fatal("status error succeeded")
			}
			for _, canary := range []string{testCode, testSecret, testToken, bodyCanary} {
				if strings.Contains(err.Error(), canary) {
					t.Fatalf("error leaked canary: %q", err)
				}
			}
		})
	}
}

func TestExchangeRejectsUnsafeResponsesWithoutLeakingCanaries(t *testing.T) {
	tests := []struct {
		name, tokenBody, userBody string
	}{
		{"empty token", `{"access_token":"","token_type":"bearer","scope":""}`, ""},
		{"wrong token type", `{"access_token":"` + testToken + `","token_type":"mac","scope":""}`, ""},
		{"granted scope", `{"access_token":"` + testToken + `","token_type":"bearer","scope":"repo"}`, ""},
		{"trailing token JSON", `{"access_token":"` + testToken + `","token_type":"bearer","scope":""} ` + bodyCanary, ""},
		{"oversized token body", strings.Repeat("x", 64*1024+1) + bodyCanary, ""},
		{"non-positive ID", validToken(), `{"id":0,"login":"ada"}`},
		{"invalid UTF-8 login", validToken(), "{\"id\":42,\"login\":\"\xff" + bodyCanary + "\"}"},
		{"control login", validToken(), `{"id":42,"login":"ada\u000a` + bodyCanary + `"}`},
		{"oversized login", validToken(), `{"id":42,"login":"` + strings.Repeat("a", 257) + bodyCanary + `"}`},
		{"oversized name", validToken(), `{"id":42,"login":"ada","name":"` + strings.Repeat("a", 257) + bodyCanary + `"}`},
		{"trailing user JSON", validToken(), `{"id":42,"login":"ada"} ` + bodyCanary},
		{"oversized user body", validToken(), strings.Repeat("x", 64*1024+1) + bodyCanary},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login/oauth/access_token" {
					fmt.Fprint(w, test.tokenBody)
					return
				}
				fmt.Fprint(w, test.userBody)
			})
			_, err := fixture.client.Exchange(t.Context(), testCode, "verifier", "")
			if err == nil {
				t.Fatal("unsafe response succeeded")
			}
			for _, canary := range []string{testCode, testSecret, testToken, bodyCanary} {
				if strings.Contains(err.Error(), canary) {
					t.Fatalf("error leaked canary: %q", err)
				}
			}
		})
	}
}

func TestExchangeFallsBackToBoundedLogin(t *testing.T) {
	for _, name := range []string{"null", `"   "`} {
		t.Run(name, func(t *testing.T) {
			fixture := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login/oauth/access_token" {
					fmt.Fprint(w, validToken())
					return
				}
				fmt.Fprintf(w, `{"id":42,"login":"ada","name":%s}`, name)
			})
			identity, err := fixture.client.Exchange(t.Context(), testCode, "verifier", "")
			if err != nil || identity.DisplayName != "ada" {
				t.Fatalf("identity = %#v, error = %v", identity, err)
			}
		})
	}
}

func validToken() string {
	return `{"access_token":"` + testToken + `","token_type":"bearer","scope":""}`
}

type fixture struct {
	server *httptest.Server
	client *Client
}

func newFixture(t *testing.T, handler http.HandlerFunc) fixture {
	t.Helper()
	if handler == nil {
		handler = func(http.ResponseWriter, *http.Request) {}
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	web := mustURL(t, server.URL)
	api := mustURL(t, server.URL+"/api/v3")
	endpoints := githubapp.Endpoints{Web: web, API: api, Upload: web, Git: web}
	clientHTTP, err := githubapp.NewHTTPClient(serverCertificatePEM(t, server), endpoints, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(endpoints, mustURL(t, "https://grepnest.example"), "client-id", []byte(testSecret), "2022-11-28", clientHTTP)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{server: server, client: client}
}

func endpointsFor(t *testing.T, web, api string) githubapp.Endpoints {
	t.Helper()
	return githubapp.Endpoints{Web: mustURL(t, web), API: mustURL(t, api), Upload: mustURL(t, api), Git: mustURL(t, api)}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	value, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func serverCertificatePEM(t *testing.T, server *httptest.Server) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
}
