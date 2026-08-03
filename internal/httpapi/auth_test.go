package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/observability"
	"github.com/grepnest/grepnest/internal/sso"
)

type authProvider struct {
	metadata   sso.Metadata
	registered bool
}

func (provider *authProvider) Metadata() sso.Metadata  { return provider.metadata }
func (provider *authProvider) Register(*http.ServeMux) { provider.registered = true }

type authSessionService struct {
	principal authn.Principal
	authErr   error
	revokeErr error
	revoked   []string
}

func (service *authSessionService) Authenticate(context.Context, string) (authn.Principal, error) {
	return service.principal, service.authErr
}
func (service *authSessionService) Revoke(_ context.Context, token string) error {
	service.revoked = append(service.revoked, token)
	return service.revokeErr
}

func TestRegisterAuthConfigExposesOnlyEnabledMetadata(t *testing.T) {
	providers := []*authProvider{
		{metadata: sso.Metadata{ID: "oidc", Label: "Sign in with SSO", LoginURL: "/auth/oidc/login"}},
		{metadata: sso.Metadata{ID: "github", Label: "Sign in with GitHub", LoginURL: "/auth/oauth/github/login"}},
	}
	mux := http.NewServeMux()
	RegisterAuth(mux, true, true, false, []sso.Provider{providers[0], providers[1]}, authn.RequestAuthenticator{}, nil, nil)
	recorder := requestAuth(mux, http.MethodGet, "/v1/auth/config", "")
	if recorder.Code != http.StatusOK || !providers[0].registered || !providers[1].registered {
		t.Fatalf("response=%d registered=%v,%v", recorder.Code, providers[0].registered, providers[1].registered)
	}
	var body struct {
		TokenLogin bool           `json:"token_login"`
		BreakGlass bool           `json:"break_glass"`
		FileReads  bool           `json:"file_reads"`
		Providers  []sso.Metadata `json:"providers"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.TokenLogin || !body.BreakGlass || body.FileReads || len(body.Providers) != 2 || body.Providers[0] != providers[0].metadata || body.Providers[1] != providers[1].metadata {
		t.Fatalf("body = %#v", body)
	}
	for _, secret := range []string{"secret", "issuer", "client_id", "groups", "client_secret_file", "ca_file"} {
		if strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("config leaked %q: %s", secret, recorder.Body.String())
		}
	}
	assertAuthPrivateHeaders(t, recorder)
	emptyMux := http.NewServeMux()
	RegisterAuth(emptyMux, false, false, false, nil, authn.RequestAuthenticator{}, nil, nil)
	empty := requestAuth(emptyMux, http.MethodGet, "/v1/auth/config", "")
	if empty.Body.String() != "{\"token_login\":false,\"break_glass\":false,\"file_reads\":false,\"providers\":[]}\n" {
		t.Fatalf("disabled config = %q", empty.Body.String())
	}
	fileMux := http.NewServeMux()
	RegisterAuth(fileMux, false, false, true, nil, authn.RequestAuthenticator{}, nil, nil)
	if file := requestAuth(fileMux, http.MethodGet, "/v1/auth/config", ""); file.Body.String() != "{\"token_login\":false,\"break_glass\":false,\"file_reads\":true,\"providers\":[]}\n" {
		t.Fatalf("file config = %q", file.Body.String())
	}
}

func TestRegisterAuthSessionReportsOnlyMethodAndDisplayName(t *testing.T) {
	static := authn.NewStatic(map[string]authn.Principal{"token": {Subject: "static-subject", Method: "static", Administrator: true, RepositoryIDs: []int64{1}}})
	tests := []struct {
		name, authorization, cookie, want string
		authenticator                     authn.RequestAuthenticator
	}{
		{"anonymous", "", "", "", authn.RequestAuthenticator{}},
		{"bearer", "Bearer token", "", "{\"method\":\"static\"}\n", authn.RequestAuthenticator{Bearer: static}},
		{"OIDC", "", "session", "{\"method\":\"oidc\"}\n", authn.RequestAuthenticator{Session: &authSessionService{principal: authn.Principal{Subject: "oidc:subject", Method: "oidc"}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mux := http.NewServeMux()
			RegisterAuth(mux, true, false, false, nil, test.authenticator, nil, nil)
			request := httptest.NewRequest(http.MethodGet, "/v1/auth/session", nil)
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			if test.cookie != "" {
				request.AddCookie(&http.Cookie{Name: authn.SessionCookieName, Value: test.cookie})
			}
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)
			if test.name == "anonymous" {
				if recorder.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d", recorder.Code)
				}
			} else if recorder.Code != http.StatusOK || recorder.Body.String() != test.want {
				t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
			}
			for _, forbidden := range []string{"subject", "administrator", "repository", "scope", "claim"} {
				if strings.Contains(recorder.Body.String(), forbidden) {
					t.Fatalf("session leaked %q: %s", forbidden, recorder.Body.String())
				}
			}
			assertAuthPrivateHeaders(t, recorder)
		})
	}
}

func TestRegisterAuthLogoutIsIdempotentAndClearsCookie(t *testing.T) {
	tests := []struct {
		name, cookie, wantResult string
		revokeErr                error
		wantStatus               int
		wantClear                bool
	}{
		{"missing", "", "success", nil, http.StatusNoContent, true}, {"valid", "valid-session", "success", nil, http.StatusNoContent, true}, {"unknown", "unknown-session", "success", nil, http.StatusNoContent, true}, {"malformed", "bad", "invalid", authn.ErrUnauthenticated, http.StatusNoContent, true}, {"store failure", "valid-session", "error", errors.New("database unavailable"), http.StatusServiceUnavailable, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sessions := &authSessionService{revokeErr: test.revokeErr}
			metrics := observability.New()
			mux := http.NewServeMux()
			RegisterAuth(mux, true, false, false, nil, authn.RequestAuthenticator{}, sessions, metrics)
			request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
			if test.cookie != "" {
				request.AddCookie(&http.Cookie{Name: authn.SessionCookieName, Value: test.cookie})
			}
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)
			cookies := recorder.Result().Cookies()
			if recorder.Code != test.wantStatus || (len(cookies) == 1) != test.wantClear {
				t.Fatalf("response = %d cookies=%#v", recorder.Code, cookies)
			}
			if test.wantClear && (cookies[0].Name != authn.SessionCookieName || cookies[0].MaxAge != -1) {
				t.Fatalf("cleared cookie = %#v", cookies[0])
			}
			if test.wantStatus == http.StatusServiceUnavailable && !strings.Contains(recorder.Body.String(), `"code":"unavailable"`) {
				t.Fatalf("body = %q", recorder.Body.String())
			}
			if (len(sessions.revoked) == 1) != (test.cookie != "") {
				t.Fatalf("revoked = %#v", sessions.revoked)
			}
			metricResponse := httptest.NewRecorder()
			metrics.Handler().ServeHTTP(metricResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if !strings.Contains(metricResponse.Body.String(), `grepnest_auth_events_total{event="logout",provider="session",result="`+test.wantResult+`"} 1`) {
				t.Fatalf("logout metric = %s", metricResponse.Body.String())
			}
			assertAuthPrivateHeaders(t, recorder)
		})
	}
}

func TestRegisterAuthLogoutRequiresSessionRequestBoundary(t *testing.T) {
	const publicOrigin = "https://grepnest.example.test"
	tests := []struct {
		name, origin, authorization, cookie string
		wantStatus                          int
		wantRevoked                         bool
	}{
		{"exact Origin", publicOrigin, "", "valid-session", http.StatusNoContent, true}, {"missing Origin", "", "", "valid-session", http.StatusUnauthorized, false}, {"null Origin", "null", "", "valid-session", http.StatusUnauthorized, false}, {"wrong scheme", "http://grepnest.example.test", "", "valid-session", http.StatusUnauthorized, false}, {"wrong host", "https://other.example.test", "", "valid-session", http.StatusUnauthorized, false}, {"wrong port", publicOrigin + ":8443", "", "valid-session", http.StatusUnauthorized, false}, {"mixed credentials", publicOrigin, "Bearer token", "valid-session", http.StatusUnauthorized, false}, {"cookie-less", "", "", "", http.StatusNoContent, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sessions := &authSessionService{}
			mux := http.NewServeMux()
			RegisterAuth(mux, true, false, false, nil, authn.RequestAuthenticator{PublicOrigin: publicOrigin}, sessions, nil)
			request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
			request.Header.Set("Origin", test.origin)
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			if test.cookie != "" {
				request.AddCookie(&http.Cookie{Name: authn.SessionCookieName, Value: test.cookie})
			}
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			if (len(sessions.revoked) == 1) != test.wantRevoked {
				t.Fatalf("revoked = %#v", sessions.revoked)
			}
			if test.wantStatus == http.StatusUnauthorized && !strings.Contains(recorder.Body.String(), `"code":"unauthenticated"`) {
				t.Fatalf("body = %q", recorder.Body.String())
			}
		})
	}
}

func TestRegisterAuthEnforcesMethodsAndExactPaths(t *testing.T) {
	tests := []struct {
		method, path string
		want         int
	}{{http.MethodPost, "/v1/auth/config", http.StatusMethodNotAllowed}, {http.MethodPost, "/v1/auth/session", http.StatusMethodNotAllowed}, {http.MethodGet, "/auth/logout", http.StatusMethodNotAllowed}, {http.MethodGet, "/v1/auth/config/extra", http.StatusNotFound}, {http.MethodGet, "/v1/auth/session/extra", http.StatusNotFound}, {http.MethodPost, "/auth/logout/extra", http.StatusNotFound}}
	mux := http.NewServeMux()
	RegisterAuth(mux, true, false, false, nil, authn.RequestAuthenticator{}, nil, nil)
	for _, test := range tests {
		recorder := requestAuth(mux, test.method, test.path, "")
		if recorder.Code != test.want {
			t.Errorf("%s %s = %d, want %d", test.method, test.path, recorder.Code, test.want)
		}
	}
}

func requestAuth(handler http.Handler, method, path, authorization string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	request.Header.Set("Authorization", authorization)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}
func assertAuthPrivateHeaders(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("privacy headers = %v", recorder.Header())
	}
}
