package browserflow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/audit"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/sso"
	"github.com/jackc/pgx/v5"
)

var oidcSpec = Spec{
	Metadata:  sso.Metadata{ID: "oidc", Label: "Sign in with SSO", LoginURL: "/auth/oidc/login"},
	LoginPath: "/auth/oidc/login", CallbackPath: "/auth/oidc/callback",
	FlowProvider: authn.ProviderOIDC, IdentityProvider: authn.ProviderOIDC,
	CookieName: sso.OIDCLoginCookieName, Method: authn.ProviderOIDC,
	SuccessOperation: audit.OperationOIDCLoginSucceeded,
	DeniedOperation:  audit.OperationOIDCLoginDenied,
}

type failingRecorder struct{ events []audit.Event }

func (r *failingRecorder) Record(_ context.Context, event audit.Event) error {
	r.events = append(r.events, event)
	return errors.New("audit unavailable")
}

func TestCallbackDenialIgnoresAuditFailure(t *testing.T) {
	recorder := &failingRecorder{}
	provider := &Provider{Spec: oidcSpec, Audit: recorder}
	response := httptest.NewRecorder()
	provider.callback(response, httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?error=sentinel-claim", nil))
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status=%d", response.Code)
	}
	if len(recorder.events) != 1 || recorder.events[0].AuthenticationMethod != authn.ProviderOIDC ||
		recorder.events[0].Operation != audit.OperationOIDCLoginDenied || strings.Contains(recorder.events[0].ActorID+recorder.events[0].TargetID, "sentinel") {
		t.Fatalf("events=%#v", recorder.events)
	}
}

type providerClient struct {
	identity authn.Identity
	err      error
	code     string
	verifier string
	nonce    string
}

func (client *providerClient) AuthorizationURL(state, nonce, verifier string) string {
	client.nonce, client.verifier = nonce, verifier
	return "https://idp.example.test/authorize?state=" + url.QueryEscape(state)
}

func (client *providerClient) Exchange(_ context.Context, code, verifier, nonce string) (authn.Identity, error) {
	client.code, client.verifier, client.nonce = code, verifier, nonce
	return client.identity, client.err
}

type providerStore struct {
	flow           authn.LoginFlow
	createErr      error
	consumeErr     error
	sessionErr     error
	consumed       bool
	consumeArgs    [][32]byte
	session        authn.SessionRecord
	loginOperation string
}

func (store *providerStore) CreateLoginFlow(_ context.Context, flow authn.LoginFlow) error {
	store.flow = flow
	return store.createErr
}
func (store *providerStore) ConsumeLoginFlow(_ context.Context, state, browser [32]byte, provider string, now time.Time) (authn.LoginFlow, error) {
	store.consumeArgs = append(store.consumeArgs, state, browser)
	if store.consumeErr != nil || store.consumed || provider != store.flow.Provider || now.Before(store.flow.CreatedAt) || !now.Before(store.flow.ExpiresAt) ||
		state != store.flow.StateHash || browser != store.flow.BrowserHash {
		if store.consumeErr != nil {
			return authn.LoginFlow{}, store.consumeErr
		}
		return authn.LoginFlow{}, pgx.ErrNoRows
	}
	store.consumed = true
	return store.flow, nil
}
func (store *providerStore) CreateSession(_ context.Context, session authn.SessionRecord) error {
	if store.sessionErr != nil {
		return store.sessionErr
	}
	store.session = session
	return nil
}
func (store *providerStore) CreateSessionAudited(ctx context.Context, session authn.SessionRecord, _ audit.Event) error {
	return store.CreateSession(ctx, session)
}
func (store *providerStore) CreateFederatedSessionAudited(ctx context.Context, identity authn.Identity, session authn.SessionRecord, operation string) error {
	store.loginOperation = operation
	userID, err := store.BindFederatedUser(ctx, identity.Issuer, identity.Subject, identity.LinkID)
	if err != nil {
		return err
	}
	session.UserID = userID
	return store.CreateSession(ctx, session)
}
func (store *providerStore) BindFederatedUser(context.Context, string, string, string) (int64, error) {
	return 1, nil
}
func (*providerStore) SessionPrincipal(context.Context, [32]byte, time.Time, time.Time) (authn.Principal, error) {
	return authn.Principal{}, errors.New("unused")
}
func (*providerStore) RevokeSession(context.Context, [32]byte) error { return nil }
func (store *providerStore) RevokeSessionAudited(ctx context.Context, hash [32]byte) error {
	return store.RevokeSession(ctx, hash)
}
func (*providerStore) DeleteExpiredAuth(context.Context, time.Time) (int64, int64, error) {
	return 0, 0, nil
}

func TestOIDCProviderLoginFailsClosedOnEntropyOrStoreErrors(t *testing.T) {
	tests := []struct {
		name   string
		random []byte
		store  *providerStore
	}{
		{"entropy", nil, &providerStore{}},
		{"store", bytes.Repeat([]byte{1}, 96), &providerStore{createErr: errors.New("database unavailable")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &Provider{
				Spec:   oidcSpec,
				Client: &providerClient{}, Store: test.store, LoginTTL: time.Minute,
				Rand: bytes.NewReader(test.random),
			}
			mux := http.NewServeMux()
			provider.Register(mux)
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil))
			if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/?auth_error=authentication_failed" ||
				len(recorder.Result().Cookies()) != 0 {
				t.Fatalf("response = %d headers=%v cookies=%#v", recorder.Code, recorder.Header(), recorder.Result().Cookies())
			}
		})
	}
}

func TestOIDCProviderLoginCreatesBoundFlowAndRedirects(t *testing.T) {
	now := time.Unix(1_000, 0)
	random := append(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)...)
	random = append(random, bytes.Repeat([]byte{3}, 32)...)
	store := &providerStore{}
	client := &providerClient{}
	provider := &Provider{
		Spec:   oidcSpec,
		Client: client, Store: store, LoginTTL: 10 * time.Minute, Now: func() time.Time { return now },
		Rand: bytes.NewReader(random), Sessions: &authn.SessionManager{Store: store, TTL: time.Hour},
	}
	mux := http.NewServeMux()
	provider.Register(mux)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil))

	if recorder.Code != http.StatusSeeOther || !strings.HasPrefix(recorder.Header().Get("Location"), "https://idp.example.test/authorize?state=") {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Header().Get("Location"))
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sso.OIDCLoginCookieName || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookies = %#v", cookies)
	}
	state := strings.TrimPrefix(recorder.Header().Get("Location"), "https://idp.example.test/authorize?state=")
	state, _ = url.QueryUnescape(state)
	stateRaw, _ := base64.RawURLEncoding.DecodeString(state)
	browserRaw, _ := base64.RawURLEncoding.DecodeString(cookies[0].Value)
	nonceRaw, _ := base64.RawURLEncoding.DecodeString(client.nonce)
	if len(stateRaw) != 32 || len(browserRaw) != 32 || len(nonceRaw) != 32 || state == cookies[0].Value || client.nonce == state || client.verifier == "" {
		t.Fatalf("state/browser/nonce/verifier not independent")
	}
	if store.flow.StateHash != sha256.Sum256(stateRaw) || store.flow.BrowserHash != sha256.Sum256(browserRaw) ||
		store.flow.Provider != "oidc" || store.flow.Nonce != client.nonce || store.flow.CodeVerifier != client.verifier ||
		store.flow.ReturnTo != "/" || !store.flow.CreatedAt.Equal(now) || !store.flow.ExpiresAt.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("flow = %#v", store.flow)
	}
	assertPrivateHeaders(t, recorder)
}

func TestProviderUsesSpecifiedLoginCookieForLoginAndCallback(t *testing.T) {
	const cookieName = "__Host-grepnest_test_browserflow_login"
	spec := oidcSpec
	spec.CookieName = cookieName

	now := time.Unix(1_000, 0)
	store := &providerStore{}
	client := &providerClient{}
	provider := &Provider{
		Spec: spec, Client: client, Store: store, LoginTTL: time.Minute,
		Now: func() time.Time { return now }, Rand: bytes.NewReader(bytes.Repeat([]byte{1}, 96)),
	}
	mux := http.NewServeMux()
	provider.Register(mux)
	login := httptest.NewRecorder()
	mux.ServeHTTP(login, httptest.NewRequest(http.MethodGet, spec.LoginPath, nil))
	if cookies := login.Result().Cookies(); len(cookies) != 1 || cookies[0].Name != cookieName {
		t.Fatalf("login cookies=%#v", cookies)
	}

	fixture := newCallbackFixture(t)
	fixture.provider.Spec.CookieName = cookieName
	callback := fixture.callback(t, "?state="+fixture.state+"&code=good", fixture.browser)
	if !fixture.store.consumed {
		t.Fatal("callback did not consume the flow using the specified cookie")
	}
	cookies := callback.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != cookieName || cookies[0].MaxAge != -1 {
		t.Fatalf("callback cookies=%#v", cookies)
	}
}

func TestOIDCProviderCallbackSuccessConsumesCreatesSessionAndRedirects(t *testing.T) {
	fixture := newCallbackFixture(t)
	recorder := fixture.callback(t, "?state="+fixture.state+"&code=good", fixture.browser)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Header().Get("Location"))
	}
	if !fixture.store.consumed || fixture.client.code != "good" || fixture.client.verifier != fixture.store.flow.CodeVerifier ||
		fixture.client.nonce != fixture.store.flow.Nonce || fixture.store.session.Provider != "oidc" ||
		fixture.store.session.UserID != 1 || fixture.store.loginOperation != audit.OperationOIDCLoginSucceeded {
		t.Fatalf("callback side effects missing: store=%#v client=%#v", fixture.store, fixture.client)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != sso.OIDCLoginCookieName || cookies[0].MaxAge != -1 ||
		cookies[1].Name != authn.SessionCookieName || cookies[1].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookies = %#v", cookies)
	}
	for _, secret := range []string{"id-token-secret", "access-token-secret"} {
		if strings.Contains(recorder.Body.String()+recorder.Header().Get("Location")+recorder.Header().Get("Set-Cookie"), secret) {
			t.Fatalf("response leaked %q", secret)
		}
	}
	assertPrivateHeaders(t, recorder)
}

func TestOIDCProviderCallbackRejectsMalformedAndBoundRequests(t *testing.T) {
	tests := []struct {
		name, query, cookie string
	}{
		{"missing state", "?code=x", "browser"},
		{"empty state", "?state=&code=x", "browser"},
		{"duplicate state", "?state=x&state=y&code=x", "browser"},
		{"missing result", "?state=x", "browser"},
		{"empty code", "?state=x&code=", "browser"},
		{"duplicate code", "?state=x&code=a&code=b", "browser"},
		{"empty error", "?state=x&error=", "browser"},
		{"duplicate error", "?state=x&error=a&error=b", "browser"},
		{"code and error", "?state=x&code=a&error=b", "browser"},
		{"code with empty error", "?state=x&code=a&error=", "browser"},
		{"error with empty code", "?state=x&code=&error=access_denied", "browser"},
		{"missing cookie", "?state=x&code=a", ""},
		{"malformed cookie", "?state=x&code=a", "malformed"},
		{"wrong cookie", "?state=x&code=a", token(9)},
		{"wrong state", "?state=" + token(8) + "&code=a", "browser"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCallbackFixture(t)
			query := strings.ReplaceAll(test.query, "state=x", "state="+fixture.state)
			cookie := test.cookie
			if cookie == "browser" {
				cookie = fixture.browser
			}
			recorder := fixture.callback(t, query, cookie)
			assertGenericFailure(t, recorder)
			if recorder.Code != http.StatusSeeOther {
				t.Fatalf("status = %d", recorder.Code)
			}
			if (test.name == "wrong cookie" || test.name == "code with empty error" || test.name == "error with empty code") && fixture.store.consumed {
				t.Fatal("invalid callback consumed flow")
			}
		})
	}
}

func TestOIDCProviderCallbackBoundsValuesBeforeConsumingFlow(t *testing.T) {
	for _, test := range []struct {
		name, nameValue    string
		wantConsumed, okay bool
	}{
		{"exact code", "code=" + strings.Repeat("c", maxCallbackValueLen), true, true},
		{"long code", "code=" + strings.Repeat("c", maxCallbackValueLen+1), false, false},
		{"exact error", "error=" + strings.Repeat("e", maxCallbackValueLen), true, false},
		{"long error", "error=" + strings.Repeat("e", maxCallbackValueLen+1), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCallbackFixture(t)
			recorder := fixture.callback(t, "?state="+fixture.state+"&"+test.nameValue, fixture.browser)
			if test.okay && recorder.Header().Get("Location") != "/" {
				t.Fatalf("exact code response = %q", recorder.Header().Get("Location"))
			}
			if test.wantConsumed && !test.okay {
				assertGenericFailure(t, recorder)
			}
			if fixture.store.consumed != test.wantConsumed {
				t.Fatalf("consumed = %t", fixture.store.consumed)
			}
		})
	}
}

func TestExactlyOneBoundsCallbackValues(t *testing.T) {
	if _, ok := exactlyOne([]string{strings.Repeat("x", maxCallbackValueLen)}); !ok {
		t.Fatal("exact boundary rejected")
	}
	if _, ok := exactlyOne([]string{strings.Repeat("x", maxCallbackValueLen+1)}); ok {
		t.Fatal("over-boundary value accepted")
	}
}

func TestOIDCProviderCallbackRejectsDuplicateBindingCookie(t *testing.T) {
	fixture := newCallbackFixture(t)
	mux := http.NewServeMux()
	fixture.provider.Register(mux)
	request := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state="+fixture.state+"&code=good", nil)
	request.Header.Add("Cookie", sso.OIDCLoginCookieName+"="+fixture.browser)
	request.Header.Add("Cookie", sso.OIDCLoginCookieName+"="+fixture.browser)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	assertGenericFailure(t, recorder)
	if fixture.store.consumed {
		t.Fatal("duplicate browser cookie consumed flow")
	}
}

func TestOIDCProviderCallbackConsumesBeforeTerminalFailures(t *testing.T) {
	tests := []struct {
		name, suffix string
		setup        func(*callbackFixture)
	}{
		{"OAuth error", "&error=access_denied&error_description=id-token-secret", nil},
		{"exchange error", "&code=bad", func(f *callbackFixture) { f.client.err = errors.New("access-token-secret") }},
		{"session error", "&code=good", func(f *callbackFixture) { f.store.sessionErr = errors.New("database unavailable") }},
		{"expired", "&code=good", func(f *callbackFixture) { f.provider.Now = func() time.Time { return time.Unix(3_000, 0) } }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCallbackFixture(t)
			if test.setup != nil {
				test.setup(fixture)
			}
			recorder := fixture.callback(t, "?state="+fixture.state+test.suffix, fixture.browser)
			assertGenericFailure(t, recorder)
			if test.name != "expired" && !fixture.store.consumed {
				t.Fatal("flow was not consumed")
			}
			if fixture.store.session.TokenHash != ([32]byte{}) {
				t.Fatal("failure created session")
			}
		})
	}
}

func TestProviderCallbackRejectsWrongIdentityProvider(t *testing.T) {
	fixture := newCallbackFixture(t)
	fixture.client.identity.Provider = authn.ProviderOAuth
	recorder := fixture.callback(t, "?state="+fixture.state+"&code=good", fixture.browser)
	assertGenericFailure(t, recorder)
	if !fixture.store.consumed || fixture.store.session.TokenHash != ([32]byte{}) {
		t.Fatalf("consumed=%t session=%#v", fixture.store.consumed, fixture.store.session)
	}
}

func TestProviderCallbackRejectsWrongFlowProvider(t *testing.T) {
	fixture := newCallbackFixture(t)
	fixture.store.flow.Provider = "wrong"
	recorder := fixture.callback(t, "?state="+fixture.state+"&code=good", fixture.browser)
	assertGenericFailure(t, recorder)
	if fixture.store.consumed || fixture.store.session.TokenHash != ([32]byte{}) {
		t.Fatalf("consumed=%t session=%#v", fixture.store.consumed, fixture.store.session)
	}
}

func TestOIDCProviderCallbackRejectsReplayAndIgnoresReturnTargets(t *testing.T) {
	fixture := newCallbackFixture(t)
	first := fixture.callback(t, "?state="+fixture.state+"&code=good&return_to=https://evil.test", fixture.browser)
	if first.Header().Get("Location") != "/" {
		t.Fatalf("success redirect = %q", first.Header().Get("Location"))
	}
	second := fixture.callback(t, "?state="+fixture.state+"&code=good", fixture.browser)
	assertGenericFailure(t, second)
}

func TestOIDCProviderEnforcesGETMethods(t *testing.T) {
	provider := &Provider{Spec: oidcSpec}
	mux := http.NewServeMux()
	provider.Register(mux)
	for _, path := range []string{"/auth/oidc/login", "/auth/oidc/callback"} {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodGet {
			t.Errorf("POST %s = %d, Allow=%q", path, recorder.Code, recorder.Header().Get("Allow"))
		}
		assertPrivateHeaders(t, recorder)
	}
}

type callbackFixture struct {
	provider *Provider
	client   *providerClient
	store    *providerStore
	state    string
	browser  string
}

func newCallbackFixture(t *testing.T) *callbackFixture {
	t.Helper()
	now := time.Unix(2_000, 0)
	state, browser := token(1), token(2)
	stateRaw, _ := base64.RawURLEncoding.DecodeString(state)
	browserRaw, _ := base64.RawURLEncoding.DecodeString(browser)
	store := &providerStore{flow: authn.LoginFlow{
		StateHash: sha256.Sum256(stateRaw), BrowserHash: sha256.Sum256(browserRaw), Provider: "oidc",
		Nonce: "nonce", CodeVerifier: "verifier", ReturnTo: "/", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}}
	client := &providerClient{identity: authn.Identity{
		Provider: "oidc", Issuer: "https://issuer.example.test", Subject: "ada", LinkID: "directory-42", DisplayName: "Ada",
	}}
	provider := &Provider{
		Spec:   oidcSpec,
		Client: client, Store: store,
		Sessions: &authn.SessionManager{Store: store, IdleTTL: time.Minute, TTL: time.Hour, Now: func() time.Time { return now }, Rand: bytes.NewReader(bytes.Repeat([]byte{4}, 32))},
		Now:      func() time.Time { return now },
	}
	return &callbackFixture{provider: provider, client: client, store: store, state: state, browser: browser}
}

func (fixture *callbackFixture) callback(t *testing.T, query, browser string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	fixture.provider.Register(mux)
	request := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback"+query, nil)
	if browser != "" {
		request.AddCookie(&http.Cookie{Name: fixture.provider.Spec.CookieName, Value: browser})
	}
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	return recorder
}

func token(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func assertGenericFailure(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Header().Get("Location") != "/?auth_error=authentication_failed" ||
		strings.Contains(recorder.Body.String()+recorder.Header().Get("Location"), "access-token-secret") ||
		len(recorder.Result().Cookies()) != 1 || recorder.Result().Cookies()[0].Name != sso.OIDCLoginCookieName ||
		recorder.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("non-generic failure: status=%d headers=%v body=%q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	assertPrivateHeaders(t, recorder)
}

func assertPrivateHeaders(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("privacy headers = %v", recorder.Header())
	}
}
