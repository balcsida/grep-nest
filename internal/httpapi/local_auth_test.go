package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/audit"
	"github.com/grepnest/grepnest/internal/authn"
)

const localAuthOrigin = "https://search.example.test"

type localAuthStore struct {
	userID     int64
	credential authn.PasswordCredential
	lookupErr  error
	allowed    bool
	attempts   int
	limit      int
	set        authn.PasswordCredential
	event      audit.Event
	sessions   []authn.SessionRecord
	revoked    int
	rotateErr  error
	loginErr   error
}

func (s *localAuthStore) PasswordCredential(_ context.Context, userName string) (int64, authn.PasswordCredential, error) {
	if userName != "recovery-admin" {
		return 0, authn.PasswordCredential{}, errors.New("unknown user")
	}
	credential := s.credential
	credential.Salt = bytes.Clone(credential.Salt)
	credential.Hash = bytes.Clone(credential.Hash)
	return s.userID, credential, s.lookupErr
}
func (s *localAuthStore) ConsumeLoginAttempt(context.Context, [32]byte, time.Time) (bool, time.Time, error) {
	if s.limit > 0 {
		s.attempts++
		return s.attempts <= s.limit, time.Time{}, nil
	}
	return s.allowed, time.Time{}, nil
}
func (s *localAuthStore) ClearLoginFailures(context.Context, [32]byte, [32]byte) error {
	s.attempts = 0
	return nil
}
func (*localAuthStore) BindFederatedUser(context.Context, string, string, string) (int64, error) {
	return 0, errors.New("unexpected OIDC bind")
}
func (*localAuthStore) CreateLoginFlow(context.Context, authn.LoginFlow) error {
	return errors.New("unexpected login flow")
}
func (*localAuthStore) ConsumeLoginFlow(context.Context, [32]byte, [32]byte, string, time.Time) (authn.LoginFlow, error) {
	return authn.LoginFlow{}, errors.New("unexpected login flow")
}
func (s *localAuthStore) CreateSession(_ context.Context, session authn.SessionRecord) error {
	s.sessions = append(s.sessions, session)
	return nil
}
func (s *localAuthStore) CreateSessionAudited(ctx context.Context, session authn.SessionRecord, _ audit.Event) error {
	return s.CreateSession(ctx, session)
}
func (s *localAuthStore) CreateFederatedSessionAudited(context.Context, authn.Identity, authn.SessionRecord, string) error {
	return errors.New("unexpected OIDC session")
}
func (*localAuthStore) SessionPrincipal(context.Context, [32]byte, time.Time, time.Time) (authn.Principal, error) {
	return authn.Principal{}, errors.New("unexpected session authentication")
}
func (s *localAuthStore) RevokeSession(context.Context, [32]byte) error {
	s.revoked++
	return nil
}
func (s *localAuthStore) RevokeSessionAudited(ctx context.Context, hash [32]byte) error {
	return s.RevokeSession(ctx, hash)
}
func (*localAuthStore) DeleteExpiredAuth(context.Context, time.Time) (int64, int64, error) {
	return 0, 0, nil
}
func (s *localAuthStore) RotatePasswordCredential(_ context.Context, _ int64, _ authn.PasswordCredential, credential authn.PasswordCredential, session authn.SessionRecord, _, _ [32]byte, event audit.Event) error {
	if s.rotateErr != nil {
		return s.rotateErr
	}
	credential.Salt = bytes.Clone(credential.Salt)
	credential.Hash = bytes.Clone(credential.Hash)
	s.set = credential
	s.event = event
	s.credential = credential
	s.sessions = append(s.sessions, session)
	s.attempts = 0
	return nil
}
func (s *localAuthStore) CreatePasswordSession(_ context.Context, _ int64, _ authn.PasswordCredential, session authn.SessionRecord, _, _ [32]byte) error {
	if s.loginErr != nil {
		return s.loginErr
	}
	s.sessions = append(s.sessions, session)
	s.attempts = 0
	return nil
}

func newLocalAuthHandler(t *testing.T, forceRotation, allowed bool) (http.Handler, *localAuthStore) {
	return newLocalAuthHandlerWithPassword(t, "sixteen-byte-secret", forceRotation, allowed)
}

func newLocalAuthHandlerWithPassword(t *testing.T, password string, forceRotation, allowed bool) (http.Handler, *localAuthStore) {
	t.Helper()
	credential, err := authn.HashPassword([]byte(password), bytes.NewReader(bytes.Repeat([]byte{1}, 48)))
	if err != nil {
		t.Fatal(err)
	}
	credential.ForceRotation = forceRotation
	store := &localAuthStore{userID: 7, credential: credential, allowed: allowed}
	sessions := &authn.SessionManager{
		Store: store, IdleTTL: time.Minute, TTL: time.Hour,
		Now:  func() time.Time { return time.Unix(1_700_000_000, 0) },
		Rand: bytes.NewReader(bytes.Repeat([]byte{2}, 96)),
	}
	local, err := authn.NewLocalAuthenticator(store, sessions, bytes.NewReader(bytes.Repeat([]byte{3}, 80)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterLocalAuth(mux, localAuthOrigin, &local, store)
	return mux, store
}

func localRequest(handler http.Handler, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.RemoteAddr = "192.0.2.10:4321"
	request.Header.Set("Origin", localAuthOrigin)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestLocalLoginIssuesOnlyStandardSession(t *testing.T) {
	handler, store := newLocalAuthHandler(t, false, true)
	response := localRequest(handler, "/auth/local", `{"user_name":"recovery-admin","password":"sixteen-byte-secret"}`)
	cookies := response.Result().Cookies()
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 || len(cookies) != 1 {
		t.Fatalf("response=%d body=%q cookies=%#v", response.Code, response.Body.String(), cookies)
	}
	cookie := cookies[0]
	if cookie.Name != authn.SessionCookieName || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Value == "" {
		t.Fatalf("cookie=%#v", cookie)
	}
	if len(store.sessions) != 1 || store.sessions[0].ForceRotation {
		t.Fatalf("sessions=%#v", store.sessions)
	}
}

func TestLocalLoginKeepsCredentialFailuresGeneric(t *testing.T) {
	handler, _ := newLocalAuthHandler(t, false, true)
	wrong := localRequest(handler, "/auth/local", `{"user_name":"recovery-admin","password":"wrong-password"}`)
	unknown := localRequest(handler, "/auth/local", `{"user_name":"missing-admin","password":"wrong-password"}`)
	forcedHandler, forcedStore := newLocalAuthHandler(t, true, true)
	forced := localRequest(forcedHandler, "/auth/local", `{"user_name":"recovery-admin","password":"sixteen-byte-secret"}`)
	if wrong.Code != http.StatusUnauthorized || wrong.Code != unknown.Code || wrong.Code != forced.Code ||
		wrong.Body.String() != unknown.Body.String() || wrong.Body.String() != forced.Body.String() ||
		!reflect.DeepEqual(wrong.Header(), unknown.Header()) || !reflect.DeepEqual(wrong.Header(), forced.Header()) {
		t.Fatalf("wrong=%d %q unknown=%d %q forced=%d %q", wrong.Code, wrong.Body.String(), unknown.Code, unknown.Body.String(), forced.Code, forced.Body.String())
	}
	if len(forcedStore.sessions) != 0 || forcedStore.revoked != 0 || len(forced.Result().Cookies()) != 0 {
		t.Fatalf("forced sessions=%d revoked=%d cookies=%#v", len(forcedStore.sessions), forcedStore.revoked, forced.Result().Cookies())
	}
}

func TestLocalLoginRejectsCredentialChangedBeforeSessionCommit(t *testing.T) {
	handler, store := newLocalAuthHandler(t, false, true)
	store.loginErr = authn.ErrUnauthenticated
	response := localRequest(handler, "/auth/local", `{"user_name":"recovery-admin","password":"sixteen-byte-secret"}`)
	if response.Code != http.StatusUnauthorized || len(response.Result().Cookies()) != 0 || len(store.sessions) != 0 {
		t.Fatalf("response=%d cookies=%#v sessions=%d", response.Code, response.Result().Cookies(), len(store.sessions))
	}
}

func TestLocalLoginReturnsOnlyAtomicThrottleResult(t *testing.T) {
	handler, _ := newLocalAuthHandler(t, false, false)
	response := localRequest(handler, "/auth/local", `{"user_name":"recovery-admin","password":"sixteen-byte-secret"}`)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "900" || response.Body.String() == "" {
		t.Fatalf("response=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
}

func TestForcedLocalLoginDoesNotClearThrottle(t *testing.T) {
	handler, store := newLocalAuthHandler(t, true, true)
	store.limit = 4
	body := `{"user_name":"recovery-admin","password":"sixteen-byte-secret"}`
	first := localRequest(handler, "/auth/local", body)
	second := localRequest(handler, "/auth/local", body)
	third := localRequest(handler, "/auth/local", body)
	if first.Code != http.StatusUnauthorized || second.Code != http.StatusUnauthorized || third.Code != http.StatusTooManyRequests {
		t.Fatalf("statuses=%d,%d,%d attempts=%d", first.Code, second.Code, third.Code, store.attempts)
	}
}

func TestLocalAuthRejectsUnsafeEnvelopeBeforeBody(t *testing.T) {
	handler, _ := newLocalAuthHandler(t, false, true)
	for _, test := range []struct {
		name, method, path, origin, fetchSite, contentType, body string
		want                                                     int
	}{
		{"method", http.MethodGet, "/auth/local", localAuthOrigin, "same-origin", "application/json", "", http.StatusMethodNotAllowed},
		{"query", http.MethodPost, "/auth/local?next=/", localAuthOrigin, "same-origin", "application/json", `{}`, http.StatusBadRequest},
		{"origin", http.MethodPost, "/auth/local", "https://evil.example", "same-origin", "text/plain", `{}`, http.StatusUnauthorized},
		{"fetch metadata", http.MethodPost, "/auth/local", localAuthOrigin, "cross-site", "text/plain", `{}`, http.StatusUnauthorized},
		{"content type", http.MethodPost, "/auth/local", localAuthOrigin, "same-origin", "application/json; charset=utf-8", `{}`, http.StatusUnsupportedMediaType},
		{"unknown field", http.MethodPost, "/auth/local", localAuthOrigin, "same-origin", "application/json", `{"user_name":"x","password":"y","extra":true}`, http.StatusBadRequest},
		{"trailing object", http.MethodPost, "/auth/local", localAuthOrigin, "same-origin", "application/json", `{"user_name":"x","password":"y"}{}`, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Origin", test.origin)
			request.Header.Set("Sec-Fetch-Site", test.fetchSite)
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if test.name == "method" && response.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("Allow=%q", response.Header().Get("Allow"))
			}
		})
	}
}

func TestLocalAuthRejectsDuplicateSecurityHeaders(t *testing.T) {
	handler, _ := newLocalAuthHandler(t, false, true)
	for _, name := range []string{"Origin", "Sec-Fetch-Site", "Content-Type"} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/auth/local", strings.NewReader(`{"user_name":"recovery-admin","password":"sixteen-byte-secret"}`))
			request.Header.Set("Origin", localAuthOrigin)
			request.Header.Set("Sec-Fetch-Site", "same-origin")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Add(name, request.Header.Get(name))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code == http.StatusNoContent {
				t.Fatalf("duplicate %s accepted", name)
			}
		})
	}
}

func TestLocalRotateRequiresForcedCredentialAndIssuesFreshSession(t *testing.T) {
	handler, store := newLocalAuthHandler(t, true, true)
	response := localRequest(handler, "/auth/local/rotate", `{"user_name":"recovery-admin","current_password":"sixteen-byte-secret","new_password":"replacement-secret-123"}`)
	cookies := response.Result().Cookies()
	if response.Code != http.StatusNoContent || len(cookies) != 1 || len(store.sessions) != 1 {
		t.Fatalf("response=%d body=%q cookies=%#v sessions=%d", response.Code, response.Body.String(), cookies, len(store.sessions))
	}
	if store.set.ForceRotation || store.event.Operation != "password_rotated" || store.event.AuthenticationMethod != "local" {
		t.Fatalf("credential=%#v event=%#v", store.set, store.event)
	}
	if !authn.VerifyPassword([]byte("replacement-secret-123"), store.set) || store.sessions[0].ForceRotation {
		t.Fatal("replacement credential or session is invalid")
	}

	normalHandler, normalStore := newLocalAuthHandler(t, false, true)
	normal := localRequest(normalHandler, "/auth/local/rotate", `{"user_name":"recovery-admin","current_password":"sixteen-byte-secret","new_password":"replacement-secret-123"}`)
	if normal.Code != http.StatusUnauthorized || normalStore.set.Hash != nil || len(normal.Result().Cookies()) != 0 {
		t.Fatalf("normal=%d set=%#v cookies=%#v", normal.Code, normalStore.set, normal.Result().Cookies())
	}
}

func TestLocalRotateValidatesReplacementLength(t *testing.T) {
	for _, password := range []string{strings.Repeat("p", 15), strings.Repeat("p", 1025)} {
		handler, store := newLocalAuthHandler(t, true, true)
		response := localRequest(handler, "/auth/local/rotate", `{"user_name":"recovery-admin","current_password":"sixteen-byte-secret","new_password":"`+password+`"}`)
		if response.Code != http.StatusBadRequest || store.set.Hash != nil || len(store.sessions) != 0 {
			t.Fatalf("length=%d response=%d sessions=%d", len(password), response.Code, len(store.sessions))
		}
	}
}

func TestLocalRotateAcceptsMaximumLengthPasswords(t *testing.T) {
	password := strings.Repeat("\x01", 1024)
	handler, store := newLocalAuthHandlerWithPassword(t, password, true, true)
	body, err := json.Marshal(struct {
		UserName        string `json:"user_name"`
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}{UserName: "recovery-admin", CurrentPassword: password, NewPassword: password})
	if err != nil {
		t.Fatal(err)
	}
	response := localRequest(handler, "/auth/local/rotate", string(body))
	if response.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("valid maximum-length credentials exceeded body cap")
	}
	if response.Code != http.StatusNoContent || len(store.sessions) != 1 {
		t.Fatalf("response=%d body=%q sessions=%d", response.Code, response.Body.String(), len(store.sessions))
	}
}

func TestLocalAuthRejectsBodyCapPlusOne(t *testing.T) {
	handler, _ := newLocalAuthHandler(t, false, true)
	response := localRequest(handler, "/auth/local", strings.Repeat(" ", localAuthMaxBodyBytes+1))
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestLocalRotateReturnsGenericUnauthorizedWhenCredentialChanged(t *testing.T) {
	handler, store := newLocalAuthHandler(t, true, true)
	store.rotateErr = authn.ErrUnauthenticated
	response := localRequest(handler, "/auth/local/rotate", `{"user_name":"recovery-admin","current_password":"sixteen-byte-secret","new_password":"replacement-secret-123"}`)
	if response.Code != http.StatusUnauthorized || len(response.Result().Cookies()) != 0 || len(store.sessions) != 0 {
		t.Fatalf("response=%d cookies=%#v sessions=%d", response.Code, response.Result().Cookies(), len(store.sessions))
	}
}
