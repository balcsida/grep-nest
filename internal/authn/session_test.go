package authn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/audit"
)

type sessionStoreStub struct {
	boundIssuer, boundSubject, boundLinkID string
	session                                SessionRecord
	principal                              Principal
	lookupHash                             [32]byte
	lookupNow, lookupIdleUntil             time.Time
	revoked                                [32]byte
	createErr                              error
	onCreate                               func()
	loginOperation                         string
}

func (s *sessionStoreStub) BindFederatedUser(_ context.Context, issuer, subject, linkID string) (int64, error) {
	s.boundIssuer, s.boundSubject, s.boundLinkID = issuer, subject, linkID
	return 42, nil
}

func (s *sessionStoreStub) CreateLoginFlow(context.Context, LoginFlow) error { return nil }
func (s *sessionStoreStub) ConsumeLoginFlow(context.Context, [32]byte, [32]byte, string, time.Time) (LoginFlow, error) {
	return LoginFlow{}, nil
}
func (s *sessionStoreStub) CreateSession(_ context.Context, session SessionRecord) error {
	if s.onCreate != nil {
		s.onCreate()
	}
	s.session = session
	return s.createErr
}
func (s *sessionStoreStub) CreateSessionAudited(ctx context.Context, session SessionRecord, _ audit.Event) error {
	return s.CreateSession(ctx, session)
}
func (s *sessionStoreStub) CreateFederatedSessionAudited(ctx context.Context, identity Identity, session SessionRecord, loginOperation string) error {
	userID, err := s.BindFederatedUser(ctx, identity.Issuer, identity.Subject, identity.LinkID)
	if err != nil {
		return err
	}
	session.UserID = userID
	s.loginOperation = loginOperation
	return s.CreateSession(ctx, session)
}
func (s *sessionStoreStub) SessionPrincipal(_ context.Context, hash [32]byte, now, idleUntil time.Time) (Principal, error) {
	s.lookupHash, s.lookupNow, s.lookupIdleUntil = hash, now, idleUntil
	return s.principal, nil
}
func (s *sessionStoreStub) RevokeSession(_ context.Context, hash [32]byte) error {
	s.revoked = hash
	return nil
}
func (s *sessionStoreStub) RevokeSessionAudited(ctx context.Context, hash [32]byte) error {
	return s.RevokeSession(ctx, hash)
}
func (s *sessionStoreStub) DeleteExpiredAuth(context.Context, time.Time) (int64, int64, error) {
	return 0, 0, nil
}

func TestSessionManagerCreatesOpaqueTokenForExactLinkID(t *testing.T) {
	now := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	store := &sessionStoreStub{}
	manager := SessionManager{Store: store, IdleTTL: 30 * time.Minute, TTL: 8 * time.Hour, Now: func() time.Time { return now }, Rand: bytes.NewReader(bytes.Repeat([]byte{7}, 32))}
	token, expiresAt, err := manager.Create(t.Context(), Identity{Provider: ProviderOIDC, Issuer: "https://issuer.example.test", Subject: "subject", LinkID: "directory-42", DisplayName: "Ada"}, audit.OperationOIDCLoginSucceeded)
	if err != nil || expiresAt != now.Add(8*time.Hour) {
		t.Fatalf("token=%q expiresAt=%v err=%v", token, expiresAt, err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || !bytes.Equal(raw, bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("opaque token=%q raw=%x err=%v", token, raw, err)
	}
	if store.boundIssuer != "https://issuer.example.test" || store.boundSubject != "subject" || store.boundLinkID != "directory-42" {
		t.Fatalf("bound identity = %#v", store)
	}
	if store.session.UserID != 42 || store.session.Provider != ProviderOIDC || store.loginOperation != audit.OperationOIDCLoginSucceeded || store.session.TokenHash != sha256.Sum256(raw) || store.session.CreatedAt != now || store.session.LastSeenAt != now || store.session.IdleExpiresAt != now.Add(30*time.Minute) || store.session.ExpiresAt != now.Add(8*time.Hour) {
		t.Fatalf("session = %#v", store.session)
	}
}

func TestSessionManagerCreatesFederatedSessionsForSupportedProviders(t *testing.T) {
	for _, test := range []struct{ provider, operation string }{
		{ProviderOIDC, audit.OperationOIDCLoginSucceeded},
		{ProviderOAuth, audit.OperationOAuthLoginSucceeded},
	} {
		t.Run(test.provider, func(t *testing.T) {
			store := &sessionStoreStub{}
			manager := SessionManager{Store: store, IdleTTL: time.Minute, TTL: time.Hour, Rand: bytes.NewReader(bytes.Repeat([]byte{7}, 32))}
			_, _, err := manager.Create(t.Context(), Identity{Provider: test.provider, Issuer: "https://issuer.example", Subject: "123", LinkID: "link-123"}, test.operation)
			if err != nil {
				t.Fatalf("Create(%q): %v", test.provider, err)
			}
			if store.session.Provider != test.provider || store.loginOperation != test.operation {
				t.Fatalf("session=%#v operation=%q", store.session, store.loginOperation)
			}
		})
	}
}

func TestSessionManagerRejectsMismatchedFederatedLoginOperations(t *testing.T) {
	for _, test := range []struct{ provider, operation string }{
		{ProviderOIDC, audit.OperationOAuthLoginSucceeded},
		{ProviderOAuth, audit.OperationOIDCLoginSucceeded},
	} {
		t.Run(test.provider, func(t *testing.T) {
			manager := SessionManager{Store: &sessionStoreStub{}, IdleTTL: time.Minute, TTL: time.Hour}
			if _, _, err := manager.Create(t.Context(), Identity{Provider: test.provider, Issuer: "https://issuer.example", Subject: "123", LinkID: "link-123"}, test.operation); err != ErrInvalidIdentity {
				t.Fatalf("Create(%q, %q) error=%v", test.provider, test.operation, err)
			}
		})
	}
}

func TestSessionManagerRejectsNonFederatedIdentityProviders(t *testing.T) {
	for _, provider := range []string{ProviderLocal, "github", "unknown"} {
		t.Run(provider, func(t *testing.T) {
			manager := SessionManager{Store: &sessionStoreStub{}, IdleTTL: time.Minute, TTL: time.Hour}
			if _, _, err := manager.Create(t.Context(), Identity{Provider: provider, Issuer: "https://issuer.example", Subject: "123", LinkID: "link-123"}, audit.OperationOIDCLoginSucceeded); err != ErrInvalidIdentity {
				t.Fatalf("Create(%q) error=%v", provider, err)
			}
		})
	}
}

func TestSessionManagerPreparesOnlyKnownSessionProviders(t *testing.T) {
	manager := SessionManager{Store: &sessionStoreStub{}, IdleTTL: time.Minute, TTL: time.Hour}
	for _, provider := range []string{ProviderOIDC, ProviderOAuth, ProviderLocal} {
		if _, err := manager.PrepareForUser(1, provider, false); err != nil {
			t.Fatalf("PrepareForUser(%q): %v", provider, err)
		}
	}
	for _, provider := range []string{"github", "unknown"} {
		if _, err := manager.PrepareForUser(1, provider, false); err != ErrInvalidIdentity {
			t.Fatalf("PrepareForUser(%q) error=%v", provider, err)
		}
	}
}

func TestInvalidLogoutIgnoresAuditFailureWithoutRecordingCookie(t *testing.T) {
	recorder := &failingAuditRecorder{}
	manager := SessionManager{Store: &sessionStoreStub{}, Audit: recorder}
	cookie := "sentinel-session-cookie"
	if err := manager.Revoke(t.Context(), cookie); err != ErrUnauthenticated {
		t.Fatalf("error=%v", err)
	}
	if len(recorder.events) != 1 || strings.Contains(fmt.Sprintf("%#v", recorder.events[0]), cookie) {
		t.Fatalf("events=%#v", recorder.events)
	}
}

func TestSessionManagerCreatesForcedRotationLocalSession(t *testing.T) {
	now := time.Unix(100, 0)
	store := &sessionStoreStub{}
	manager := SessionManager{Store: store, IdleTTL: time.Minute, TTL: time.Hour, Now: func() time.Time { return now }, Rand: bytes.NewReader(bytes.Repeat([]byte{7}, 32))}
	if _, _, err := manager.CreateForUser(t.Context(), 7, "local", true); err != nil {
		t.Fatal(err)
	}
	if !store.session.ForceRotation || store.session.Provider != "local" {
		t.Fatalf("session = %#v", store.session)
	}
}

func TestSessionManagerPreparesLocalSessionWithoutPersisting(t *testing.T) {
	now := time.Unix(100, 0)
	store := &sessionStoreStub{}
	manager := SessionManager{Store: store, IdleTTL: time.Minute, TTL: time.Hour, Now: func() time.Time { return now }, Rand: bytes.NewReader(bytes.Repeat([]byte{7}, 32))}
	prepared, err := manager.PrepareForUser(7, "local", false)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Token == "" || prepared.ExpiresAt != now.Add(time.Hour) || prepared.Record.UserID != 7 || prepared.Record.ForceRotation || store.session.UserID != 0 {
		t.Fatalf("prepared=%#v persisted=%#v", prepared, store.session)
	}
}

func TestSessionManagerGeneratesIndependentAuditID(t *testing.T) {
	manager := SessionManager{
		Store: &sessionStoreStub{}, IdleTTL: time.Minute, TTL: time.Hour,
		Rand:      bytes.NewReader(bytes.Repeat([]byte{7}, 32)),
		AuditRand: bytes.NewReader(bytes.Repeat([]byte{0xab}, 16)),
	}
	prepared, err := manager.PrepareForUser(7, "local", false)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Record.AuditID != "abababababababababababababababab" {
		t.Fatalf("audit ID=%q", prepared.Record.AuditID)
	}
	if strings.Contains(prepared.Token, prepared.Record.AuditID) {
		t.Fatalf("audit ID derived from token: %#v", prepared)
	}
}

func TestSessionManagerRevokesOpaqueToken(t *testing.T) {
	store := &sessionStoreStub{}
	manager := SessionManager{Store: store}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if err := manager.Revoke(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(bytes.Repeat([]byte{7}, 32)); store.revoked != want {
		t.Fatalf("revoked=%x want=%x", store.revoked, want)
	}
}

func TestSessionManagerAuthenticatesWithHashAndFreshExpiry(t *testing.T) {
	now := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	raw := bytes.Repeat([]byte{9}, 32)
	token := base64.RawURLEncoding.EncodeToString(raw)
	store := &sessionStoreStub{principal: Principal{Subject: "42", RepositoryIDs: []int64{101}}}
	manager := SessionManager{Store: store, IdleTTL: 30 * time.Minute, Now: func() time.Time { return now }}
	principal, err := manager.Authenticate(t.Context(), token)
	if err != nil || principal.Subject != "42" || principal.RepositoryIDs[0] != 101 {
		t.Fatalf("principal=%#v err=%v", principal, err)
	}
	if store.lookupHash != sha256.Sum256(raw) || store.lookupNow != now || store.lookupIdleUntil != now.Add(30*time.Minute) {
		t.Fatalf("lookup hash=%x now=%v idleUntil=%v", store.lookupHash, store.lookupNow, store.lookupIdleUntil)
	}
	principal.RepositoryIDs[0] = 999
	if store.principal.RepositoryIDs[0] != 101 {
		t.Fatalf("stored repositories mutated: %#v", store.principal.RepositoryIDs)
	}
}

func TestSessionManagerPreservesForcedRotationPrincipal(t *testing.T) {
	store := &sessionStoreStub{principal: Principal{Subject: "7", Method: "local", ForceRotation: true}}
	manager := SessionManager{Store: store, IdleTTL: time.Minute}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	principal, err := manager.Authenticate(t.Context(), token)
	if err != nil || !principal.ForceRotation || principal.Method != "local" {
		t.Fatalf("principal=%#v err=%v", principal, err)
	}
}
