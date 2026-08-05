package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strconv"
	"time"

	"github.com/grepnest/grepnest/internal/audit"
)

type SessionManager struct {
	Store     SessionStore
	IdleTTL   time.Duration
	TTL       time.Duration
	Now       func() time.Time
	Rand      io.Reader
	AuditRand io.Reader
	Audit     audit.Recorder
}

type PreparedSession struct {
	Token     string
	ExpiresAt time.Time
	Record    SessionRecord
}

func (m SessionManager) Create(ctx context.Context, identity Identity, loginOperation string) (string, time.Time, error) {
	if m.Store == nil || m.IdleTTL <= 0 || m.TTL < m.IdleTTL || !validIdentity(identity) || (identity.Provider != ProviderOIDC && identity.Provider != ProviderOAuth) || (identity.Provider == ProviderOIDC && loginOperation != audit.OperationOIDCLoginSucceeded) || (identity.Provider == ProviderOAuth && loginOperation != audit.OperationOAuthLoginSucceeded) {
		return "", time.Time{}, ErrInvalidIdentity
	}
	prepared, err := m.PrepareForUser(1, identity.Provider, false)
	if err != nil {
		return "", time.Time{}, err
	}
	prepared.Record.UserID = 0
	if err := m.Store.CreateFederatedSessionAudited(ctx, identity, prepared.Record, loginOperation); err != nil {
		return "", time.Time{}, err
	}
	return prepared.Token, prepared.ExpiresAt, nil
}

func (m SessionManager) CreateForUser(ctx context.Context, userID int64, provider string, forceRotation bool) (string, time.Time, error) {
	prepared, err := m.PrepareForUser(userID, provider, forceRotation)
	if err != nil {
		return "", time.Time{}, err
	}
	event := audit.Event{
		ActorType: "user", ActorID: strconv.FormatInt(userID, 10),
		TargetType: "session", TargetID: prepared.Record.AuditID, AuthenticationMethod: provider,
		Operation: audit.OperationSessionCreated, Outcome: "success",
		RequestID: audit.RequestID(ctx),
	}
	if err := m.Store.CreateSessionAudited(ctx, prepared.Record, event); err != nil {
		return "", time.Time{}, err
	}
	return prepared.Token, prepared.ExpiresAt, nil
}

func (m SessionManager) PrepareForUser(userID int64, provider string, forceRotation bool) (PreparedSession, error) {
	if m.Store == nil || m.IdleTTL <= 0 || m.TTL < m.IdleTTL || userID <= 0 || (provider != ProviderOIDC && provider != ProviderOAuth && provider != ProviderLocal) {
		return PreparedSession{}, ErrInvalidIdentity
	}
	random := make([]byte, 32)
	reader := m.Rand
	if reader == nil {
		reader = rand.Reader
	}
	if _, err := io.ReadFull(reader, random); err != nil {
		return PreparedSession{}, err
	}
	auditRandom := make([]byte, 16)
	auditReader := m.AuditRand
	if auditReader == nil {
		auditReader = rand.Reader
	}
	if _, err := io.ReadFull(auditReader, auditRandom); err != nil {
		return PreparedSession{}, err
	}
	now := time.Now()
	if m.Now != nil {
		now = m.Now()
	}
	expiresAt := now.Add(m.TTL)
	record := SessionRecord{
		TokenHash: sha256.Sum256(random), AuditID: hex.EncodeToString(auditRandom), UserID: userID, Provider: provider,
		ForceRotation: forceRotation,
		CreatedAt:     now, LastSeenAt: now, IdleExpiresAt: now.Add(m.IdleTTL), ExpiresAt: expiresAt,
	}
	return PreparedSession{Token: base64.RawURLEncoding.EncodeToString(random), ExpiresAt: expiresAt, Record: record}, nil
}

func (m SessionManager) Authenticate(ctx context.Context, token string) (Principal, error) {
	if m.Store == nil || m.IdleTTL <= 0 {
		return Principal{}, ErrUnauthenticated
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return Principal{}, ErrUnauthenticated
	}
	now := time.Now()
	if m.Now != nil {
		now = m.Now()
	}
	principal, err := m.Store.SessionPrincipal(ctx, sha256.Sum256(raw), now, now.Add(m.IdleTTL))
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	return clonePrincipal(principal), nil
}

func (m SessionManager) Revoke(ctx context.Context, token string) error {
	if m.Store == nil {
		m.rejectedLogout(ctx)
		return ErrUnauthenticated
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		m.rejectedLogout(ctx)
		return ErrUnauthenticated
	}
	hash := sha256.Sum256(raw)
	return m.Store.RevokeSessionAudited(ctx, hash)
}

func (m SessionManager) rejectedLogout(ctx context.Context) {
	if m.Audit != nil {
		_ = m.Audit.Record(ctx, audit.Event{
			ActorType: "anonymous", TargetType: "session",
			Operation: audit.OperationLogout, Outcome: "invalid",
			RequestID: audit.RequestID(ctx),
		})
	}
}
