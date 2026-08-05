package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/grepnest/grepnest/internal/audit"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/jackc/pgx/v5"
)

func (s *Store) BindFederatedUser(ctx context.Context, issuer, subject, externalID string) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	userID, err := bindFederatedUser(ctx, tx, issuer, subject, externalID)
	if err != nil {
		return 0, err
	}
	return userID, tx.Commit(ctx)
}

func (s *Store) CreateFederatedSessionAudited(ctx context.Context, identity authn.Identity, session authn.SessionRecord, loginOperation string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	userID, err := bindFederatedUser(ctx, tx, identity.Issuer, identity.Subject, identity.LinkID)
	if err != nil {
		return err
	}
	session.UserID = userID
	if err := createSession(ctx, tx, session); err != nil {
		return err
	}
	for _, operation := range []string{loginOperation, audit.OperationSessionCreated} {
		if err := appendAudit(ctx, tx, audit.Event{
			ActorType: "user", ActorID: strconv.FormatInt(userID, 10),
			TargetType: "session", TargetID: session.AuditID, AuthenticationMethod: identity.Provider,
			Operation: operation, Outcome: "success",
			RequestID: audit.RequestID(ctx),
		}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func bindFederatedUser(ctx context.Context, tx pgx.Tx, issuer, subject, externalID string) (int64, error) {
	var userID int64
	err := tx.QueryRow(ctx, `select users.id from user_identities
		join users on users.id=user_identities.user_id
		where issuer=$1 and subject=$2 and users.source='scim'
			and users.scim_active and users.suspended_at is null and users.deleted_at is null`,
		issuer, subject).Scan(&userID)
	if err == nil {
		return userID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	if err := tx.QueryRow(ctx, `select id from users where external_id=$1 and source='scim'
		and scim_active and suspended_at is null and deleted_at is null for update`,
		externalID).Scan(&userID); err != nil {
		return 0, err
	}
	err = tx.QueryRow(ctx, `insert into user_identities (user_id,issuer,subject) values ($1,$2,$3)
		on conflict (issuer,subject) do nothing returning user_id`, userID, issuer, subject).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `select users.id from user_identities
			join users on users.id=user_identities.user_id
			where issuer=$1 and subject=$2 and users.source='scim'
				and users.scim_active and users.suspended_at is null and users.deleted_at is null`,
			issuer, subject).Scan(&userID)
	}
	return userID, err
}

func (s *Store) CreateLoginFlow(ctx context.Context, flow authn.LoginFlow) error {
	_, err := s.pool.Exec(ctx, `insert into auth_login_flows (state_hash, browser_hash, provider, nonce, code_verifier, return_to, created_at, expires_at) values ($1,$2,$3,$4,$5,$6,$7,$8)`, flow.StateHash[:], flow.BrowserHash[:], flow.Provider, flow.Nonce, flow.CodeVerifier, flow.ReturnTo, flow.CreatedAt, flow.ExpiresAt)
	return err
}

func (s *Store) ConsumeLoginFlow(ctx context.Context, stateHash, browserHash [32]byte, provider string, now time.Time) (authn.LoginFlow, error) {
	flow := authn.LoginFlow{StateHash: stateHash, BrowserHash: browserHash}
	err := s.pool.QueryRow(ctx, `delete from auth_login_flows where state_hash=$1 and browser_hash=$2 and provider=$3 and expires_at>$4 returning provider, nonce, code_verifier, return_to, created_at, expires_at`, stateHash[:], browserHash[:], provider, now).Scan(&flow.Provider, &flow.Nonce, &flow.CodeVerifier, &flow.ReturnTo, &flow.CreatedAt, &flow.ExpiresAt)
	return flow, err
}

func (s *Store) CreateSession(ctx context.Context, session authn.SessionRecord) error {
	return createSession(ctx, s.pool, session)
}

func (s *Store) CreateSessionAudited(ctx context.Context, session authn.SessionRecord, event audit.Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := createSession(ctx, tx, session); err != nil {
		return err
	}
	if err := appendAudit(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func createSession(ctx context.Context, executor auditExecutor, session authn.SessionRecord) error {
	if session.AuditID == "" {
		_, err := executor.Exec(ctx, `insert into auth_sessions (token_hash, user_id, provider, force_rotation, created_at, last_seen_at, idle_expires_at, expires_at) values ($1,$2,$3,$4,$5,$6,$7,$8)`, session.TokenHash[:], session.UserID, session.Provider, session.ForceRotation, session.CreatedAt, session.LastSeenAt, session.IdleExpiresAt, session.ExpiresAt)
		return err
	}
	if len(session.AuditID) != 32 || session.AuditID != strings.ToLower(session.AuditID) {
		return authn.ErrInvalidIdentity
	}
	if _, err := hex.DecodeString(session.AuditID); err != nil {
		return authn.ErrInvalidIdentity
	}
	_, err := executor.Exec(ctx, `insert into auth_sessions (token_hash, audit_id, user_id, provider, force_rotation, created_at, last_seen_at, idle_expires_at, expires_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, session.TokenHash[:], session.AuditID, session.UserID, session.Provider, session.ForceRotation, session.CreatedAt, session.LastSeenAt, session.IdleExpiresAt, session.ExpiresAt)
	return err
}

func (s *Store) SessionPrincipal(ctx context.Context, tokenHash [32]byte, now, idleUntil time.Time) (authn.Principal, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return authn.Principal{}, err
	}
	defer tx.Rollback(ctx)
	var userID int64
	var provider string
	var forceRotation bool
	err = tx.QueryRow(ctx, `with live_session as (
            update auth_sessions session set last_seen_at=$2, idle_expires_at=least($3, session.expires_at)
            from users user_record
            where session.token_hash=$1 and session.user_id=user_record.id
              and session.revoked_at is null and session.expires_at>$2 and session.idle_expires_at>$2
              and user_record.scim_active and user_record.suspended_at is null and user_record.deleted_at is null
              and (session.provider<>'local' or (user_record.source='local'
                and exists(select 1 from user_roles where user_id=user_record.id)))
            returning session.user_id,session.provider,session.force_rotation
	        ) select user_id,provider,force_rotation from live_session`, tokenHash[:], now, idleUntil).Scan(&userID, &provider, &forceRotation)
	if err != nil {
		return authn.Principal{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return authn.Principal{}, err
	}
	principal, err := s.UserPrincipal(ctx, userID, nil)
	if err != nil {
		return authn.Principal{}, err
	}
	principal.Method = provider
	principal.ForceRotation = forceRotation
	return principal, nil
}

func (s *Store) RevokeSession(ctx context.Context, tokenHash [32]byte) error {
	_, err := s.pool.Exec(ctx, `update auth_sessions set revoked_at=now() where token_hash=$1 and revoked_at is null`, tokenHash[:])
	return err
}

func (s *Store) RevokeSessionAudited(ctx context.Context, tokenHash [32]byte) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var userID int64
	var method string
	var auditID string
	err = tx.QueryRow(ctx, `update auth_sessions set revoked_at=now()
		where token_hash=$1 and revoked_at is null returning user_id,provider,audit_id`, tokenHash[:]).
		Scan(&userID, &method, &auditID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			_ = s.AppendAudit(ctx, audit.Event{
				ActorType: "anonymous", TargetType: "session",
				Operation: audit.OperationLogout, Outcome: "invalid",
				RequestID: audit.RequestID(ctx),
			})
			return nil
		}
		return err
	}
	for _, operation := range []string{audit.OperationLogout, audit.OperationSessionRevoked} {
		if err := appendAudit(ctx, tx, audit.Event{
			ActorType: "user", ActorID: strconv.FormatInt(userID, 10),
			TargetType: "session", TargetID: auditID, AuthenticationMethod: method,
			Operation: operation, Outcome: "success",
			RequestID: audit.RequestID(ctx),
		}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteExpiredAuth(ctx context.Context, now time.Time) (flows, sessions int64, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)
	if result, err := tx.Exec(ctx, `delete from auth_login_flows where expires_at <= $1`, now); err != nil {
		return 0, 0, err
	} else {
		flows = result.RowsAffected()
	}
	if result, err := tx.Exec(ctx, `delete from auth_sessions where idle_expires_at <= $1 or expires_at <= $1 or revoked_at is not null`, now); err != nil {
		return 0, 0, err
	} else {
		sessions = result.RowsAffected()
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	return flows, sessions, nil
}

var _ authn.SessionStore = (*Store)(nil)
