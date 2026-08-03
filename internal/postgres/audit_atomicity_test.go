//go:build integration

package postgres

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/audit"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/scim"
	"github.com/jackc/pgx/v5"
)

func TestAuditFailureRollsBackSecurityMutationFamilies(t *testing.T) {
	store := migratedStore(t)
	adminID := seedSecurityUser(t, store, "admin", "local", true)
	targetID := insertIdentityUser(t, store, "target", "target")
	now := time.Now().UTC()
	failing := func(targetType, operation string) audit.Event {
		return audit.Event{
			ActorType: "system", TargetType: targetType, AuthenticationMethod: "operator",
			Operation: operation, Outcome: "success",
			CreatedAt: time.Date(1_000_000, 1, 1, 0, 0, 0, 0, time.UTC),
		}
	}

	if err := store.SuspendAdminUserAudited(t.Context(), adminID, targetID, true,
		failing("user", audit.OperationUserSuspended)); err == nil {
		t.Fatal("admin mutation survived audit insert failure")
	}
	var suspended bool
	if err := store.pool.QueryRow(t.Context(), `select suspended_at is not null from users where id=$1`, targetID).Scan(&suspended); err != nil || suspended {
		t.Fatalf("admin mutation committed suspended=%v err=%v", suspended, err)
	}

	if _, err := store.CreateUserAudited(t.Context(), scim.User{
		ExternalID: "audit-rollback", UserName: "audit-rollback",
	}, []audit.Event{failing("user", audit.OperationSCIMUserCreated)}); err == nil {
		t.Fatal("SCIM mutation survived audit insert failure")
	}
	var count int
	if err := store.pool.QueryRow(t.Context(), `select count(*) from users where external_id='audit-rollback'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("SCIM mutation committed count=%d err=%v", count, err)
	}

	token := authn.APITokenRecord{
		TokenHash: [32]byte{7}, Prefix: "gnp_atomic", UserID: adminID,
		CreatedAt: now,
	}
	if _, err := store.CreateAPITokenAudited(t.Context(), token,
		failing("api_token", audit.OperationAPITokenCreated)); err == nil {
		t.Fatal("token mutation survived audit insert failure")
	}
	if err := store.pool.QueryRow(t.Context(), `select count(*) from api_tokens where token_hash=$1`, token.TokenHash[:]).Scan(&count); err != nil || count != 0 {
		t.Fatalf("token mutation committed count=%d err=%v", count, err)
	}

	session := authn.SessionRecord{
		TokenHash: [32]byte{8}, UserID: adminID, Provider: "local",
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	if err := store.CreateSessionAudited(t.Context(), session,
		failing("session", audit.OperationSessionCreated)); err == nil {
		t.Fatal("session mutation survived audit insert failure")
	}
	if err := store.pool.QueryRow(t.Context(), `select count(*) from auth_sessions where token_hash=$1`, session.TokenHash[:]).Scan(&count); err != nil || count != 0 {
		t.Fatalf("session mutation committed count=%d err=%v", count, err)
	}

	if err := store.SetPasswordCredential(t.Context(), adminID, testCredential(1), testAudit(audit.OperationPasswordSet)); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPasswordCredential(t.Context(), adminID, testCredential(2),
		failing("user", audit.OperationPasswordRotated)); err == nil {
		t.Fatal("password mutation survived audit insert failure")
	}
	_, credential, err := store.PasswordCredential(t.Context(), "admin")
	if err != nil || credential.Hash[0] != 1 {
		t.Fatalf("password mutation committed credential=%#v err=%v", credential, err)
	}
}

func TestFederatedSessionAuditFailureRollsBackIdentityAndSession(t *testing.T) {
	store := migratedStore(t)
	insertIdentityUser(t, store, "github:https://github.com:123", "ada")
	if _, err := store.pool.Exec(t.Context(), `drop table audit_events`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	identity := authn.Identity{Provider: authn.ProviderOAuth, Issuer: "https://github.com", Subject: "123", LinkID: "github:https://github.com:123"}
	err := store.CreateFederatedSessionAudited(t.Context(), identity, authn.SessionRecord{
		TokenHash: [32]byte{44}, AuditID: "cccccccccccccccccccccccccccccccc", Provider: authn.ProviderOAuth,
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour),
	}, audit.OperationOAuthLoginSucceeded)
	if err == nil {
		t.Fatal("federated authentication survived audit failure")
	}
	var identities, sessions int
	if err := store.pool.QueryRow(t.Context(), `select (select count(*) from user_identities),(select count(*) from auth_sessions)`).Scan(&identities, &sessions); err != nil || identities != 0 || sessions != 0 {
		t.Fatalf("identities=%d sessions=%d err=%v", identities, sessions, err)
	}
}

func TestLocalSuccessAuditFailureRollsBackThrottleAndCredentialState(t *testing.T) {
	for _, rotation := range []bool{false, true} {
		t.Run(map[bool]string{false: "login", true: "rotation"}[rotation], func(t *testing.T) {
			store := migratedStore(t)
			userID := seedSecurityUser(t, store, "atomic-local", "local", true)
			expected := testCredential(1)
			expected.ForceRotation = rotation
			if err := store.SetPasswordCredential(t.Context(), userID, expected, testAudit(audit.OperationPasswordSet)); err != nil {
				t.Fatal(err)
			}
			accountKey, sourceKey := [32]byte{1}, [32]byte{2}
			if _, err := store.pool.Exec(t.Context(), `insert into login_throttles
				(key_hash,failures,window_started_at) values ($1,1,now()),($2,1,now())`,
				accountKey[:], sourceKey[:]); err != nil {
				t.Fatal(err)
			}
			if _, err := store.pool.Exec(t.Context(), `drop table audit_events`); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			session := authn.SessionRecord{
				TokenHash: [32]byte{9}, AuditID: strings.Repeat("a", 32), UserID: userID,
				Provider: "local", CreatedAt: now, LastSeenAt: now,
				IdleExpiresAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour),
			}
			var err error
			if rotation {
				replacement := testCredential(2)
				replacement.ForceRotation = false
				err = store.RotatePasswordCredential(t.Context(), userID, expected, replacement, session,
					accountKey, sourceKey, testAudit(audit.OperationPasswordRotated))
			} else {
				expected.ForceRotation = false
				err = store.CreatePasswordSession(t.Context(), userID, expected, session, accountKey, sourceKey)
			}
			if err == nil {
				t.Fatal("mutation survived audit failure")
			}
			var throttles, sessions int
			if scanErr := store.pool.QueryRow(t.Context(), `select
				(select count(*) from login_throttles),
				(select count(*) from auth_sessions)`).Scan(&throttles, &sessions); scanErr != nil {
				t.Fatal(scanErr)
			}
			if throttles != 2 || sessions != 0 {
				t.Fatalf("throttles=%d sessions=%d", throttles, sessions)
			}
			_, stored, lookupErr := store.PasswordCredential(t.Context(), "atomic-local")
			if lookupErr != nil || stored.Hash[0] != 1 || stored.ForceRotation != rotation {
				t.Fatalf("credential=%#v err=%v", stored, lookupErr)
			}
		})
	}
}

func TestSCIMAuditExcludesProvisioningSecretsAndProfiles(t *testing.T) {
	store := migratedStore(t)
	events := []audit.Event{{
		ActorType: "scim", ActorID: "provisioning", TargetType: "user",
		AuthenticationMethod: "scim_token", Operation: audit.OperationSCIMUserCreated,
		Outcome: "success",
	}}
	created, err := store.CreateUserAudited(t.Context(), scim.User{
		ExternalID: "sentinel-external", UserName: "sentinel-user",
		DisplayName: "sentinel-profile", Emails: []scim.Email{{Value: "sentinel@example.com"}},
	}, events)
	if err != nil {
		t.Fatal(err)
	}
	stored, _, err := store.AuditEvents(t.Context(), 10)
	if err != nil || len(stored) != 1 || stored[0].TargetID != created.ID {
		t.Fatalf("events=%#v err=%v", stored, err)
	}
	encoded := strings.Join([]string{
		stored[0].ActorType, stored[0].ActorID, stored[0].TargetType, stored[0].TargetID,
		stored[0].AuthenticationMethod, stored[0].Operation, stored[0].Outcome, stored[0].RequestID,
	}, " ")
	for _, secret := range []string{"sentinel-external", "sentinel-user", "sentinel-profile", "sentinel@example.com", "sentinel-token"} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("audit event leaked %q: %q", secret, encoded)
		}
	}
}

func TestSCIMServiceRecordsFixedLifecycleOperations(t *testing.T) {
	store := migratedStore(t)
	service := scim.Service{Store: store, BaseURL: "https://grepnest.example", MaxResults: 100}
	user, err := service.CreateUser(t.Context(), scim.User{
		Schemas: []string{scim.UserSchema}, ExternalID: "lifecycle-user", UserName: "lifecycle-user",
	})
	if err != nil {
		t.Fatal(err)
	}
	userID := scimID(t, user.ID)
	userResourceID := user.ID
	user.ID, user.Meta = "", scim.Meta{}
	if _, err := service.ReplaceUser(t.Context(), userID, user); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PatchUser(t.Context(), userID, scim.PatchRequest{
		Schemas:    []string{scim.PatchSchema},
		Operations: []scim.PatchOperation{{Op: "replace", Path: "active", Value: []byte(`false`)}},
	}); err != nil {
		t.Fatal(err)
	}
	group, err := service.CreateGroup(t.Context(), scim.Group{
		Schemas: []string{scim.GroupSchema}, ExternalID: "lifecycle-group",
		DisplayName: "Lifecycle", Members: []scim.Member{{Value: userResourceID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	groupID := scimID(t, group.ID)
	group.ID, group.Meta = "", scim.Meta{}
	for index := range group.Members {
		group.Members[index].Ref, group.Members[index].Display = "", ""
	}
	if _, err := service.ReplaceGroup(t.Context(), groupID, group); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PatchGroup(t.Context(), groupID, scim.PatchRequest{
		Schemas:    []string{scim.PatchSchema},
		Operations: []scim.PatchOperation{{Op: "remove", Path: `members[value eq "` + userResourceID + `"]`}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteGroup(t.Context(), groupID); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteUser(t.Context(), userID); err != nil {
		t.Fatal(err)
	}
	events, _, err := store.AuditEvents(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, event := range events {
		seen[event.Operation] = true
		if event.ActorType != "scim" || event.ActorID != "provisioning" ||
			event.AuthenticationMethod != "scim_token" || event.TargetID == "" {
			t.Fatalf("unsafe event=%#v", event)
		}
	}
	for _, operation := range []string{
		audit.OperationSCIMUserCreated, audit.OperationSCIMUserReplaced,
		audit.OperationSCIMUserPatched, audit.OperationSCIMUserDeactivated,
		audit.OperationSCIMUserDeleted, audit.OperationSCIMGroupCreated,
		audit.OperationSCIMGroupReplaced, audit.OperationSCIMGroupPatched,
		audit.OperationSCIMGroupDeleted, audit.OperationGroupMembershipChanged,
	} {
		if !seen[operation] {
			t.Errorf("missing operation %q in %#v", operation, events)
		}
	}
}

func TestAuthenticationAndTokenOperationsUseSafeFixedEvents(t *testing.T) {
	store := migratedStore(t)
	ctx := audit.WithRequestID(t.Context(), "request-42")
	userID := insertIdentityUser(t, store, "directory-auth", "directory-auth")
	sessions := authn.SessionManager{
		Store: store, IdleTTL: time.Hour, TTL: 2 * time.Hour,
		Rand: bytes.NewReader(bytes.Repeat([]byte{4}, 32)),
	}
	token, _, err := sessions.Create(ctx, authn.Identity{
		Provider: "oidc", Issuer: "https://issuer.example", Subject: "subject-1",
		LinkID: "directory-auth",
	}, audit.OperationOIDCLoginSucceeded)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.Revoke(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err := sessions.Revoke(ctx, token); err != nil {
		t.Fatalf("idempotent logout: %v", err)
	}
	tokens := authn.TokenManager{
		Store: store, Audit: store, Rand: bytes.NewReader(bytes.Repeat([]byte{5}, 32)),
		Now: func() time.Time { return time.Now().UTC() },
	}
	tokenID, _, err := tokens.CreateWithMethod(ctx, userID, "oidc", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeAPITokenAudited(ctx, userID, tokenID, audit.Event{
		ActorType: "user", ActorID: strconv.FormatInt(userID, 10), TargetType: "api_token",
		TargetID: strconv.FormatInt(tokenID, 10), AuthenticationMethod: "oidc",
		Operation: audit.OperationAPITokenRevoked, Outcome: "success", RequestID: "request-42",
	}); err != nil {
		t.Fatal(err)
	}
	for name, values := range map[string][2]int64{
		"already revoked": {userID, tokenID},
		"missing":         {userID, tokenID + 1000},
		"foreign":         {insertIdentityUser(t, store, "foreign-owner", "foreign-owner"), tokenID},
	} {
		ownerID, id := values[0], values[1]
		if err := store.RevokeAPITokenAudited(ctx, ownerID, id, audit.Event{
			ActorType: "user", ActorID: strconv.FormatInt(ownerID, 10), TargetType: "api_token",
			TargetID: strconv.FormatInt(id, 10), AuthenticationMethod: "oidc",
			Operation: audit.OperationAPITokenRevoked, Outcome: "success", RequestID: "request-42",
		}); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	if _, err := tokens.Authenticate(ctx, "gnp_sentinel-presented-token"); err == nil {
		t.Fatal("invalid API token authenticated")
	}
	events, _, err := store.AuditEvents(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	revocations := 0
	for _, event := range events {
		seen[event.Operation] = true
		if event.Operation == audit.OperationAPITokenRevoked {
			revocations++
		}
		if event.RequestID != "request-42" {
			t.Fatalf("request correlation missing: %#v", event)
		}
		if (event.Operation == audit.OperationSessionCreated || event.Operation == audit.OperationSessionRevoked ||
			event.Operation == audit.OperationLogout || event.Operation == audit.OperationOIDCLoginSucceeded) &&
			event.Outcome == "success" && event.TargetID == "" {
			t.Fatalf("session audit ID missing: %#v", event)
		}
		if strings.Contains(strings.Join([]string{event.ActorID, event.TargetID, event.RequestID}, " "), "sentinel") {
			t.Fatalf("event leaked presented token: %#v", event)
		}
	}
	if revocations != 1 {
		t.Fatalf("revocation events=%d events=%#v", revocations, events)
	}
	for _, operation := range []string{
		audit.OperationOIDCLoginSucceeded, audit.OperationSessionCreated,
		audit.OperationLogout, audit.OperationSessionRevoked,
		audit.OperationAPITokenCreated, audit.OperationAPITokenRevoked,
		audit.OperationAPITokenUseRejected,
	} {
		if !seen[operation] {
			t.Errorf("missing operation %q in %#v", operation, events)
		}
	}
}
