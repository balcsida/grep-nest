package audit

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrInvalidEvent = errors.New("invalid audit event")

type Recorder interface {
	Record(context.Context, Event) error
}

type requestIDKey struct{}

func WithRequestID(ctx context.Context, requestID string) context.Context {
	if !bounded(requestID, 128) {
		requestID = ""
	}
	return context.WithValue(ctx, requestIDKey{}, requestID)
}

func RequestID(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDKey{}).(string)
	if !bounded(requestID, 128) {
		return ""
	}
	return requestID
}

const (
	OperationOIDCLoginSucceeded     = "oidc_login_succeeded"
	OperationOIDCLoginDenied        = "oidc_login_denied"
	OperationOAuthLoginSucceeded    = "oauth_login_succeeded"
	OperationOAuthLoginDenied       = "oauth_login_denied"
	OperationLocalLoginSucceeded    = "local_login_succeeded"
	OperationLocalLoginDenied       = "local_login_denied"
	OperationLogout                 = "logout"
	OperationSessionCreated         = "session_created"
	OperationSessionRevoked         = "session_revoked"
	OperationAPITokenCreated        = "api_token_created"
	OperationAPITokenUseRejected    = "api_token_use_rejected"
	OperationAPITokenRevoked        = "api_token_revoked"
	OperationPasswordSet            = "password_set"
	OperationPasswordRotated        = "password_rotated"
	OperationBreakGlassPasswordSet  = "break_glass_password_set"
	OperationUserSuspended          = "user_suspended"
	OperationUserRestored           = "user_restored"
	OperationUserCredentialsRevoked = "user_credentials_revoked"
	OperationSCIMUserCreated        = "scim_user_created"
	OperationSCIMUserReplaced       = "scim_user_replaced"
	OperationSCIMUserPatched        = "scim_user_patched"
	OperationSCIMUserDeactivated    = "scim_user_deactivated"
	OperationSCIMUserDeleted        = "scim_user_deleted"
	OperationSCIMGroupCreated       = "scim_group_created"
	OperationSCIMGroupReplaced      = "scim_group_replaced"
	OperationSCIMGroupPatched       = "scim_group_patched"
	OperationSCIMGroupDeleted       = "scim_group_deleted"
	OperationGroupMembershipChanged = "group_membership_changed"
	OperationGroupRoleChanged       = "group_role_changed"
	OperationGroupRepositoryChanged = "group_repository_grant_changed"
	OperationUserRoleChanged        = "user_role_changed"
	OperationUserRepositoryChanged  = "user_repository_grant_changed"
	OperationAdminMutationDenied    = "admin_mutation_denied"
)

var operations = map[string]struct{}{
	OperationOIDCLoginSucceeded: {}, OperationOIDCLoginDenied: {},
	OperationOAuthLoginSucceeded: {}, OperationOAuthLoginDenied: {},
	OperationLocalLoginSucceeded: {}, OperationLocalLoginDenied: {},
	OperationLogout: {}, OperationSessionCreated: {}, OperationSessionRevoked: {},
	OperationAPITokenCreated: {}, OperationAPITokenUseRejected: {}, OperationAPITokenRevoked: {},
	OperationPasswordSet: {}, OperationPasswordRotated: {}, OperationBreakGlassPasswordSet: {},
	OperationUserSuspended: {}, OperationUserRestored: {}, OperationUserCredentialsRevoked: {},
	OperationSCIMUserCreated: {}, OperationSCIMUserReplaced: {}, OperationSCIMUserPatched: {},
	OperationSCIMUserDeactivated: {}, OperationSCIMUserDeleted: {},
	OperationSCIMGroupCreated: {}, OperationSCIMGroupReplaced: {}, OperationSCIMGroupPatched: {},
	OperationSCIMGroupDeleted: {}, OperationGroupMembershipChanged: {}, OperationGroupRoleChanged: {},
	OperationGroupRepositoryChanged: {}, OperationUserRoleChanged: {}, OperationUserRepositoryChanged: {},
	OperationAdminMutationDenied: {},
}

type Event struct {
	ActorType            string    `json:"actor_type"`
	ActorID              string    `json:"actor_id"`
	TargetType           string    `json:"target_type"`
	TargetID             string    `json:"target_id"`
	AuthenticationMethod string    `json:"authentication_method"`
	Operation            string    `json:"operation"`
	Outcome              string    `json:"outcome"`
	RequestID            string    `json:"request_id"`
	CreatedAt            time.Time `json:"created_at"`
}

func NewEvent(event Event) (Event, error) {
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	return event, nil
}

func (event Event) Validate() error {
	if !oneOf(event.ActorType, "anonymous", "operator", "scim", "system", "user") ||
		!oneOf(event.TargetType, "api_token", "authentication", "group", "session", "user") ||
		!oneOf(event.AuthenticationMethod, "", "api_token", "local", "oauth", "oidc", "operator", "scim_token") ||
		!oneOf(event.Outcome, "success", "denied", "invalid", "error") ||
		!bounded(event.ActorID, 128) || !bounded(event.TargetID, 128) ||
		!bounded(event.RequestID, 128) || !operation(event.Operation) {
		return ErrInvalidEvent
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func bounded(value string, maximum int) bool {
	if len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func operation(value string) bool {
	_, ok := operations[value]
	return ok && strings.Trim(value, "abcdefghijklmnopqrstuvwxyz0123456789_") == ""
}
