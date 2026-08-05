package audit

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEventRejectsUnapprovedOperation(t *testing.T) {
	event := Event{
		ActorType: "user", ActorID: "7", TargetType: "user", TargetID: "8",
		AuthenticationMethod: "oidc", Operation: "free_form_operation", Outcome: "success",
	}
	if _, err := NewEvent(event); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("error=%v", err)
	}
}

func TestEventAcceptsOAuthAuthentication(t *testing.T) {
	event := Event{
		ActorType: "anonymous", TargetType: "authentication",
		AuthenticationMethod: "oauth", Operation: OperationOAuthLoginDenied, Outcome: "denied",
	}
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRequestIDContextRejectsUnboundedValues(t *testing.T) {
	ctx := WithRequestID(t.Context(), "request-1")
	if got := RequestID(ctx); got != "request-1" {
		t.Fatalf("request ID=%q", got)
	}
	if got := RequestID(WithRequestID(t.Context(), strings.Repeat("x", 129))); got != "" {
		t.Fatalf("unbounded request ID=%q", got)
	}
}

func TestEventValidateBoundsFields(t *testing.T) {
	valid := Event{
		ActorType: "operator", ActorID: "recovery-admin",
		TargetType: "user", TargetID: "42",
		AuthenticationMethod: "local", Operation: "break_glass_password_set",
		Outcome: "success", RequestID: "request-1", CreatedAt: time.Now(),
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []Event{
		{ActorType: "unknown", TargetType: "user", Operation: "login", Outcome: "success"},
		{ActorType: "operator", TargetType: "secret", Operation: "login", Outcome: "success"},
		{ActorType: "operator", TargetType: "user", AuthenticationMethod: "password", Operation: "login", Outcome: "success"},
		{ActorType: "operator", TargetType: "user", Operation: "login", Outcome: "maybe"},
		{ActorType: "operator", ActorID: strings.Repeat("x", 129), TargetType: "user", Operation: "login", Outcome: "success"},
		{ActorType: "operator", TargetType: "user", Operation: strings.Repeat("x", 65), Outcome: "success"},
		{ActorType: "operator", TargetType: "user", Operation: "login\ncookie=value", Outcome: "success"},
	}
	for _, event := range tests {
		if err := event.Validate(); err == nil {
			t.Fatalf("accepted invalid event %#v", event)
		}
	}
}

func TestNewEventSetsTimestampAfterValidation(t *testing.T) {
	event, err := NewEvent(Event{
		ActorType: "system", TargetType: "authentication",
		Operation: OperationOIDCLoginDenied, Outcome: "denied",
	})
	if err != nil || event.CreatedAt.IsZero() {
		t.Fatalf("event=%#v err=%v", event, err)
	}
	if _, err := NewEvent(Event{ActorType: "secret"}); err == nil {
		t.Fatal("invalid event accepted")
	}
}
