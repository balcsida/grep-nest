package graphclient

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grepnest/grepnest/internal/graphprotocol"
)

// The client's error codes must survive as distinguishable causes, so callers can tell a
// rejected secret from an unreachable runtime instead of seeing one opaque failure.
func TestClientErrorsCarryDistinguishableCauses(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"rejected secret", http.StatusUnauthorized, `{"error":{"code":"unauthorized"}}`, graphprotocol.ErrUnauthorized},
		{"runtime error", http.StatusBadGateway, `{"error":{"code":"unavailable"}}`, graphprotocol.ErrUnreachable},
		{"malformed reply", http.StatusOK, `not json`, graphprotocol.ErrInvalidReply},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(testCase.status)
				_, _ = writer.Write([]byte(testCase.body))
			}))
			defer server.Close()

			client, err := New(server.URL, []byte("secret"), server.Client(), 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Context(t.Context(), graphprotocol.ContextRequest{}); !errors.Is(err, testCase.want) {
				t.Fatalf("Context() error = %v, want %v", err, testCase.want)
			}
		})
	}
}

// An unreachable runtime must report as unreachable, not as a generic failure.
func TestClientReportsUnreachableRuntime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	address := server.URL
	server.Close()

	client, err := New(address, []byte("secret"), http.DefaultClient, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Context(t.Context(), graphprotocol.ContextRequest{}); !errors.Is(err, graphprotocol.ErrUnreachable) {
		t.Fatalf("Context() error = %v, want %v", err, graphprotocol.ErrUnreachable)
	}
}
