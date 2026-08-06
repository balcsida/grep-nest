package mcpserver

import (
	"errors"
	"testing"

	"github.com/grepnest/grepnest/internal/graphprotocol"
)

// Every transport failure used to collapse into "graph service is unavailable", so an
// operator could not tell a rejected secret from an unreachable runtime.
func TestGraphErrorDistinguishesTransportFailures(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
		want string
	}{
		{"rejected secret", graphprotocol.ErrUnauthorized, "graph runtime rejected the request; check the shared internal secret"},
		{"runtime down", graphprotocol.ErrUnreachable, "graph runtime is unreachable; check that it is running and that the graph URL is correct"},
		{"malformed reply", graphprotocol.ErrInvalidReply, "graph runtime returned a malformed response"},
		{"oversized reply", graphprotocol.ErrReplyTooLarge, "graph runtime response exceeded the configured limit"},
		{"genuinely unclassified", errors.New("boom"), "graph service is unavailable"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := graphError(testCase.err).Error(); got != testCase.want {
				t.Fatalf("graphError() = %q, want %q", got, testCase.want)
			}
		})
	}
}
