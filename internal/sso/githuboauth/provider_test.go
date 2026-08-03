package githuboauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/grepnest/grepnest/internal/audit"
	"github.com/grepnest/grepnest/internal/authn"
)

func TestNewProviderUsesFixedGitHubMetadataAndRoutes(t *testing.T) {
	provider := NewProvider(nil, nil, nil, nil, time.Minute)
	metadata := provider.Metadata()
	if metadata.ID != "github" || metadata.Label != "Sign in with GitHub" || metadata.LoginURL != "/auth/oauth/github/login" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if provider.Spec.LoginPath != "/auth/oauth/github/login" || provider.Spec.CallbackPath != "/auth/oauth/github/callback" || provider.Spec.FlowProvider != "github" || provider.Spec.IdentityProvider != authn.ProviderOAuth || provider.Spec.CookieName != "__Host-grepnest_oauth_github_login" || provider.Spec.Method != authn.ProviderOAuth || provider.Spec.SuccessOperation != audit.OperationOAuthLoginSucceeded || provider.Spec.DeniedOperation != audit.OperationOAuthLoginDenied {
		t.Fatalf("spec = %#v", provider.Spec)
	}

	mux := http.NewServeMux()
	provider.Register(mux)
	for _, path := range []string{"/auth/oauth/github/login", "/auth/oauth/github/callback"} {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s status = %d", path, recorder.Code)
		}
	}
}
