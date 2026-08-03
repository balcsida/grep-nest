package githuboauth

import (
	"time"

	"github.com/grepnest/grepnest/internal/audit"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/sso"
	"github.com/grepnest/grepnest/internal/sso/browserflow"
)

func NewProvider(client browserflow.Client, store authn.SessionStore, sessions *authn.SessionManager, recorder audit.Recorder, loginTTL time.Duration) *browserflow.Provider {
	return &browserflow.Provider{
		Spec: browserflow.Spec{
			Metadata:  sso.Metadata{ID: "github", Label: "Sign in with GitHub", LoginURL: "/auth/oauth/github/login"},
			LoginPath: "/auth/oauth/github/login", CallbackPath: "/auth/oauth/github/callback",
			FlowProvider: "github", IdentityProvider: authn.ProviderOAuth,
			CookieName: "__Host-grepnest_oauth_github_login", Method: authn.ProviderOAuth,
			SuccessOperation: audit.OperationOAuthLoginSucceeded, DeniedOperation: audit.OperationOAuthLoginDenied,
		},
		Client: client, Store: store, Sessions: sessions, Audit: recorder, LoginTTL: loginTTL,
	}
}
