package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOIDC(t *testing.T) {
	for _, test := range []struct {
		name string
		set  func(*testing.T)
		want bool
	}{
		{"valid", func(*testing.T) {}, true},
		{"HTTP origin", func(t *testing.T) { t.Setenv("GREPNEST_PUBLIC_URL", "http://search.example.test") }, false},
		{"HTTP issuer", func(t *testing.T) { t.Setenv("GREPNEST_OIDC_ISSUER_URL", "http://id.example.test") }, false},
		{"missing client ID", func(t *testing.T) { t.Setenv("GREPNEST_OIDC_CLIENT_ID", "") }, false},
		{"client secret is directory", func(t *testing.T) { t.Setenv("GREPNEST_OIDC_CLIENT_SECRET_FILE", t.TempDir()) }, false},
		{"missing openid scope", func(t *testing.T) { t.Setenv("GREPNEST_OIDC_SCOPES", "profile,email") }, false},
		{"offline access scope", func(t *testing.T) { t.Setenv("GREPNEST_OIDC_SCOPES", "openid,offline_access") }, false},
		{"missing link claim", func(t *testing.T) { t.Setenv("GREPNEST_OIDC_LINK_CLAIM", "") }, false},
		{"idle below minimum", func(t *testing.T) { t.Setenv("GREPNEST_SSO_SESSION_IDLE", "4m") }, false},
		{"absolute above maximum", func(t *testing.T) { t.Setenv("GREPNEST_SSO_SESSION_TTL", "25h") }, false},
		{"login flow above maximum", func(t *testing.T) { t.Setenv("GREPNEST_SSO_LOGIN_FLOW_TTL", "16m") }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			setValidOIDCEnvironment(t)
			test.set(t)
			got, err := Load()
			if test.want {
				if err != nil {
					t.Fatal(err)
				}
				if !got.SSO.OIDC.Enabled || got.SSO.OIDC.LinkClaim != "oid" || got.SSO.SessionIdle != 30*time.Minute || got.SSO.SessionTTL != 8*time.Hour || got.SSO.LoginFlowTTL != 10*time.Minute {
					t.Fatalf("SSO = %#v", got.SSO)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}

func TestLoadGitHubOAuth(t *testing.T) {
	for _, test := range []struct {
		name           string
		set            func(*testing.T)
		wantOIDC       bool
		wantGitHub     bool
		wantBreakGlass bool
		wantErr        bool
	}{
		{"neither provider", func(t *testing.T) { setValidEnvironment(t) }, false, false, false, false},
		{"OIDC only", setValidOIDCEnvironment, true, false, false, false},
		{"GitHub only", setValidGitHubOAuthEnvironment, false, true, false, false},
		{"both providers", func(t *testing.T) { setValidOIDCEnvironment(t); setGitHubOAuthEnvironment(t) }, true, true, false, false},
		{"partial GitHub pair", func(t *testing.T) {
			setValidEnvironment(t)
			setDurableEnvironment(t)
			t.Setenv("GREPNEST_OAUTH_GITHUB_CLIENT_ID", "grepnest")
		}, false, false, false, true},
		{"missing database", func(t *testing.T) { setValidGitHubOAuthEnvironment(t); t.Setenv("GREPNEST_DATABASE_URL", "") }, false, false, false, true},
		{"missing public URL", func(t *testing.T) { setValidGitHubOAuthEnvironment(t); t.Setenv("GREPNEST_PUBLIC_URL", "") }, false, false, false, true},
		{"HTTP public URL", func(t *testing.T) {
			setValidGitHubOAuthEnvironment(t)
			t.Setenv("GREPNEST_PUBLIC_URL", "http://search.example.test")
		}, false, false, false, true},
		{"secret is directory", func(t *testing.T) {
			setValidGitHubOAuthEnvironment(t)
			t.Setenv("GREPNEST_OAUTH_GITHUB_CLIENT_SECRET_FILE", t.TempDir())
		}, false, false, false, true},
		{"OAuth only break glass", func(t *testing.T) {
			setValidGitHubOAuthEnvironment(t)
			t.Setenv("GREPNEST_BREAK_GLASS_ENABLED", "true")
		}, false, true, true, false},
		{"break glass without provider", func(t *testing.T) { setValidEnvironment(t); t.Setenv("GREPNEST_BREAK_GLASS_ENABLED", "true") }, false, false, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.set(t)
			got, err := Load()
			if test.wantErr {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Load() error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.SSO.OIDC.Enabled != test.wantOIDC || got.SSO.OAuth.GitHub.Enabled != test.wantGitHub || got.SSO.BreakGlass != test.wantBreakGlass {
				t.Fatalf("SSO = %#v", got.SSO)
			}
		})
	}
}

func TestLoadBreakGlass(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		setValidOIDCEnvironment(t)
		got, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if got.SSO.BreakGlass {
			t.Fatal("break glass enabled by default")
		}
	})
	t.Run("exact true enables durable OIDC HTTPS mode", func(t *testing.T) {
		setValidOIDCEnvironment(t)
		t.Setenv("GREPNEST_BREAK_GLASS_ENABLED", "true")
		got, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if !got.SSO.BreakGlass {
			t.Fatal("break glass disabled")
		}
	})
	for _, value := range []string{"1", "TRUE", " true"} {
		t.Run("rejects "+value, func(t *testing.T) {
			setValidOIDCEnvironment(t)
			t.Setenv("GREPNEST_BREAK_GLASS_ENABLED", value)
			if _, err := Load(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
	t.Run("exact false stays disabled", func(t *testing.T) {
		setValidEnvironment(t)
		t.Setenv("GREPNEST_BREAK_GLASS_ENABLED", "false")
		got, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if got.SSO.BreakGlass {
			t.Fatal("break glass enabled")
		}
	})
	t.Run("requires OIDC", func(t *testing.T) {
		setValidEnvironment(t)
		setDurableEnvironment(t)
		t.Setenv("GREPNEST_BREAK_GLASS_ENABLED", "true")
		if _, err := Load(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Load() error = %v", err)
		}
	})
	t.Run("rejects static mode", func(t *testing.T) {
		setValidEnvironment(t)
		t.Setenv("GREPNEST_BREAK_GLASS_ENABLED", "true")
		if _, err := Load(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Load() error = %v", err)
		}
	})
}

func setValidOIDCEnvironment(t *testing.T) {
	t.Helper()
	setValidEnvironment(t)
	setDurableEnvironment(t)
	t.Setenv("GREPNEST_PUBLIC_URL", "https://search.example.test")
	t.Setenv("GREPNEST_OIDC_ISSUER_URL", "https://id.example.test")
	t.Setenv("GREPNEST_OIDC_CLIENT_ID", "grepnest")
	t.Setenv("GREPNEST_OIDC_CLIENT_SECRET_FILE", writeSecret(t, "secret"))
	t.Setenv("GREPNEST_OIDC_LINK_CLAIM", "oid")
}

func setValidGitHubOAuthEnvironment(t *testing.T) {
	t.Helper()
	setValidEnvironment(t)
	setDurableEnvironment(t)
	setGitHubOAuthEnvironment(t)
}

func setGitHubOAuthEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("GREPNEST_PUBLIC_URL", "https://search.example.test")
	t.Setenv("GREPNEST_OAUTH_GITHUB_CLIENT_ID", "grepnest")
	t.Setenv("GREPNEST_OAUTH_GITHUB_CLIENT_SECRET_FILE", writeSecret(t, "secret"))
}

func writeSecret(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
