package config

import (
	"net/url"
	"os"
	"strings"
	"time"
)

type SSO struct {
	PublicURL    *url.URL
	SessionIdle  time.Duration
	SessionTTL   time.Duration
	LoginFlowTTL time.Duration
	BreakGlass   bool
	OIDC         OIDC
	OAuth        OAuth
}

type OAuth struct{ GitHub GitHubOAuth }

type GitHubOAuth struct {
	Enabled          bool
	ClientID         string
	ClientSecretFile string
}

type OIDC struct {
	Enabled          bool
	IssuerURL        string
	ClientID         string
	ClientSecretFile string
	CAFile           string
	Scopes           []string
	LinkClaim        string
	DisplayNameClaim string
}

func loadSSO(databaseURL string) (SSO, error) {
	sso := SSO{}
	var err error
	if sso.SessionIdle, err = parseBoundedDuration("GREPNEST_SSO_SESSION_IDLE", os.Getenv("GREPNEST_SSO_SESSION_IDLE"), 30*time.Minute, 5*time.Minute, 24*time.Hour); err != nil {
		return SSO{}, err
	}
	if sso.SessionTTL, err = parseBoundedDuration("GREPNEST_SSO_SESSION_TTL", os.Getenv("GREPNEST_SSO_SESSION_TTL"), 8*time.Hour, 5*time.Minute, 24*time.Hour); err != nil {
		return SSO{}, err
	}
	if sso.SessionIdle > sso.SessionTTL {
		return SSO{}, invalid("GREPNEST_SSO_SESSION_IDLE must not exceed GREPNEST_SSO_SESSION_TTL")
	}
	if sso.LoginFlowTTL, err = parseBoundedDuration("GREPNEST_SSO_LOGIN_FLOW_TTL", os.Getenv("GREPNEST_SSO_LOGIN_FLOW_TTL"), 10*time.Minute, time.Minute, 15*time.Minute); err != nil {
		return SSO{}, err
	}

	issuerURL := os.Getenv("GREPNEST_OIDC_ISSUER_URL")
	clientID := os.Getenv("GREPNEST_OIDC_CLIENT_ID")
	clientSecretFile := os.Getenv("GREPNEST_OIDC_CLIENT_SECRET_FILE")
	githubClientID := os.Getenv("GREPNEST_OAUTH_GITHUB_CLIENT_ID")
	githubClientSecretFile := os.Getenv("GREPNEST_OAUTH_GITHUB_CLIENT_SECRET_FILE")
	oidcEnabled := issuerURL != "" || clientID != "" || clientSecretFile != ""
	githubEnabled := githubClientID != "" || githubClientSecretFile != ""
	if !oidcEnabled && !githubEnabled {
		switch os.Getenv("GREPNEST_BREAK_GLASS_ENABLED") {
		case "", "false":
		case "true":
			return SSO{}, invalid("GREPNEST_BREAK_GLASS_ENABLED requires an external provider")
		default:
			return SSO{}, invalid("GREPNEST_BREAK_GLASS_ENABLED must be true or false")
		}
		return sso, nil
	}
	if databaseURL == "" {
		return SSO{}, invalid("GREPNEST_DATABASE_URL is required for browser SSO")
	}
	if oidcEnabled {
		for _, setting := range []struct{ name, value string }{
			{"GREPNEST_OIDC_ISSUER_URL", issuerURL},
			{"GREPNEST_OIDC_CLIENT_ID", clientID},
			{"GREPNEST_OIDC_CLIENT_SECRET_FILE", clientSecretFile},
			{"GREPNEST_OIDC_LINK_CLAIM", os.Getenv("GREPNEST_OIDC_LINK_CLAIM")},
		} {
			if setting.value == "" {
				return SSO{}, invalid(setting.name + " is required for OIDC")
			}
		}
		info, err := os.Stat(clientSecretFile)
		if err != nil || !info.Mode().IsRegular() {
			return SSO{}, invalid("GREPNEST_OIDC_CLIENT_SECRET_FILE must be a regular file")
		}
	}
	if githubEnabled {
		for _, setting := range []struct{ name, value string }{
			{"GREPNEST_OAUTH_GITHUB_CLIENT_ID", githubClientID},
			{"GREPNEST_OAUTH_GITHUB_CLIENT_SECRET_FILE", githubClientSecretFile},
		} {
			if setting.value == "" {
				return SSO{}, invalid(setting.name + " is required for GitHub OAuth")
			}
		}
		info, err := os.Stat(githubClientSecretFile)
		if err != nil || !info.Mode().IsRegular() {
			return SSO{}, invalid("GREPNEST_OAUTH_GITHUB_CLIENT_SECRET_FILE must be a regular file")
		}
	}
	if sso.PublicURL, err = parseHTTPSOrigin("GREPNEST_PUBLIC_URL", os.Getenv("GREPNEST_PUBLIC_URL")); err != nil {
		return SSO{}, err
	}
	if oidcEnabled {
		issuer, err := url.ParseRequestURI(issuerURL)
		if err != nil || issuer.Scheme != "https" || issuer.Hostname() == "" || issuer.User != nil || issuer.ForceQuery || issuer.RawQuery != "" || issuer.Fragment != "" {
			return SSO{}, invalid("GREPNEST_OIDC_ISSUER_URL must be an HTTPS URL without userinfo, query, or fragment")
		}
		scopes, err := parseScopes(valueOr("GREPNEST_OIDC_SCOPES", "openid,profile,email"))
		if err != nil {
			return SSO{}, err
		}
		sso.OIDC = OIDC{
			Enabled:          true,
			IssuerURL:        issuerURL,
			ClientID:         clientID,
			ClientSecretFile: clientSecretFile,
			CAFile:           os.Getenv("GREPNEST_OIDC_CA_FILE"),
			Scopes:           scopes,
			LinkClaim:        os.Getenv("GREPNEST_OIDC_LINK_CLAIM"),
			DisplayNameClaim: valueOr("GREPNEST_OIDC_DISPLAY_NAME_CLAIM", "name"),
		}
	}
	if githubEnabled {
		sso.OAuth.GitHub = GitHubOAuth{
			Enabled:          true,
			ClientID:         githubClientID,
			ClientSecretFile: githubClientSecretFile,
		}
	}
	switch os.Getenv("GREPNEST_BREAK_GLASS_ENABLED") {
	case "", "false":
	case "true":
		sso.BreakGlass = true
	default:
		return SSO{}, invalid("GREPNEST_BREAK_GLASS_ENABLED must be true or false")
	}
	return sso, nil
}

func parseHTTPSOrigin(name, value string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, invalid(name + " must be an HTTPS origin")
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed, nil
}

func parseScopes(value string) ([]string, error) {
	seen := map[string]bool{}
	scopes := make([]string, 0, len(strings.Split(value, ",")))
	for _, scope := range strings.Split(value, ",") {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return nil, invalid("GREPNEST_OIDC_SCOPES must not contain empty values")
		}
		if scope == "offline_access" {
			return nil, invalid("GREPNEST_OIDC_SCOPES must not contain offline_access")
		}
		if !seen[scope] {
			seen[scope] = true
			scopes = append(scopes, scope)
		}
	}
	if !seen["openid"] {
		return nil, invalid("GREPNEST_OIDC_SCOPES must contain openid")
	}
	return scopes, nil
}

func parseBoundedDuration(name, value string, fallback, min, max time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < min || parsed > max {
		return 0, invalid(name + " must be between " + min.String() + " and " + max.String())
	}
	return parsed, nil
}
