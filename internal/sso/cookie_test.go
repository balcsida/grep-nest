package sso

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCookieAttributesAndExpiry(t *testing.T) {
	expires := time.Unix(2_000_000_000, 0).UTC()
	now := expires.Add(-time.Hour)
	tests := []struct {
		name     string
		cookie   *http.Cookie
		wantName string
		wantSite http.SameSite
	}{
		{"session", SessionCookie("session", expires, now), "__Host-grepnest_session", http.SameSiteStrictMode},
		{"login", LoginCookie("__Host-grepnest_oidc_login", "browser", expires, now), "__Host-grepnest_oidc_login", http.SameSiteLaxMode},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cookie := test.cookie
			if cookie.Name != test.wantName || cookie.Value == "" || cookie.Path != "/" || cookie.Domain != "" ||
				!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != test.wantSite ||
				!cookie.Expires.Equal(expires) || cookie.MaxAge != 3600 {
				t.Fatalf("cookie = %#v", cookie)
			}
		})
	}
}

func TestCookieDeletionUsesBrowserWireSemantics(t *testing.T) {
	for _, cookie := range []*http.Cookie{ClearSessionCookie(), ClearLoginCookie("__Host-grepnest_oidc_login")} {
		if cookie.MaxAge != -1 || !cookie.Expires.Before(time.Now()) || cookie.Path != "/" ||
			cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly {
			t.Fatalf("cookie = %#v", cookie)
		}
		recorder := httptest.NewRecorder()
		http.SetCookie(recorder, cookie)
		if wire := recorder.Header().Get("Set-Cookie"); !strings.Contains(wire, "Max-Age=0") {
			t.Fatalf("Set-Cookie = %q", wire)
		}
	}
}
