package sso

import (
	"net/http"
	"time"

	"github.com/grepnest/grepnest/internal/authn"
)

const OIDCLoginCookieName = "__Host-grepnest_oidc_login"

func SessionCookie(value string, expires, now time.Time) *http.Cookie {
	return liveCookie(authn.SessionCookieName, value, expires, now, http.SameSiteStrictMode)
}

func LoginCookie(name, value string, expires, now time.Time) *http.Cookie {
	return liveCookie(name, value, expires, now, http.SameSiteLaxMode)
}

func ClearSessionCookie() *http.Cookie {
	return deletedCookie(authn.SessionCookieName, http.SameSiteStrictMode)
}

func ClearLoginCookie(name string) *http.Cookie { return deletedCookie(name, http.SameSiteLaxMode) }

func liveCookie(name, value string, expires, now time.Time, sameSite http.SameSite) *http.Cookie {
	maxAge := int(time.Until(expires).Seconds())
	if !now.IsZero() {
		maxAge = int(expires.Sub(now).Seconds())
	}
	if maxAge < 1 {
		maxAge = 1
	}
	return &http.Cookie{
		Name: name, Value: value, Path: "/", Expires: expires, MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: sameSite,
	}
}

func deletedCookie(name string, sameSite http.SameSite) *http.Cookie {
	return &http.Cookie{
		Name: name, Path: "/", Expires: time.Unix(1, 0).UTC(), MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: sameSite,
	}
}
