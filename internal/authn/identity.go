package authn

import (
	"errors"
	"unicode"
	"unicode/utf8"
)

var ErrInvalidIdentity = errors.New("invalid identity")

const (
	ProviderOIDC  = "oidc"
	ProviderOAuth = "oauth"
	ProviderLocal = "local"
)

type Identity struct {
	Provider, Issuer, Subject, LinkID, DisplayName string
}

func validIdentity(identity Identity) bool {
	return validIdentityField(identity.Provider) && validIdentityField(identity.Issuer) && validIdentityField(identity.Subject) && validIdentityField(identity.LinkID) && validIdentityDisplayName(identity.DisplayName)
}

func validIdentityField(value string) bool {
	if value == "" || !utf8.ValidString(value) || len(value) > 2048 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validIdentityDisplayName(value string) bool {
	if !utf8.ValidString(value) || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
