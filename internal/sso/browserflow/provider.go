package browserflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/grepnest/grepnest/internal/audit"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/sso"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

type Client interface {
	AuthorizationURL(state, nonce, verifier string) string
	Exchange(context.Context, string, string, string) (authn.Identity, error)
}

type Spec struct {
	Metadata                                                            sso.Metadata
	LoginPath, CallbackPath, FlowProvider, IdentityProvider, CookieName string
	Method, SuccessOperation, DeniedOperation                           string
}

type Provider struct {
	Spec     Spec
	Client   Client
	Store    authn.SessionStore
	Sessions *authn.SessionManager
	LoginTTL time.Duration
	Now      func() time.Time
	Rand     io.Reader
	Audit    audit.Recorder
}

const maxCallbackValueLen = 2048

func (provider *Provider) Metadata() sso.Metadata { return provider.Spec.Metadata }

func (provider *Provider) Register(mux *http.ServeMux) {
	mux.Handle(provider.Spec.LoginPath, getOnly(http.HandlerFunc(provider.login)))
	mux.Handle(provider.Spec.CallbackPath, getOnly(http.HandlerFunc(provider.callback)))
}

func (provider *Provider) login(writer http.ResponseWriter, request *http.Request) {
	privateHeaders(writer)
	state, stateRaw, err := provider.randomToken()
	if err != nil {
		provider.loginFail(request.Context(), writer)
		return
	}
	browser, browserRaw, err := provider.randomToken()
	if err != nil {
		provider.loginFail(request.Context(), writer)
		return
	}
	nonce, _, err := provider.randomToken()
	if err != nil {
		provider.loginFail(request.Context(), writer)
		return
	}
	now := provider.now()
	expires := now.Add(provider.LoginTTL)
	verifier := oauth2.GenerateVerifier()
	flow := authn.LoginFlow{
		StateHash: sha256.Sum256(stateRaw), BrowserHash: sha256.Sum256(browserRaw),
		Provider: provider.Spec.FlowProvider, Nonce: nonce, CodeVerifier: verifier, ReturnTo: "/",
		CreatedAt: now, ExpiresAt: expires,
	}
	if !provider.validSpec() || provider.Client == nil || provider.Store == nil || provider.LoginTTL <= 0 ||
		provider.Store.CreateLoginFlow(request.Context(), flow) != nil {
		provider.loginFail(request.Context(), writer)
		return
	}
	http.SetCookie(writer, sso.LoginCookie(provider.Spec.CookieName, browser, expires, now))
	http.Redirect(writer, request, provider.Client.AuthorizationURL(state, nonce, verifier), http.StatusSeeOther)
}

func (provider *Provider) callback(writer http.ResponseWriter, request *http.Request) {
	privateHeaders(writer)
	if !provider.validSpec() {
		provider.callbackFail(request.Context(), writer, "error")
		return
	}
	http.SetCookie(writer, sso.ClearLoginCookie(provider.Spec.CookieName))
	query := request.URL.Query()
	state, ok := exactlyOne(query["state"])
	if !ok {
		provider.callbackFail(request.Context(), writer, "invalid")
		return
	}
	codeValues, codePresent := query["code"]
	errorValues, errorPresent := query["error"]
	code, validCode := exactlyOne(codeValues)
	oauthError, validError := exactlyOne(errorValues)
	if !((validCode && !errorPresent) || (validError && !codePresent)) {
		provider.callbackFail(request.Context(), writer, "invalid")
		return
	}
	stateHash, ok := tokenHash(state)
	if !ok {
		provider.callbackFail(request.Context(), writer, "invalid")
		return
	}
	browser, count := cookieValue(request, provider.Spec.CookieName)
	browserHash, validBrowser := tokenHash(browser)
	if count != 1 || !validBrowser {
		provider.callbackFail(request.Context(), writer, "invalid")
		return
	}
	if provider.Store == nil {
		provider.callbackFail(request.Context(), writer, "error")
		return
	}
	flow, err := provider.Store.ConsumeLoginFlow(request.Context(), stateHash, browserHash, provider.Spec.FlowProvider, provider.now())
	if err != nil {
		result := "error"
		if errors.Is(err, pgx.ErrNoRows) {
			result = "invalid"
		}
		provider.callbackFail(request.Context(), writer, result)
		return
	}
	if validError {
		_ = oauthError
		provider.callbackFail(request.Context(), writer, "denied")
		return
	}
	if provider.Client == nil || provider.Sessions == nil {
		provider.callbackFail(request.Context(), writer, "error")
		return
	}
	identity, err := provider.Client.Exchange(request.Context(), code, flow.CodeVerifier, flow.Nonce)
	if err != nil {
		provider.callbackFail(request.Context(), writer, "invalid")
		return
	}
	if identity.Provider != provider.Spec.IdentityProvider {
		provider.callbackFail(request.Context(), writer, "invalid")
		return
	}
	token, expires, err := provider.Sessions.Create(request.Context(), identity, provider.Spec.SuccessOperation)
	if err != nil {
		provider.callbackFail(request.Context(), writer, "error")
		return
	}
	http.SetCookie(writer, sso.SessionCookie(token, expires, provider.now()))
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

func (provider *Provider) randomToken() (string, []byte, error) {
	raw := make([]byte, 32)
	reader := provider.Rand
	if reader == nil {
		reader = rand.Reader
	}
	if _, err := io.ReadFull(reader, raw); err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(raw), raw, nil
}

func (provider *Provider) now() time.Time {
	if provider.Now != nil {
		return provider.Now()
	}
	return time.Now()
}

func (provider *Provider) validSpec() bool {
	return provider.Spec.Metadata.ID != "" && provider.Spec.Metadata.Label != "" && provider.Spec.Metadata.LoginURL != "" &&
		provider.Spec.LoginPath != "" && provider.Spec.CallbackPath != "" && provider.Spec.FlowProvider != "" &&
		provider.Spec.IdentityProvider != "" && provider.Spec.CookieName != "" && provider.Spec.Method != "" &&
		provider.Spec.SuccessOperation != "" && provider.Spec.DeniedOperation != ""
}

func (*Provider) fail(writer http.ResponseWriter) {
	writer.Header().Set("Location", "/?auth_error=authentication_failed")
	writer.WriteHeader(http.StatusSeeOther)
}

func (provider *Provider) loginFail(ctx context.Context, writer http.ResponseWriter) {
	if provider.Audit != nil {
		_ = provider.Audit.Record(ctx, audit.Event{
			ActorType: "anonymous", TargetType: "authentication",
			AuthenticationMethod: provider.Spec.Method, Operation: provider.Spec.DeniedOperation,
			Outcome: "error", RequestID: audit.RequestID(ctx),
		})
	}
	provider.fail(writer)
}

func (provider *Provider) callbackFail(ctx context.Context, writer http.ResponseWriter, result string) {
	if provider.Audit != nil {
		outcome := "denied"
		if result == "error" {
			outcome = "error"
		} else if result == "invalid" {
			outcome = "invalid"
		}
		_ = provider.Audit.Record(ctx, audit.Event{
			ActorType: "anonymous", TargetType: "authentication",
			AuthenticationMethod: provider.Spec.Method, Operation: provider.Spec.DeniedOperation,
			Outcome: outcome, RequestID: audit.RequestID(ctx),
		})
	}
	provider.fail(writer)
}

func exactlyOne(values []string) (string, bool) {
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && returnValue != "" && len(returnValue) <= maxCallbackValueLen
}

func tokenHash(value string) ([32]byte, bool) {
	if len(value) > maxCallbackValueLen {
		return [32]byte{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, false
	}
	return sha256.Sum256(raw), true
}

func cookieValue(request *http.Request, name string) (string, int) {
	var value string
	count := 0
	for _, cookie := range request.Cookies() {
		if cookie.Name == name {
			value = cookie.Value
			count++
		}
	}
	return value, count
}

func privateHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Referrer-Policy", "no-referrer")
}

func getOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			privateHeaders(writer)
			writer.Header().Set("Allow", http.MethodGet)
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(writer, request)
	})
}
