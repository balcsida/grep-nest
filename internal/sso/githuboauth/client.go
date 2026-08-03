package githuboauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/githubapp"
	"golang.org/x/oauth2"
)

const maxResponseBytes = 64 * 1024

type Client struct {
	endpoints  githubapp.Endpoints
	oauth      oauth2.Config
	http       *http.Client
	issuer     string
	apiVersion string
}

func NewClient(endpoints githubapp.Endpoints, publicURL *url.URL, clientID string, clientSecret []byte, apiVersion string, httpClient *http.Client) (*Client, error) {
	issuer, err := canonicalIssuer(endpoints.Web)
	if err != nil {
		return nil, err
	}
	if endpoints.API == nil || publicURL == nil || httpClient == nil {
		return nil, errors.New("GitHub OAuth configuration is invalid")
	}
	callback := publicURL.ResolveReference(&url.URL{Path: "/auth/oauth/github/callback"}).String()
	redirectDenyingClient := *httpClient
	redirectDenyingClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		endpoints: endpoints,
		oauth: oauth2.Config{
			ClientID: clientID, ClientSecret: string(clientSecret), RedirectURL: callback,
			Endpoint: oauth2.Endpoint{
				AuthURL:  githubapp.EndpointURL(endpoints.Web, "login", "oauth", "authorize"),
				TokenURL: githubapp.EndpointURL(endpoints.Web, "login", "oauth", "access_token"),
			},
		},
		http: &redirectDenyingClient, issuer: issuer, apiVersion: apiVersion,
	}, nil
}

func (client *Client) AuthorizationURL(state, _ string, verifier string) string {
	return client.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

func (client *Client) Exchange(ctx context.Context, code, verifier, _ string) (authn.Identity, error) {
	values := url.Values{
		"client_id":     {client.oauth.ClientID},
		"client_secret": {client.oauth.ClientSecret},
		"code":          {code},
		"redirect_uri":  {client.oauth.RedirectURL},
		"code_verifier": {verifier},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.oauth.Endpoint.TokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return authn.Identity{}, errors.New("build GitHub OAuth token request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.http.Do(request)
	if err != nil {
		return authn.Identity{}, errors.New("GitHub OAuth token request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return authn.Identity{}, fmt.Errorf("GitHub OAuth token status %d", response.StatusCode)
	}
	data, err := boundedBody(response.Body)
	if err != nil {
		return authn.Identity{}, errors.New("read GitHub OAuth token response")
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if err := decodeOne(data, &token); err != nil || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "bearer") || token.Scope != "" {
		return authn.Identity{}, errors.New("GitHub OAuth token response is invalid")
	}

	request, err = http.NewRequestWithContext(ctx, http.MethodGet, githubapp.EndpointURL(client.endpoints.API, "user"), nil)
	if err != nil {
		return authn.Identity{}, errors.New("build GitHub user request")
	}
	githubapp.SetAPIHeaders(request.Header, client.apiVersion)
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	response, err = client.http.Do(request)
	if err != nil {
		return authn.Identity{}, errors.New("GitHub user request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return authn.Identity{}, fmt.Errorf("GitHub user status %d", response.StatusCode)
	}
	data, err = boundedBody(response.Body)
	if err != nil {
		return authn.Identity{}, errors.New("read GitHub user response")
	}
	var user struct {
		ID    int64   `json:"id"`
		Login string  `json:"login"`
		Name  *string `json:"name"`
	}
	if err := decodeOne(data, &user); err != nil || user.ID <= 0 || !validName(user.Login) || (user.Name != nil && !validOptionalName(*user.Name)) {
		return authn.Identity{}, errors.New("GitHub user response is invalid")
	}
	displayName := user.Login
	if user.Name != nil && strings.TrimSpace(*user.Name) != "" {
		displayName = strings.TrimSpace(*user.Name)
	}
	subject := strconv.FormatInt(user.ID, 10)
	linkID := "github:" + client.issuer + ":" + subject
	if len(client.issuer) > 2048 || len(linkID) > 2048 {
		return authn.Identity{}, errors.New("GitHub user identity is invalid")
	}
	return authn.Identity{Provider: authn.ProviderOAuth, Issuer: client.issuer, Subject: subject, LinkID: linkID, DisplayName: displayName}, nil
}

func canonicalIssuer(web *url.URL) (string, error) {
	if web == nil || web.Scheme != "https" || web.Hostname() == "" || web.User != nil || web.RawQuery != "" || web.Fragment != "" || (web.EscapedPath() != "" && web.EscapedPath() != "/") {
		return "", errors.New("GitHub web endpoint must be an HTTPS origin")
	}
	host := strings.ToLower(web.Hostname())
	if port := web.Port(); port != "" && port != "443" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return (&url.URL{Scheme: "https", Host: host}).String(), nil
}

func boundedBody(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes || !utf8.Valid(data) {
		return nil, errors.New("invalid bounded response")
	}
	return data, nil
}

func decodeOne(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func validName(value string) bool {
	return value != "" && validOptionalName(value)
}

func validOptionalName(value string) bool {
	if len(value) > 256 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
