package githubapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grepnest/grepnest/internal/observability"
)

const githubMediaType = "application/vnd.github+json"

type Client struct {
	endpoints  Endpoints
	http       *http.Client
	signer     *Signer
	apiVersion string
	maxBytes   int64
	now        func() time.Time
	metrics    *observability.Metrics
	mu         sync.Mutex
	tokens     map[string]Token
}

func NewClient(endpoints Endpoints, httpClient *http.Client, signer *Signer, apiVersion string, maxBytes int64, now func() time.Time, metricSet ...*observability.Metrics) *Client {
	if now == nil {
		now = time.Now
	}
	var metrics *observability.Metrics
	if len(metricSet) > 0 {
		metrics = metricSet[0]
	}
	return &Client{endpoints: endpoints, http: httpClient, signer: signer, apiVersion: apiVersion, maxBytes: maxBytes, now: now, metrics: metrics, tokens: make(map[string]Token)}
}

func (c *Client) InstallationToken(ctx context.Context, installationID int64, repositoryIDs []int64) (Token, error) {
	ids := append([]int64(nil), repositoryIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	key := tokenKey(installationID, ids)
	c.mu.Lock()
	token, ok := c.tokens[key]
	c.mu.Unlock()
	if ok && c.now().Before(token.ExpiresAt.Add(-time.Minute)) {
		return token, nil
	}

	jwt, err := c.signer.JWT()
	if err != nil {
		return Token{}, fmt.Errorf("sign GitHub App JWT: %w", err)
	}
	body, err := json.Marshal(struct {
		RepositoryIDs []int64 `json:"repository_ids,omitempty"`
	}{ids})
	if err != nil {
		return Token{}, err
	}
	var response struct {
		Value     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	_, err = c.doJSON(ctx, "installation_token", http.MethodPost, c.apiURL("app", "installations", strconv.FormatInt(installationID, 10), "access_tokens"), body, "Bearer "+jwt, c.maxBytes, &response)
	if err != nil {
		return Token{}, err
	}
	if response.Value == "" || response.ExpiresAt.IsZero() {
		return Token{}, errors.New("GitHub token response is invalid")
	}
	token = Token{Value: response.Value, ExpiresAt: response.ExpiresAt}
	c.mu.Lock()
	c.tokens[key] = token
	c.mu.Unlock()
	return token, nil
}

func (c *Client) Installations(ctx context.Context) ([]Installation, error) {
	type wireInstallation struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"account"`
		SuspendedAt *time.Time `json:"suspended_at"`
	}
	var result []Installation
	next := c.apiURL("app", "installations")
	for next != nil {
		var page []wireInstallation
		jwt, err := c.signer.JWT()
		if err != nil {
			return nil, fmt.Errorf("sign GitHub App JWT: %w", err)
		}
		link, err := c.doJSON(ctx, "installations", http.MethodGet, next, nil, "Bearer "+jwt, c.maxBytes, &page)
		if err != nil {
			return nil, err
		}
		for _, item := range page {
			status := "active"
			if item.SuspendedAt != nil {
				status = "suspended"
			}
			result = append(result, Installation{ID: item.ID, AccountLogin: item.Account.Login, AccountType: item.Account.Type, Status: status, SuspendedAt: item.SuspendedAt})
		}
		next, err = c.nextPage(link)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (c *Client) InstallationRepositories(ctx context.Context, installationID int64) ([]Repository, error) {
	type wireRepository struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
		Owner    struct {
			Login string `json:"login"`
		} `json:"owner"`
		Name          string `json:"name"`
		CloneURL      string `json:"clone_url"`
		HTMLURL       string `json:"html_url"`
		DefaultBranch string `json:"default_branch"`
		Private       bool   `json:"private"`
		Archived      bool   `json:"archived"`
		Disabled      bool   `json:"disabled"`
		SizeKB        int64  `json:"size"`
	}
	var result []Repository
	next := c.apiURL("installation", "repositories")
	for next != nil {
		var page struct {
			Repositories []wireRepository `json:"repositories"`
		}
		link, err := c.doInstallationJSON(ctx, "repositories", installationID, next, c.maxBytes, &page)
		if err != nil {
			return nil, err
		}
		for _, item := range page.Repositories {
			if item.SizeKB < 0 || item.SizeKB > math.MaxInt64/1024 {
				return nil, errors.New("GitHub repository size is invalid")
			}
			result = append(result, Repository{ID: item.ID, InstallationID: installationID, SizeBytes: item.SizeKB * 1024, FullName: item.FullName, Owner: item.Owner.Login, Name: item.Name, CloneURL: item.CloneURL, HTMLURL: item.HTMLURL, DefaultBranch: item.DefaultBranch, Private: item.Private, Archived: item.Archived, Disabled: item.Disabled})
		}
		next, err = c.nextPage(link)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (c *Client) DefaultBranchSHA(ctx context.Context, installationID int64, owner, name, branch string) (string, error) {
	var response struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	_, err := c.doInstallationJSON(ctx, "default_branch", installationID, c.apiURL("repos", owner, name, "branches", branch), c.maxBytes, &response)
	return response.Commit.SHA, err
}

func (c *Client) ReadContents(ctx context.Context, installationID int64, owner, name, path, ref string, maxBytes int64) (Content, error) {
	segments := []string{"repos", owner, name, "contents"}
	segments = append(segments, strings.Split(path, "/")...)
	endpoint := c.apiURL(segments...)
	query := endpoint.Query()
	query.Set("ref", ref)
	endpoint.RawQuery = query.Encode()
	limit := maxBytes
	if limit <= 0 || limit > c.maxBytes {
		limit = c.maxBytes
	}
	var content Content
	_, err := c.doInstallationJSON(ctx, "contents", installationID, endpoint, limit, &content)
	return content, err
}

func (c *Client) doInstallationJSON(ctx context.Context, operation string, installationID int64, endpoint *url.URL, limit int64, target any) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := c.InstallationToken(ctx, installationID, nil)
		if err != nil {
			return "", err
		}
		link, err := c.doJSON(ctx, operation, http.MethodGet, endpoint, nil, "Bearer "+token.Value, limit, target)
		var statusError HTTPStatusError
		if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusUnauthorized || attempt == 1 {
			return link, err
		}
		c.mu.Lock()
		delete(c.tokens, tokenKey(installationID, nil))
		c.mu.Unlock()
	}
	panic("unreachable")
}

type HTTPStatusError struct {
	StatusCode int
}

func (err HTTPStatusError) Error() string {
	return fmt.Sprintf("GitHub API status %d", err.StatusCode)
}

func (c *Client) doJSON(ctx context.Context, operation, method string, endpoint *url.URL, body []byte, authorization string, limit int64, target any) (link string, resultErr error) {
	result := "error"
	if c.metrics != nil {
		defer func() { c.metrics.ObserveGitHub(operation, result) }()
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	SetAPIHeaders(request.Header, c.apiVersion)
	request.Header.Set("Authorization", authorization)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return "", fmt.Errorf("GitHub API request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", HTTPStatusError{StatusCode: response.StatusCode}
	}
	reader := io.LimitReader(response.Body, limit+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", errors.New("read GitHub API response")
	}
	if int64(len(data)) > limit {
		return "", errors.New("GitHub API response too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return "", errors.New("decode GitHub API response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("decode GitHub API response: trailing JSON")
	}
	result = "success"
	return response.Header.Get("Link"), nil
}

func (c *Client) apiURL(segments ...string) *url.URL {
	endpoint, _ := url.Parse(EndpointURL(c.endpoints.API, segments...))
	return endpoint
}

func EndpointURL(base *url.URL, segments ...string) string {
	endpoint := *base
	rawPath := strings.TrimSuffix(endpoint.EscapedPath(), "/")
	for _, segment := range segments {
		rawPath += "/" + url.PathEscape(segment)
	}
	path, _ := url.PathUnescape(rawPath)
	endpoint.Path, endpoint.RawPath = path, rawPath
	endpoint.RawQuery, endpoint.Fragment = "", ""
	return endpoint.String()
}

func SetAPIHeaders(header http.Header, apiVersion string) {
	header.Set("Accept", githubMediaType)
	header.Set("User-Agent", "GrepNest")
	header.Set("X-GitHub-Api-Version", apiVersion)
}

func (c *Client) nextPage(link string) (*url.URL, error) {
	for _, value := range splitLinkHeader(link, ',') {
		parts := splitLinkHeader(value, ';')
		nextRelation := false
		for _, parameter := range parts[1:] {
			name, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(name), "rel") {
				continue
			}
			value = strings.TrimSpace(value)
			if strings.HasPrefix(value, `"`) {
				var err error
				value, err = strconv.Unquote(value)
				if err != nil {
					return nil, errors.New("invalid GitHub pagination link")
				}
			}
			for _, relation := range strings.Fields(value) {
				if relation == "next" {
					nextRelation = true
				}
			}
		}
		if !nextRelation {
			continue
		}
		raw := strings.TrimSpace(parts[0])
		if len(raw) < 2 || raw[0] != '<' || raw[len(raw)-1] != '>' {
			return nil, errors.New("invalid GitHub pagination link")
		}
		next, err := url.Parse(raw[1 : len(raw)-1])
		apiPath := strings.TrimSuffix(c.endpoints.API.Path, "/")
		if err != nil || next.Scheme != c.endpoints.API.Scheme || next.Host != c.endpoints.API.Host || hasDotSegment(next.Path) || !strings.HasPrefix(next.Path, apiPath+"/") {
			return nil, errors.New("invalid GitHub pagination link")
		}
		return next, nil
	}
	return nil, nil
}

func splitLinkHeader(value string, separator byte) []string {
	var values []string
	start := 0
	angle, quoted, escaped := false, false, false
	for i := range len(value) {
		switch {
		case escaped:
			escaped = false
		case quoted && value[i] == '\\':
			escaped = true
		case value[i] == '"':
			quoted = !quoted
		case !quoted && value[i] == '<':
			angle = true
		case !quoted && value[i] == '>':
			angle = false
		case !quoted && !angle && value[i] == separator:
			values = append(values, value[start:i])
			start = i + 1
		}
	}
	return append(values, value[start:])
}

func hasDotSegment(path string) bool {
	for segment := range strings.SplitSeq(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func tokenKey(installationID int64, repositoryIDs []int64) string {
	var key strings.Builder
	key.WriteString(strconv.FormatInt(installationID, 10))
	for _, id := range repositoryIDs {
		key.WriteByte(':')
		key.WriteString(strconv.FormatInt(id, 10))
	}
	return key.String()
}
