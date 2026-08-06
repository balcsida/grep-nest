package graphclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/grepnest/grepnest/internal/graphprotocol"
)

const defaultMaxRequestBytes = 64 << 10

type Client struct {
	baseURL          *url.URL
	secret           []byte
	httpClient       *http.Client
	maxRequestBytes  int64
	maxResponseBytes int64
}

var _ graphprotocol.QueryEngine = (*Client)(nil)

type Error struct {
	Status int
	Code   string
}

func (err *Error) Error() string {
	return "graph client: " + err.Code
}

// Unwrap exposes the transport failure cause so callers can distinguish a rejected
// secret from an unreachable runtime with errors.Is.
func (err *Error) Unwrap() error {
	switch err.Code {
	case "unauthorized":
		return graphprotocol.ErrUnauthorized
	case "unavailable":
		return graphprotocol.ErrUnreachable
	case "invalid_response":
		return graphprotocol.ErrInvalidReply
	case "response_too_large":
		return graphprotocol.ErrReplyTooLarge
	default:
		return nil
	}
}

func New(baseURL string, secret []byte, httpClient *http.Client, maxResponseBytes int64) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(baseURL, "#") ||
		parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
		return nil, errors.New("invalid graph URL")
	}
	if len(secret) == 0 {
		return nil, errors.New("graph secret is required")
	}
	if maxResponseBytes <= 0 {
		return nil, errors.New("positive response limit is required")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	cloned := *httpClient
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	return &Client{
		baseURL: parsed, secret: bytes.Clone(secret), httpClient: &cloned,
		maxRequestBytes: defaultMaxRequestBytes, maxResponseBytes: maxResponseBytes,
	}, nil
}

func (client *Client) Context(ctx context.Context, request graphprotocol.ContextRequest) (graphprotocol.ContextResponse, error) {
	var response graphprotocol.ContextResponse
	err := client.call(ctx, "/internal/v1/graph/context", request, &response)
	return response, err
}

func (client *Client) Impact(ctx context.Context, request graphprotocol.ImpactRequest) (graphprotocol.ImpactResponse, error) {
	var response graphprotocol.ImpactResponse
	err := client.call(ctx, "/internal/v1/graph/impact", request, &response)
	return response, err
}

func (client *Client) Trace(ctx context.Context, request graphprotocol.TraceRequest) (graphprotocol.TraceResponse, error) {
	var response graphprotocol.TraceResponse
	err := client.call(ctx, "/internal/v1/graph/trace", request, &response)
	return response, err
}

func (client *Client) Cypher(ctx context.Context, request graphprotocol.CypherRequest) (graphprotocol.CypherResponse, error) {
	var response graphprotocol.CypherResponse
	err := client.call(ctx, "/internal/v1/graph/cypher", request, &response)
	return response, err
}

func (client *Client) call(ctx context.Context, path string, input, output any) error {
	data, err := json.Marshal(input)
	if err != nil {
		return &Error{Code: "invalid_request"}
	}
	if int64(len(data)) > client.maxRequestBytes {
		return &Error{Code: "request_too_large"}
	}
	endpoint := *client.baseURL
	endpoint.Path += path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return &Error{Code: "invalid_request"}
	}
	request.Header.Set("Authorization", "Bearer "+string(client.secret))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return &Error{Code: "unavailable"}
	}
	defer response.Body.Close()
	reader := io.LimitReader(response.Body, client.maxResponseBytes+1)
	body, err := io.ReadAll(reader)
	if err != nil {
		return &Error{Status: response.StatusCode, Code: "unavailable"}
	}
	if int64(len(body)) > client.maxResponseBytes {
		return &Error{Status: response.StatusCode, Code: "response_too_large"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError(response.StatusCode, body)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(output); err != nil {
		return &Error{Status: response.StatusCode, Code: "invalid_response"}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return &Error{Status: response.StatusCode, Code: "invalid_response"}
	}
	return nil
}

func responseError(status int, body []byte) error {
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &envelope)
	code := envelope.Error.Code
	switch code {
	case "invalid_request", "unauthorized", "not_found", "unavailable", "response_too_large":
	default:
		code = "unavailable"
	}
	return &Error{Status: status, Code: code}
}
