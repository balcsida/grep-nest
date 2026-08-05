package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/grepnest/grepnest/internal/admin"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/jackc/pgx/v5"
)

func RegisterAdmin(mux *http.ServeMux, authenticator authn.RequestAuthenticator, service *admin.Service, maxItems int, maxRequestBytes, maxResponseBytes int64) {
	service.MaxItems = maxItems
	get := func(load func(*http.Request) (any, error)) http.Handler {
		return exactMethod(http.MethodGet, AuthenticateRequest(authenticator, administratorOnly(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			value, err := load(request)
			if err != nil {
				writeAdminError(writer, err)
				return
			}
			writeBoundedJSON(writer, value, maxResponseBytes)
		}))))
	}
	mux.Handle("/v1/admin/overview", get(func(request *http.Request) (any, error) {
		return service.Overview(request.Context(), PrincipalFromContext(request.Context()))
	}))
	mux.Handle("/v1/admin/repositories", get(func(request *http.Request) (any, error) {
		items, truncated, err := service.Repositories(request.Context(), PrincipalFromContext(request.Context()))
		return struct {
			Repositories []admin.Repository `json:"repositories"`
			Truncated    bool               `json:"truncated"`
		}{items, truncated}, err
	}))
	mux.Handle("/v1/admin/jobs", get(func(request *http.Request) (any, error) {
		cursor, err := decodeAdminJobCursor(request.URL.Query().Get("cursor"))
		if err != nil {
			return nil, err
		}
		items, truncated, err := service.Jobs(request.Context(), PrincipalFromContext(request.Context()), cursor)
		if err != nil {
			return nil, err
		}
		var nextCursor string
		if truncated {
			if len(items) == 0 {
				return nil, errors.New("truncated jobs response is empty")
			}
			nextCursor, err = encodeAdminJobCursor(items[len(items)-1])
		}
		return struct {
			Jobs       []admin.Job `json:"jobs"`
			Truncated  bool        `json:"truncated"`
			NextCursor string      `json:"next_cursor,omitempty"`
		}{items, truncated, nextCursor}, err
	}))
	mux.Handle("/v1/admin/scip/uploads", get(func(request *http.Request) (any, error) {
		items, truncated, err := service.SCIPUploads(request.Context(), PrincipalFromContext(request.Context()))
		return struct {
			Uploads   []admin.SCIPUpload `json:"uploads"`
			Truncated bool               `json:"truncated"`
		}{items, truncated}, err
	}))
	mux.Handle("/v1/admin/scip/dependencies", get(func(request *http.Request) (any, error) {
		items, truncated, err := service.SCIPDependencies(request.Context(), PrincipalFromContext(request.Context()))
		return struct {
			Dependencies []admin.SCIPDependency `json:"dependencies"`
			Truncated    bool                   `json:"truncated"`
		}{items, truncated}, err
	}))
	mux.Handle("/v1/admin/webhook-deliveries", get(func(request *http.Request) (any, error) {
		items, truncated, err := service.Deliveries(request.Context(), PrincipalFromContext(request.Context()))
		return struct {
			Deliveries []admin.Delivery `json:"deliveries"`
			Truncated  bool             `json:"truncated"`
		}{items, truncated}, err
	}))
	mux.Handle("/v1/admin/github", get(func(request *http.Request) (any, error) {
		return service.GitHubInfo(request.Context(), PrincipalFromContext(request.Context()))
	}))

	action := func(parse func(string) (int64, bool), call func(*http.Request, int64) error) http.Handler {
		return exactMethod(http.MethodPost, AuthenticateRequest(authenticator, administratorOnly(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			id, ok := parse(request.URL.Path)
			if !ok {
				writeError(writer, http.StatusBadRequest, "invalid_request", "request is invalid", false)
				return
			}
			if err := call(request, id); err != nil {
				writeAdminError(writer, err)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		}))))
	}
	mux.Handle("/v1/admin/repositories/", action(
		func(path string) (int64, bool) { return adminPathID(path, "/v1/admin/repositories/", "/reindex") },
		func(request *http.Request, id int64) error {
			return service.Reindex(request.Context(), PrincipalFromContext(request.Context()), id)
		},
	))
	mux.Handle("/v1/admin/jobs/", action(
		func(path string) (int64, bool) { return adminPathID(path, "/v1/admin/jobs/", "/retry") },
		func(request *http.Request, id int64) error {
			return service.Retry(request.Context(), PrincipalFromContext(request.Context()), id)
		},
	))
	mux.Handle("/v1/admin/reconcile", action(
		func(path string) (int64, bool) { return 0, path == "/v1/admin/reconcile" },
		func(request *http.Request, _ int64) error {
			return service.Reconcile(request.Context(), PrincipalFromContext(request.Context()))
		},
	))
	registerAdminIdentity(mux, authenticator, service, maxRequestBytes, maxResponseBytes)
}

type adminJobCursor struct {
	Version   int       `json:"v"`
	UpdatedAt time.Time `json:"updated_at"`
	ID        int64     `json:"id"`
}

func decodeAdminJobCursor(value string) (*admin.JobCursor, error) {
	if value == "" {
		return nil, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, admin.ErrInvalid
	}
	var cursor adminJobCursor
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&cursor); err != nil {
		return nil, admin.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || cursor.Version != 1 || cursor.UpdatedAt.IsZero() || cursor.ID <= 0 {
		return nil, admin.ErrInvalid
	}
	return &admin.JobCursor{UpdatedAt: cursor.UpdatedAt, ID: cursor.ID}, nil
}

func encodeAdminJobCursor(job admin.Job) (string, error) {
	data, err := json.Marshal(adminJobCursor{Version: 1, UpdatedAt: job.UpdatedAt, ID: job.ID})
	return base64.RawURLEncoding.EncodeToString(data), err
}

func adminPathID(path, prefix, suffix string) (int64, bool) {
	value := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if value == path || value == "" || prefix+value+suffix != path {
		return 0, false
	}
	id, err := strconv.ParseInt(value, 10, 64)
	return id, err == nil && id > 0
}

func writeAdminError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, admin.ErrInvalid):
		writeError(writer, http.StatusBadRequest, "invalid_request", "request is invalid", false)
	case errors.Is(err, admin.ErrSelfAdministration), errors.Is(err, admin.ErrFinalAdministrator):
		writeError(writer, http.StatusConflict, "conflict", "administrator change conflicts with the active account", false)
	case errors.Is(err, admin.ErrForbidden):
		writeError(writer, http.StatusForbidden, "forbidden", "administrator access required", false)
	case errors.Is(err, pgx.ErrNoRows):
		writeError(writer, http.StatusNotFound, "not_found", "admin resource not found", false)
	default:
		writeError(writer, http.StatusServiceUnavailable, "unavailable", "admin service is unavailable", true)
	}
}
