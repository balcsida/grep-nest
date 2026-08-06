package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/scipgraph"
	"github.com/grepnest/grepnest/pkg/api"
	"github.com/jackc/pgx/v5"
)

var scipCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type scipDependenciesRequest struct {
	RepositoryID int64 `json:"repository_id"`
	api.RepositoryPackages
}

type scipRepositoryRequest struct {
	RepositoryID int64 `json:"repository_id"`
}

func RegisterSCIP(mux *http.ServeMux, authenticator authn.RequestAuthenticator, service *scipgraph.Service, maxRequestBytes, maxUploadBytes, maxResponseBytes int64) {
	mux.Handle("/v1/scip/uploads", exactMethod(http.MethodPost, AuthenticateRequest(authenticator, administratorOnly(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Content-Type") != "application/vnd.scip+protobuf" {
			writeError(writer, http.StatusUnsupportedMediaType, "invalid_request", "request is invalid", false)
			return
		}
		query := request.URL.Query()
		if len(query) != 2 || len(query["repository_id"]) != 1 || len(query["commit"]) != 1 {
			writeError(writer, http.StatusBadRequest, "invalid_request", "request is invalid", false)
			return
		}
		repositoryID, err := strconv.ParseInt(query.Get("repository_id"), 10, 64)
		commit := query.Get("commit")
		if err != nil || repositoryID < 1 || !scipCommitPattern.MatchString(commit) {
			writeError(writer, http.StatusBadRequest, "invalid_request", "request is invalid", false)
			return
		}
		controller := http.NewResponseController(writer)
		setWriteDeadline := func() {
			_ = controller.SetWriteDeadline(time.Now().Add(10 * time.Second))
		}
		principal := PrincipalFromContext(request.Context())
		if err := service.ValidateUpload(request.Context(), principal, repositoryID, commit); err != nil {
			setWriteDeadline()
			writeSCIPError(writer, err)
			return
		}
		_ = controller.SetReadDeadline(time.Time{})
		data, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, maxUploadBytes))
		if err != nil {
			setWriteDeadline()
			writeError(writer, invalidRequestStatus(err), "invalid_request", "request is invalid", false)
			return
		}
		if err := service.Upload(request.Context(), principal, repositoryID, commit, data); err != nil {
			setWriteDeadline()
			writeSCIPError(writer, err)
			return
		}
		setWriteDeadline()
		writer.WriteHeader(http.StatusNoContent)
	})))))

	mux.Handle("/v1/scip/navigation", exactMethod(http.MethodPost, AuthenticateRequest(authenticator, jsonSCIPHandler(maxRequestBytes, func(writer http.ResponseWriter, request *http.Request, input api.SCIPNavigationRequest) {
		response, err := service.Navigate(request.Context(), PrincipalFromContext(request.Context()), input)
		if err != nil {
			writeSCIPError(writer, err)
			return
		}
		writeBoundedJSON(writer, response, maxResponseBytes)
	}))))
	mux.Handle("/v1/scip/dependencies", exactMethod(http.MethodPut, AuthenticateRequest(authenticator, administratorOnly(jsonSCIPHandler(maxRequestBytes, func(writer http.ResponseWriter, request *http.Request, input scipDependenciesRequest) {
		if input.RepositoryID < 1 {
			writeSCIPError(writer, scipgraph.ErrInvalidRequest)
			return
		}
		if err := service.SetDependencies(request.Context(), PrincipalFromContext(request.Context()), input.RepositoryID, input.RepositoryPackages); err != nil {
			writeSCIPError(writer, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})))))
	mux.Handle("/v1/scip/dependencies/github", exactMethod(http.MethodPost, AuthenticateRequest(authenticator, administratorOnly(jsonSCIPHandler(maxRequestBytes, func(writer http.ResponseWriter, request *http.Request, input scipRepositoryRequest) {
		if input.RepositoryID < 1 {
			writeSCIPError(writer, scipgraph.ErrInvalidRequest)
			return
		}
		response, err := service.RefreshGitHubDependencies(request.Context(), PrincipalFromContext(request.Context()), input.RepositoryID)
		if err != nil {
			writeSCIPError(writer, err)
			return
		}
		writeBoundedJSON(writer, response, maxResponseBytes)
	})))))
}

func administratorOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !PrincipalFromContext(request.Context()).Administrator {
			writeSCIPError(writer, scipgraph.ErrForbidden)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func jsonSCIPHandler[T any](maxBytes int64, handle func(http.ResponseWriter, *http.Request, T)) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Content-Type") != "application/json" {
			writeError(writer, http.StatusUnsupportedMediaType, "invalid_request", "request is invalid", false)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, maxBytes)
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		var input T
		if err := decoder.Decode(&input); err != nil {
			writeError(writer, invalidRequestStatus(err), "invalid_request", "request is invalid", false)
			return
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			writeError(writer, invalidRequestStatus(err), "invalid_request", "request is invalid", false)
			return
		}
		handle(writer, request, input)
	})
}

func writeSCIPError(writer http.ResponseWriter, err error) {
	status, code, message, retryable := classifySCIPError(err)
	writeError(writer, status, code, message, retryable)
}

func SCIPErrorMessage(err error) string {
	_, _, message, _ := classifySCIPError(err)
	return message
}

func classifySCIPError(err error) (int, string, string, bool) {
	switch {
	case errors.Is(err, scipgraph.ErrForbidden):
		return http.StatusForbidden, "forbidden", "administrator access required", false
	case errors.Is(err, scipgraph.ErrInvalidRequest), errors.Is(err, scipgraph.ErrInvalidIndex):
		return http.StatusBadRequest, "invalid_request", "request is invalid", false
	case errors.Is(err, scipgraph.ErrNotIndexed):
		return http.StatusConflict, "not_indexed", "repository is not indexed", false
	case errors.Is(err, scipgraph.ErrStaleCommit):
		return http.StatusConflict, "stale_commit", "requested commit is not the indexed revision", false
	case errors.Is(err, scipgraph.ErrSCIPUnavailable):
		return http.StatusConflict, "scip_unavailable", "repository is indexed for search but has no SCIP index; code navigation is unavailable", false
	case errors.Is(err, scipgraph.ErrSCIPStale):
		return http.StatusConflict, "scip_stale", "SCIP index was built for an earlier commit than the indexed revision", true
	case errors.Is(err, scipgraph.ErrSymbolNotFound):
		return http.StatusNotFound, "symbol_not_found", "no symbol at the requested position", false
	case errors.Is(err, scipgraph.ErrStaleIndex):
		return http.StatusConflict, "not_indexed", "repository is not indexed", true
	case errors.Is(err, pgx.ErrNoRows):
		return http.StatusNotFound, "not_found", "repository not found", false
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable, "unavailable", "SCIP service is unavailable", true
	default:
		return http.StatusServiceUnavailable, "unavailable", "SCIP service is unavailable", true
	}
}
