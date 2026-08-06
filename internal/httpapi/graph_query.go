package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/graphprotocol"
	"github.com/grepnest/grepnest/internal/graphservice"
	"github.com/grepnest/grepnest/pkg/api"
)

func RegisterGraphQueries(mux *http.ServeMux, authenticator authn.Authenticator, service *graphservice.Service, maxRequestBytes, maxResponseBytes int64) {
	mux.Handle("/v1/graph/context", exactMethod(http.MethodPost, AuthenticateBearer(authenticator, jsonSCIPHandler(maxRequestBytes, func(writer http.ResponseWriter, request *http.Request, input api.GraphContextRequest) {
		response, err := service.Context(request.Context(), PrincipalFromContext(request.Context()), input)
		if err != nil {
			writeGraphQueryError(writer, err)
			return
		}
		writeBoundedJSON(writer, response, maxResponseBytes)
	}))))
	mux.Handle("/v1/graph/impact", exactMethod(http.MethodPost, AuthenticateBearer(authenticator, jsonSCIPHandler(maxRequestBytes, func(writer http.ResponseWriter, request *http.Request, input api.GraphImpactRequest) {
		response, err := service.Impact(request.Context(), PrincipalFromContext(request.Context()), input)
		if err != nil {
			writeGraphQueryError(writer, err)
			return
		}
		writeBoundedJSON(writer, response, maxResponseBytes)
	}))))
	mux.Handle("/v1/graph/trace", exactMethod(http.MethodPost, AuthenticateBearer(authenticator, jsonSCIPHandler(maxRequestBytes, func(writer http.ResponseWriter, request *http.Request, input api.GraphTraceRequest) {
		response, err := service.Trace(request.Context(), PrincipalFromContext(request.Context()), input)
		if err != nil {
			writeGraphQueryError(writer, err)
			return
		}
		writeBoundedJSON(writer, response, maxResponseBytes)
	}))))
	mux.Handle("/v1/graph/cypher", exactMethod(http.MethodPost, AuthenticateBearer(authenticator, administratorOnly(jsonSCIPHandler(maxRequestBytes, func(writer http.ResponseWriter, request *http.Request, input api.GraphCypherRequest) {
		response, err := service.Cypher(request.Context(), PrincipalFromContext(request.Context()), input)
		if err != nil {
			writeGraphQueryError(writer, err)
			return
		}
		writeBoundedJSON(writer, response, maxResponseBytes)
	})))))
}

func writeGraphQueryError(writer http.ResponseWriter, err error) {
	status, code, message, retryable := classifyGraphQueryError(err)
	writeError(writer, status, code, message, retryable)
}

func classifyGraphQueryError(err error) (int, string, string, bool) {
	switch {
	case errors.Is(err, graphservice.ErrAdminRequired):
		return http.StatusForbidden, "forbidden", "administrator access required", false
	case errors.Is(err, graphservice.ErrInvalidRequest), errors.Is(err, graphservice.ErrInvalidRepositorySelector):
		return http.StatusBadRequest, "invalid_request", "request is invalid", false
	case errors.Is(err, graphservice.ErrRepositoryNotFound):
		return http.StatusNotFound, "not_found", "repository not found", false
	case errors.Is(err, graphservice.ErrRepositoryRequired):
		return http.StatusConflict, "ambiguous", "repository selection is ambiguous", false
	case errors.Is(err, graphservice.ErrBranchNotIndexed):
		return http.StatusConflict, "branch_not_indexed", "branch is not indexed", false
	case errors.Is(err, graphservice.ErrGraphNotReady):
		return http.StatusConflict, "graph_not_ready", "graph is not ready", true
	case errors.Is(err, graphprotocol.ErrUnauthorized):
		return http.StatusBadGateway, "graph_unauthorized", "graph runtime rejected the request; check the shared internal secret", false
	case errors.Is(err, graphprotocol.ErrUnreachable):
		return http.StatusServiceUnavailable, "graph_unreachable", "graph runtime is unreachable; check that it is running and that the graph URL is correct", true
	case errors.Is(err, graphprotocol.ErrInvalidReply):
		return http.StatusBadGateway, "graph_invalid_response", "graph runtime returned a malformed response", false
	case errors.Is(err, graphprotocol.ErrReplyTooLarge):
		return http.StatusBadGateway, "graph_response_too_large", "graph runtime response exceeded the configured limit", false
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "timeout", "graph query timed out", true
	default:
		return http.StatusServiceUnavailable, "unavailable", "graph service is unavailable", true
	}
}
