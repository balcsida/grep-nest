package mcpserver

import (
	"context"
	"errors"

	"github.com/grepnest/grepnest/internal/graphprotocol"
	"github.com/grepnest/grepnest/internal/graphservice"
	"github.com/grepnest/grepnest/internal/httpapi"
	"github.com/grepnest/grepnest/pkg/api"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerGraphTools(server *mcp.Server, service *graphservice.Service, maxOutputBytes int64) {
	if service == nil {
		return
	}
	mcp.AddTool(server, &mcp.Tool{Name: "context", Description: "Inspect a symbol's incoming and outgoing code relationships.", InputSchema: graphContextSchema()}, func(ctx context.Context, _ *mcp.CallToolRequest, input api.GraphContextRequest) (*mcp.CallToolResult, any, error) {
		response, err := service.Context(ctx, httpapi.PrincipalFromContext(ctx), input)
		return graphResult(response, err, maxOutputBytes)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "impact", Description: "Analyze the upstream or downstream impact of a code symbol.", InputSchema: graphImpactSchema()}, func(ctx context.Context, _ *mcp.CallToolRequest, input api.GraphImpactRequest) (*mcp.CallToolResult, any, error) {
		response, err := service.Impact(ctx, httpapi.PrincipalFromContext(ctx), input)
		return graphResult(response, err, maxOutputBytes)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "trace", Description: "Trace code relationships between two symbols.", InputSchema: graphTraceSchema()}, func(ctx context.Context, _ *mcp.CallToolRequest, input api.GraphTraceRequest) (*mcp.CallToolResult, any, error) {
		response, err := service.Trace(ctx, httpapi.PrincipalFromContext(ctx), input)
		return graphResult(response, err, maxOutputBytes)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "cypher", Description: "Run an administrator-only read query against the code graph.", InputSchema: graphCypherSchema()}, func(ctx context.Context, _ *mcp.CallToolRequest, input api.GraphCypherRequest) (*mcp.CallToolResult, any, error) {
		response, err := service.Cypher(ctx, httpapi.PrincipalFromContext(ctx), input)
		return graphResult(response, err, maxOutputBytes)
	})
}

func graphResult[T any](response T, err error, maxBytes int64) (*mcp.CallToolResult, any, error) {
	if err != nil {
		return nil, *new(T), graphError(err)
	}
	if !fitsOutput(response, maxBytes) {
		return nil, *new(T), errOutputBudget
	}
	return structuredResult(), response, nil
}

func graphError(err error) error {
	switch {
	case errors.Is(err, graphservice.ErrAdminRequired):
		return errors.New("administrator access required")
	case errors.Is(err, graphservice.ErrInvalidRequest), errors.Is(err, graphservice.ErrInvalidRepositorySelector):
		return errors.New("graph request is invalid")
	case errors.Is(err, graphservice.ErrRepositoryNotFound):
		return errors.New("repository not found")
	case errors.Is(err, graphservice.ErrRepositoryRequired):
		return errors.New("repository selection is ambiguous")
	case errors.Is(err, graphservice.ErrBranchNotIndexed):
		return errors.New("branch is not indexed")
	case errors.Is(err, graphservice.ErrGraphNotReady):
		return errors.New("graph is not ready")
	case errors.Is(err, graphprotocol.ErrUnauthorized):
		return errors.New("graph runtime rejected the request; check the shared internal secret")
	case errors.Is(err, graphprotocol.ErrUnreachable):
		return errors.New("graph runtime is unreachable; check that it is running and that the graph URL is correct")
	case errors.Is(err, graphprotocol.ErrInvalidReply):
		return errors.New("graph runtime returned a malformed response")
	case errors.Is(err, graphprotocol.ErrReplyTooLarge):
		return errors.New("graph runtime response exceeded the configured limit")
	default:
		return errors.New("graph service is unavailable")
	}
}

func graphBaseProperties() map[string]any {
	return map[string]any{
		"repo":   map[string]any{"oneOf": []any{positiveIntegerSchema("GitHub repository ID"), map[string]any{"type": "string", "minLength": 1, "description": "repository name"}}},
		"branch": map[string]any{"type": "string", "minLength": 1, "description": "indexed branch"},
	}
}

func graphContextSchema() map[string]any {
	properties := graphBaseProperties()
	properties["uid"] = map[string]any{"type": "string", "minLength": 1, "description": "symbol UID"}
	properties["name"] = map[string]any{"type": "string", "minLength": 1, "description": "symbol name"}
	properties["file_path"] = map[string]any{"type": "string", "minLength": 1, "description": "repository-relative source path"}
	properties["kind"] = map[string]any{"type": "string", "minLength": 1, "description": "symbol kind"}
	properties["relations"] = relationSchema()
	properties["per_category_limit"] = cappedIntegerSchema("maximum relationships per category; default: 100; values above 100 are capped", 100)
	properties["per_category_offset"] = map[string]any{"type": "integer", "minimum": 0, "description": "relationships to skip per category"}
	properties["include_content"] = map[string]any{"type": "boolean", "description": "include source content for the symbol"}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "oneOf": []any{map[string]any{"required": []string{"uid"}}, map[string]any{"required": []string{"name"}}}}
}

func graphImpactSchema() map[string]any {
	properties := graphBaseProperties()
	properties["target_uid"] = map[string]any{"type": "string", "minLength": 1, "description": "target symbol UID"}
	properties["direction"] = map[string]any{"type": "string", "enum": []string{"upstream", "downstream"}, "description": "relationship direction"}
	properties["relations"] = relationSchema()
	properties["min_confidence"] = map[string]any{"type": "number", "minimum": 0, "maximum": 1, "description": "minimum relationship confidence"}
	properties["include_tests"] = map[string]any{"type": "boolean", "description": "include test symbols"}
	properties["max_depth"] = cappedIntegerSchema("maximum traversal depth; default: 3; values above 32 are capped", 3)
	properties["limit"] = cappedIntegerSchema("maximum results; default: 100; values above 100 are capped", 100)
	properties["offset"] = map[string]any{"type": "integer", "minimum": 0, "description": "results to skip"}
	properties["summary_only"] = map[string]any{"type": "boolean", "description": "omit relationship details"}
	return map[string]any{"type": "object", "additionalProperties": false, "required": []string{"target_uid", "direction"}, "properties": properties}
}

func graphTraceSchema() map[string]any {
	properties := graphBaseProperties()
	properties["source_uid"] = map[string]any{"type": "string", "minLength": 1, "description": "source symbol UID"}
	properties["target_uid"] = map[string]any{"type": "string", "minLength": 1, "description": "target symbol UID"}
	properties["max_depth"] = cappedIntegerSchema("maximum traversal depth; default: 10; values above 30 are capped", 10)
	return map[string]any{"type": "object", "additionalProperties": false, "required": []string{"source_uid", "target_uid"}, "properties": properties}
}

func graphCypherSchema() map[string]any {
	properties := graphBaseProperties()
	properties["statement"] = map[string]any{"type": "string", "minLength": 1, "description": "read-only Cypher statement"}
	properties["parameters"] = map[string]any{"type": "object", "additionalProperties": true, "description": "JSON query parameters"}
	properties["max_rows"] = cappedIntegerSchema("maximum rows; default: 100; values above 100 are capped", 100)
	properties["max_bytes"] = cappedIntegerSchema("maximum response bytes; default: 262144; values above 262144 are capped", 256<<10)
	return map[string]any{"type": "object", "additionalProperties": false, "required": []string{"statement"}, "properties": properties}
}

func relationSchema() map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"calls", "references", "extends", "implements"}}, "uniqueItems": true, "description": "relationship kinds"}
}

func cappedIntegerSchema(description string, defaultValue int) map[string]any {
	return map[string]any{"type": "integer", "minimum": 0, "default": defaultValue, "description": description}
}
