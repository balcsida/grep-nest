package graphprotocol

import (
	"context"
	"errors"
)

// Transport failure causes shared by the graph client and its callers. Callers used to
// see every one of these as a single opaque "graph service is unavailable", which hides
// the difference between a misconfigured secret and an unreachable runtime.
var (
	ErrUnauthorized  = errors.New("graph_unauthorized")
	ErrUnreachable   = errors.New("graph_unreachable")
	ErrInvalidReply  = errors.New("graph_invalid_response")
	ErrReplyTooLarge = errors.New("graph_response_too_large")
)

const (
	StatusFound     = "found"
	StatusAmbiguous = "ambiguous"
	StatusNotFound  = "not_found"
	StatusOK        = "ok"
	StatusNoPath    = "no_path"
)

type RepositorySnapshot struct {
	ID       int64  `json:"id"`
	GitHubID int64  `json:"github_id"`
	Name     string `json:"name"`
	Branch   string `json:"branch"`
	Commit   string `json:"commit"`
}

type Scope struct {
	SelectedRepositoryID int64                `json:"selected_repository_id,omitempty"`
	Repositories         []RepositorySnapshot `json:"repositories"`
}

type Position struct {
	StartLine      int32 `json:"start_line"`
	StartCharacter int32 `json:"start_character"`
	EndLine        int32 `json:"end_line"`
	EndCharacter   int32 `json:"end_character"`
}

type Symbol struct {
	UID          string   `json:"uid"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	FilePath     string   `json:"file_path"`
	Language     string   `json:"language"`
	Signature    string   `json:"signature,omitempty"`
	RepositoryID int64    `json:"repository_id"`
	Range        Position `json:"range"`
	Test         bool     `json:"test"`
}

type Relationship struct {
	SourceRepositoryID int64    `json:"source_repository_id"`
	TargetRepositoryID int64    `json:"target_repository_id"`
	SourceUID          string   `json:"source_uid"`
	TargetUID          string   `json:"target_uid"`
	Kind               string   `json:"kind"`
	Path               string   `json:"path,omitempty"`
	Range              Position `json:"range"`
	Confidence         float64  `json:"confidence"`
	ResolutionReason   string   `json:"resolution_reason,omitempty"`
}

type Boundary struct {
	RepositoryID int64  `json:"repository_id,omitempty"`
	Repository   string `json:"repository,omitempty"`
	Reason       string `json:"reason"`
	Depth        int    `json:"depth,omitempty"`
}

type ContextRequest struct {
	Scope             Scope    `json:"scope"`
	UID               string   `json:"uid,omitempty"`
	Name              string   `json:"name,omitempty"`
	FilePath          string   `json:"file_path,omitempty"`
	Kind              string   `json:"kind,omitempty"`
	Relations         []string `json:"relations,omitempty"`
	PerCategoryLimit  int      `json:"per_category_limit,omitempty"`
	PerCategoryOffset int      `json:"per_category_offset,omitempty"`
}

type ContextResponse struct {
	Status        string                    `json:"status"`
	Symbol        *Symbol                   `json:"symbol,omitempty"`
	Candidates    []Symbol                  `json:"candidates,omitempty"`
	Incoming      map[string][]Symbol       `json:"incoming,omitempty"`
	Outgoing      map[string][]Symbol       `json:"outgoing,omitempty"`
	IncomingEdges map[string][]Relationship `json:"incoming_edges,omitempty"`
	OutgoingEdges map[string][]Relationship `json:"outgoing_edges,omitempty"`
	Boundaries    []Boundary                `json:"boundaries,omitempty"`
	Commits       map[string]string         `json:"commits"`
}

type ImpactRequest struct {
	Scope         Scope    `json:"scope"`
	TargetUID     string   `json:"target_uid"`
	Direction     string   `json:"direction"`
	Relations     []string `json:"relations,omitempty"`
	MinConfidence float64  `json:"min_confidence,omitempty"`
	IncludeTests  bool     `json:"include_tests,omitempty"`
	MaxDepth      int      `json:"max_depth,omitempty"`
	Limit         int      `json:"limit,omitempty"`
	Offset        int      `json:"offset,omitempty"`
	SummaryOnly   bool     `json:"summary_only,omitempty"`
}

type ImpactResponse struct {
	Status     string            `json:"status"`
	Candidates []Symbol          `json:"candidates,omitempty"`
	ByDepth    map[int][]Symbol  `json:"by_depth"`
	Edges      []Relationship    `json:"edges,omitempty"`
	Boundaries []Boundary        `json:"boundaries,omitempty"`
	Commits    map[string]string `json:"commits"`
	Partial    bool              `json:"partial"`
}

type TraceRequest struct {
	Scope     Scope  `json:"scope"`
	SourceUID string `json:"source_uid"`
	TargetUID string `json:"target_uid"`
	MaxDepth  int    `json:"max_depth,omitempty"`
}

type TraceResponse struct {
	Status     string            `json:"status"`
	Candidates []Symbol          `json:"candidates,omitempty"`
	Nodes      []Symbol          `json:"nodes,omitempty"`
	Edges      []Relationship    `json:"edges,omitempty"`
	Boundaries []Boundary        `json:"boundaries,omitempty"`
	Commits    map[string]string `json:"commits"`
}

type CypherRequest struct {
	Scope      Scope          `json:"scope"`
	Admin      bool           `json:"admin"`
	Statement  string         `json:"statement"`
	Parameters map[string]any `json:"parameters,omitempty"`
	MaxRows    int            `json:"max_rows,omitempty"`
	MaxBytes   int            `json:"max_bytes,omitempty"`
}

type CypherResponse struct {
	Columns    []string          `json:"columns"`
	Rows       [][]any           `json:"rows"`
	Truncated  bool              `json:"truncated"`
	Boundaries []Boundary        `json:"boundaries,omitempty"`
	Commits    map[string]string `json:"commits,omitempty"`
}

type QueryEngine interface {
	Context(context.Context, ContextRequest) (ContextResponse, error)
	Impact(context.Context, ImpactRequest) (ImpactResponse, error)
	Trace(context.Context, TraceRequest) (TraceResponse, error)
	Cypher(context.Context, CypherRequest) (CypherResponse, error)
}
