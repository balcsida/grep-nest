package scipgraph

import (
	"context"
	"errors"
	"path"
	"strings"

	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/githubapp"
	"github.com/grepnest/grepnest/internal/repository"
	"github.com/grepnest/grepnest/pkg/api"
	"github.com/scip-code/scip/bindings/go/scip"
)

const (
	defaultMaxResults = 100
	maxPostgresInt    = 1<<31 - 1
)

var (
	ErrForbidden      = errors.New("forbidden")
	ErrInvalidRequest = errors.New("invalid_request")
	ErrNotIndexed     = errors.New("not_indexed")
	// Navigate used to collapse all four conditions below into ErrNotIndexed, which
	// reported a healthy, search-indexed repository as unindexed. They are distinct
	// causes with distinct operator remedies, so they get distinct sentinels.
	ErrStaleCommit     = errors.New("stale_commit")
	ErrSCIPUnavailable = errors.New("scip_unavailable")
	ErrSCIPStale       = errors.New("scip_stale")
	ErrSymbolNotFound  = errors.New("symbol_not_found")
)

type ServiceStore interface {
	AuthorizedRepository(context.Context, int64, []int64, int64) (repository.Repository, error)
	AnyAuthorizedRepository(context.Context, int64) (repository.Repository, error)
	ReplaceSCIP(context.Context, int64, string, Upload) error
	OccurrenceAt(context.Context, int64, string, string, int, OccurrencePosition) (StoredOccurrence, error)
	// SCIPIndexCommit reports the commit of the most recent SCIP upload for a
	// repository, or "" when none exists. Consulted only on the error path.
	SCIPIndexCommit(context.Context, int64) (string, error)
	Locations(context.Context, authn.Principal, StoredOccurrence, string, int) ([]Location, bool, error)
	ReplacePackages(context.Context, int64, string, []PackageMapping) error
}

type DependencyReader interface {
	DependencySBOM(context.Context, int64, string, string) (githubapp.SBOM, bool, error)
}

type Service struct {
	Store      ServiceStore
	GitHub     DependencyReader
	MaxResults int
}

func (service *Service) RefreshGitHubDependencies(ctx context.Context, principal authn.Principal, repositoryID int64) (api.DependencyRefreshResponse, error) {
	if !principal.Administrator {
		return api.DependencyRefreshResponse{}, ErrForbidden
	}
	repository, err := service.authorizedRepository(ctx, principal, repositoryID)
	if err != nil {
		return api.DependencyRefreshResponse{}, err
	}
	owner, name, ok := strings.Cut(repository.Name, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return api.DependencyRefreshResponse{}, ErrInvalidRequest
	}
	sbom, available, err := service.GitHub.DependencySBOM(ctx, repository.InstallationID, owner, name)
	if err != nil || !available {
		return api.DependencyRefreshResponse{Available: available}, err
	}

	packages := make(map[string][]Package, len(sbom.Packages))
	for _, item := range sbom.Packages {
		for _, purl := range item.PURLs {
			pkg, err := ParsePackageURL(purl)
			if err == nil {
				packages[item.SPDXID] = append(packages[item.SPDXID], pkg)
			}
		}
	}
	seen := make(map[string]struct{})
	mappings := make([]PackageMapping, 0)
	add := func(ids []string, relation string) {
		for _, id := range ids {
			for _, pkg := range packages[id] {
				key := relation + "\x00" + pkg.PURL
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				mappings = append(mappings, PackageMapping{Package: pkg, Relation: relation, Source: "github"})
			}
		}
	}
	add(sbom.DocumentDescribes, "provides")
	for _, relationship := range sbom.Relationships {
		if relationship.Type == "DEPENDS_ON" {
			add([]string{relationship.RelatedSPDXElement}, "depends_on")
		}
	}
	if err := service.Store.ReplacePackages(ctx, repository.ID, "github", mappings); err != nil {
		return api.DependencyRefreshResponse{}, err
	}
	return api.DependencyRefreshResponse{Available: true, Packages: len(mappings)}, nil
}

func (service *Service) Upload(ctx context.Context, principal authn.Principal, repositoryID int64, commit string, data []byte) error {
	repository, err := service.validateUpload(ctx, principal, repositoryID, commit)
	if err != nil {
		return err
	}
	upload, err := Parse(data)
	if err != nil {
		return err
	}
	err = service.Store.ReplaceSCIP(ctx, repository.ID, commit, upload)
	if errors.Is(err, ErrStaleIndex) {
		return ErrNotIndexed
	}
	return err
}

func (service *Service) ValidateUpload(ctx context.Context, principal authn.Principal, repositoryID int64, commit string) error {
	_, err := service.validateUpload(ctx, principal, repositoryID, commit)
	return err
}

func (service *Service) validateUpload(ctx context.Context, principal authn.Principal, repositoryID int64, commit string) (repository.Repository, error) {
	if !principal.Administrator {
		return repository.Repository{}, ErrForbidden
	}
	repository, err := service.authorizedRepository(ctx, principal, repositoryID)
	if err != nil {
		return repository, err
	}
	if repository.IndexedSHA == "" || commit != repository.IndexedSHA {
		return repository, ErrNotIndexed
	}
	return repository, nil
}

func (service *Service) Navigate(ctx context.Context, principal authn.Principal, request api.SCIPNavigationRequest) (api.SCIPNavigationResponse, error) {
	if !validNavigationRequest(request) {
		return api.SCIPNavigationResponse{}, ErrInvalidRequest
	}
	repository, err := service.authorizedRepository(ctx, principal, request.RepositoryID)
	if err != nil {
		return api.SCIPNavigationResponse{}, err
	}
	if repository.IndexedSHA == "" {
		return api.SCIPNavigationResponse{}, ErrNotIndexed
	}
	if request.Commit != "" && request.Commit != repository.IndexedSHA {
		return api.SCIPNavigationResponse{}, ErrStaleCommit
	}
	origin, err := service.Store.OccurrenceAt(ctx, repository.ID, repository.IndexedSHA, request.Path, request.Line-1, navigationPosition(request))
	if errors.Is(err, ErrOccurrenceNotFound) {
		return api.SCIPNavigationResponse{}, service.classifyMissingOccurrence(ctx, repository)
	}
	if err != nil {
		return api.SCIPNavigationResponse{}, err
	}
	locations, truncated, err := service.Store.Locations(ctx, principal, origin, request.Operation, service.maxResults())
	if err != nil {
		return api.SCIPNavigationResponse{}, err
	}
	response := api.SCIPNavigationResponse{Locations: make([]api.SCIPLocation, 0, len(locations)), Truncated: truncated}
	for _, location := range locations {
		target, err := service.authorizedRepository(ctx, principal, location.RepositoryID)
		if err != nil || target.IndexedSHA == "" || target.IndexedSHA != location.Commit {
			continue
		}
		response.Locations = append(response.Locations, api.SCIPLocation{
			RepositoryID: location.RepositoryID, RepositoryName: location.RepositoryName, Branch: target.Branch, WebURL: location.WebURL,
			Commit: location.Commit, Path: location.Path, Symbol: location.Symbol,
			StartLine: int(location.StartLine) + 1, StartCharacter: int(location.StartCharacter),
			EndLine: int(location.EndLine) + 1, EndCharacter: int(location.EndCharacter),
			PositionEncoding: scip.PositionEncoding(location.PositionEncoding).String(),
			Roles:            location.Roles, Approximate: location.Approximate,
		})
	}
	return response, nil
}

// classifyMissingOccurrence explains why no occurrence was found. OccurrenceAt joins
// uploads against the repository's current indexed_sha, so a SCIP index built for an
// older commit is invisible to it and is indistinguishable from an absent one without
// this extra lookup.
func (service *Service) classifyMissingOccurrence(ctx context.Context, repo repository.Repository) error {
	commit, err := service.Store.SCIPIndexCommit(ctx, repo.ID)
	switch {
	case err != nil:
		return err
	case commit == "":
		return ErrSCIPUnavailable
	case commit != repo.IndexedSHA:
		return ErrSCIPStale
	default:
		return ErrSymbolNotFound
	}
}

func (service *Service) SetDependencies(ctx context.Context, principal authn.Principal, repositoryID int64, purls api.RepositoryPackages) error {
	if !principal.Administrator {
		return ErrForbidden
	}
	repository, err := service.authorizedRepository(ctx, principal, repositoryID)
	if err != nil {
		return err
	}
	mappings := make([]PackageMapping, 0, len(purls.Provides)+len(purls.DependsOn))
	seen := make(map[string]struct{}, cap(mappings))
	for _, group := range []struct {
		values   []string
		relation string
	}{{purls.Provides, "provides"}, {purls.DependsOn, "depends_on"}} {
		for _, purl := range group.values {
			pkg, err := ParsePackageURL(purl)
			if err != nil {
				return ErrInvalidRequest
			}
			key := group.relation + "\x00" + pkg.PURL
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			mappings = append(mappings, PackageMapping{Package: pkg, Relation: group.relation, Source: "manual"})
		}
	}
	return service.Store.ReplacePackages(ctx, repository.ID, "manual", mappings)
}

func (service *Service) authorizedRepository(ctx context.Context, principal authn.Principal, repositoryID int64) (repository.Repository, error) {
	if principal.Administrator && (principal.Method == "oidc" || principal.Method == "local") &&
		principal.InstallationID == 0 && len(principal.RepositoryIDs) == 0 {
		return service.Store.AnyAuthorizedRepository(ctx, repositoryID)
	}
	return service.Store.AuthorizedRepository(ctx, principal.InstallationID, principal.RepositoryIDs, repositoryID)
}

func (service *Service) maxResults() int {
	if service.MaxResults <= 0 {
		return defaultMaxResults
	}
	return service.MaxResults
}

func validNavigationRequest(request api.SCIPNavigationRequest) bool {
	if request.RepositoryID <= 0 || request.Line < 1 || request.Line > maxPostgresInt ||
		request.Character < 0 || request.Character > maxPostgresInt ||
		request.Commit != "" && !validCommit(request.Commit) || !validNavigationPosition(request) {
		return false
	}
	if request.Operation != "definitions" && request.Operation != "references" && request.Operation != "implementations" {
		return false
	}
	clean := path.Clean(request.Path)
	return request.Path != "" && clean == request.Path && clean != "." && clean != ".." &&
		!path.IsAbs(request.Path) && !strings.HasPrefix(clean, "../") && !strings.ContainsAny(request.Path, "\\\x00")
}

func validNavigationPosition(request api.SCIPNavigationRequest) bool {
	if request.CharacterUTF8 == nil && request.CharacterUTF16 == nil && request.CharacterUTF32 == nil {
		return true
	}
	return request.CharacterUTF8 != nil && request.CharacterUTF16 != nil && request.CharacterUTF32 != nil &&
		*request.CharacterUTF8 >= 0 && *request.CharacterUTF8 <= maxPostgresInt &&
		*request.CharacterUTF16 >= 0 && *request.CharacterUTF16 <= maxPostgresInt &&
		*request.CharacterUTF32 >= 0 && *request.CharacterUTF32 <= maxPostgresInt
}

func validCommit(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func navigationPosition(request api.SCIPNavigationRequest) OccurrencePosition {
	if request.CharacterUTF8 == nil {
		return OccurrencePosition{UTF8: request.Character, UTF16: request.Character, UTF32: request.Character}
	}
	return OccurrencePosition{UTF8: *request.CharacterUTF8, UTF16: *request.CharacterUTF16, UTF32: *request.CharacterUTF32}
}
