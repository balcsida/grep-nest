package postgres

import (
	"context"
	"errors"

	"github.com/grepnest/grepnest/internal/admin"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/scipgraph"
	"github.com/jackc/pgx/v5"
	"github.com/scip-code/scip/bindings/go/scip"
)

func (s *Store) AdminSCIPUploads(ctx context.Context, installationID int64, repositoryIDs []int64, limit int) ([]admin.SCIPUpload, bool, error) {
	rows, err := s.pool.Query(ctx, `select uploads.id,repositories.github_id,repositories.owner||'/'||repositories.name,
		uploads.commit,uploads.project_root,uploads.indexer_name,uploads.indexer_version,uploads.uploaded_at
		from scip_uploads uploads join repositories on repositories.id=uploads.repository_id
		join installations on installations.id=repositories.installation_id
		where ($1=0 and coalesce(cardinality($2::bigint[]),0)=0 and installations.status='active' and repositories.enabled and not repositories.archived
			or ($1=0 or installations.github_id=$1) and repositories.github_id=any($2))
		order by uploads.uploaded_at desc,uploads.id desc limit $3`, installationID, repositoryIDs, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items := make([]admin.SCIPUpload, 0, limit+1)
	for rows.Next() {
		var x admin.SCIPUpload
		if err := rows.Scan(&x.ID, &x.RepositoryID, &x.Repository, &x.Commit, &x.ProjectRoot, &x.IndexerName, &x.IndexerVersion, &x.UploadedAt); err != nil {
			return nil, false, err
		}
		items = append(items, x)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	return items, more, nil
}

func (s *Store) AdminSCIPDependencies(ctx context.Context, installationID int64, repositoryIDs []int64, limit int) ([]admin.SCIPDependency, bool, error) {
	rows, err := s.pool.Query(ctx, `select repositories.github_id,repositories.owner||'/'||repositories.name,
		packages.source,packages.relation,packages.purl,packages.manager,packages.name,packages.version
		from repository_packages packages join repositories on repositories.id=packages.repository_id
		join installations on installations.id=repositories.installation_id
		where ($1=0 and coalesce(cardinality($2::bigint[]),0)=0 and installations.status='active' and repositories.enabled and not repositories.archived
			or ($1=0 or installations.github_id=$1) and repositories.github_id=any($2))
		order by repositories.github_id,packages.source,packages.relation,packages.purl limit $3`, installationID, repositoryIDs, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items := make([]admin.SCIPDependency, 0, limit+1)
	for rows.Next() {
		var x admin.SCIPDependency
		if err := rows.Scan(&x.RepositoryID, &x.Repository, &x.Source, &x.Relation, &x.PURL, &x.Manager, &x.Name, &x.Version); err != nil {
			return nil, false, err
		}
		items = append(items, x)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	return items, more, nil
}

func (s *Store) ReplaceSCIP(ctx context.Context, repositoryID int64, commit string, upload scipgraph.Upload) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := tx.QueryRow(ctx, `select id from repositories where id=$1 and indexed_sha=$2 for update`, repositoryID, commit).Scan(&repositoryID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return scipgraph.ErrStaleIndex
		}
		return err
	}
	if _, err := tx.Exec(ctx, `delete from scip_uploads where repository_id=$1`, repositoryID); err != nil {
		return err
	}
	var uploadID int64
	if err := tx.QueryRow(ctx, `insert into scip_uploads
		(repository_id, commit, project_root, indexer_name, indexer_version)
		values ($1, $2, $3, $4, $5) returning id`, repositoryID, commit, upload.ProjectRoot, upload.IndexerName, upload.IndexerVersion).Scan(&uploadID); err != nil {
		return err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"scip_occurrences"},
		[]string{"upload_id", "path", "start_line", "start_character", "end_line", "end_character", "position_encoding", "symbol", "global_symbol_key", "roles", "local"},
		pgx.CopyFromSlice(len(upload.Occurrences), func(index int) ([]any, error) {
			occurrence := upload.Occurrences[index]
			key, err := scipgraph.VersionlessSymbolKey(occurrence.Symbol)
			return []any{uploadID, occurrence.Path, occurrence.StartLine, occurrence.StartCharacter, occurrence.EndLine, occurrence.EndCharacter,
				occurrence.PositionEncoding, occurrence.Symbol, key, occurrence.Roles, occurrence.Local}, err
		})); err != nil {
		return err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"scip_relationships"},
		[]string{"upload_id", "document_path", "source_symbol", "source_global_symbol_key", "target_symbol", "target_global_symbol_key",
			"is_definition", "is_reference", "is_implementation", "is_type_definition"},
		pgx.CopyFromSlice(len(upload.Relationships), func(index int) ([]any, error) {
			relationship := upload.Relationships[index]
			sourceKey, err := scipgraph.VersionlessSymbolKey(relationship.Source)
			if err != nil {
				return nil, err
			}
			targetKey, err := scipgraph.VersionlessSymbolKey(relationship.Target)
			return []any{uploadID, relationship.Path, relationship.Source, sourceKey, relationship.Target, targetKey,
				relationship.Definition, relationship.Reference, relationship.Implementation, relationship.TypeDefinition}, err
		})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ReplacePackages(ctx context.Context, repositoryID int64, source string, mappings []scipgraph.PackageMapping) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := tx.QueryRow(ctx, `select id from repositories where id=$1 for update`, repositoryID).Scan(&repositoryID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `delete from repository_packages where repository_id=$1 and source=$2`, repositoryID, source); err != nil {
		return err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"repository_packages"},
		[]string{"repository_id", "source", "relation", "purl", "manager", "name", "version"},
		pgx.CopyFromSlice(len(mappings), func(index int) ([]any, error) {
			mapping := mappings[index]
			return []any{repositoryID, source, mapping.Relation, mapping.Package.PURL, mapping.Package.Manager, mapping.Package.Name, mapping.Package.Version}, nil
		})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) OccurrenceAt(ctx context.Context, repositoryID int64, commit, path string, line int, position scipgraph.OccurrencePosition) (scipgraph.StoredOccurrence, error) {
	var occurrence scipgraph.StoredOccurrence
	err := s.pool.QueryRow(ctx, `select uploads.id, uploads.repository_id, uploads.commit,
		occurrences.path, occurrences.start_line, occurrences.start_character,
		occurrences.end_line, occurrences.end_character, occurrences.position_encoding, occurrences.symbol,
		occurrences.roles, occurrences.local
		from scip_uploads uploads
		join repositories on repositories.id=uploads.repository_id and repositories.indexed_sha=uploads.commit
		join scip_occurrences occurrences on occurrences.upload_id=uploads.id
		where uploads.repository_id=$1 and uploads.commit=$2 and occurrences.path=$3
		and (occurrences.start_line<$4 or occurrences.start_line=$4 and occurrences.start_character<=case occurrences.position_encoding when 1 then $5::integer when 2 then $6::integer when 3 then $7::integer end)
		and (occurrences.end_line>$4 or occurrences.end_line=$4 and occurrences.end_character>case occurrences.position_encoding when 1 then $5::integer when 2 then $6::integer when 3 then $7::integer end)
		order by occurrences.start_line desc, occurrences.start_character desc,
			occurrences.end_line, occurrences.end_character
		limit 1`, repositoryID, commit, path, line, position.UTF8, position.UTF16, position.UTF32).Scan(
		&occurrence.UploadID, &occurrence.RepositoryID, &occurrence.Commit,
		&occurrence.Path, &occurrence.StartLine, &occurrence.StartCharacter,
		&occurrence.EndLine, &occurrence.EndCharacter, &occurrence.PositionEncoding, &occurrence.Symbol,
		&occurrence.Roles, &occurrence.Local)
	if errors.Is(err, pgx.ErrNoRows) {
		return scipgraph.StoredOccurrence{}, scipgraph.ErrOccurrenceNotFound
	}
	return occurrence, err
}

func (s *Store) SCIPIndexCommit(ctx context.Context, repositoryID int64) (string, error) {
	var commit string
	err := s.pool.QueryRow(ctx, `select commit from scip_uploads where repository_id=$1
		order by uploaded_at desc, id desc limit 1`, repositoryID).Scan(&commit)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return commit, err
}

func (s *Store) Locations(ctx context.Context, principal authn.Principal, origin scipgraph.StoredOccurrence, operation string, max int) ([]scipgraph.Location, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)
	var current bool
	if err := tx.QueryRow(ctx, `select exists (
		select 1 from scip_uploads uploads
		join repositories on repositories.id=uploads.repository_id and repositories.indexed_sha=uploads.commit
		where uploads.id=$1 and uploads.repository_id=$2 and uploads.commit=$3
	)`, origin.UploadID, origin.RepositoryID, origin.Commit).Scan(&current); err != nil {
		return nil, false, err
	}
	if !current {
		return nil, false, scipgraph.ErrStaleIndex
	}
	locations, truncated, err := s.exactLocations(ctx, tx, principal, origin, operation, max)
	if err != nil || len(locations) != 0 {
		return locations, truncated, err
	}
	return s.approximateLocations(ctx, tx, principal, origin, operation, max)
}

const exactLocationsSQL = `with authorized_uploads as (
		select uploads.id, uploads.repository_id, repositories.github_id, repositories.owner || '/' || repositories.name repository_name, repositories.web_url, uploads.commit
		from scip_uploads uploads
		join repositories on repositories.id=uploads.repository_id and repositories.indexed_sha=uploads.commit
		join installations on installations.id=repositories.installation_id
		where ($1=0 or installations.github_id=$1) and repositories.github_id=any($2)
		and installations.status='active' and repositories.enabled and not repositories.archived
	), origin_authorized as (
		select id from authorized_uploads where id=$4 and repository_id=$8
	), targets as (
		select $4::bigint upload_id, $9::text document_path, $3::text symbol, $5::boolean local,
			case $6 when 'definitions' then 1 else 0 end role_filter
		from origin_authorized where $6 in ('definitions', 'references')
		union
		select relationships.upload_id, relationships.document_path, relationships.target_symbol,
			left(relationships.target_symbol, 6)='local ',
			case when $6='definitions' then 1 when $6='references' then 0 else -1 end
		from scip_relationships relationships
		join authorized_uploads on authorized_uploads.id=relationships.upload_id
		cross join origin_authorized
		where (($6='definitions' and relationships.is_definition)
			or ($6='references' and relationships.is_reference))
		and relationships.source_symbol=$3
		and (not $5 or (relationships.upload_id=$4 and relationships.document_path=$9))
		union
		select relationships.upload_id, relationships.document_path, relationships.source_symbol,
			left(relationships.source_symbol, 6)='local ',
			case when $6='implementations' then 1 when $6='references' then 0 else -1 end
		from scip_relationships relationships
		join authorized_uploads on authorized_uploads.id=relationships.upload_id
		cross join origin_authorized
		where (($6='references' and relationships.is_reference)
			or ($6='implementations' and relationships.is_implementation))
		and relationships.target_symbol=$3
		and (not $5 or (relationships.upload_id=$4 and relationships.document_path=$9))
	), matches as (
		select distinct occurrences.*
		from targets
		join scip_occurrences occurrences on occurrences.symbol=targets.symbol
			and occurrences.local=targets.local
			and (not targets.local or (occurrences.upload_id=targets.upload_id and occurrences.path=targets.document_path))
		where targets.role_filter=-1
			or targets.role_filter=1 and occurrences.roles & 1 <> 0
			or targets.role_filter=0 and occurrences.roles & 1 = 0
	)
	select authorized_uploads.github_id, authorized_uploads.repository_name, authorized_uploads.web_url, authorized_uploads.commit,
		matches.path, matches.start_line, matches.start_character,
		matches.end_line, matches.end_character, matches.position_encoding, matches.symbol, matches.roles
	from matches
	join authorized_uploads on authorized_uploads.id=matches.upload_id
	order by authorized_uploads.github_id, matches.path, matches.start_line, matches.start_character,
		matches.end_line, matches.end_character, matches.symbol, matches.id
	limit $7`

func (s *Store) exactLocations(ctx context.Context, tx pgx.Tx, principal authn.Principal, origin scipgraph.StoredOccurrence, operation string, max int) ([]scipgraph.Location, bool, error) {
	if len(principal.RepositoryIDs) == 0 {
		return []scipgraph.Location{}, false, nil
	}
	rows, err := tx.Query(ctx, exactLocationsSQL,
		principal.InstallationID, principal.RepositoryIDs, origin.Symbol, origin.UploadID,
		origin.Local, operation, max+1, origin.RepositoryID, origin.Path)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	locations := make([]scipgraph.Location, 0, max+1)
	for rows.Next() {
		var location scipgraph.Location
		if err := rows.Scan(&location.RepositoryID, &location.RepositoryName, &location.WebURL, &location.Commit,
			&location.Path, &location.StartLine, &location.StartCharacter, &location.EndLine,
			&location.EndCharacter, &location.PositionEncoding, &location.Symbol, &location.Roles); err != nil {
			return nil, false, err
		}
		locations = append(locations, location)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(locations) > max
	if truncated {
		locations = locations[:max]
	}
	return locations, truncated, nil
}

func (s *Store) approximateLocations(ctx context.Context, tx pgx.Tx, principal authn.Principal, origin scipgraph.StoredOccurrence, operation string, max int) ([]scipgraph.Location, bool, error) {
	parsed, err := scip.ParseSymbol(origin.Symbol)
	if err != nil || parsed.Package == nil || len(principal.RepositoryIDs) == 0 {
		return []scipgraph.Location{}, false, nil
	}
	key, err := scipgraph.VersionlessSymbolKey(origin.Symbol)
	if err != nil || key == nil {
		return []scipgraph.Location{}, false, err
	}
	rows, err := tx.Query(ctx, `with authorized_uploads as (
		select uploads.id, uploads.repository_id, repositories.github_id,
			repositories.owner || '/' || repositories.name repository_name, repositories.web_url, uploads.commit
		from scip_uploads uploads
		join repositories on repositories.id=uploads.repository_id and repositories.indexed_sha=uploads.commit
		join installations on installations.id=repositories.installation_id
		where ($1=0 or installations.github_id=$1) and repositories.github_id=any($2)
		and installations.status='active' and repositories.enabled and not repositories.archived
	), origin_authorized as (
		select id from authorized_uploads where id=$3 and repository_id=$4
	), dependency as (
		select 1 from repository_packages
		where repository_id=$4 and relation='depends_on'
		and manager=$5 and name=$6 and version=$7
	), providers as (
		select distinct uploads.id
		from authorized_uploads uploads
		join repository_packages provider on provider.repository_id=uploads.repository_id and provider.relation='provides'
		join dependency on true
		join origin_authorized on true
		where provider.manager=$5 and provider.name=$6
		and (provider.source='manual' or not exists (
			select 1 from authorized_uploads manual_uploads
			join repository_packages manual on manual.repository_id=manual_uploads.repository_id
			where manual.source='manual' and manual.relation='provides'
			and manual.manager=$5 and manual.name=$6
		))
	), matches as (
		select occurrences.* from providers
		join scip_occurrences occurrences on occurrences.upload_id=providers.id
			and occurrences.global_symbol_key=$8
		where ($9='definitions' and occurrences.roles & 1 <> 0)
			or ($9='references' and occurrences.roles & 1 = 0)
		union
		select occurrences.* from providers
		join scip_relationships relationships on relationships.upload_id=providers.id
			and relationships.source_global_symbol_key=$8
		join scip_occurrences occurrences on occurrences.upload_id=relationships.upload_id
			and occurrences.symbol=relationships.target_symbol
			and occurrences.local=(left(relationships.target_symbol, 6)='local ')
			and (left(relationships.target_symbol, 6)<>'local ' or occurrences.path=relationships.document_path)
		where ($9='definitions' and relationships.is_definition and occurrences.roles & 1 <> 0)
			or ($9='references' and relationships.is_reference and occurrences.roles & 1 = 0)
		union
		select occurrences.* from providers
		join scip_relationships relationships on relationships.upload_id=providers.id
			and relationships.target_global_symbol_key=$8
		join scip_occurrences occurrences on occurrences.upload_id=relationships.upload_id
			and occurrences.symbol=relationships.source_symbol
			and occurrences.local=(left(relationships.source_symbol, 6)='local ')
			and (left(relationships.source_symbol, 6)<>'local ' or occurrences.path=relationships.document_path)
		where ($9='references' and relationships.is_reference and occurrences.roles & 1 = 0)
			or ($9='implementations' and relationships.is_implementation and occurrences.roles & 1 <> 0)
	)
	select authorized_uploads.github_id, authorized_uploads.repository_name, authorized_uploads.web_url, authorized_uploads.commit,
		matches.path, matches.start_line, matches.start_character, matches.end_line,
		matches.end_character, matches.position_encoding, matches.symbol, matches.roles
	from matches join authorized_uploads on authorized_uploads.id=matches.upload_id
	order by authorized_uploads.github_id, matches.path, matches.start_line, matches.start_character,
		matches.end_line, matches.end_character, matches.symbol, matches.id
	limit $10`, principal.InstallationID, principal.RepositoryIDs, origin.UploadID, origin.RepositoryID,
		parsed.Package.Manager, parsed.Package.Name, parsed.Package.Version, key, operation, max+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	locations := make([]scipgraph.Location, 0, max+1)
	for rows.Next() {
		var location scipgraph.Location
		if err := rows.Scan(&location.RepositoryID, &location.RepositoryName, &location.WebURL, &location.Commit,
			&location.Path, &location.StartLine, &location.StartCharacter, &location.EndLine,
			&location.EndCharacter, &location.PositionEncoding, &location.Symbol, &location.Roles); err != nil {
			return nil, false, err
		}
		location.Approximate = true
		locations = append(locations, location)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(locations) > max
	if truncated {
		locations = locations[:max]
	}
	return locations, truncated, nil
}
