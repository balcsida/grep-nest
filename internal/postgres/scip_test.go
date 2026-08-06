//go:build integration

package postgres

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/scipgraph"
	"github.com/jackc/pgx/v5"
)

const (
	globalSymbol         = "scip go example.com/grepnest v1 pkg/Item#"
	implementationSymbol = "scip go example.com/grepnest v1 pkg/Concrete#"
	localSymbol          = "local 0"
	definitionRole       = int32(1)
)

func TestReplaceSCIPIsAtomicAndCurrent(t *testing.T) {
	store := migratedStore(t)
	repositoryID := seedReadyRepository(t, store, 101, testSHA('a'))
	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('a'), uploadWith("a.go", globalSymbol, definitionRole)); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('a'), uploadWith("b.go", globalSymbol, definitionRole)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.OccurrenceAt(t.Context(), repositoryID, testSHA('a'), "a.go", 0, occurrencePosition(1)); !errors.Is(err, scipgraph.ErrOccurrenceNotFound) || errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("removed occurrence err = %v", err)
	}
	if _, err := store.OccurrenceAt(t.Context(), repositoryID, testSHA('b'), "b.go", 0, occurrencePosition(1)); !errors.Is(err, scipgraph.ErrOccurrenceNotFound) || errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("stale occurrence err = %v", err)
	}

	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('b'), uploadWith("stale.go", globalSymbol, definitionRole)); !errors.Is(err, scipgraph.ErrStaleIndex) {
		t.Fatalf("stale replacement err = %v", err)
	}
	if occurrence, err := store.OccurrenceAt(t.Context(), repositoryID, testSHA('a'), "b.go", 0, occurrencePosition(1)); err != nil || occurrence.Path != "b.go" {
		t.Fatalf("current occurrence = %#v, err = %v", occurrence, err)
	}
	duplicate := uploadWith("duplicate.go", globalSymbol, definitionRole)
	duplicate.Occurrences = append(duplicate.Occurrences, duplicate.Occurrences[0])
	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('a'), duplicate); err == nil {
		t.Fatal("duplicate replacement succeeded")
	}
	if occurrence, err := store.OccurrenceAt(t.Context(), repositoryID, testSHA('a'), "b.go", 0, occurrencePosition(1)); err != nil || occurrence.Path != "b.go" {
		t.Fatalf("occurrence after rollback = %#v, err = %v", occurrence, err)
	}
}

func TestOccurrenceAtReturnsSmallestContainingRange(t *testing.T) {
	store := migratedStore(t)
	repositoryID := seedReadyRepository(t, store, 101, testSHA('a'))
	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('a'), scipgraph.Upload{Occurrences: []scipgraph.Occurrence{
		{Path: "a.go", Symbol: globalSymbol, StartLine: 0, StartCharacter: 0, EndLine: 10, EndCharacter: 0, PositionEncoding: 1},
		{Path: "a.go", Symbol: globalSymbol, StartLine: 2, StartCharacter: 1, EndLine: 2, EndCharacter: 8, PositionEncoding: 1},
		{Path: "a.go", Symbol: globalSymbol, StartLine: 2, StartCharacter: 2, EndLine: 2, EndCharacter: 6, PositionEncoding: 2},
	}}); err != nil {
		t.Fatal(err)
	}

	occurrence, err := store.OccurrenceAt(t.Context(), repositoryID, testSHA('a'), "a.go", 2, occurrencePosition(4))
	if err != nil {
		t.Fatal(err)
	}
	if occurrence.StartLine != 2 || occurrence.StartCharacter != 2 || occurrence.EndLine != 2 || occurrence.EndCharacter != 6 || occurrence.PositionEncoding != 2 {
		t.Fatalf("OccurrenceAt() = %#v", occurrence)
	}
}

func TestOccurrenceAtUsesUploadPositionEncoding(t *testing.T) {
	store := migratedStore(t)
	position := scipgraph.OccurrencePosition{UTF8: 5, UTF16: 4, UTF32: 3}
	for encoding, character := range []int32{5, 4, 3} {
		repositoryID := seedReadyRepository(t, store, int64(101+encoding), testSHA(byte('a'+encoding)))
		if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA(byte('a'+encoding)), scipgraph.Upload{Occurrences: []scipgraph.Occurrence{{
			Path: "a.go", Symbol: globalSymbol, StartCharacter: character, EndCharacter: character + 1, PositionEncoding: int32(encoding + 1),
		}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.OccurrenceAt(t.Context(), repositoryID, testSHA(byte('a'+encoding)), "a.go", 0, position); err != nil {
			t.Fatalf("encoding %d: %v", encoding+1, err)
		}
	}
}

func TestSCIPTablesCascadeWithRepository(t *testing.T) {
	store := migratedStore(t)
	repositoryID := seedReadyRepository(t, store, 101, testSHA('a'))
	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('a'), scipgraph.Upload{
		Occurrences:   []scipgraph.Occurrence{{Path: "a.go", Symbol: globalSymbol, EndCharacter: 2, PositionEncoding: 1}},
		Relationships: []scipgraph.Relationship{{Source: globalSymbol, Target: implementationSymbol, Implementation: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(t.Context(), `insert into repository_packages
		(repository_id, source, relation, purl, manager, name, version)
		values ($1, 'manual', 'provides', 'pkg:golang/example.com/grepnest@v1', 'gomod', 'example.com/grepnest', 'v1')`, repositoryID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(t.Context(), "delete from repositories where id=$1", repositoryID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"scip_uploads", "scip_occurrences", "scip_relationships", "repository_packages"} {
		var count int
		if err := store.pool.QueryRow(t.Context(), "select count(*) from "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s rows = %d, err = %v", table, count, err)
		}
	}
}

func TestSCIPLocationsAuthorizeAndScopeSymbols(t *testing.T) {
	store := migratedStore(t)
	firstID := seedReadyRepository(t, store, 101, testSHA('a'))
	secondID := seedReadyRepository(t, store, 102, testSHA('b'))
	thirdID := seedReadyRepository(t, store, 103, testSHA('c'))
	fourthID := seedReadyRepository(t, store, 104, testSHA('d'))

	if err := store.ReplaceSCIP(t.Context(), firstID, testSHA('a'), scipgraph.Upload{Occurrences: []scipgraph.Occurrence{
		{Path: "origin.go", Symbol: globalSymbol, EndCharacter: 2, PositionEncoding: 1},
		{Path: "local.go", Symbol: localSymbol, EndCharacter: 2, PositionEncoding: 1, Local: true},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceSCIP(t.Context(), secondID, testSHA('b'), scipgraph.Upload{Occurrences: []scipgraph.Occurrence{
		{Path: "definition.go", Symbol: globalSymbol, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
		{Path: "local.go", Symbol: localSymbol, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole, Local: true},
		{Path: "implementation.go", Symbol: implementationSymbol, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
	}, Relationships: []scipgraph.Relationship{{Source: implementationSymbol, Target: globalSymbol, Implementation: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceSCIP(t.Context(), thirdID, testSHA('c'), uploadWith("forbidden.go", globalSymbol, definitionRole)); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceSCIP(t.Context(), fourthID, testSHA('d'), uploadWith("forbidden-origin.go", globalSymbol, 0)); err != nil {
		t.Fatal(err)
	}

	principal := authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101, 102}}
	origin, err := store.OccurrenceAt(t.Context(), firstID, testSHA('a'), "origin.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	definitions, truncated, err := store.Locations(t.Context(), principal, origin, "definitions", 10)
	if err != nil || truncated || len(definitions) != 1 || definitions[0].RepositoryID != 102 ||
		definitions[0].WebURL != "web" || definitions[0].Path != "definition.go" {
		t.Fatalf("definitions = %#v, truncated = %v, err = %v", definitions, truncated, err)
	}
	definition, err := store.OccurrenceAt(t.Context(), secondID, testSHA('b'), "definition.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	references, truncated, err := store.Locations(t.Context(), principal, definition, "references", 10)
	if err != nil || truncated || len(references) != 1 || references[0].RepositoryID != 101 || references[0].Path != "origin.go" {
		t.Fatalf("references = %#v, truncated = %v, err = %v", references, truncated, err)
	}
	implementations, truncated, err := store.Locations(t.Context(), principal, origin, "implementations", 10)
	if err != nil || truncated || len(implementations) != 1 || implementations[0].RepositoryID != 102 || implementations[0].Path != "implementation.go" {
		t.Fatalf("implementations = %#v, truncated = %v, err = %v", implementations, truncated, err)
	}

	localOrigin, err := store.OccurrenceAt(t.Context(), firstID, testSHA('a'), "local.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	locations, truncated, err := store.Locations(t.Context(), principal, localOrigin, "definitions", 10)
	if err != nil || truncated || len(locations) != 0 {
		t.Fatalf("local definitions = %#v, truncated = %v, err = %v", locations, truncated, err)
	}

	unauthorizedOrigin, err := store.OccurrenceAt(t.Context(), fourthID, testSHA('d'), "forbidden-origin.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	locations, truncated, err = store.Locations(t.Context(), principal, unauthorizedOrigin, "definitions", 10)
	if err != nil || truncated || len(locations) != 0 {
		t.Fatalf("unauthorized-origin definitions = %#v, truncated = %v, err = %v", locations, truncated, err)
	}
}

func TestSCIPLocalSymbolsAreDocumentScoped(t *testing.T) {
	store := migratedStore(t)
	repositoryID := seedReadyRepository(t, store, 101, testSHA('a'))
	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('a'), scipgraph.Upload{
		Occurrences: []scipgraph.Occurrence{
			{Path: "a.go", Symbol: localSymbol, EndCharacter: 2, PositionEncoding: 1, Local: true},
			{Path: "a.go", Symbol: localSymbol, StartCharacter: 3, EndCharacter: 5, PositionEncoding: 1, Roles: definitionRole, Local: true},
			{Path: "b.go", Symbol: localSymbol, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole, Local: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	origin, err := store.OccurrenceAt(t.Context(), repositoryID, testSHA('a'), "a.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	locations, truncated, err := store.Locations(
		t.Context(),
		authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101}},
		origin,
		"definitions",
		10,
	)
	if err != nil || truncated || len(locations) != 1 || locations[0].Path != "a.go" || locations[0].StartCharacter != 3 {
		t.Fatalf("local definitions = %#v, truncated = %v, err = %v", locations, truncated, err)
	}
}

func TestSCIPRelationshipsNavigateDefinitionsAndReferences(t *testing.T) {
	store := migratedStore(t)
	repositoryID := seedReadyRepository(t, store, 101, testSHA('a'))
	const (
		definitionSource = "scip go example.com/grepnest v1 pkg/Source#"
		definition       = "scip go example.com/grepnest v1 pkg/Definition#"
		referenceSource  = "scip go example.com/grepnest v1 pkg/Reference#"
		referenceTarget  = "scip go example.com/grepnest v1 pkg/Target#"
	)
	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('a'), scipgraph.Upload{
		Occurrences: []scipgraph.Occurrence{
			{Path: "definition-source.go", Symbol: definitionSource, EndCharacter: 2, PositionEncoding: 1},
			{Path: "definition.go", Symbol: definition, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
			{Path: "definition-reference.go", Symbol: definition, EndCharacter: 2, PositionEncoding: 1},
			{Path: "reference-source-definition.go", Symbol: referenceSource, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
			{Path: "reference-source.go", Symbol: referenceSource, EndCharacter: 2, PositionEncoding: 1},
			{Path: "reference-target-definition.go", Symbol: referenceTarget, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
			{Path: "reference-target.go", Symbol: referenceTarget, EndCharacter: 2, PositionEncoding: 1},
		},
		Relationships: []scipgraph.Relationship{
			{Path: "definition-source.go", Source: definitionSource, Target: definition, Definition: true},
			{Path: "reference-source.go", Source: referenceSource, Target: referenceTarget, Reference: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	principal := authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101}}
	for _, test := range []struct {
		originPath, operation string
		paths                 []string
	}{
		{"definition-source.go", "definitions", []string{"definition.go"}},
		{"reference-target.go", "references", []string{"reference-source.go", "reference-target.go"}},
		{"reference-source.go", "references", []string{"reference-source.go", "reference-target.go"}},
	} {
		origin, err := store.OccurrenceAt(t.Context(), repositoryID, testSHA('a'), test.originPath, 0, occurrencePosition(1))
		if err != nil {
			t.Fatal(err)
		}
		locations, truncated, err := store.Locations(t.Context(), principal, origin, test.operation, 10)
		if err != nil || truncated || len(locations) != len(test.paths) {
			t.Fatalf("%s = %#v, truncated = %v, err = %v", test.operation, locations, truncated, err)
		}
		for index, location := range locations {
			if location.Path != test.paths[index] || test.operation == "references" && location.Roles&definitionRole != 0 {
				t.Fatalf("%s = %#v", test.operation, locations)
			}
		}
	}
}

func TestSCIPLocationsRejectStaleOrigin(t *testing.T) {
	store := migratedStore(t)
	repositoryID := seedReadyRepository(t, store, 101, testSHA('a'))
	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('a'), uploadWith("origin.go", globalSymbol, 0)); err != nil {
		t.Fatal(err)
	}
	origin, err := store.OccurrenceAt(t.Context(), repositoryID, testSHA('a'), "origin.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('a'), uploadWith("replacement.go", globalSymbol, 0)); err != nil {
		t.Fatal(err)
	}
	_, _, err = store.Locations(t.Context(), authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101}}, origin, "definitions", 10)
	if !errors.Is(err, scipgraph.ErrStaleIndex) {
		t.Fatalf("Locations() error = %v", err)
	}
}

func TestSCIPLocalRelationshipsAreDocumentScoped(t *testing.T) {
	store := migratedStore(t)
	repositoryID := seedReadyRepository(t, store, 101, testSHA('a'))
	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('a'), scipgraph.Upload{
		Occurrences: []scipgraph.Occurrence{
			{Path: "a.go", Symbol: "local 0", EndCharacter: 2, PositionEncoding: 1, Local: true},
			{Path: "a.go", Symbol: "local 1", StartCharacter: 3, EndCharacter: 5, PositionEncoding: 1, Roles: definitionRole, Local: true},
			{Path: "b.go", Symbol: "local 2", EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole, Local: true},
		},
		Relationships: []scipgraph.Relationship{
			{Path: "a.go", Source: "local 0", Target: "local 1", Definition: true},
			{Path: "b.go", Source: "local 0", Target: "local 2", Definition: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	origin, err := store.OccurrenceAt(t.Context(), repositoryID, testSHA('a'), "a.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	locations, truncated, err := store.Locations(
		t.Context(),
		authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101}},
		origin,
		"definitions",
		10,
	)
	if err != nil || truncated || len(locations) != 1 || locations[0].Path != "a.go" || locations[0].Symbol != "local 1" {
		t.Fatalf("local relationship definitions = %#v, truncated = %v, err = %v", locations, truncated, err)
	}
}

func TestExactSCIPSymbolLookupUsesIndex(t *testing.T) {
	store := migratedStore(t)
	tx, err := store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), "set local enable_seqscan=off"); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(t.Context(), "explain (costs off) "+exactLocationsSQL,
		int64(10), []int64{101}, globalSymbol, int64(1), false, "references", 11, int64(1), "a.go")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, index := range []string{
		"scip_occurrences_symbol_lookup",
		"scip_relationships_source_lookup",
		"scip_relationships_target_lookup",
	} {
		if !strings.Contains(plan.String(), index) {
			t.Fatalf("plan does not use %s:\n%s", index, plan.String())
		}
	}
}

func TestSCIPLocationsUseDeterministicTotalOrder(t *testing.T) {
	store := migratedStore(t)
	repositoryID := seedReadyRepository(t, store, 101, testSHA('a'))
	const (
		firstImplementation  = "scip go example.com/grepnest v1 pkg/A#"
		secondImplementation = "scip go example.com/grepnest v1 pkg/B#"
		lastImplementation   = "scip go example.com/grepnest v1 pkg/Z#"
	)
	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('a'), scipgraph.Upload{
		Occurrences: []scipgraph.Occurrence{
			{Path: "origin.go", Symbol: globalSymbol, EndCharacter: 2, PositionEncoding: 1},
			{Path: "implementations.go", Symbol: lastImplementation, EndLine: 1, PositionEncoding: 1, Roles: definitionRole},
			{Path: "implementations.go", Symbol: secondImplementation, EndCharacter: 5, PositionEncoding: 1, Roles: definitionRole},
			{Path: "implementations.go", Symbol: firstImplementation, EndCharacter: 5, PositionEncoding: 1, Roles: definitionRole},
		},
		Relationships: []scipgraph.Relationship{
			{Source: lastImplementation, Target: globalSymbol, Implementation: true},
			{Source: secondImplementation, Target: globalSymbol, Implementation: true},
			{Source: firstImplementation, Target: globalSymbol, Implementation: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	origin, err := store.OccurrenceAt(t.Context(), repositoryID, testSHA('a'), "origin.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	locations, truncated, err := store.Locations(t.Context(), authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101}}, origin, "implementations", 10)
	if err != nil || truncated || len(locations) != 3 {
		t.Fatalf("locations = %#v, truncated = %v, err = %v", locations, truncated, err)
	}
	for index, symbol := range []string{firstImplementation, secondImplementation, lastImplementation} {
		if locations[index].Symbol != symbol {
			t.Fatalf("locations[%d].Symbol = %q, want %q", index, locations[index].Symbol, symbol)
		}
	}
}

func TestSCIPLocationsReportTruncation(t *testing.T) {
	store := migratedStore(t)
	repositoryID := seedReadyRepository(t, store, 101, testSHA('a'))
	if err := store.ReplaceSCIP(t.Context(), repositoryID, testSHA('a'), scipgraph.Upload{Occurrences: []scipgraph.Occurrence{
		{Path: "origin.go", Symbol: globalSymbol, EndCharacter: 2, PositionEncoding: 1},
		{Path: "one.go", Symbol: globalSymbol, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
		{Path: "two.go", Symbol: globalSymbol, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
	}}); err != nil {
		t.Fatal(err)
	}
	origin, err := store.OccurrenceAt(t.Context(), repositoryID, testSHA('a'), "origin.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	locations, truncated, err := store.Locations(t.Context(), authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101}}, origin, "definitions", 1)
	if err != nil || !truncated || len(locations) != 1 {
		t.Fatalf("locations = %#v, truncated = %v, err = %v", locations, truncated, err)
	}
}

func TestPackageReplacementPreservesOtherSources(t *testing.T) {
	store := migratedStore(t)
	repositoryID := seedReadyRepository(t, store, 101, testSHA('a'))
	manual := packageMapping("pkg:golang/example.com/acme/lib@v2", "provides", "manual")
	github := packageMapping("pkg:golang/example.com/acme/lib@v1", "provides", "github")
	if err := store.ReplacePackages(t.Context(), repositoryID, "manual", []scipgraph.PackageMapping{manual}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplacePackages(t.Context(), repositoryID, "github", []scipgraph.PackageMapping{github}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplacePackages(t.Context(), repositoryID, "github", nil); err != nil {
		t.Fatal(err)
	}
	var source, purl string
	if err := store.pool.QueryRow(t.Context(), `select source, purl from repository_packages where repository_id=$1`, repositoryID).Scan(&source, &purl); err != nil {
		t.Fatal(err)
	}
	if source != "manual" || purl != manual.Package.PURL {
		t.Fatalf("remaining package = %q %q", source, purl)
	}
}

func TestPackageReplacementIsSerialized(t *testing.T) {
	store := migratedStore(t)
	repositoryID := seedReadyRepository(t, store, 101, testSHA('a'))
	const writers = 8
	for round := 0; round < 3; round++ {
		if err := store.ReplacePackages(t.Context(), repositoryID, "manual", nil); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errors := make(chan error, writers)
		var group sync.WaitGroup
		for writer := 0; writer < writers; writer++ {
			group.Add(1)
			go func(writer int) {
				defer group.Done()
				<-start
				errors <- store.ReplacePackages(t.Context(), repositoryID, "manual", []scipgraph.PackageMapping{
					packageMapping(fmt.Sprintf("pkg:npm/acme-%d@1.0.0", writer), "provides", "manual"),
				})
			}(writer)
		}
		close(start)
		group.Wait()
		close(errors)
		for err := range errors {
			if err != nil {
				t.Fatal(err)
			}
		}
		var count int
		if err := store.pool.QueryRow(t.Context(), `select count(*) from repository_packages
			where repository_id=$1 and source='manual'`, repositoryID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("round %d committed %d replacements", round, count)
		}
	}
}

func TestDependencyAssistedLocationsRequireDependencyAndPreferManualProvider(t *testing.T) {
	store := migratedStore(t)
	originID := seedReadyRepository(t, store, 101, testSHA('a'))
	manualID := seedReadyRepository(t, store, 102, testSHA('b'))
	githubID := seedReadyRepository(t, store, 103, testSHA('c'))
	const (
		originSymbol   = "scip gomod example.com/acme/lib v1 pkg/Item#"
		providerSymbol = "scip gomod example.com/acme/lib v2 pkg/Item#"
	)
	if err := store.ReplaceSCIP(t.Context(), originID, testSHA('a'), uploadWith("origin.go", originSymbol, 0)); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceSCIP(t.Context(), manualID, testSHA('b'), uploadWith("manual.go", providerSymbol, definitionRole)); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceSCIP(t.Context(), githubID, testSHA('c'), uploadWith("github.go", providerSymbol, definitionRole)); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplacePackages(t.Context(), manualID, "manual", []scipgraph.PackageMapping{packageMapping("pkg:golang/example.com/acme/lib@v2", "provides", "manual")}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplacePackages(t.Context(), githubID, "github", []scipgraph.PackageMapping{packageMapping("pkg:golang/example.com/acme/lib@v2", "provides", "github")}); err != nil {
		t.Fatal(err)
	}
	principal := authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101, 102, 103}}
	origin, err := store.OccurrenceAt(t.Context(), originID, testSHA('a'), "origin.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	locations, _, err := store.Locations(t.Context(), principal, origin, "definitions", 10)
	if err != nil || len(locations) != 0 {
		t.Fatalf("locations without dependency = %#v, err = %v", locations, err)
	}
	if err := store.ReplacePackages(t.Context(), originID, "manual", []scipgraph.PackageMapping{packageMapping("pkg:golang/example.com/acme/lib@v1", "depends_on", "manual")}); err != nil {
		t.Fatal(err)
	}
	locations, truncated, err := store.Locations(t.Context(), principal, origin, "definitions", 10)
	if err != nil || truncated || len(locations) != 1 || locations[0].RepositoryID != 102 || !locations[0].Approximate {
		t.Fatalf("dependency-assisted locations = %#v, truncated = %v, err = %v", locations, truncated, err)
	}
}

func TestDependencyAssistedLocationsTraverseRelationships(t *testing.T) {
	store := migratedStore(t)
	originID := seedReadyRepository(t, store, 101, testSHA('a'))
	providerID := seedReadyRepository(t, store, 102, testSHA('b'))
	const (
		originSymbol            = "scip gomod example.com/acme/lib v1 pkg/Item#"
		providerSymbol          = "scip gomod example.com/acme/lib v2 pkg/Item#"
		definitionSymbol        = "scip gomod example.com/acme/lib v2 pkg/Definition#"
		originReferenceSource   = "scip gomod example.com/acme/lib v1 pkg/Reference#"
		providerReferenceSource = "scip gomod example.com/acme/lib v2 pkg/Reference#"
		originReferenceTarget   = "scip gomod example.com/acme/lib v1 pkg/Target#"
		providerReferenceTarget = "scip gomod example.com/acme/lib v2 pkg/Target#"
	)
	if err := store.ReplaceSCIP(t.Context(), originID, testSHA('a'), scipgraph.Upload{Occurrences: []scipgraph.Occurrence{
		{Path: "origin.go", Symbol: originSymbol, EndCharacter: 2, PositionEncoding: 1},
		{Path: "reference-source-origin-definition.go", Symbol: originReferenceSource, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
		{Path: "reference-target-origin-definition.go", Symbol: originReferenceTarget, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceSCIP(t.Context(), providerID, testSHA('b'), scipgraph.Upload{
		Occurrences: []scipgraph.Occurrence{
			{Path: "definition.go", Symbol: definitionSymbol, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
			{Path: "reference-source-definition.go", Symbol: providerReferenceSource, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
			{Path: "reference-source.go", Symbol: providerReferenceSource, EndCharacter: 2, PositionEncoding: 1},
			{Path: "reference-target-definition.go", Symbol: providerReferenceTarget, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
			{Path: "reference-target.go", Symbol: providerReferenceTarget, EndCharacter: 2, PositionEncoding: 1},
		},
		Relationships: []scipgraph.Relationship{
			{Path: "definition.go", Source: providerSymbol, Target: definitionSymbol, Definition: true},
			{Path: "reference-source.go", Source: providerReferenceSource, Target: providerReferenceTarget, Reference: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplacePackages(t.Context(), originID, "manual", []scipgraph.PackageMapping{
		packageMapping("pkg:golang/example.com/acme/lib@v1", "depends_on", "manual"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplacePackages(t.Context(), providerID, "manual", []scipgraph.PackageMapping{
		packageMapping("pkg:golang/example.com/acme/lib@v2", "provides", "manual"),
	}); err != nil {
		t.Fatal(err)
	}
	principal := authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101, 102}}
	for _, test := range []struct {
		originPath, operation string
		paths                 []string
	}{
		{"origin.go", "definitions", []string{"definition.go"}},
		{"reference-target-origin-definition.go", "references", []string{"reference-source.go", "reference-target.go"}},
		{"reference-source-origin-definition.go", "references", []string{"reference-source.go", "reference-target.go"}},
	} {
		origin, err := store.OccurrenceAt(t.Context(), originID, testSHA('a'), test.originPath, 0, occurrencePosition(1))
		if err != nil {
			t.Fatal(err)
		}
		locations, truncated, err := store.Locations(t.Context(), principal, origin, test.operation, 10)
		if err != nil || truncated || len(locations) != len(test.paths) {
			t.Fatalf("%s = %#v, truncated = %v, err = %v", test.operation, locations, truncated, err)
		}
		for index, location := range locations {
			if location.Path != test.paths[index] || !location.Approximate || test.operation == "references" && location.Roles&definitionRole != 0 {
				t.Fatalf("%s = %#v", test.operation, locations)
			}
		}
	}
}

func TestDependencyAssistedLocationsAreBoundedAndExactFirst(t *testing.T) {
	store := migratedStore(t)
	originID := seedReadyRepository(t, store, 201, testSHA('a'))
	firstProviderID := seedReadyRepository(t, store, 202, testSHA('b'))
	secondProviderID := seedReadyRepository(t, store, 203, testSHA('c'))
	thirdProviderID := seedReadyRepository(t, store, 204, testSHA('d'))
	fourthProviderID := seedReadyRepository(t, store, 205, testSHA('e'))
	unauthorizedID := seedReadyRepository(t, store, 206, testSHA('f'))
	staleID := seedReadyRepository(t, store, 207, testSHA('1'))
	const (
		originSymbol         = "scip gomod example.com/acme/lib v1 pkg/Item#"
		thirdProviderSymbol  = "scip gomod example.com/acme/lib v4 pkg/Item#"
		fourthProviderSymbol = "scip gomod example.com/acme/lib v5 pkg/Item#"
	)
	if err := store.ReplaceSCIP(t.Context(), originID, testSHA('a'), scipgraph.Upload{Occurrences: []scipgraph.Occurrence{
		{Path: "origin.go", Symbol: originSymbol, EndCharacter: 2, PositionEncoding: 1},
		{Path: "exact.go", Symbol: originSymbol, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []struct {
		id      int64
		sha     string
		version string
		symbol  string
	}{
		{firstProviderID, testSHA('b'), "v2", "scip gomod example.com/acme/lib v2 pkg/Other#"},
		{secondProviderID, testSHA('c'), "v3", "scip gomod example.com/acme/lib v3 pkg/Another#"},
		{thirdProviderID, testSHA('d'), "v4", thirdProviderSymbol},
		{fourthProviderID, testSHA('e'), "v5", fourthProviderSymbol},
		{unauthorizedID, testSHA('f'), "v6", "scip gomod example.com/acme/lib v6 pkg/Item#"},
		{staleID, testSHA('1'), "v7", "scip gomod example.com/acme/lib v7 pkg/Item#"},
	} {
		upload := uploadWith(provider.version+".go", provider.symbol, definitionRole)
		if err := store.ReplaceSCIP(t.Context(), provider.id, provider.sha, upload); err != nil {
			t.Fatal(err)
		}
		if err := store.ReplacePackages(t.Context(), provider.id, "manual", []scipgraph.PackageMapping{packageMapping("pkg:golang/example.com/acme/lib@"+provider.version, "provides", "manual")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ReplacePackages(t.Context(), originID, "manual", []scipgraph.PackageMapping{packageMapping("pkg:golang/example.com/acme/lib@v1", "depends_on", "manual")}); err != nil {
		t.Fatal(err)
	}
	principal := authn.Principal{InstallationID: 10, RepositoryIDs: []int64{201, 202, 203, 204, 205, 207}}
	origin, err := store.OccurrenceAt(t.Context(), originID, testSHA('a'), "origin.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	locations, truncated, err := store.Locations(t.Context(), principal, origin, "definitions", 1)
	if err != nil || truncated || len(locations) != 1 || locations[0].Path != "exact.go" || locations[0].Approximate {
		t.Fatalf("exact-first locations = %#v, truncated = %v, err = %v", locations, truncated, err)
	}
	if err := store.ReplaceSCIP(t.Context(), originID, testSHA('a'), uploadWith("origin.go", originSymbol, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(t.Context(), "update repositories set indexed_sha=$2 where id=$1", staleID, testSHA('2')); err != nil {
		t.Fatal(err)
	}
	origin, err = store.OccurrenceAt(t.Context(), originID, testSHA('a'), "origin.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	locations, truncated, err = store.Locations(t.Context(), principal, origin, "definitions", 1)
	if err != nil || !truncated || len(locations) != 1 || !locations[0].Approximate || locations[0].Symbol != thirdProviderSymbol {
		t.Fatalf("bounded approximate locations = %#v, truncated = %v, err = %v", locations, truncated, err)
	}
}

func packageMapping(purl, relation, source string) scipgraph.PackageMapping {
	pkg, err := scipgraph.ParsePackageURL(purl)
	if err != nil {
		panic(err)
	}
	return scipgraph.PackageMapping{Package: pkg, Relation: relation, Source: source}
}

func uploadWith(path, symbol string, roles int32) scipgraph.Upload {
	return scipgraph.Upload{ProjectRoot: "file:///src", IndexerName: "test", IndexerVersion: "1", Occurrences: []scipgraph.Occurrence{{
		Path: path, Symbol: symbol, EndCharacter: 2, PositionEncoding: 1, Roles: roles,
	}}}
}

func occurrencePosition(character int) scipgraph.OccurrencePosition {
	return scipgraph.OccurrencePosition{UTF8: character, UTF16: character, UTF32: character}
}

func seedReadyRepository(t *testing.T, store *Store, githubID int64, sha string) int64 {
	t.Helper()
	if err := store.UpsertInstallation(t.Context(), InstallationUpdate{GitHubID: 10, AccountLogin: "acme", AccountType: "Organization", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	repository, err := store.UpsertRepository(t.Context(), RepositoryUpdate{
		GitHubID: githubID, InstallationID: 10, Owner: "acme", Name: fmt.Sprintf("repo-%d", githubID), CloneURL: "clone", WebURL: "web", DefaultBranch: "main", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(t.Context(), "update repositories set indexed_sha=$2, desired_sha=$2, status='ready' where id=$1", repository.ID, sha); err != nil {
		t.Fatal(err)
	}
	return repository.ID
}

func TestLocationsAllowUnscopedInstallationPrincipals(t *testing.T) {
	store := migratedStore(t)
	originID := seedReadyRepository(t, store, 101, testSHA('a'))
	providerID := seedReadyRepository(t, store, 102, testSHA('b'))
	const dependencySymbol = "scip gomod example.com/acme/lib v1 pkg/Item#"
	if err := store.ReplaceSCIP(t.Context(), originID, testSHA('a'), scipgraph.Upload{Occurrences: []scipgraph.Occurrence{
		{Path: "origin.go", Symbol: globalSymbol, EndCharacter: 2, PositionEncoding: 1},
		{Path: "definition.go", Symbol: globalSymbol, EndCharacter: 2, PositionEncoding: 1, Roles: definitionRole},
		{Path: "dependent.go", Symbol: dependencySymbol, EndCharacter: 2, PositionEncoding: 1},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceSCIP(t.Context(), providerID, testSHA('b'), uploadWith("provider.go", dependencySymbol, definitionRole)); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplacePackages(t.Context(), providerID, "manual", []scipgraph.PackageMapping{packageMapping("pkg:golang/example.com/acme/lib@v1", "provides", "manual")}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplacePackages(t.Context(), originID, "manual", []scipgraph.PackageMapping{packageMapping("pkg:golang/example.com/acme/lib@v1", "depends_on", "manual")}); err != nil {
		t.Fatal(err)
	}

	principal := authn.Principal{RepositoryIDs: []int64{101, 102}}
	origin, err := store.OccurrenceAt(t.Context(), originID, testSHA('a'), "origin.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	definitions, _, err := store.Locations(t.Context(), principal, origin, "definitions", 10)
	if err != nil || len(definitions) != 1 || definitions[0].Path != "definition.go" {
		t.Fatalf("definitions = %#v, err = %v", definitions, err)
	}

	dependent, err := store.OccurrenceAt(t.Context(), originID, testSHA('a'), "dependent.go", 0, occurrencePosition(1))
	if err != nil {
		t.Fatal(err)
	}
	crossRepo, _, err := store.Locations(t.Context(), principal, dependent, "definitions", 10)
	if err != nil || len(crossRepo) != 1 || crossRepo[0].RepositoryID != 102 || crossRepo[0].Path != "provider.go" {
		t.Fatalf("crossRepo = %#v, err = %v", crossRepo, err)
	}
}
