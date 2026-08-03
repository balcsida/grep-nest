//go:build integration

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var schemaName = regexp.MustCompile(`^grepnest_test_[0-9a-f]{16}$`)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("GREPNEST_TEST_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("GREPNEST_REQUIRE_POSTGRES") == "1" {
			t.Fatal("GREPNEST_TEST_POSTGRES_DSN is not set")
		}
		t.Skip("GREPNEST_TEST_POSTGRES_DSN is not set")
	}

	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)

	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatal(err)
	}
	schema := "grepnest_test_" + hex.EncodeToString(bytes)
	if !schemaName.MatchString(schema) {
		t.Fatalf("invalid schema name %q", schema)
	}
	if _, err := admin.Exec(t.Context(), "create schema "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(t.Context(), "drop schema "+schema+" cascade")
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, err := connection.Exec(ctx, "set search_path to "+schema)
		return err
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestMigrateIsConcurrentAndIdempotent(t *testing.T) {
	pool := testPool(t)
	errors := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() { defer group.Done(); errors <- Migrate(t.Context(), pool) }()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"installations", "repositories", "webhook_deliveries", "index_jobs", "search_nodes", "scip_uploads", "scip_occurrences", "scip_relationships", "repository_packages", "graph_uploads", "graph_nodes", "graph_edges", "graph_jobs", "users", "user_identities", "user_roles", "user_repository_grants", "auth_login_flows", "auth_sessions", "groups", "group_memberships", "group_roles", "group_repository_grants", "api_tokens", "password_credentials", "login_throttles", "audit_events"} {
		var found bool
		if err := pool.QueryRow(t.Context(), `select to_regclass($1) is not null`, name).Scan(&found); err != nil || !found {
			t.Fatalf("relation %s: found=%v err=%v", name, found, err)
		}
	}
	var count int
	if err := pool.QueryRow(t.Context(), `select count(*) from schema_migrations`).Scan(&count); err != nil || count != 16 {
		t.Fatalf("migrations=%d err=%v", count, err)
	}
	for _, test := range []struct {
		table, provider string
		valid           bool
	}{
		{"auth_login_flows", "oidc", true}, {"auth_login_flows", "github", true}, {"auth_login_flows", "oauth", false},
		{"auth_sessions", "oidc", true}, {"auth_sessions", "oauth", true}, {"auth_sessions", "local", true}, {"auth_sessions", "github", false},
	} {
		t.Run(test.table+"/"+test.provider, func(t *testing.T) {
			var err error
			if test.table == "auth_login_flows" {
				_, err = pool.Exec(t.Context(), `insert into auth_login_flows (state_hash,browser_hash,provider,nonce,code_verifier,return_to,created_at,expires_at) values (digest($1,'sha256'),digest($2,'sha256'),$3,'nonce','verifier','/',now(),now()+interval '1 minute')`, test.table+test.provider, test.provider+test.table, test.provider)
			} else {
				_, err = pool.Exec(t.Context(), `with user_record as (insert into users (external_id,user_name,source) values ($1,$1,'scim') returning id) insert into auth_sessions (token_hash,user_id,provider,created_at,last_seen_at,idle_expires_at,expires_at) values (digest($1,'sha256'),(select id from user_record),$2,now(),now(),now()+interval '1 minute',now()+interval '1 hour')`, test.table+test.provider, test.provider)
			}
			if test.valid && err != nil {
				t.Fatal(err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid provider accepted")
			}
		})
	}
	var repositoryIDNullable string
	if err := pool.QueryRow(t.Context(), `select is_nullable from information_schema.columns
		where table_schema=current_schema() and table_name='webhook_deliveries' and column_name='repository_id'`).
		Scan(&repositoryIDNullable); err != nil || repositoryIDNullable != "YES" {
		t.Fatalf("repository_id nullable=%q err=%v", repositoryIDNullable, err)
	}
	for _, index := range []string{
		"webhook_deliveries_repository_received",
		"scip_occurrences_position", "scip_occurrences_symbol_lookup", "scip_occurrences_global_symbol_key",
		"scip_relationships_source_lookup", "scip_relationships_target_lookup",
		"scip_relationships_source_global_symbol_key", "scip_relationships_target_global_symbol_key",
		"repository_packages_lookup",
		"groups_external_id_active",
	} {
		var found bool
		if err := pool.QueryRow(t.Context(), `select exists(
			select 1 from pg_indexes where schemaname=current_schema() and indexname=$1)`, index).Scan(&found); err != nil || !found {
			t.Fatalf("index %s: found=%v err=%v", index, found, err)
		}
	}
	for _, column := range []struct{ table, name string }{
		{"scip_occurrences", "position_encoding"},
		{"scip_occurrences", "global_symbol_key"},
		{"scip_relationships", "document_path"},
		{"scip_relationships", "source_global_symbol_key"},
		{"scip_relationships", "target_global_symbol_key"},
	} {
		var found bool
		if err := pool.QueryRow(t.Context(), `select exists(select 1 from information_schema.columns
			where table_schema=current_schema() and table_name=$1 and column_name=$2)`, column.table, column.name).Scan(&found); err != nil || !found {
			t.Fatalf("column %s.%s: found=%v err=%v", column.table, column.name, found, err)
		}
	}
	for _, constraint := range []string{
		"scip_uploads_repository_unique", "scip_uploads_commit_sha",
		"scip_occurrences_start_line_nonnegative", "scip_occurrences_start_character_nonnegative",
		"scip_occurrences_end_line_order", "scip_occurrences_end_character_nonnegative",
		"scip_occurrences_range", "scip_occurrences_position_encoding",
		"scip_occurrences_unique", "scip_relationships_unique",
		"repository_packages_source", "repository_packages_relation", "repository_packages_unique",
	} {
		var found bool
		if err := pool.QueryRow(t.Context(), `select exists(
			select 1 from pg_constraint where connamespace=current_schema()::regnamespace and conname=$1)`, constraint).Scan(&found); err != nil || !found {
			t.Fatalf("constraint %s: found=%v err=%v", constraint, found, err)
		}
	}
}

func TestMigrateInvalidatesAppliedV4SCIPRows(t *testing.T) {
	pool := testPool(t)
	if _, err := pool.Exec(t.Context(), `create table schema_migrations (version bigint primary key)`); err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := migrationDescriptors(entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.version >= 5 {
			continue
		}
		sql, err := migrationFiles.ReadFile("migrations/" + migration.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), string(sql)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), "insert into schema_migrations (version) values ($1)", migration.version); err != nil {
			t.Fatal(err)
		}
	}

	repositoryID := seedReadyRepository(t, New(pool), 101, testSHA('a'))
	var uploadID int64
	if err := pool.QueryRow(t.Context(), `insert into scip_uploads
		(repository_id, commit, project_root, indexer_name, indexer_version)
		values ($1, $2, '', 'test', '1') returning id`, repositoryID, testSHA('a')).Scan(&uploadID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `insert into scip_occurrences
		(upload_id, path, start_line, start_character, end_line, end_character, symbol, roles, local)
		values ($1, 'a.go', 0, 0, 0, 1, $2, 0, false)`, uploadID, globalSymbol); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `insert into scip_relationships
		(upload_id, source_symbol, target_symbol, is_definition, is_reference, is_implementation, is_type_definition)
		values ($1, $2, $3, false, false, true, false)`, uploadID, implementationSymbol, globalSymbol); err != nil {
		t.Fatal(err)
	}

	if err := Migrate(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	var uploads, version int
	if err := pool.QueryRow(t.Context(), "select count(*) from scip_uploads").Scan(&uploads); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), "select count(*) from schema_migrations where version=5").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if uploads != 0 || version != 1 {
		t.Fatalf("uploads = %d, migration 5 rows = %d", uploads, version)
	}
}

func TestMigrateUpgradesAppliedV1(t *testing.T) {
	pool := testPool(t)
	legacy, err := migrationFiles.ReadFile("migrations/001_milestone_2.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), string(legacy)); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"alter table repositories drop column if exists size_bytes",
		"alter table webhook_deliveries alter column installation_id set not null",
		"alter table index_jobs drop column if exists target_ref",
		"alter table index_jobs drop column if exists reason",
		"alter table index_jobs drop column if exists priority",
		"alter table index_jobs drop column if exists max_attempts",
		"alter table index_jobs drop constraint if exists index_jobs_check",
		"alter table index_jobs add check ((state = 'running') = (lease_owner is not null and lease_expires_at is not null))",
		"drop index if exists index_jobs_claim",
		"create index index_jobs_claim on index_jobs(run_after, id) where state = 'queued'",
		"create table schema_migrations (version bigint primary key)",
		"insert into schema_migrations (version) values (1)",
	} {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}

	if err := Migrate(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"size_bytes", "target_ref", "reason", "priority", "max_attempts"} {
		var found bool
		if err := pool.QueryRow(t.Context(), `select exists(
			select 1 from information_schema.columns
			where table_schema = current_schema() and table_name = case when $1 = 'size_bytes' then 'repositories' else 'index_jobs' end and column_name = $1)`, column).Scan(&found); err != nil || !found {
			t.Fatalf("column %s: found=%v err=%v", column, found, err)
		}
	}
	var nullable, index, lease string
	if err := pool.QueryRow(t.Context(), `select is_nullable from information_schema.columns
		where table_schema = current_schema() and table_name = 'webhook_deliveries' and column_name = 'installation_id'`).Scan(&nullable); err != nil || nullable != "YES" {
		t.Fatalf("installation_id nullable=%q err=%v", nullable, err)
	}
	if err := pool.QueryRow(t.Context(), `select is_nullable from information_schema.columns
		where table_schema = current_schema() and table_name = 'webhook_deliveries' and column_name = 'repository_id'`).Scan(&nullable); err != nil || nullable != "YES" {
		t.Fatalf("repository_id nullable=%q err=%v", nullable, err)
	}
	if err := pool.QueryRow(t.Context(), `select indexdef from pg_indexes where schemaname = current_schema() and indexname = 'index_jobs_claim'`).Scan(&index); err != nil || !strings.Contains(index, "priority DESC") {
		t.Fatalf("claim index=%q err=%v", index, err)
	}
	if err := pool.QueryRow(t.Context(), `select pg_get_constraintdef(oid) from pg_constraint
		where conrelid = 'index_jobs'::regclass and conname = 'index_jobs_check'`).Scan(&lease); err != nil || !strings.Contains(lease, "<> 'running'::text") {
		t.Fatalf("lease constraint=%q err=%v", lease, err)
	}
}

func TestMigrateUpgradesIntermediateV1(t *testing.T) {
	pool := testPool(t)
	legacy, err := migrationFiles.ReadFile("migrations/001_milestone_2.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), string(legacy)); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"alter table webhook_deliveries alter column installation_id drop not null",
		"alter table index_jobs add column target_ref text not null default ''",
		"alter table index_jobs add column reason varchar(128) not null default 'unspecified'",
		"alter table index_jobs add column priority integer not null default 0",
		"alter table index_jobs add column max_attempts integer not null default 5 check (max_attempts between 1 and 5)",
		"alter table index_jobs drop constraint index_jobs_check",
		"alter table index_jobs add check ((state = 'running' and lease_owner is not null and lease_expires_at is not null) or (state <> 'running' and lease_owner is null and lease_expires_at is null))",
		"drop index index_jobs_claim",
		"create index index_jobs_claim on index_jobs(priority desc, run_after, id) where state = 'queued'",
		"create table schema_migrations (version bigint primary key)",
		"insert into schema_migrations (version) values (1)",
	} {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	var found bool
	if err := pool.QueryRow(t.Context(), `select exists(
		select 1 from information_schema.columns
		where table_schema = current_schema() and table_name = 'repositories' and column_name = 'size_bytes')`).Scan(&found); err != nil || !found {
		t.Fatalf("size_bytes found=%v err=%v", found, err)
	}
}

func TestIndexJobLeaseConstraint(t *testing.T) {
	pool := testPool(t)
	if err := Migrate(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	var installationID int64
	if err := pool.QueryRow(t.Context(), `
		insert into installations (github_id, account_login, account_type, status)
		values (1, 'test', 'User', 'active') returning id`).Scan(&installationID); err != nil {
		t.Fatal(err)
	}
	nextRepositoryID := int64(1)
	newRepository := func() int64 {
		nextRepositoryID++
		var repositoryID int64
		if err := pool.QueryRow(t.Context(), `
			insert into repositories (
				github_id, installation_id, owner, name, clone_url, web_url,
				default_branch, private, archived, enabled, status
			) values ($1, $2, 'owner', $3, 'https://example.invalid/clone',
				'https://example.invalid/web', 'main', false, false, true, 'pending')
			returning id`, nextRepositoryID, installationID, fmt.Sprintf("repository-%d", nextRepositoryID)).Scan(&repositoryID); err != nil {
			t.Fatal(err)
		}
		return repositoryID
	}
	expectRejected := func(state string, owner, expires any) {
		t.Helper()
		_, err := pool.Exec(t.Context(), `
			insert into index_jobs (repository_id, target_sha, state, lease_owner, lease_expires_at)
			values ($1, repeat('a', 40), $2, $3, $4)`, newRepository(), state, owner, expires)
		if err == nil {
			t.Fatalf("state %q accepted incomplete lease", state)
		}
	}

	for _, state := range []string{"queued", "succeeded", "failed", "superseded"} {
		expectRejected(state, "worker", nil)
		expectRejected(state, nil, time.Now())
	}
	expectRejected("running", "worker", nil)
	expectRejected("running", nil, time.Now())
	if _, err := pool.Exec(t.Context(), `
		insert into index_jobs (repository_id, target_sha, state, lease_owner, lease_expires_at)
		values ($1, repeat('a', 40), 'running', 'worker', now())`, newRepository()); err != nil {
		t.Fatal(err)
	}
}
