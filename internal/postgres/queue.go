package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/grepnest/grepnest/internal/admin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Store) AdminJobs(ctx context.Context, installationID int64, repositoryIDs []int64, limit int, cursor *admin.JobCursor) ([]admin.Job, bool, error) {
	var updatedAt *time.Time
	var id int64
	if cursor != nil {
		updatedAt, id = &cursor.UpdatedAt, cursor.ID
	}
	rows, err := s.pool.Query(ctx, `select jobs.id,repositories.github_id,repositories.owner||'/'||repositories.name,
		jobs.target_sha,jobs.target_ref,jobs.reason,jobs.state,coalesce(jobs.error_code,''),jobs.attempt,jobs.max_attempts,
		jobs.priority,jobs.run_after,jobs.created_at,jobs.updated_at from index_jobs jobs
		join repositories on repositories.id=jobs.repository_id join installations on installations.id=repositories.installation_id
		where ($1=0 and coalesce(cardinality($2::bigint[]),0)=0 and installations.status='active' and repositories.enabled and not repositories.archived
			or ($1=0 or installations.github_id=$1) and repositories.github_id=any($2))
		and ($3::timestamptz is null or (jobs.updated_at, jobs.id) < ($3, $4))
		order by jobs.updated_at desc, jobs.id desc
		limit $5`, installationID, repositoryIDs, updatedAt, id, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items := make([]admin.Job, 0, limit+1)
	for rows.Next() {
		var x admin.Job
		if err := rows.Scan(&x.ID, &x.RepositoryID, &x.Repository, &x.TargetSHA, &x.TargetRef, &x.Reason, &x.State, &x.ErrorCode, &x.Attempt, &x.MaxAttempts, &x.Priority, &x.RunAfter, &x.CreatedAt, &x.UpdatedAt); err != nil {
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

func (s *Store) EnqueueAdminIndex(ctx context.Context, r admin.IndexRequest) error {
	return s.EnqueueIndex(ctx, IndexRequest{RepositoryID: r.RepositoryID, TargetSHA: r.TargetSHA, TargetRef: r.TargetRef, Reason: r.Reason})
}

func (s *Store) RetryAdminJob(ctx context.Context, installationID int64, repositoryIDs []int64, id int64) error {
	result, err := s.pool.Exec(ctx, `update index_jobs jobs set state='queued',run_after=now(),lease_owner=null,
		lease_expires_at=null,error_code=null,error_message=null,attempt=0,updated_at=now() from repositories
		join installations on installations.id=repositories.installation_id where jobs.id=$1
		and jobs.repository_id=repositories.id and jobs.state='failed' and jobs.target_sha=repositories.desired_sha
		and repositories.enabled and not repositories.archived and installations.status='active'
		and ($2=0 and coalesce(cardinality($3::bigint[]),0)=0
			or ($2=0 or installations.github_id=$2) and repositories.github_id=any($3))`, id, installationID, repositoryIDs)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

var ErrNoJob = errors.New("no index job available")
var ErrLeaseLost = errors.New("index job lease lost")

type IndexRequest struct {
	RepositoryID                 int64
	TargetSHA, TargetRef, Reason string
	Priority, MaxAttempts        int
}

type IndexJob struct {
	ID, RepositoryID             int64
	TargetSHA, TargetRef, Reason string
	State, LeaseOwner            string
	Attempt, Priority            int
	MaxAttempts                  int
	LeaseExpiresAt               time.Time
}

func (s *Store) EnqueueIndex(ctx context.Context, request IndexRequest) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := enqueueIndex(ctx, tx, request); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func enqueueIndex(ctx context.Context, tx pgx.Tx, request IndexRequest) error {
	var desiredSHA *string
	var defaultBranch string
	if err := tx.QueryRow(ctx, `select desired_sha, default_branch from repositories where id=$1 for update`, request.RepositoryID).Scan(&desiredSHA, &defaultBranch); err != nil {
		return err
	}
	if request.TargetRef == "" {
		request.TargetRef = "refs/heads/" + defaultBranch
	}
	if request.Reason == "" {
		request.Reason = "reconcile"
	}
	if request.MaxAttempts <= 0 || request.MaxAttempts > 5 {
		request.MaxAttempts = 5
	}
	if _, err := tx.Exec(ctx, `update repositories set desired_sha=$2, status='pending', error_code=null, updated_at=now() where id=$1`, request.RepositoryID, request.TargetSHA); err != nil {
		return err
	}
	if desiredSHA != nil && *desiredSHA == request.TargetSHA {
		var exists bool
		if err := tx.QueryRow(ctx, `select exists(select 1 from index_jobs where repository_id=$1 and state in ('queued','running') and target_sha=$2)`, request.RepositoryID, request.TargetSHA).Scan(&exists); err != nil || exists {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `delete from index_jobs where repository_id=$1 and state='queued'`, request.RepositoryID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `insert into index_jobs(repository_id, target_ref, target_sha, reason, priority, max_attempts, state)
		values($1,$2,$3,$4,$5,$6,'queued')`, request.RepositoryID, request.TargetRef, request.TargetSHA, request.Reason, request.Priority, request.MaxAttempts)
	return err
}

func (s *Store) ClaimIndex(ctx context.Context, owner string) (IndexJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return IndexJob{}, err
	}
	defer tx.Rollback(ctx)
	var job IndexJob
	err = tx.QueryRow(ctx, `
		with next as (
			select j.id from installations
			join repositories on repositories.installation_id=installations.id
			join index_jobs j on j.repository_id=repositories.id
			where j.state='queued' and j.run_after<=now() and repositories.enabled
			and not repositories.archived and installations.status='active'
			and not exists(select 1 from index_jobs running where running.repository_id=j.repository_id and running.state='running')
			order by j.priority desc, j.run_after, j.id
			for share of installations for update of repositories, j skip locked limit 1
		)
		update index_jobs set state='running', attempt=attempt+1, lease_owner=$1,
			lease_expires_at=now()+interval '2 minutes', updated_at=now()
		where id=(select id from next)
		returning id, repository_id, target_ref, target_sha, reason, priority, max_attempts,
			state, lease_owner, attempt, lease_expires_at`, owner).
		Scan(&job.ID, &job.RepositoryID, &job.TargetRef, &job.TargetSHA, &job.Reason, &job.Priority, &job.MaxAttempts,
			&job.State, &job.LeaseOwner, &job.Attempt, &job.LeaseExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return IndexJob{}, ErrNoJob
	}
	if err != nil {
		return IndexJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return IndexJob{}, err
	}
	return job, nil
}

func (s *Store) RenewLease(ctx context.Context, id int64, owner string) error {
	result, err := s.pool.Exec(ctx, `update index_jobs set lease_expires_at=now()+interval '2 minutes', updated_at=now()
		where id=$1 and state='running' and lease_owner=$2 and lease_expires_at>now()`, id, owner)
	return leaseResult(result, err)
}

func (s *Store) CompleteIndex(ctx context.Context, id int64, owner string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var repositoryID int64
	var targetSHA, desiredSHA, installationStatus string
	var enabled, archived bool
	if err := tx.QueryRow(ctx, `select repositories.id, index_jobs.target_sha,
		coalesce(repositories.desired_sha, ''), repositories.enabled, repositories.archived, installations.status
		from installations join repositories on repositories.installation_id=installations.id
		join index_jobs on index_jobs.repository_id=repositories.id
		where index_jobs.id=$1 and index_jobs.state='running' and index_jobs.lease_owner=$2
		and index_jobs.lease_expires_at>now()
		for share of installations for update of repositories, index_jobs`, id, owner).
		Scan(&repositoryID, &targetSHA, &desiredSHA, &enabled, &archived, &installationStatus); errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	} else if err != nil {
		return err
	}
	state := "superseded"
	errorCode := ""
	available := enabled && !archived && installationStatus == "active"
	if available && desiredSHA == targetSHA {
		state = "succeeded"
		if _, err := tx.Exec(ctx, `update repositories set indexed_sha=$2, status='ready', error_code=null, last_indexed_at=now(), updated_at=now() where id=$1`, repositoryID, targetSHA); err != nil {
			return err
		}
		if err := enqueueGraph(ctx, tx, repositoryID, targetSHA); err != nil {
			return err
		}
	} else if !available {
		errorCode = "repository_unavailable"
	}
	if _, err := tx.Exec(ctx, `update index_jobs set state=$2, lease_owner=null, lease_expires_at=null,
		error_code=nullif($3, ''), error_message=null, updated_at=now() where id=$1`, id, state, errorCode); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func enqueueGraph(ctx context.Context, tx pgx.Tx, repositoryID int64, targetSHA string) error {
	_, err := tx.Exec(ctx, `update graph_jobs set state='superseded', updated_at=now()
		where repository_id=$1 and state='queued' and target_sha<>$2`, repositoryID, targetSHA)
	if err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `select exists(select 1 from graph_jobs
		where repository_id=$1 and target_sha=$2 and state in ('queued','running'))`, repositoryID, targetSHA).Scan(&exists); err != nil || exists {
		return err
	}
	_, err = tx.Exec(ctx, `insert into graph_jobs(repository_id,target_sha,state,max_attempts)
		values($1,$2,'queued',5)
		on conflict do nothing`, repositoryID, targetSHA)
	return err
}

func (s *Store) FailIndex(ctx context.Context, id int64, owner, errorCode string, retry bool) error {
	return s.finishFailure(ctx, id, owner, errorCode, retry)
}

func (s *Store) finishFailure(ctx context.Context, id int64, owner, errorCode string, retry bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var repositoryID int64
	var targetSHA, desiredSHA, installationStatus string
	var enabled, archived bool
	var attempt, maxAttempts int
	if err := tx.QueryRow(ctx, `select repositories.id, index_jobs.target_sha, repositories.desired_sha,
		repositories.enabled, repositories.archived, installations.status, index_jobs.attempt, index_jobs.max_attempts
		from installations join repositories on repositories.installation_id=installations.id
		join index_jobs on index_jobs.repository_id=repositories.id
		where index_jobs.id=$1 and index_jobs.state='running' and index_jobs.lease_owner=$2
		and index_jobs.lease_expires_at>now()
		for share of installations for update of repositories, index_jobs`, id, owner).
		Scan(&repositoryID, &targetSHA, &desiredSHA, &enabled, &archived, &installationStatus, &attempt, &maxAttempts); errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	} else if err != nil {
		return err
	}
	state := "failed"
	if !enabled || archived || installationStatus != "active" {
		state, errorCode = "superseded", "repository_unavailable"
	} else if desiredSHA != targetSHA {
		state = "superseded"
	} else if retry && attempt < maxAttempts {
		state = "queued"
	}
	if _, err := tx.Exec(ctx, `update index_jobs set state=$2, lease_owner=null, lease_expires_at=null,
		error_code=$3, error_message=null,
		run_after=case when $2::varchar='queued' then now()+interval '1 second'*
			least(5*power(2::double precision, attempt-1), 300)*random() else run_after end,
		updated_at=now() where id=$1`, id, state, errorCode); err != nil {
		return err
	}
	if state == "failed" {
		if _, err := tx.Exec(ctx, `update repositories set status='failed', error_code=$2, updated_at=now() where id=$1 and enabled`, repositoryID, errorCode); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ReapExpired(ctx context.Context, limit int) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	type expiredJob struct {
		id, repositoryID int64
		target, desired  string
		attempt, maximum int
		available        bool
	}
	rows, err := tx.Query(ctx, `select j.id, j.repository_id, j.target_sha, r.desired_sha, j.attempt,
		j.max_attempts, r.enabled and not r.archived and i.status='active'
		from installations i join repositories r on r.installation_id=i.id
		join index_jobs j on j.repository_id=r.id
		where j.state='running' and j.lease_expires_at<=now()
		order by j.lease_expires_at, j.id
		for share of i for update of r, j skip locked limit $1`, limit)
	if err != nil {
		return 0, err
	}
	var jobs []expiredJob
	for rows.Next() {
		var job expiredJob
		if err := rows.Scan(&job.id, &job.repositoryID, &job.target, &job.desired, &job.attempt, &job.maximum, &job.available); err != nil {
			rows.Close()
			return 0, err
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, job := range jobs {
		state := "failed"
		errorCode := "lease_expired"
		if !job.available {
			state, errorCode = "superseded", "repository_unavailable"
		} else if job.desired != job.target {
			state = "superseded"
		} else if job.attempt < job.maximum {
			state = "queued"
		}
		if _, err := tx.Exec(ctx, `update index_jobs set state=$2, lease_owner=null, lease_expires_at=null,
			error_code=$3, error_message=null,
			run_after=case when $2::varchar='queued' then now()+interval '1 second'*
				least(5*power(2::double precision, attempt-1), 300)*random() else run_after end,
			updated_at=now() where id=$1`, job.id, state, errorCode); err != nil {
			return 0, err
		}
		if state == "failed" {
			if _, err := tx.Exec(ctx, `update repositories set status='failed', error_code='lease_expired', updated_at=now() where id=$1 and enabled`, job.repositoryID); err != nil {
				return 0, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return int64(len(jobs)), nil
}

func (s *Store) ActiveJobIDs(ctx context.Context) (map[int64]struct{}, error) {
	rows, err := s.pool.Query(ctx, `select id from index_jobs where state='running' and lease_expires_at>now()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[int64]struct{}{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result[id] = struct{}{}
	}
	return result, rows.Err()
}

func (s *Store) QueueDepths(ctx context.Context) (map[string]int64, error) {
	result := map[string]int64{"queued": 0, "running": 0, "succeeded": 0, "failed": 0, "superseded": 0}
	rows, err := s.pool.Query(ctx, `select state, count(*) from index_jobs where state in ('queued','running','succeeded','failed','superseded') group by state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var count int64
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		result[state] = count
	}
	return result, rows.Err()
}

func (s *Store) Prune(ctx context.Context) (int64, int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)
	deliveries, err := tx.Exec(ctx, `delete from webhook_deliveries where received_at<now()-interval '30 days'`)
	if err != nil {
		return 0, 0, err
	}
	jobs, err := tx.Exec(ctx, `delete from index_jobs where id in (
		select id from (select id, row_number() over(partition by repository_id order by updated_at desc, id desc) rank
			from index_jobs where state in ('succeeded','failed','superseded')) terminal where rank>100)`)
	if err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	return deliveries.RowsAffected(), jobs.RowsAffected(), nil
}

func leaseResult(result pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return nil
}
